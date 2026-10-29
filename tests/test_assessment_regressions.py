"""Gegenbeispiele fuer die forensische Bewertungslogik."""

from copy import deepcopy

import pytest

from appanalyse.models import AppInfo, ApkAnalysis, DeviceInfo, Permission, Priority
from appanalyse.scoring import score_app


def disguised_calculator():
    return AppInfo(
        package="de.training.rechner", users=[0],
        installer="com.android.shell",
        launcher_activities=["de.training.rechner/.Main"],
        apk=ApkAnalysis(
            label="Rechner", libraries=["OkHttp WebSocket"],
            endpoints=["wss://training.invalid/ws"],
            fg_service_types=["remoteMessaging"], exclude_from_recents=True,
        ),
    )


@pytest.mark.parametrize("origin", ["store", "oem", "system"])
def test_release_calculator_function_hints_survive_origin(origin):
    baseline = disguised_calculator()
    app = deepcopy(baseline)
    if origin == "store":
        app.installer = "com.android.vending"
    elif origin == "oem":
        app.oem_signed = True
        app.signature_hash = "deadbeef"
    else:
        app.is_system = True
    score_app(baseline)
    score_app(app)
    assert app.priority == baseline.priority == Priority.UNBEDINGT_PRUEFEN
    assert app.score_v() == baseline.score_v()


@pytest.mark.parametrize("library", [False, True])
def test_calculator_with_only_network_capability_is_not_camouflage(library):
    app = AppInfo(
        package="de.training.calc", installer="com.android.shell", users=[0],
        launcher_activities=["de.training.calc/.Main"],
        permissions=[Permission("android.permission.INTERNET", granted=True)],
        apk=ApkAnalysis(label="Rechner", libraries=["OkHttp WebSocket"] if library else []),
    )
    score_app(app)
    assert app.score_v() == 0
    assert app.priority == Priority.UNAUFFAELLIG


@pytest.mark.parametrize("apk", [None, ApkAnalysis(error="Manifest nicht lesbar")])
def test_missing_or_failed_apk_is_not_a_clean_result(apk):
    app = AppInfo(package="de.training.tool", installer="com.android.vending", apk=apk,
                  launcher_activities=["de.training.tool/.Main"])
    score_app(app)
    assert app.priority == Priority.NICHT_BEURTEILBAR
    assert any("beurteilbar" in f.text or "unvollstaendig" in f.text for f in app.findings)


def test_existing_suspicion_is_retained_despite_partial_analysis():
    app = disguised_calculator()
    app.apk.error = "Zertifikate nicht auswertbar"
    score_app(app)
    assert app.priority == Priority.UNBEDINGT_PRUEFEN
    assert any("unvollstaendig" in f.text for f in app.findings)


def test_report_displays_incomplete_analysis_and_escapes_app_content(tmp_path):
    from appanalyse.report.html import write_all

    app = AppInfo(package="de.training.invalid", installer="com.android.vending",
                  launcher_activities=["de.training.invalid/.Main"],
                  apk=ApkAnalysis(label='<script>alert("app")</script>', error="Manifestfehler"))
    score_app(app)
    path = write_all(tmp_path, DeviceInfo(serial="test"), [app], {"online": False, "umfang": "Nur Test-App"})
    report = path.read_text(encoding="utf-8")
    assert "Nicht abschliessend beurteilbar" in report
    assert 'data-prio="p4"' in report
    assert "Manifestfehler" in report
    assert "Untersuchungsumfang: Nur Test-App" in report
    assert '<script>alert("app")</script>' not in report
    assert "&lt;script&gt;" in report


def test_scan_keeps_apk_of_clean_app_by_default(tmp_path, monkeypatch):
    from appanalyse import cli, collect
    from appanalyse.reputation.lookup import ReputationChecker

    def fake_scan(recorder, serial, options, reputation, apk_dir, progress):
        apk_dir.mkdir()
        (apk_dir / "de.training.clean.apk").write_bytes(b"retained evidence")
        app = AppInfo(package="de.training.clean", apk=ApkAnalysis(),
                      launcher_activities=["de.training.clean/.Main"])
        return DeviceInfo(serial=serial), [app]

    monkeypatch.setattr(cli, "_resolve_serial", lambda serial, console: "test")
    monkeypatch.setattr(collect, "run_scan", fake_scan)
    # Keine Benutzer-Caches oder Netzwerkzugriffe in diesem Integrationstest.
    monkeypatch.setattr(ReputationChecker, "__init__", lambda self, **kw: None)
    monkeypatch.setattr(ReputationChecker, "close", lambda self: None)
    assert cli.main(["scan", "--offline", "--out", str(tmp_path)]) == 0
    assert next(tmp_path.rglob("de.training.clean.apk")).read_bytes() == b"retained evidence"


def test_failed_apk_command_returns_partial_failure(tmp_path):
    from appanalyse.cli import main

    invalid = tmp_path / "invalid.apk"
    invalid.write_bytes(b"not an APK")
    assert main(["apk", str(invalid)]) == 2


def test_failed_pull_sets_partial_scan_status(tmp_path, monkeypatch):
    from appanalyse import collect
    from appanalyse.models import Profile, Reputation
    from appanalyse.recorder import Recorder, TEILWEISE

    class FakeCollector:
        def __init__(self, *args): pass
        def device_info(self): return DeviceInfo(serial="test")
        def profiles(self): return [Profile(user_id=0, running=True)]
        def collect_packages(self, profiles):
            return {"de.training.tool": AppInfo(package="de.training.tool", installer="com.android.vending",
                                                launcher_activities=["de.training.tool/.Main"])}
        def collect_launchers(self, *args): pass
        def collect_special_access(self, *args): pass
        def collect_activity(self, *args): pass
        def collect_appops(self, *args): pass
        def pull_apk(self, *args): return None

    class FakeReputation:
        def check(self, *args, **kw): return Reputation()

    monkeypatch.setattr(collect, "Collector", FakeCollector)
    recorder = Recorder(tmp_path)
    _, apps = collect.run_scan(recorder, "test", collect.ScanOptions(), FakeReputation(), tmp_path / "apks")
    assert apps[0].priority == Priority.NICHT_BEURTEILBAR
    status = next(s for s in recorder.status if s.step == "apk_analyse")
    assert status.state == TEILWEISE and status.count == 0
    assert recorder.finalize() == 2
