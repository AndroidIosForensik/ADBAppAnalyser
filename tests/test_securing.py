"""Tests der Datensicherungs-Empfehlung (run-as / adb backup / root)."""

from __future__ import annotations

from appanalyse.models import ApkAnalysis, AppInfo
from appanalyse.securing import acquisition_plan


def _app(pkg="de.test.app", debuggable=False, allow_backup=True, system=False, apk=True):
    a = AppInfo(package=pkg, is_system=system)
    if apk:
        a.apk = ApkAnalysis(debuggable=debuggable, allow_backup=allow_backup)
    return a


def test_debuggable_nutzt_run_as_ohne_root():
    plan = acquisition_plan(_app(debuggable=True), "SER1")
    assert plan.method == "run-as"
    assert plan.root_required is False
    joined = " ".join(c for c, _ in plan.commands)
    assert "run-as de.test.app" in joined
    assert "-s SER1" in joined  # Seriennummer eingesetzt
    assert any("sha256sum" in c for c, _ in plan.commands)  # Beweiskette


def test_nicht_debuggable_mit_backup():
    plan = acquisition_plan(_app(debuggable=False, allow_backup=True), "SER1")
    assert plan.method == "adb-backup"
    assert plan.root_required is False
    assert any("backup" in c for c, _ in plan.commands)


def test_nicht_debuggable_ohne_backup_braucht_root():
    plan = acquisition_plan(_app(debuggable=False, allow_backup=False), "SER1")
    assert plan.method == "root"
    assert plan.root_required is True
    assert any("su -c" in c for c, _ in plan.commands)


def test_system_app():
    plan = acquisition_plan(_app(system=True), "SER1")
    assert plan.method == "system"
    assert plan.root_required is True


def test_ohne_seriennummer_platzhalter():
    plan = acquisition_plan(_app(debuggable=True), "")
    assert any("<SERIAL>" in c for c, _ in plan.commands)


def test_as_dict_struktur():
    d = acquisition_plan(_app(debuggable=True), "S").as_dict()
    assert d["methode"] == "run-as"
    assert d["root_noetig"] is False
    assert isinstance(d["befehle"], list) and d["befehle"][0]["befehl"]
