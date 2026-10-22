"""Tests des Reputationsabgleichs mit gemockter HTTP-Sitzung und echtem Cache."""

from __future__ import annotations

from appanalyse.models import ApkAnalysis, AppInfo, CertInfo
from appanalyse.reputation.cache import Cache
from appanalyse.reputation.ioc import IocDatabase
from appanalyse.reputation.lookup import ReputationChecker


class FakeResponse:
    def __init__(self, status: int, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeSession:
    """Simuliert requests.Session: liefert je URL-Muster eine feste Antwort."""

    def __init__(self, rules: dict[str, FakeResponse]):
        self.rules = rules
        self.headers = {}
        self.calls: list[str] = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        for needle, resp in self.rules.items():
            if needle in url:
                return resp
        return FakeResponse(500)


def _app(pkg="com.foo.chat", sha256="a" * 64):
    return AppInfo(package=pkg, apk=ApkAnalysis(sha256=sha256))


def test_play_und_fdroid_treffer(tmp_path):
    session = FakeSession(
        {
            "play.google.com": FakeResponse(200),
            "f-droid.org": FakeResponse(404),
        }
    )
    checker = ReputationChecker(cache=Cache(tmp_path), session=session)
    rep = checker.check(_app(), is_candidate=False)
    assert rep.in_play is True
    assert rep.in_fdroid is False


def test_cache_verhindert_zweite_abfrage(tmp_path):
    session = FakeSession({"play.google.com": FakeResponse(404), "f-droid.org": FakeResponse(200)})
    cache = Cache(tmp_path)
    checker = ReputationChecker(cache=cache, session=session)
    checker.check(_app(pkg="com.bar"), is_candidate=False)
    n_first = len(session.calls)
    # Zweiter Aufruf desselben Pakets darf keine neuen HTTP-Aufrufe ausloesen.
    checker2 = ReputationChecker(cache=cache, session=session)
    checker2.check(_app(pkg="com.bar"), is_candidate=False)
    assert len(session.calls) == n_first


def test_system_app_ueberspringt_online(tmp_path):
    session = FakeSession({"play.google.com": FakeResponse(200)})
    checker = ReputationChecker(cache=Cache(tmp_path), session=session)
    app = _app()
    app.is_system = True
    rep = checker.check(app, is_candidate=False)
    assert rep.in_play is None
    assert session.calls == []


def test_offline_macht_keine_abfragen(tmp_path):
    checker = ReputationChecker(offline=True, cache=Cache(tmp_path))
    rep = checker.check(_app(), is_candidate=False)
    assert rep.in_play is None
    assert checker.session is None


def test_ioc_treffer_per_paketname(tmp_path):
    cache = Cache(tmp_path)
    # IOC-Datenbank direkt setzen (statt Download).
    checker = ReputationChecker(offline=True, cache=cache)
    checker.ioc = IocDatabase({"com.spyzee": "TheTruthSpy"}, {})
    rep = checker.check(_app(pkg="com.spyzee"), is_candidate=False)
    assert rep.ioc_match == "TheTruthSpy"


def test_ioc_treffer_per_zertifikat(tmp_path):
    checker = ReputationChecker(offline=True, cache=Cache(tmp_path))
    checker.ioc = IocDatabase({}, {"aabbcc": "FamilieX"})
    app = _app()
    app.apk.certificates = [CertInfo(sha1="AABBCC")]
    rep = checker.check(app, is_candidate=False)
    assert rep.ioc_match == "FamilieX"


def test_vt_nur_fuer_kandidaten_mit_key(tmp_path):
    session = FakeSession(
        {
            "play.google.com": FakeResponse(200),
            "f-droid.org": FakeResponse(200),
            "virustotal.com": FakeResponse(404),
        }
    )
    checker = ReputationChecker(cache=Cache(tmp_path), vt_key="KEY", session=session)
    # Kein Kandidat -> kein VT.
    rep = checker.check(_app(), is_candidate=False)
    assert rep.vt_known is None
    assert not any("virustotal" in c for c in session.calls)
    # Kandidat -> VT wird abgefragt (404 => unbekannt).
    rep2 = checker.check(_app(pkg="com.candidate"), is_candidate=True)
    assert rep2.vt_known is False
    assert any("virustotal" in c for c in session.calls)
