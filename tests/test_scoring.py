"""Tests der Bewertungslogik: Kategoriesummen und Prioritaeten je Szenario."""

from __future__ import annotations

from appanalyse.models import (
    ApkAnalysis,
    AppInfo,
    CertInfo,
    Permission,
    Priority,
    Reputation,
)
from appanalyse.scoring import score_app


def _perm(name, granted=True):
    return Permission(name=name, granted=granted, runtime=True)


def _tarnchat_app() -> AppInfo:
    """Getarnte, selbst gebaute Chat-App wie die Test-App 'Rechner'."""
    apk = ApkAnalysis(
        label="Rechner",
        sha256="a" * 64,
        debuggable=True,
        libraries=["OkHttp WebSocket"],
        library_evidence={"OkHttp WebSocket": "Lokhttp3/internal/ws/RealWebSocket;"},
        protocol_signatures=["WebSocket-GUID"],
        protocol_evidence={"WebSocket-GUID": "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"},
        endpoints=["wss://203.0.113.7:8443/ws"],
        fg_service_types=["remoteMessaging"],
        pinning=True,
        exclude_from_recents=True,
        has_launcher=True,  # Manifest hat Launcher (Rechner-Activity)
        certificates=[CertInfo(subject="Common Name: Android Debug", is_debug=True)],
    )
    app = AppInfo(
        package="de.rechenhilfe.app",
        label="Rechner",
        installer="com.android.shell",
        package_source="3",
        first_install="2026-09-20 22:10:05",
        users=[0],
        launcher_activities=["de.rechenhilfe.app/.CalculatorActivity"],
        permissions=[_perm("android.permission.INTERNET"), _perm("android.permission.POST_NOTIFICATIONS")],
        apk=apk,
        reputation=Reputation(in_play=False, in_fdroid=False),
        rx_bytes=1000,
        tx_bytes=500,
    )
    return app


def test_tarnchat_wird_unbedingt_geprueft():
    app = _tarnchat_app()
    score_app(app)
    assert app.priority == Priority.UNBEDINGT_PRUEFEN
    # Belege muessen die entscheidenden Punkte nennen.
    texte = " ".join(f.text for f in app.findings)
    assert "Rechner" in texte  # Tarnname
    assert "remoteMessaging" in texte
    assert app.scores["chat"] >= 25
    assert app.scores["herkunft"] >= 40


def test_tarnchat_ohne_launcher_runtime():
    # Launcher-Komponente deaktiviert (Manifest-Launcher, aber kein Runtime-Eintrag).
    app = _tarnchat_app()
    app.launcher_activities = []
    score_app(app)
    texte = " ".join(f.text for f in app.findings)
    assert "Launcher-Komponente deaktiviert" in texte
    assert app.priority == Priority.UNBEDINGT_PRUEFEN


def test_bekannter_messenger_sideloaded():
    app = AppInfo(
        package="org.telegram.messenger.web",
        label="Telegram",
        installer="com.android.packageinstaller",
        package_source="3",
        users=[0],
        apk=ApkAnalysis(label="Telegram", libraries=["OkHttp WebSocket"]),
        reputation=Reputation(in_play=True),
        launcher_activities=["org.telegram.messenger.web/.Main"],
    )
    score_app(app)
    assert app.priority == Priority.BEKANNTER_MESSENGER
    assert any("Echtheit pruefen" in f.text for f in app.findings)


def test_systemapp_unauffaellig():
    app = AppInfo(
        package="com.android.settings",
        label="Einstellungen",
        is_system=True,
        users=[0],
        launcher_activities=["com.android.settings/.Settings"],
        apk=ApkAnalysis(label="Einstellungen", certificates=[CertInfo(subject="CN=Android, O=Google", self_signed=True)]),
    )
    score_app(app)
    assert app.priority == Priority.UNAUFFAELLIG
    assert app.scores["herkunft"] == 0


def test_ioc_treffer():
    app = AppInfo(package="com.spyzee", users=[0], reputation=Reputation(ioc_match="TheTruthSpy"))
    score_app(app)
    assert app.priority == Priority.UNBEDINGT_PRUEFEN
    assert any("IOC" in f.evidence for f in app.findings)


def test_bekannter_mod():
    app = AppInfo(package="com.gbwhatsapp", users=[0], launcher_activities=["x"])
    score_app(app)
    assert app.priority == Priority.UNBEDINGT_PRUEFEN


def test_accessibility_unbekannte_app():
    app = AppInfo(
        package="com.hidden.helper",
        users=[0],
        accessibility=True,
        launcher_activities=[],
        apk=ApkAnalysis(has_launcher=False),
    )
    score_app(app)
    assert app.priority == Priority.UNBEDINGT_PRUEFEN
    assert any("Bedienungshilfe" in f.text for f in app.findings)


def test_harmlose_sideload_app_ohne_chat():
    # Seitlich geladen, aber keinerlei Chat-/Verschleierungsmerkmale und im Store.
    app = AppInfo(
        package="com.example.hallo",
        label="Hallo",
        installer="com.android.vending",
        users=[0],
        launcher_activities=["com.example.hallo/.Main"],
        apk=ApkAnalysis(label="Hallo", has_launcher=True, certificates=[CertInfo(subject="CN=Dev, O=Firma GmbH, C=DE")]),
        reputation=Reputation(in_play=True),
    )
    score_app(app)
    # com.example -> Herkunftspunkte, aber kein Chat/Verschleierung.
    assert app.priority in (Priority.UNAUFFAELLIG, Priority.PRUEFEN_EMPFOHLEN)
    assert app.scores["chat"] == 0
