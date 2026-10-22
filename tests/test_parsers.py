"""Tests der ADB-Ausgabeparser gegen anonymisierte Fixtures und Grenzfaelle."""

from __future__ import annotations

import pathlib

import pytest

from appanalyse.parsers import (
    activity,
    appops,
    dumpsys_package,
    netstats,
    notification,
    pm,
    special_access,
    usagestats,
    users,
)

FIX = pathlib.Path(__file__).parent / "fixtures"


def read(name: str) -> str:
    return (FIX / name).read_text("utf-8")


# -- dumpsys package ------------------------------------------------------


@pytest.fixture(scope="module")
def blocks():
    return dumpsys_package.parse(read("dumpsys_packages.txt"))


def test_alle_pakete_erkannt(blocks):
    assert set(blocks) == {
        "com.android.settings",
        "org.telegram.messenger.web",
        "de.rechenhilfe.app",
        "com.hidden.vault",
        "com.work.chatclient",
    }


def test_systemapp_erkennung(blocks):
    settings = blocks["com.android.settings"]
    assert settings.is_system is True
    assert settings.users[0].enabled is True
    assert settings.installer == ""  # null -> leer


def test_sideloaded_messenger(blocks):
    tg = blocks["org.telegram.messenger.web"]
    assert tg.is_system is False
    assert tg.installer == "com.android.packageinstaller"
    assert tg.package_source == "3"  # aus Datei installiert
    assert tg.signature_hash == "9744bfe6"
    assert tg.version_name == "12.8.0"
    u0 = tg.users[0]
    assert u0.runtime_permissions["android.permission.INTERNET"][0] is True
    assert u0.runtime_permissions["android.permission.RECORD_AUDIO"][0] is False


def test_adb_installiert_ueber_shell(blocks):
    app = blocks["de.rechenhilfe.app"]
    assert app.installer == "com.android.shell"  # klassisches adb install
    assert app.package_source == "3"


def test_deaktivierte_launcher_komponente(blocks):
    vault = blocks["com.hidden.vault"]
    u0 = vault.users[0]
    assert u0.enabled is False  # enabled=2 -> deaktiviert
    assert "com.hidden.vault/.LauncherActivity" in u0.disabled_components
    assert vault.installer == ""


def test_nur_zweitprofil(blocks):
    app = blocks["com.work.chatclient"]
    assert app.users[0].installed is False
    assert app.users[10].installed is True


def test_leerer_block_bricht_nicht():
    # Ein Block ohne Felder darf keine Ausnahme werfen.
    text = "Packages:\n  Package [x.y] (0):\n"
    parsed = dumpsys_package.parse(text)
    assert "x.y" in parsed
    assert parsed["x.y"].users == {}


# -- pm list --------------------------------------------------------------


def test_pm_detail_pfad_mit_gleichheitszeichen():
    entries, bad = pm.parse_detail(read("pm_list.txt"))
    assert not bad
    tg = entries["org.telegram.messenger.web"]
    # Der APK-Pfad enthaelt '==' und muss vollstaendig erhalten bleiben.
    assert tg.apk_path.endswith("/base.apk")
    assert "==" in tg.apk_path
    assert tg.installer == "com.android.packageinstaller"
    assert tg.uid == "10198"


def test_pm_detail_meldet_kaputte_zeile():
    entries, bad = pm.parse_detail("kaputt ohne package praefix\n")
    assert entries == {}
    assert len(bad) == 1


# -- users ----------------------------------------------------------------


def test_profile_typen():
    profs = {p.user_id: p for p in users.parse(read("users.txt"))}
    assert profs[0].type == "primaer"
    assert profs[10].type == "private_space"
    assert profs[10].running is True


# -- launchers ------------------------------------------------------------


def test_launcher_aliase():
    launchers = activity.parse_launchers(read("launchers.txt"))
    assert len(launchers["org.telegram.messenger.web"]) == 2
    assert "de.rechenhilfe.app" in launchers
    assert "com.hidden.vault" not in launchers  # kein Launcher-Eintrag


# -- services -------------------------------------------------------------


def test_services_foreground():
    text = (
        "  * ServiceRecord{1 u0 com.foo.app/.ChatService c:com.foo.app}\n"
        "    app=ProcessRecord{2 100:com.foo.app/u0a1}\n"
        "    isForeground=true foregroundServiceType=remoteMessaging\n"
        "  * ServiceRecord{3 u0 com.bar.app/.SyncService c:com.bar.app}\n"
        "    app=ProcessRecord{4 200:com.bar.app/u0a2}\n"
    )
    info = activity.parse_services(text)
    assert "com.foo.app" in info.foreground
    assert "com.bar.app" in info.packages
    assert "com.bar.app" not in info.foreground


# -- netstats -------------------------------------------------------------


def test_netstats_summiert_nur_tag0():
    text = (
        "  ident=[{...}] uid=10198 set=DEFAULT tag=0x0\n"
        "    NetworkStatsHistory: bucketDuration=7200\n"
        "      st=1 rb=100 rp=1 tb=40 tp=1 op=0\n"
        "      st=2 rb=50 rp=1 tb=10 tp=1 op=0\n"
        "  ident=[{...}] uid=10198 set=DEFAULT tag=0x8003\n"
        "    NetworkStatsHistory: bucketDuration=7200\n"
        "      st=1 rb=999 rp=1 tb=999 tp=1 op=0\n"
    )
    stats = netstats.parse(text)
    assert stats["10198"] == (150, 50)  # getaggter Block 0x8003 ignoriert


def test_netstats_live_zaehler_ergaenzen_verlauf():
    # App ohne gespeicherten Verlauf, aber mit Live-Zaehlern (gerade erst genutzt).
    text = (
        "  ident=[{...}] uid=10198 set=FOREGROUND tag=0x0\n"
        "    NetworkStatsHistory: bucketDuration=7200\n"
        "      st=1 rb=100 rp=1 tb=40 tp=1 op=0\n"
        "  mAppUidStatsMap:\n"
        "    uid rxBytes rxPackets txBytes txPackets\n"
        "    10198 90 2 500 3\n"
        "    10216 2214 13 1327 13\n"
        "  mUidCounterSetMap:\n"
    )
    stats = netstats.parse(text)
    assert stats["10216"] == (2214, 1327)  # nur live vorhanden
    assert stats["10198"] == (100, 500)  # je Richtung der groessere Wert


# -- usagestats -----------------------------------------------------------


def test_usagestats_nimmt_spaeteste_nutzung():
    text = (
        'package=com.foo lastTimeUsed="2026-09-01 10:00:00" appLaunchCount=2\n'
        'package=com.foo lastTimeUsed="2026-09-20 18:30:00" appLaunchCount=7\n'
        'package=com.never lastTimeUsed="1970-01-01 01:00:00" appLaunchCount=0\n'
    )
    u = usagestats.parse(text)
    assert u["com.foo"].last_used == "2026-09-20 18:30:00"
    assert u["com.foo"].launch_count == 7
    assert u["com.never"].last_used == ""  # Epoch-Anfang gilt als nie genutzt


# -- notification ---------------------------------------------------------


def test_notification_zaehlt_ohne_inhalt():
    text = (
        "    NotificationRecord(0x1: pkg=com.foo user=UserHandle{0} id=1: Notification(...))\n"
        "    NotificationRecord(0x2: pkg=com.foo user=UserHandle{0} id=2: Notification(...))\n"
        "    NotificationRecord(0x3: pkg=com.bar user=UserHandle{0} id=3: Notification(...))\n"
    )
    counts = notification.parse(text)
    assert counts == {"com.foo": 2, "com.bar": 1}


# -- special access -------------------------------------------------------


def test_component_liste():
    value = "com.a/.L1:com.b/.L2"
    assert special_access.parse_component_list(value) == {"com.a", "com.b"}
    assert special_access.parse_component_list("null") == set()


def test_role_holder():
    assert special_access.parse_role_holder("com.android.messaging\n") == "com.android.messaging"
    assert special_access.parse_role_holder("") == ""


# -- appops ---------------------------------------------------------------


def test_appops_nur_relevante():
    text = (
        "Uid mode: COARSE_LOCATION: ignore\n"
        "CAMERA: foreground\n"
        "RECORD_AUDIO: allow\n"
        "SYSTEM_ALERT_WINDOW: allow\n"
        "READ_HEART_RATE: ignore\n"
    )
    ops = appops.parse(text)
    assert ops["CAMERA"] == "foreground"
    assert ops["SYSTEM_ALERT_WINDOW"] == "allow"
    assert "READ_HEART_RATE" not in ops  # nicht relevant
