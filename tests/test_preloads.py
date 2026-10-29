"""Tests gegen Fehlalarme bei Hersteller-Vorinstallationen (Xiaomi, Oppo, Samsung).

Auf solchen Geraeten haben viele Drittanbieter-Apps installer=null, obwohl sie
vom Hersteller oder Partner vorinstalliert sind. Seitlich per adb oder Datei
installierte Apps muessen trotzdem weiter auffallen.
"""

from __future__ import annotations

from appanalyse.collect import mark_oem_signed
from appanalyse.models import ApkAnalysis, AppInfo, Priority, Reputation
from appanalyse.parsers import dumpsys_package
from appanalyse.scoring import score_app


def _app(**kw) -> AppInfo:
    base = dict(
        package="com.vendor.helper",
        users=[0],
        installer="",
        initiating_installer="",
        initiating_recorded=True,  # Android 11+
        launcher_activities=[],
        apk=ApkAnalysis(label="Helper", has_launcher=False, exclude_from_recents=True),
        reputation=Reputation(in_play=False, in_fdroid=False),
    )
    base.update(kw)
    return AppInfo(**base)


def texte(app):
    return " ".join(f.text for f in app.findings)


# -- Parser ---------------------------------------------------------------


def test_parser_liest_install_reason_und_ausloeser():
    text = (
        "Packages:\n"
        "  Package [com.miui.x] (1):\n"
        "    installerPackageName=null\n"
        "    initiatingPackageName=null\n"
        "    signatures=PackageSignatures{a version:3, signatures:[b2d95fc0], past signatures:[]}\n"
        "    User 0: ceDataInode=1 installed=true hidden=false suspended=false stopped=false enabled=0\n"
        "      installReason=0\n"
        "  Package [com.old.app] (2):\n"
        "    installerPackageName=null\n"
        "    User 0: ceDataInode=2 installed=true enabled=0\n"
    )
    b = dumpsys_package.parse(text)
    assert b["com.miui.x"].initiating_recorded is True
    assert b["com.miui.x"].users[0].install_reason == "0"
    assert b["com.miui.x"].signature_hash == "b2d95fc0"
    # Aelteres Android: Zeile fehlt -> nicht unterscheidbar
    assert b["com.old.app"].initiating_recorded is False


# -- Signaturvergleich ----------------------------------------------------


def test_signatur_kurzwert_begruendet_keine_herstellersignatur():
    text = (
        "Packages:\n"
        "  Package [android] (1):\n"
        "    codePath=/system/framework/framework-res.apk\n"
        "    flags=[ SYSTEM ]\n"
        "    signatures=PackageSignatures{a version:3, signatures:[b2d95fc0], past signatures:[]}\n"
        "  Package [com.miui.cleaner] (2):\n"
        "    codePath=/data/app/~~x==/com.miui.cleaner-y==\n"
        "    signatures=PackageSignatures{b version:3, signatures:[b2d95fc0], past signatures:[]}\n"
        "  Package [de.fremd.app] (3):\n"
        "    codePath=/data/app/~~z==/de.fremd.app-w==\n"
        "    signatures=PackageSignatures{c version:2, signatures:[deadbeef], past signatures:[]}\n"
    )
    blocks = dumpsys_package.parse(text)
    apps = {
        "com.miui.cleaner": AppInfo(package="com.miui.cleaner", signature_hash="b2d95fc0"),
        "de.fremd.app": AppInfo(package="de.fremd.app", signature_hash="deadbeef"),
    }
    mark_oem_signed(apps, blocks)
    assert apps["com.miui.cleaner"].oem_signed is False
    assert apps["de.fremd.app"].oem_signed is False


def test_legacy_herstellerflag_ueberstimmt_keine_herkunft():
    app = _app(oem_signed=True, signature_hash="b2d95fc0")
    score_app(app)
    assert app.priority == Priority.UNAUFFAELLIG
    assert app.scores["herkunft"] == 5
    assert "kein kryptografischer Identitaetsnachweis" in texte(app)
    assert "Vom Hersteller signiert" not in texte(app)


# -- Partner-Vorinstallation (fremd signiert, installer=null) ------------


def test_partner_vorinstallation_kein_fehlalarm():
    # z. B. com.facebook.appmanager auf Samsung/Xiaomi: installer=null,
    # Ausloeser=null, nicht im Play Store, kein Launcher.
    app = _app(package="com.facebook.appmanager")
    score_app(app)
    assert app.priority == Priority.UNAUFFAELLIG
    assert app.scores["herkunft"] == 5  # nur der Vorinstallations-Hinweis
    assert app.scores["verschleierung"] < 25  # kein Launcher zaehlt hier nicht
    assert "Vorinstallation" in texte(app)


def test_gleiches_profil_per_adb_bleibt_verdaechtig():
    # Identisch, aber per adb installiert -> darf NICHT entschaerft werden.
    app = _app(initiating_installer="com.android.shell",
               apk=ApkAnalysis(label="Helper", has_launcher=False, exclude_from_recents=True,
                               libraries=["OkHttp WebSocket"]))
    score_app(app)
    assert "Per adb" in texte(app)
    assert app.scores["herkunft"] >= 40
    assert app.priority == Priority.UNBEDINGT_PRUEFEN


def test_aus_datei_installiert():
    app = _app(installer="com.google.android.packageinstaller")
    score_app(app)
    assert "APK-Datei" in texte(app)


def test_aelteres_android_bleibt_vorsichtig():
    app = _app(initiating_recorded=False)
    score_app(app)
    assert "aeltere Android-Version" in texte(app)
    assert app.scores["herkunft"] >= 40  # 20 + nicht Play + nicht F-Droid


def test_smart_switch_ausloeser():
    app = _app(initiating_installer="com.sec.android.easyMover")
    score_app(app)
    assert "ausgeloest durch com.sec.android.easyMover" in texte(app)


# -- Deaktivierte Bloatware ----------------------------------------------


def test_deaktivierte_app_ohne_launcher_ist_keine_tarnung():
    app = _app(initiating_installer="com.android.shell", enabled=False,
               apk=ApkAnalysis(label="Bloat", has_launcher=True))
    score_app(app)
    assert "Launcher" not in texte(app)
    assert "komplett deaktiviert" in texte(app)


def test_messenger_ohne_installquelle_bekommt_echtheitshinweis():
    app = _app(package="com.facebook.orca",
               apk=ApkAnalysis(label="Messenger", has_launcher=True),
               launcher_activities=["com.facebook.orca/.Main"])
    score_app(app)
    assert app.priority == Priority.BEKANNTER_MESSENGER
    assert "Echtheit" in texte(app)
