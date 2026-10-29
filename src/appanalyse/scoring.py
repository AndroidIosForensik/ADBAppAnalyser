"""Bewertung einer App anhand nachvollziehbarer Regeln.

Jede Regel erzeugt einen ``Finding`` mit Kategorie, Punkten, deutschem Text und
konkretem Beleg. Die Punkte summieren sich je Kategorie (Herkunft, Chat,
Verschleierung, Aktivitaet). Die Prioritaet ergibt sich aus harten Treffern
(IOC, Mod, Sonderzugriffe) und aus Schwellen der Kategoriesummen.

Die Gewichte sind bewusst als Konstanten gebuendelt, damit sie nach dem ersten
echten Scan leicht kalibriert werden koennen.
"""

from __future__ import annotations

from .datasets import Datasets, load as load_datasets
from .models import AppInfo, Category, Finding, Priority

# -- Gewichte --------------------------------------------------------------

W_INSTALLER_SIDELOAD = 25
W_INSTALLER_UNKNOWN = 20
W_PRELOAD_HINT = 5
W_NOT_IN_PLAY = 15
W_NOT_IN_FDROID = 10
W_VT_UNKNOWN = 15
W_DEBUG_CERT = 35
W_TEST_ONLY = 25
W_DEBUGGABLE = 20
W_THIN_DN = 10
W_PKG_EXAMPLE = 15
W_PKG_SYSTEMLIKE = 25

W_REALTIME_LIB = 25
W_FG_REMOTE_MSG = 20
W_ENDPOINTS = 15
W_CHAT_TERMS = 15
W_WEB_WRAPPER = 15
W_PINNING = 10
W_FCM = 5
W_SHARE_TARGET = 5
W_PERM_COMBO = 5
W_CRYPTO_LIB = 5

W_CAMOUFLAGE = 30
W_LAUNCHER_DISABLED = 25
W_NO_LAUNCHER = 20
W_SECOND_PROFILE = 20
W_MULTI_ALIAS = 10
W_MULTI_ALIAS_MESSENGER = 3
W_EXCLUDE_RECENTS = 10
W_OBFUSCATED = 10
W_HIDDEN = 10

W_ACT_TRAFFIC = 5
W_ACT_RECENT_USE = 5
W_ACT_NOTIF = 5
W_ACT_FG_SERVICE = 5
W_ACT_RECENT_INSTALL = 5

# Schwellen fuer die Prioritaeten.
T_HERKUNFT = 40
T_CHAT = 25
T_VERSCHLEIERUNG = 25
T_VERSCHLEIERUNG_HOCH = 40


def score_app(app: AppInfo, datasets: Datasets | None = None, context: bool = True) -> None:
    """Fuellt ``app.findings``, ``app.scores`` und ``app.priority``.

    ``context`` = False bedeutet: reine APK-Analyse ohne Geraetekontext (Befehl
    ``apk``). Dann entfallen Regeln, die ADB-Daten brauchen (Installer/Store,
    Launcher-Sichtbarkeit, Zweitprofil, Zustand, Aktivitaet), damit keine
    Fehlalarme aus fehlenden Kontextdaten entstehen.
    """
    ds = datasets or load_datasets()
    findings: list[Finding] = []

    is_messenger = app.package in ds.messengers
    is_mod = app.package in ds.mods
    # Ein bekannter Installer ist Kontext, keine Zusicherung ueber die Funktion.
    # Insbesondere duerfen kurze dumpsys-Signaturwerte keine Entwarnung ausloesen.
    installer = app.installer or app.initiating_installer
    trusted_origin = context and (
        app.is_system or installer in ds.trusted_installers
    )
    if context and app.signature_hash:
        findings.append(
            Finding(
                Category.HINWEIS, 0,
                "Signatur-Kurzwert aus dumpsys; kein kryptografischer Identitaetsnachweis.",
                f"Signatur-Kurzwert {app.signature_hash}",
            )
        )

    _score_origin(app, ds, findings, context, trusted_origin)
    _score_chat(app, findings)
    _score_camouflage(app, ds, findings, is_messenger, context)
    if app.apk and app.apk.error:
        findings.append(Finding(Category.HINWEIS, 0,
                                "APK-Analyse unvollstaendig; keine Entwarnung moeglich.", app.apk.error))
    elif app.apk is None:
        findings.append(Finding(Category.HINWEIS, 0,
                                "Keine APK-Analyse vorhanden; Funktion nicht abschliessend beurteilbar.", "APK nicht untersucht"))
    if context:
        _score_activity(app, findings)

    # Kategoriesummen bilden.
    scores = {c.value: 0 for c in Category if c != Category.HINWEIS}
    for f in findings:
        if f.category != Category.HINWEIS:
            scores[f.category.value] += f.weight
    app.scores = scores
    app.findings = findings

    app.priority = _priority(app, ds, findings, is_messenger, is_mod, trusted_origin)


# -- Herkunft --------------------------------------------------------------


def _score_origin(app: AppInfo, ds: Datasets, findings: list[Finding], context: bool = True, trusted_origin: bool = False) -> None:
    inst, init = app.installer, app.initiating_installer
    preload = _preload_like(app)
    ev = (
        f"installer={inst or 'null'}, initiating={init or 'null'}, "
        f"installReason={app.install_reason or '?'}, packageSource={app.package_source or '?'}"
    )
    if not context:
        pass  # Ohne Geraetekontext keine Installer-/Store-Bewertung.
    elif trusted_origin:
        pass  # Bekannter Installer/Systemstatus: kein Herkunftsverdacht daraus.
    elif "com.android.shell" in (inst, init):
        findings.append(Finding(Category.HERKUNFT, W_INSTALLER_SIDELOAD,
                                "Per adb vom PC installiert (kein App-Store).", ev))
    elif inst in ds.sideload_installers or init in ds.sideload_installers or app.package_source in ("3", "4"):
        findings.append(Finding(Category.HERKUNFT, W_INSTALLER_SIDELOAD,
                                "Aus einer APK-Datei installiert (Paketinstaller), nicht aus einem Store.", ev))
    elif preload:
        findings.append(Finding(Category.HERKUNFT, W_PRELOAD_HINT,
                                "Installer und Ausloeser unbekannt; Vorinstallation nicht nachgewiesen.", ev))
    elif not inst and not init:
        findings.append(Finding(Category.HERKUNFT, W_INSTALLER_UNKNOWN,
                                "Kein Installer hinterlegt (aeltere Android-Version: Vorinstallation und Sideload nicht unterscheidbar).", ev))
    elif not inst and init not in ds.trusted_installers:
        findings.append(Finding(Category.HERKUNFT, W_INSTALLER_UNKNOWN,
                                f"Installation ausgeloest durch {init}, nicht durch einen App-Store.", ev))
    elif inst not in ds.trusted_installers:
        findings.append(Finding(Category.HERKUNFT, W_INSTALLER_UNKNOWN,
                                f"Installer ist keine bekannte Store-Quelle ({inst}).", ev))

    rep = app.reputation
    if rep.in_play is False and preload:
        # Hersteller-Apps stehen oft nicht im Play Store - nur als Info, ohne Punkte.
        findings.append(Finding(Category.HINWEIS, 0,
                                "Nicht im Play Store gefunden; Herkunft bleibt unbekannt.", "Play: 404"))
    elif rep.in_play is False:
        findings.append(
            Finding(Category.HERKUNFT, W_NOT_IN_PLAY, "Nicht im Google Play Store gefunden.", "Play: 404")
        )
        if rep.in_fdroid is False:
            findings.append(
                Finding(Category.HERKUNFT, W_NOT_IN_FDROID, "Auch nicht bei F-Droid gefunden.", "F-Droid: 404")
            )
    if rep.vt_known is False:
        findings.append(
            Finding(Category.HERKUNFT, W_VT_UNKNOWN, "Bei VirusTotal unbekannt (Hash nicht bekannt).", "VirusTotal: 404")
        )

    if apk := app.apk:
        for cert in apk.certificates:
            if cert.is_debug:
                findings.append(
                    Finding(Category.HERKUNFT, W_DEBUG_CERT, "Zertifikatsname enthaelt Android Debug (Hinweis, kein Identitaetsnachweis).", f"Zertifikat-Subject: {cert.subject}")
                )
                break
        else:
            thin = next(
                (c for c in apk.certificates if c.self_signed and _thin_dn(c.subject)),
                None,
            )
            if thin:
                findings.append(
                    Finding(Category.HERKUNFT, W_THIN_DN, "Selbstsigniert mit sehr knappen Zertifikatsangaben.", f"Subject: {thin.subject}")
                )
        if apk.test_only:
            findings.append(Finding(Category.HERKUNFT, W_TEST_ONLY, "Als testOnly markiert (Test-Build).", "manifest: testOnly=true"))
        if apk.debuggable:
            findings.append(Finding(Category.HERKUNFT, W_DEBUGGABLE, "Debuggable (Entwickler-Build).", "manifest: debuggable=true"))

    pkg = app.package.lower()
    if pkg.startswith("com.example") or "myapplication" in pkg:
        findings.append(Finding(Category.HERKUNFT, W_PKG_EXAMPLE, "Vorlagen-Paketname (com.example/myapplication).", f"package={app.package}"))
    elif not app.is_system and _system_like(pkg):
        findings.append(Finding(Category.HERKUNFT, W_PKG_SYSTEMLIKE, "Systemnaher Paketname ohne System-Kennzeichnung.", f"package={app.package}"))


# -- Chat-Funktion ---------------------------------------------------------


def _score_chat(app: AppInfo, findings: list[Finding]) -> None:
    apk = app.apk
    if not apk:
        return
    from .apk.indicators import REALTIME_LIBS, CRYPTO_LIBS

    # Haupt-Chatindikator: entweder eine erkannte Echtzeit-/Chat-Bibliothek ODER
    # (bei Obfuskierung) eine Protokoll-Signatur. Beide zahlen nur einmal in die
    # Punkte; eine zusaetzliche Signatur wird ohne Punkte als Beleg ergaenzt.
    realtime = [l for l in apk.libraries if l in REALTIME_LIBS]
    if realtime:
        lib = realtime[0]
        findings.append(
            Finding(Category.CHAT, W_REALTIME_LIB, f"Echtzeit-/Chat-Bibliothek erkannt ({lib}).", f"DEX: {apk.library_evidence.get(lib, lib)}")
        )
        if apk.protocol_signatures:
            sig = apk.protocol_signatures[0]
            findings.append(
                Finding(Category.CHAT, 0, f"Zusaetzliche Protokoll-Signatur: {sig}.", f"Code: {apk.protocol_evidence.get(sig, sig)}")
            )
    elif apk.protocol_signatures:
        sig = apk.protocol_signatures[0]
        findings.append(
            Finding(Category.CHAT, W_REALTIME_LIB, f"Netzwerk-Protokollmerkmal erkannt ({sig}); kein Chatnachweis.", f"Code: {apk.protocol_evidence.get(sig, sig)}")
        )

    if "remoteMessaging" in apk.fg_service_types:
        findings.append(
            Finding(Category.CHAT, W_FG_REMOTE_MSG, "Foreground-Dienst vom Typ remoteMessaging deklariert; Nutzung nicht nachgewiesen.", "manifest: foregroundServiceType=remoteMessaging")
        )

    if apk.endpoints:
        findings.append(
            Finding(Category.CHAT, W_ENDPOINTS, "Server-Endpunkt(e) im Code (ws/mqtt/IP:Port).", f"Code: {apk.endpoints[0]}")
        )

    if apk.chat_terms:
        findings.append(
            Finding(Category.CHAT, W_CHAT_TERMS, "Chat-typische Begriffe im Code/Ressourcen.", "Begriffe: " + ", ".join(apk.chat_terms[:6]))
        )

    if apk.code_kind in ("webview", "cordova") and apk.endpoints:
        findings.append(Finding(Category.CHAT, W_WEB_WRAPPER, "Web-Wrapper mit externer Zieladresse.", f"code_kind={apk.code_kind}"))

    if apk.pinning or apk.embedded_cert:
        findings.append(
            Finding(Category.CHAT, W_PINNING, "Zertifikats-Pinning bzw. eingebettetes Zertifikat.", "Pin/Cert im Code gefunden")
        )

    if "fcm_service" in apk.components:
        findings.append(Finding(Category.CHAT, W_FCM, "Push-Empfang ueber Firebase Cloud Messaging.", "manifest: MESSAGING_EVENT"))
    if "share_target" in apk.components:
        findings.append(Finding(Category.CHAT, W_SHARE_TARGET, "Registriert als Teilen-Ziel (SEND).", "manifest: action.SEND"))

    crypto = [l for l in apk.libraries if l in CRYPTO_LIBS]
    if crypto:
        findings.append(Finding(Category.CHAT, W_CRYPTO_LIB, f"Verschluesselungsbibliothek ({crypto[0]}).", f"DEX: {apk.library_evidence.get(crypto[0], crypto[0])}"))

    if _perm_combo(app):
        findings.append(Finding(Category.CHAT, W_PERM_COMBO, "Berechtigungskombination passend zu Chat (Internet + Benachrichtigungen + Mikro/Kamera/Kontakte).", "siehe Berechtigungen"))


# -- Verschleierung --------------------------------------------------------


def _score_camouflage(app: AppInfo, ds: Datasets, findings: list[Finding], is_messenger: bool, context: bool = True) -> None:
    from .apk.indicators import match_camouflage

    label = app.display_name
    camo = match_camouflage(label)
    if camo and _has_chat(app) and not is_messenger:
        findings.append(
            Finding(Category.VERSCHLEIERUNG, W_CAMOUFLAGE, f"Name '{label}' zusammen mit mehreren Nachrichtenhinweisen: Zusatzfunktion pruefen.", f"Namensmerkmal: {camo}")
        )

    # Kein Launcher ist bei Vorinstallationen (Hintergrund-Helfer) und bei vom
    # Nutzer komplett deaktivierten Apps (abgeschaltete Bloatware) normal und
    # keine Tarnung - diese Faelle werden ausgenommen.
    launcher_relevant = context and app.enabled and not _preload_like(app)
    if not app.enabled and context:
        findings.append(Finding(Category.HINWEIS, 0, "App ist komplett deaktiviert (kann nicht laufen).", "enabled=deaktiviert"))

    if launcher_relevant and app.apk and app.apk.has_launcher and not app.launcher_activities:
        # Manifest deklariert Launcher, aber die Laufzeitabfrage zeigt keinen.
        findings.append(
            Finding(Category.VERSCHLEIERUNG, W_LAUNCHER_DISABLED, "Launcher-Komponente deaktiviert (im System nicht sichtbar).", "query-activities ohne Treffer trotz Launcher im Manifest")
        )
    elif launcher_relevant and not app.launcher_activities and not app.is_system:
        findings.append(
            Finding(Category.VERSCHLEIERUNG, W_NO_LAUNCHER, "Kein Launcher-Eintrag (erscheint nicht im App-Menue).", "keine LAUNCHER-Aktivitaet")
        )

    if context and app.second_profile_only:
        findings.append(
            Finding(Category.VERSCHLEIERUNG, W_SECOND_PROFILE, "Nur in einem Zweitprofil installiert (z. B. Privater Bereich/Klon).", f"Benutzer: {app.users}")
        )

    aliases = app.apk.launcher_aliases if app.apk else 0
    if aliases >= 1:
        weight = W_MULTI_ALIAS_MESSENGER if is_messenger else W_MULTI_ALIAS
        findings.append(
            Finding(Category.VERSCHLEIERUNG, weight, "Mehrere Launcher-Aliase (austauschbares Icon/Name).", f"{aliases} activity-alias mit LAUNCHER")
        )

    if app.apk and app.apk.exclude_from_recents:
        findings.append(Finding(Category.VERSCHLEIERUNG, W_EXCLUDE_RECENTS, "Blendet sich aus der Uebersicht letzter Apps aus.", "manifest: excludeFromRecents=true"))

    if app.apk and (app.apk.obfuscated or app.apk.packer):
        note = f"Packer: {app.apk.packer}" if app.apk.packer else "stark obfuskierter Code"
        findings.append(Finding(Category.VERSCHLEIERUNG, W_OBFUSCATED, "Starke Verschleierung des Codes.", note))

    if app.hidden or app.suspended or app.only_kept_data:
        detail = "hidden" if app.hidden else "suspended" if app.suspended else "nur Daten behalten"
        findings.append(Finding(Category.VERSCHLEIERUNG, W_HIDDEN, f"App ist verborgen/inaktiv gesetzt ({detail}).", f"Zustand: {detail}"))


# -- Aktivitaet ------------------------------------------------------------


def _score_activity(app: AppInfo, findings: list[Finding]) -> None:
    if (app.rx_bytes or 0) + (app.tx_bytes or 0) > 0:
        findings.append(Finding(Category.AKTIVITAET, W_ACT_TRAFFIC, "Hat Datenverkehr verursacht.", f"empfangen={app.rx_bytes or 0} B, gesendet={app.tx_bytes or 0} B"))
    if app.last_used:
        findings.append(Finding(Category.AKTIVITAET, W_ACT_RECENT_USE, "Wurde zuletzt genutzt.", f"zuletzt: {app.last_used}"))
    if app.notification_count:
        findings.append(Finding(Category.AKTIVITAET, W_ACT_NOTIF, "Hat aktive Benachrichtigungen.", f"Anzahl: {app.notification_count}"))
    if app.foreground_services:
        findings.append(Finding(Category.AKTIVITAET, W_ACT_FG_SERVICE, "Laeuft mit Foreground-Dienst.", "Dienst aktiv"))
    if _recently_installed(app):
        findings.append(Finding(Category.AKTIVITAET, W_ACT_RECENT_INSTALL, "In den letzten 30 Tagen installiert/aktualisiert.", f"install: {app.first_install or app.last_update}"))


# -- Prioritaet ------------------------------------------------------------


def _priority(app: AppInfo, ds: Datasets, findings: list[Finding], is_messenger: bool, is_mod: bool, trusted_origin: bool = False) -> Priority:
    rep = app.reputation
    herkunft = app.scores.get(Category.HERKUNFT.value, 0)
    chat = app.scores.get(Category.CHAT.value, 0)
    verschl = app.scores.get(Category.VERSCHLEIERUNG.value, 0)

    special = app.accessibility or app.notification_listener or app.device_admin

    # 1) Harte Treffer, unabhaengig von der Herkunft.
    if rep.ioc_match:
        findings.insert(0, Finding(Category.HINWEIS, 0, f"Treffer in Stalkerware-IOC-Liste: {rep.ioc_match}.", "IOC"))
        return Priority.UNBEDINGT_PRUEFEN
    if is_mod:
        findings.insert(0, Finding(Category.HINWEIS, 0, "Bekannter modifizierter Messenger-Klon.", f"package={app.package}"))
        return Priority.UNBEDINGT_PRUEFEN
    # Sensibler Sonderzugriff ist nur bei UNBEKANNTER Herkunft ein Alarm; System-/
    # Store-Apps (z. B. der Launcher mit Benachrichtigungszugriff) sind normal.
    if special and not is_messenger and not trusted_origin:
        which = []
        if app.accessibility:
            which.append("Bedienungshilfe")
        if app.notification_listener:
            which.append("Benachrichtigungszugriff")
        if app.device_admin:
            which.append("Geraeteadmin")
        findings.insert(0, Finding(Category.HINWEIS, 0, "Sensibler Sonderzugriff aktiv: " + ", ".join(which) + ".", "Sonderzugriff"))
        return Priority.UNBEDINGT_PRUEFEN

    # 2) Bekannte Messenger: eigene Einstufung (vor den Schwellen), da Chatfunktion
    #    bei ihnen erwartbar ist. Ausserhalb eines Stores -> Echtheit pruefen.
    if is_messenger and app.apk and not app.apk.error:
        if _sideloaded(app, ds):
            findings.insert(0, Finding(Category.HINWEIS, 0, "Bekannter Messenger, aber ausserhalb eines Stores installiert - Echtheit pruefen.", f"installer={app.installer or 'null'}"))
        return Priority.BEKANNTER_MESSENGER

    # 3) Funktions-/Tarnhinweise gelten unabhaengig von Installer und Signierer.
    if herkunft >= T_HERKUNFT and (chat >= T_CHAT or verschl >= T_VERSCHLEIERUNG):
        return Priority.UNBEDINGT_PRUEFEN
    if verschl >= T_VERSCHLEIERUNG_HOCH and chat >= T_CHAT:
        return Priority.UNBEDINGT_PRUEFEN
    if herkunft >= T_HERKUNFT:
        return Priority.PRUEFEN_EMPFOHLEN
    if chat >= T_CHAT and herkunft >= 20 and _has_chat(app):
        return Priority.PRUEFEN_EMPFOHLEN
    if verschl >= T_VERSCHLEIERUNG:
        return Priority.PRUEFEN_EMPFOHLEN

    if app.apk is None or app.apk.error:
        return Priority.NICHT_BEURTEILBAR
    return Priority.UNAUFFAELLIG


# -- Hilfen ----------------------------------------------------------------


def _preload_like(app: AppInfo) -> bool:
    """Fehlende Herkunftsdaten; das beweist keine Vorinstallation.

    Die Herkunft bleibt unbekannt. Negative Store-Treffer und ein fehlender
    Launcher werden ohne belastbaren Kontext nicht zu harten Befunden kombiniert.
    """
    return (
        not app.is_system
        and not app.installer
        and not app.initiating_installer
        and app.initiating_recorded
    )


def _has_chat(app: AppInfo) -> bool:
    apk = app.apk
    if not apk:
        return False
    from .apk.indicators import REALTIME_LIBS

    realtime = any(l in REALTIME_LIBS for l in apk.libraries) or bool(apk.protocol_signatures)
    # Eine Bibliothek, URL oder INTERNET allein erklaert keine Tarnung.
    return bool(
        (apk.chat_terms and (realtime or apk.endpoints or "remoteMessaging" in apk.fg_service_types))
        or (realtime and apk.endpoints and "remoteMessaging" in apk.fg_service_types)
    )


def _has_network(app: AppInfo) -> bool:
    if any(p.name.endswith("permission.INTERNET") for p in app.permissions):
        return True
    apk = app.apk
    if apk and (apk.endpoints or apk.libraries):
        return True
    return (app.rx_bytes or 0) + (app.tx_bytes or 0) > 0


def _perm_combo(app: AppInfo) -> bool:
    names = {p.name.rsplit(".", 1)[-1] for p in app.permissions if p.granted is not False}
    has_internet = "INTERNET" in names
    has_notif = "POST_NOTIFICATIONS" in names
    sensitive = names & {"RECORD_AUDIO", "CAMERA", "READ_CONTACTS", "READ_SMS"}
    return has_internet and has_notif and bool(sensitive)


def _sideloaded(app: AppInfo, ds: Datasets) -> bool:
    if app.is_system:
        return False
    installer = app.installer or app.initiating_installer
    if not installer:
        return True
    return installer not in ds.trusted_installers


def _thin_dn(subject: str) -> bool:
    # "Duenn": nur ein Namensbestandteil (typisch: nur Common Name).
    parts = [p for p in subject.split(",") if "=" in p or ":" in p]
    return len(parts) <= 1


def _system_like(pkg: str) -> bool:
    needles = ("com.android.", "com.google.android.", "android.", "com.samsung.", "system")
    return any(pkg.startswith(n) or pkg == n.rstrip(".") for n in needles)


def _recently_installed(app: AppInfo) -> bool:
    import datetime

    stamp = app.first_install or app.last_update
    if not stamp:
        return False
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(stamp[:19], fmt)
            return (datetime.datetime.now() - dt).days <= 30
        except ValueError:
            continue
    return False
