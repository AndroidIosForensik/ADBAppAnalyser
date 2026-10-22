"""Sammelt alle Geraetedaten per ADB und baut daraus die AppInfo-Liste.

Die Sammlung ist strikt lesend: kein Root, keine Grants, keine Aenderung von
Einstellungen. Jeder Schritt bekommt einen Status; unbekannte Formate werden als
Parse-Hinweis vermerkt und brechen den Lauf nicht ab.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import adb
from .models import AppInfo, DeviceInfo, Permission, Profile
from .parsers import (
    activity,
    appops,
    dumpsys_package,
    netstats,
    notification,
    pm,
    special_access,
    usagestats,
    users as users_parser,
)
from .recorder import FEHLER, LEER, OK, TEILWEISE, Recorder


@dataclass
class ScanOptions:
    pull_apk: bool = True
    all_apks: bool = False
    keep_all_apks: bool = False


class Collector:
    def __init__(self, recorder: Recorder, serial: str, user: int = 0):
        self.rec = recorder
        self.serial = serial
        self.user = user

    def shell(self, name: str, tokens: list[str], timeout: int = 120):
        return self.rec.run(name, adb.shell_args(self.serial, tokens), timeout=timeout)

    # -- Geraet & Profile -------------------------------------------------

    def device_info(self) -> DeviceInfo:
        info = DeviceInfo(serial=self.serial)
        props = {
            "ro.product.model": "model",
            "ro.product.manufacturer": "manufacturer",
            "ro.build.version.release": "android_release",
            "ro.build.version.sdk": "sdk",
            "ro.build.version.security_patch": "security_patch",
            "ro.build.fingerprint": "fingerprint",
            "ro.build.tags": "build_tags",
        }
        res = self.shell("geraeteeigenschaften", ["getprop"])
        text = res.text
        for key, attr in props.items():
            m = re.search(rf"\[{re.escape(key)}\]:\s*\[([^\]]*)\]", text)
            if m:
                setattr(info, attr, m.group(1))
        time_res = self.shell("geraetezeit", ["date", "+%Y-%m-%d %H:%M:%S %z"])
        info.device_time = time_res.text.strip()
        self.rec.add_status("geraet", OK if res.ok else FEHLER, 1, res.problem)
        return info

    def profiles(self) -> list[Profile]:
        res = self.shell("benutzerliste", ["cmd", "user", "list", "-v"])
        profs = users_parser.parse(res.text)
        if not profs:
            profs = [Profile(user_id=0, name="", type="primaer", running=True)]
        self.rec.add_status("profile", OK if profs else LEER, len(profs), res.problem)
        return profs

    # -- Pakete -----------------------------------------------------------

    def collect_packages(
        self, profiles: list[Profile], trust_oem_signature: bool = True
    ) -> dict[str, AppInfo]:
        """Baut die AppInfo-Basis aus dumpsys package packages plus pm-Listen.

        ``trust_oem_signature``: Bei Geraeten mit ``release-keys`` gilt eine
        Drittanbieter-App, die wie eine System-App signiert ist, als Hersteller-
        Vorinstallation. Bei ``test-keys`` (Custom-ROM, Emulator) ist der
        Plattformschluessel oeffentlich - dann wird dieser Signatur nicht vertraut.
        """
        res = self.shell("pakete_dumpsys", ["dumpsys", "package", "packages"], timeout=180)
        blocks = dumpsys_package.parse(res.text)
        if not blocks:
            self.rec.add_status("pakete", FEHLER, 0, res.problem or "Keine Paketbloecke erkannt.")
            return {}

        # Detailliste je Benutzer (APK-Pfad, Installer) und "nur Daten behalten".
        pm_detail: dict[str, pm.PmEntry] = {}
        installed_names: set[str] = set()
        kept_data: set[str] = set()
        for prof in profiles:
            uid = prof.user_id
            d = self.shell(
                f"pm_detail_u{uid}",
                ["pm", "list", "packages", "-f", "-i", "-U", "--show-versioncode", "--user", str(uid)],
            )
            entries, bad = pm.parse_detail(d.text)
            for line in bad:
                self.rec.add_hint("pakete", line[:80], "Nicht zuordenbare Paketzeile.")
            pm_detail.update(entries)
            installed_names |= set(entries)
            u = self.shell(f"pm_uninstalled_u{uid}", ["pm", "list", "packages", "-u", "--user", str(uid)])
            kept_data |= pm.parse_names(u.text)

        # "Nur Daten behalten": in -u sichtbar, aber nicht in der Installationsliste.
        kept_only = kept_data - installed_names

        apps: dict[str, AppInfo] = {}
        for pkg, block in blocks.items():
            installed_users = sorted(u for u, st in block.users.items() if st.installed)
            if not installed_users and pkg not in kept_only:
                continue
            app = _build_app(pkg, block, pm_detail.get(pkg), profiles)
            if pkg in kept_only and not installed_users:
                app.only_kept_data = True
            apps[pkg] = app

        # Hersteller-Vorinstallationen erkennen: Drittanbieter-App mit derselben
        # Signatur wie eine System-App (Xiaomi/Oppo/Samsung spielen viele Apps so
        # vor, oft mit installer=null). Diese Signatur kann ein Dritter nicht faelschen.
        if trust_oem_signature:
            mark_oem_signed(apps, blocks)

        count = len(apps)
        self.rec.add_status("pakete", OK if count else LEER, count, "Paketdaten, keine App-Daten.")
        return apps

    def collect_launchers(self, apps: dict[str, AppInfo], profiles: list[Profile]) -> None:
        for prof in profiles:
            if not prof.running:
                continue
            uid = prof.user_id
            res = self.shell(
                f"launcher_u{uid}",
                ["cmd", "package", "query-activities", "--brief", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", "--user", str(uid)],
            )
            for pkg, acts in activity.parse_launchers(res.text).items():
                if pkg in apps:
                    for a in acts:
                        entry = f"{pkg}/{a}"
                        if entry not in apps[pkg].launcher_activities:
                            apps[pkg].launcher_activities.append(entry)

    # -- Sonderzugriffe ---------------------------------------------------

    def collect_special_access(self, apps: dict[str, AppInfo]) -> None:
        a11y = self.shell("bedienungshilfen", ["settings", "get", "secure", "enabled_accessibility_services"])
        notif = self.shell("benachrichtigungszugriff", ["settings", "get", "secure", "enabled_notification_listeners"])
        admin = self.shell("geraeteadmins", ["dumpsys", "device_policy"])
        a11y_pkgs = special_access.parse_component_list(a11y.text)
        notif_pkgs = special_access.parse_component_list(notif.text)
        admin_pkgs = special_access.parse_device_admins(admin.text)
        for pkg, app in apps.items():
            app.accessibility = pkg in a11y_pkgs
            app.notification_listener = pkg in notif_pkgs
            app.device_admin = pkg in admin_pkgs

        roles = {
            "SMS": "android.app.role.SMS",
            "Telefon": "android.app.role.DIALER",
            "Standard-Launcher": "android.app.role.HOME",
            "Assistent": "android.app.role.ASSISTANT",
        }
        for label, role in roles.items():
            r = self.shell(f"rolle_{label}", ["cmd", "role", "get-role-holders", role])
            holder = special_access.parse_role_holder(r.text)
            if holder in apps:
                apps[holder].roles.append(label)
        self.rec.add_status("sonderzugriffe", OK, len(apps), "")

    # -- Aktivitaet -------------------------------------------------------

    def collect_activity(self, apps: dict[str, AppInfo]) -> None:
        by_uid = {app.uid: app for app in apps.values() if app.uid}

        net = self.shell("netzwerkverkehr", ["dumpsys", "netstats", "detail"], timeout=150)
        for uid, (rx, tx) in netstats.parse(net.text).items():
            if uid in by_uid:
                by_uid[uid].rx_bytes = rx
                by_uid[uid].tx_bytes = tx

        usage = self.shell("nutzung", ["dumpsys", "usagestats"], timeout=150)
        for pkg, u in usagestats.parse(usage.text).items():
            if pkg in apps:
                apps[pkg].last_used = u.last_used
                apps[pkg].launch_count = u.launch_count or None

        notif = self.shell("benachrichtigungen", ["dumpsys", "notification"], timeout=120)
        for pkg, c in notification.parse(notif.text).items():
            if pkg in apps:
                apps[pkg].notification_count = c

        svc = self.shell("dienste", ["dumpsys", "activity", "services"], timeout=120)
        info = activity.parse_services(svc.text)
        for pkg, app in apps.items():
            if pkg in info.services:
                app.running_services = info.services[pkg]
            if pkg in info.foreground:
                app.foreground_services = info.services.get(pkg, ["?"])
        self.rec.add_status("aktivitaet", OK, len(apps), "")

    def collect_appops(self, app: AppInfo) -> None:
        res = self.shell(f"appops_{app.package}", ["cmd", "appops", "get", app.package])
        app.appops = appops.parse(res.text)

    # -- APK sichern ------------------------------------------------------

    def pull_apk(self, app: AppInfo, dest_dir: Path) -> Path | None:
        res = self.shell(f"pfad_{app.package}", ["pm", "path", "--user", str(self.user), app.package])
        paths = [l[len("package:"):].strip() for l in res.text.splitlines() if l.startswith("package:")]
        base = next((p for p in paths if p.endswith("base.apk")), paths[0] if paths else "")
        if not base:
            return None
        dest_dir.mkdir(parents=True, exist_ok=True)
        local = dest_dir / f"{app.package}.apk"
        # adb pull erfolgt ausserhalb der Shell (Binaeruebertragung).
        pull = self.rec.run(f"pull_{app.package}", ["-s", self.serial, "pull", base, str(local)], timeout=180)
        if pull.ok and local.exists():
            app.apk_paths = paths
            return local
        return None


def run_scan(
    recorder: Recorder,
    serial: str,
    options: ScanOptions,
    reputation,
    apk_dir: Path,
    progress=lambda msg: None,
) -> tuple[DeviceInfo, list[AppInfo]]:
    """Fuehrt den vollstaendigen, rein lesenden Scan aus und bewertet die Apps."""
    from .apk import analyzer
    from .scoring import score_app

    col = Collector(recorder, serial)

    def phase(name: str, step: str, fn):
        """Fuehrt eine Sammelphase aus; ein Fehler bricht den Scan nicht ab."""
        progress(name)
        try:
            return fn()
        except Exception as exc:  # pragma: no cover - defensiv
            recorder.add_status(step, "FEHLER", 0, f"{type(exc).__name__}: {exc}")
            return None

    device = phase("Geraeteinformationen", "geraet", col.device_info) or DeviceInfo(serial=serial)
    device.profiles = phase("Profile", "profile", col.profiles) or []

    # Bei test-keys (Custom-ROM/Emulator) ist der Plattformschluessel oeffentlich.
    trust_oem = "test-keys" not in (device.build_tags or "")
    apps = phase(
        "Installierte Pakete", "pakete",
        lambda: col.collect_packages(device.profiles, trust_oem_signature=trust_oem),
    ) or {}
    phase("Launcher", "launcher", lambda: col.collect_launchers(apps, device.profiles))
    phase("Sonderzugriffe", "sonderzugriffe", lambda: col.collect_special_access(apps))
    phase("Aktivitaet und Datenverkehr", "aktivitaet", lambda: col.collect_activity(apps))

    app_list = list(apps.values())

    # APKs sichern und statisch analysieren (Nicht-System bzw. alle mit --all-apks).
    if options.pull_apk:
        targets = [a for a in app_list if options.all_apks or _wants_apk(a)]
        for i, app in enumerate(targets, 1):
            progress(f"APK-Analyse {i}/{len(targets)}: {app.package}")
            try:
                local = col.pull_apk(app, apk_dir)
                if local:
                    app.apk = analyzer.analyze(local)
                col.collect_appops(app)
            except Exception as exc:  # pragma: no cover - defensiv
                recorder.add_hint("apk", app.package, f"APK-Analyse fehlgeschlagen: {exc}")
        recorder.add_status("apk_analyse", OK, len(targets), "APK-Metadaten und Code-Strings.")

    # Reputationsabgleich (Play/F-Droid/IOC; VT nur fuer Kandidaten). Ein Fehler
    # bei einer einzelnen App (z. B. Netzproblem) darf den Scan nie abbrechen.
    progress("Abgleich mit Listen/Online")
    for app in app_list:
        try:
            app.reputation = reputation.check(app, is_candidate=False)
        except Exception as exc:  # pragma: no cover - defensiv
            recorder.add_hint("reputation", app.package, f"Abgleich fehlgeschlagen: {exc}")
        score_app(app)
    # VirusTotal gezielt fuer auffaellige Apps, danach neu bewerten.
    for app in app_list:
        if app.priority.value in ("pruefen_empfohlen", "unbedingt_pruefen"):
            try:
                new_rep = reputation.check(app, is_candidate=True)
            except Exception as exc:  # pragma: no cover - defensiv
                recorder.add_hint("reputation", app.package, f"VT-Abgleich fehlgeschlagen: {exc}")
                continue
            if new_rep.vt_known is not None:
                app.reputation.vt_known = new_rep.vt_known
                app.reputation.vt_detections = new_rep.vt_detections
                score_app(app)

    return device, app_list


def mark_oem_signed(apps: dict[str, AppInfo], blocks: dict) -> None:
    """Markiert Nicht-System-Apps, die wie eine System-App signiert sind."""
    system_sigs = {b.signature_hash for b in blocks.values() if b.is_system and b.signature_hash}
    for app in apps.values():
        if not app.is_system and app.signature_hash and app.signature_hash in system_sigs:
            app.oem_signed = True


def _wants_apk(app: AppInfo) -> bool:
    """APK sichern fuer Nicht-System-Apps und aktualisierte System-Apps ohne Store."""
    from .datasets import load as load_datasets

    if not app.is_system:
        return True
    if app.is_updated_system:
        return (app.installer or "") not in load_datasets().trusted_installers
    return False


def _build_app(pkg: str, block: dumpsys_package.PackageBlock, entry, profiles: list[Profile]) -> AppInfo:
    installed_users = sorted(u for u, st in block.users.items() if st.installed)
    primary = 0 if 0 in installed_users else (installed_users[0] if installed_users else 0)
    ustate = block.users.get(primary)

    app = AppInfo(
        package=pkg,
        uid=block.uid,
        version_name=block.version_name,
        version_code=block.version_code,
        min_sdk=block.min_sdk,
        target_sdk=block.target_sdk,
        users=installed_users,
        last_update=block.last_update,
        installer=block.installer,
        initiating_installer=block.initiating_installer,
        initiating_recorded=block.initiating_recorded,
        package_source=block.package_source,
        signature_hash=block.signature_hash,
        is_system=block.is_system,
        is_updated_system=block.is_updated_system,
        flags=block.flags,
        private_flags=block.private_flags,
    )
    if entry:
        app.apk_paths = [entry.apk_path] if entry.apk_path else []
        if not app.uid:
            app.uid = entry.uid

    if ustate:
        app.install_reason = ustate.install_reason
        app.enabled = ustate.enabled
        app.hidden = ustate.hidden
        app.suspended = ustate.suspended
        app.stopped = ustate.stopped
        app.first_install = ustate.first_install
        app.disabled_components = ustate.disabled_components

    # Zweitprofil-Erkennung: nirgends auf dem primaeren Benutzer 0 installiert,
    # aber in einem Nicht-Primaerprofil vorhanden.
    if installed_users and 0 not in installed_users:
        non_primary = {p.user_id for p in profiles if p.type != "primaer"}
        if set(installed_users) & non_primary:
            app.second_profile_only = True

    # Berechtigungen zusammenfuehren: Install-Permissions + Laufzeit (primaerer User).
    perms: list[Permission] = []
    for name, granted in sorted(block.install_permissions.items()):
        perms.append(Permission(name=name, granted=granted, runtime=False))
    if ustate:
        for name, (granted, flags) in sorted(ustate.runtime_permissions.items()):
            perms.append(Permission(name=name, granted=granted, flags=flags, runtime=True))
    app.permissions = perms
    return app
