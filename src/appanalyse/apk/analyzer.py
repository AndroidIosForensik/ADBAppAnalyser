"""Statische APK-Analyse: Manifest, Signaturzertifikate und Code-Strings.

Manifest und Zertifikate kommen aus androguard; die Code-Merkmale aus dem
eigenen, schnellen String-Leser (DEX + Nicht-DEX). Die Funktion ist robust:
Jeder Teilschritt ist gekapselt, sodass ein Fehler in einem Bereich die anderen
Ergebnisse nicht verwirft. Ein globaler Fehler landet in ``ApkAnalysis.error``.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from ..models import ApkAnalysis, CertInfo
from . import indicators, native_strings
from .dex_strings import read_apk_strings

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _silence_androguard() -> None:
    """Schaltet das sehr gespraechige loguru-Logging von androguard ab."""
    try:
        from loguru import logger

        logger.remove()
    except Exception:
        pass


def analyze(apk_path: str | Path) -> ApkAnalysis:
    path = Path(apk_path)
    result = ApkAnalysis(apk_path=str(path))
    try:
        data = path.read_bytes()
        result.size = len(data)
        result.sha256 = hashlib.sha256(data).hexdigest()
    except OSError as exc:
        result.error = f"APK nicht lesbar: {exc}"
        return result

    _silence_androguard()

    # 1) Code-Strings (unabhaengig von androguard, damit auch bei Manifestfehlern
    #    verwertbar). DEX zuerst, dann Nicht-DEX-Code.
    try:
        names = _zip_names(path)
        result.code_kind = native_strings.detect_code_kind(names)
        strings = read_apk_strings(path)
        if result.code_kind != "dex":
            strings = strings + native_strings.read_native_strings(path)
        _apply_code_findings(result, strings)
        # Zusaetzlich Ressourcen/Assets nach eingebettetem Zertifikat / Pin durchsuchen
        # (viele selbst gebaute Apps legen das gepinnte PEM in res/raw oder assets ab).
        _scan_embedded_secrets(path, result)
    except Exception as exc:  # pragma: no cover - defensiv
        result.error = f"Code-Analyse teilweise fehlgeschlagen: {exc}"

    # 2) Manifest und Zertifikate ueber androguard.
    try:
        from androguard.core.apk import APK

        apk = APK(str(path))
        _apply_manifest(result, apk)
        _apply_certificates(result, apk)
    except Exception as exc:
        if not result.error:
            result.error = f"Manifest-/Zertifikatsanalyse fehlgeschlagen: {exc}"
    return result


def _zip_names(path: Path) -> list[str]:
    try:
        with zipfile.ZipFile(path) as zf:
            return zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return []


def _scan_embedded_secrets(path: Path, result: ApkAnalysis) -> None:
    """Durchsucht res/raw und assets nach eingebettetem Zertifikat bzw. Pin.

    Das eingebettete PEM liegt als Ressource (nicht im DEX-String-Pool), wird von
    der reinen DEX-Analyse also nicht erfasst. Wir lesen daher kleine Dateien
    unter ``res/raw/`` und ``assets/`` gezielt mit.
    """
    import re

    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                name = info.filename
                if not (name.startswith("res/raw/") or name.startswith("assets/")):
                    continue
                if info.file_size > 2_000_000:
                    continue
                try:
                    data = zf.read(name)
                except (zipfile.BadZipFile, OSError):
                    continue
                text = data.decode("latin-1", "replace")
                if "BEGIN CERTIFICATE" in text or "BEGIN PUBLIC KEY" in text:
                    result.embedded_cert = True
                if re.search(r"sha256/[A-Za-z0-9+/=]{20,}", text):
                    result.pinning = True
    except (zipfile.BadZipFile, OSError):
        pass


def _apply_code_findings(result: ApkAnalysis, strings: list[str]) -> None:
    libs = indicators.match_libraries(strings)
    result.libraries = [name for name, _ in libs]
    result.library_evidence = dict(libs)
    protos = indicators.match_protocol_signatures(strings)
    result.protocol_signatures = [n for n, _ in protos]
    result.protocol_evidence = dict(protos)
    result.endpoints = indicators.match_endpoints(strings)
    result.chat_terms = indicators.match_chat_terms(strings)
    result.embedded_cert = indicators.has_embedded_cert(strings)
    result.pinning = indicators.has_pinning(strings)
    result.packer = indicators.match_packer(strings)
    result.obfuscated = _looks_obfuscated(strings)


def _looks_obfuscated(strings: list[str]) -> bool:
    """Heuristik: viele sehr kurze Klassendeskriptoren deuten auf R8/ProGuard.

    Wir zaehlen Deskriptoren der Form ``La;`` / ``Lb/c;`` (1-2 Zeichen je Segment).
    Ueberwiegen sie deutlich, gilt der Code als stark obfuskiert.
    """
    import re

    descriptors = [s for s in strings if s.startswith("L") and s.endswith(";")]
    if len(descriptors) < 200:
        return False
    short = sum(
        1 for s in descriptors if re.fullmatch(r"L(?:[a-zA-Z0-9]{1,2}/)*[a-zA-Z0-9]{1,2};", s)
    )
    return short / max(len(descriptors), 1) > 0.5


def _apply_manifest(result: ApkAnalysis, apk) -> None:
    result.label = apk.get_app_name() or ""
    result.debuggable = _bool_attr(apk, "debuggable")
    result.test_only = _bool_attr(apk, "testOnly")
    # allowBackup ist standardmaessig true, wenn nicht gesetzt.
    backup = apk.get_attribute_value("application", "allowBackup")
    result.allow_backup = backup is None or str(backup).lower() == "true"
    cleartext = apk.get_attribute_value("application", "usesCleartextTraffic")
    result.uses_cleartext = None if cleartext is None else str(cleartext).lower() == "true"
    result.network_security_config = bool(
        apk.get_attribute_value("application", "networkSecurityConfig")
    )

    try:
        _parse_manifest_xml(result, apk)
    except Exception:
        pass


def _bool_attr(apk, name: str) -> bool:
    value = apk.get_attribute_value("application", name)
    return value is not None and str(value).lower() == "true"


def _parse_manifest_xml(result: ApkAnalysis, apk) -> None:
    """Detailauswertung des Manifests via lxml (Komponenten, Filter, FG-Typen)."""
    root = apk.get_android_manifest_xml()
    if root is None:
        return

    def attr(el, name: str) -> str:
        return el.get(f"{{{ANDROID_NS}}}{name}") or ""

    components: dict[str, list[str]] = {}

    def add(kind: str, name: str) -> None:
        components.setdefault(kind, []).append(name or "?")

    launcher_activities = 0
    alias_launchers = 0

    for tag in ("activity", "activity-alias", "service", "receiver"):
        for el in root.iter(tag):
            name = attr(el, "name")
            if tag == "activity" and attr(el, "excludeFromRecents").lower() == "true":
                result.exclude_from_recents = True
            if tag == "service":
                fst = attr(el, "foregroundServiceType")
                if fst:
                    for t in fst.split("|"):
                        if t and t not in result.fg_service_types:
                            result.fg_service_types.append(t)
            perm = attr(el, "permission")
            if perm.endswith("BIND_ACCESSIBILITY_SERVICE"):
                add("accessibility_service", name)
            if perm.endswith("BIND_NOTIFICATION_LISTENER_SERVICE"):
                add("notification_listener", name)
            if perm.endswith("BIND_DEVICE_ADMIN"):
                add("device_admin", name)
            if perm.endswith("BIND_TELECOM_CONNECTION_SERVICE"):
                add("connection_service", name)

            # Intent-Filter der Komponente durchgehen.
            for ifilter in el.iter("intent-filter"):
                actions = {
                    attr(a, "name")
                    for a in ifilter.iter("action")
                }
                categories = {
                    attr(c, "name")
                    for c in ifilter.iter("category")
                }
                if "android.intent.action.MAIN" in actions and (
                    "android.intent.category.LAUNCHER" in categories
                ):
                    launcher_activities += 1
                    if tag == "activity-alias":
                        alias_launchers += 1
                if "android.intent.action.BOOT_COMPLETED" in actions:
                    add("boot_receiver", name)
                if "com.google.firebase.MESSAGING_EVENT" in actions:
                    add("fcm_service", name)
                if actions & {
                    "android.intent.action.SEND",
                    "android.intent.action.SEND_MULTIPLE",
                }:
                    add("share_target", name)
                if "android.intent.action.SENDTO" in actions:
                    add("sendto", name)
                if "android.accessibilityservice.AccessibilityService" in actions:
                    add("accessibility_service", name)
                if "android.service.notification.NotificationListenerService" in actions:
                    add("notification_listener", name)

    result.components = components
    result.has_launcher = launcher_activities > 0
    # Aliase, die selbst Launcher sind, plus mehrere Launcher-Aktivitaeten.
    result.launcher_aliases = alias_launchers


def _apply_certificates(result: ApkAnalysis, apk) -> None:
    schemes = _scheme_map(apk)
    for cert in apk.get_certificates():
        info = CertInfo()
        try:
            info.subject = cert.subject.human_friendly
            info.issuer = cert.issuer.human_friendly
            info.sha256 = cert.sha256.hex()
            info.sha1 = cert.sha1.hex()
            info.not_before = _fmt_dt(cert.not_valid_before)
            info.not_after = _fmt_dt(cert.not_valid_after)
            info.self_signed = info.subject == info.issuer
            info.is_debug = "CN=Android Debug" in info.subject or "Android Debug" in info.subject
            info.scheme = schemes.get(info.sha256, "")
        except Exception:
            pass
        result.certificates.append(info)


def _scheme_map(apk) -> dict[str, str]:
    """Ordnet jedem Zertifikat (per SHA256) das hoechste Signaturschema zu."""
    mapping: dict[str, str] = {}
    for scheme, getter in (
        ("v1", "get_certificates_v1"),
        ("v2", "get_certificates_v2"),
        ("v3", "get_certificates_v3"),
    ):
        try:
            for cert in getattr(apk, getter)():
                mapping[cert.sha256.hex()] = scheme
        except Exception:
            continue
    return mapping


def _fmt_dt(value) -> str:
    try:
        return value.strftime("%Y-%m-%d")
    except Exception:
        return str(value)
