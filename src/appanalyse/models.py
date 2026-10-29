"""Zentrale Datenmodelle fuer die App-Analyse.

Alle Felder sind bewusst optional bzw. mit Standardwerten versehen, damit ein
Teilausfall einzelner ADB-Abfragen nicht die gesamte Auswertung verhindert.
Die Sammlung ist rein lesend; hier werden nur Beobachtungen abgelegt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Priority(str, Enum):
    """Einstufung einer App fuer die Pruefliste (aufsteigender Ernst)."""

    UNAUFFAELLIG = "unauffaellig"
    NICHT_BEURTEILBAR = "nicht_beurteilbar"
    BEKANNTER_MESSENGER = "bekannter_messenger"
    PRUEFEN_EMPFOHLEN = "pruefen_empfohlen"
    UNBEDINGT_PRUEFEN = "unbedingt_pruefen"


# Reihenfolge fuer Sortierung: hoeher = weiter oben in der Pruefliste.
PRIORITY_RANK = {
    Priority.UNBEDINGT_PRUEFEN: 3,
    Priority.PRUEFEN_EMPFOHLEN: 2,
    Priority.BEKANNTER_MESSENGER: 1,
    Priority.UNAUFFAELLIG: 0,
    Priority.NICHT_BEURTEILBAR: 1,
}

PRIORITY_LABEL = {
    Priority.UNBEDINGT_PRUEFEN: "Unbedingt pruefen",
    Priority.PRUEFEN_EMPFOHLEN: "Pruefen empfohlen",
    Priority.BEKANNTER_MESSENGER: "Bekannter Messenger",
    Priority.UNAUFFAELLIG: "Unauffaellig",
    Priority.NICHT_BEURTEILBAR: "Nicht abschliessend beurteilbar",
}


class Category(str, Enum):
    """Kategorie eines Befunds; bestimmt, in welche Punktesumme er einzahlt."""

    HERKUNFT = "herkunft"
    CHAT = "chat"
    VERSCHLEIERUNG = "verschleierung"
    AKTIVITAET = "aktivitaet"
    HINWEIS = "hinweis"  # rein informativ, ohne Punkte


@dataclass
class Finding:
    """Ein einzelner Befund mit nachvollziehbarem Beleg.

    ``evidence`` ist die konkrete Quelle (z. B. eine dumpsys-Zeile oder ein
    gefundener DEX-String), damit jeder Punkt im Bericht ueberpruefbar bleibt.
    """

    category: Category
    weight: int
    text: str
    evidence: str = ""

    def as_dict(self) -> dict:
        return {
            "kategorie": self.category.value,
            "punkte": self.weight,
            "text": self.text,
            "beleg": self.evidence,
        }


@dataclass
class Permission:
    """Eine angeforderte Berechtigung inkl. Gewaehrungsstatus je Benutzer."""

    name: str
    granted: Optional[bool] = None  # None = Install-Permission ohne Laufzeitfrage
    flags: str = ""
    runtime: bool = False

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "gewaehrt": self.granted,
            "flags": self.flags,
            "laufzeit": self.runtime,
        }


@dataclass
class CertInfo:
    """Signaturzertifikat einer APK."""

    subject: str = ""
    issuer: str = ""
    sha256: str = ""
    sha1: str = ""
    not_before: str = ""
    not_after: str = ""
    scheme: str = ""  # v1 / v2 / v3
    is_debug: bool = False
    self_signed: bool = False

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "gueltig_ab": self.not_before,
            "gueltig_bis": self.not_after,
            "schema": self.scheme,
            "debug_zertifikat": self.is_debug,
            "selbstsigniert": self.self_signed,
        }


@dataclass
class ApkAnalysis:
    """Ergebnis der statischen APK-Analyse (Manifest, Zertifikat, Code-Strings)."""

    apk_path: str = ""
    sha256: str = ""
    size: int = 0
    label: str = ""  # sichtbarer App-Name aus den Ressourcen

    debuggable: bool = False
    test_only: bool = False
    allow_backup: bool = True
    uses_cleartext: Optional[bool] = None
    network_security_config: bool = False

    certificates: list[CertInfo] = field(default_factory=list)

    # Aus dem Manifest gezogene Merkmale
    has_launcher: bool = True
    launcher_aliases: int = 0
    exclude_from_recents: bool = False
    fg_service_types: list[str] = field(default_factory=list)
    components: dict[str, list[str]] = field(default_factory=dict)  # typ -> Namen

    # Aus dem Code (DEX/native/web) gezogene Merkmale
    libraries: list[str] = field(default_factory=list)
    library_evidence: dict[str, str] = field(default_factory=dict)
    protocol_signatures: list[str] = field(default_factory=list)
    protocol_evidence: dict[str, str] = field(default_factory=dict)
    endpoints: list[str] = field(default_factory=list)
    chat_terms: list[str] = field(default_factory=list)
    embedded_cert: bool = False
    pinning: bool = False
    obfuscated: bool = False
    packer: str = ""
    code_kind: str = "dex"  # dex / flutter / react-native / cordova / xamarin / webview

    error: str = ""  # gesetzt, wenn die Analyse fehlschlug

    def as_dict(self) -> dict:
        return {
            "apk_pfad": self.apk_path,
            "sha256": self.sha256,
            "groesse": self.size,
            "label": self.label,
            "debuggable": self.debuggable,
            "test_only": self.test_only,
            "allow_backup": self.allow_backup,
            "klartext_verkehr": self.uses_cleartext,
            "network_security_config": self.network_security_config,
            "zertifikate": [c.as_dict() for c in self.certificates],
            "hat_launcher": self.has_launcher,
            "launcher_aliase": self.launcher_aliases,
            "exclude_from_recents": self.exclude_from_recents,
            "fg_service_typen": self.fg_service_types,
            "komponenten": self.components,
            "bibliotheken": self.libraries,
            "bibliothek_belege": self.library_evidence,
            "protokoll_signaturen": self.protocol_signatures,
            "protokoll_belege": self.protocol_evidence,
            "endpunkte": self.endpoints,
            "chat_begriffe": self.chat_terms,
            "eingebettetes_zertifikat": self.embedded_cert,
            "pinning": self.pinning,
            "obfuskiert": self.obfuscated,
            "packer": self.packer,
            "code_art": self.code_kind,
            "fehler": self.error,
        }


@dataclass
class Reputation:
    """Ergebnis des Online-/Listen-Abgleichs fuer ein Paket."""

    in_play: Optional[bool] = None
    in_fdroid: Optional[bool] = None
    vt_known: Optional[bool] = None
    vt_detections: Optional[int] = None
    ioc_match: str = ""  # Name der IOC-Familie, falls getroffen
    known_messenger: bool = False
    known_mod: str = ""  # Name des bekannten Messenger-Mods, falls getroffen

    def as_dict(self) -> dict:
        return {
            "in_play": self.in_play,
            "in_fdroid": self.in_fdroid,
            "vt_bekannt": self.vt_known,
            "vt_treffer": self.vt_detections,
            "ioc_treffer": self.ioc_match,
            "bekannter_messenger": self.known_messenger,
            "bekannter_mod": self.known_mod,
        }


@dataclass
class AppInfo:
    """Alle je installiertem Paket gesammelten Beobachtungen und die Bewertung."""

    package: str
    uid: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    apk_paths: list[str] = field(default_factory=list)
    users: list[int] = field(default_factory=list)

    first_install: str = ""
    last_update: str = ""
    installer: str = ""
    initiating_installer: str = ""
    initiating_recorded: bool = False  # Feld vorhanden (Android 11+)
    package_source: str = ""
    install_reason: str = ""  # 0 unbekannt, 1 Richtlinie, 2 Wiederherstellung, 3 Einrichtung, 4 Nutzer
    signature_hash: str = ""  # Kurzwert aus dumpsys, je Zertifikat gleich
    oem_signed: bool = False  # Legacy-Feld; Kurzhashes belegen keine Herstellersignatur.

    is_system: bool = False
    is_updated_system: bool = False
    flags: list[str] = field(default_factory=list)
    private_flags: list[str] = field(default_factory=list)

    # Sichtbarkeit / Zustand
    label: str = ""
    enabled: bool = True
    hidden: bool = False
    suspended: bool = False
    stopped: bool = False
    only_kept_data: bool = False  # per pm list -u sichtbar, aber nicht installiert
    disabled_components: list[str] = field(default_factory=list)
    launcher_activities: list[str] = field(default_factory=list)
    second_profile_only: bool = False

    permissions: list[Permission] = field(default_factory=list)

    # Sonderzugriffe
    accessibility: bool = False
    notification_listener: bool = False
    device_admin: bool = False
    roles: list[str] = field(default_factory=list)
    appops: dict[str, str] = field(default_factory=dict)

    # Aktivitaet
    last_used: str = ""
    launch_count: Optional[int] = None
    rx_bytes: Optional[int] = None
    tx_bytes: Optional[int] = None
    notification_count: Optional[int] = None
    running_services: list[str] = field(default_factory=list)
    foreground_services: list[str] = field(default_factory=list)

    apk: Optional[ApkAnalysis] = None
    reputation: Reputation = field(default_factory=Reputation)

    # Bewertung (von scoring.py gesetzt)
    findings: list[Finding] = field(default_factory=list)
    scores: dict[str, int] = field(default_factory=dict)
    priority: Priority = Priority.UNAUFFAELLIG

    @property
    def display_name(self) -> str:
        return self.label or (self.apk.label if self.apk else "") or self.package

    def score(self, category: Category) -> int:
        return self.scores.get(category.value, 0)

    def score_h(self) -> int:
        return self.scores.get(Category.HERKUNFT.value, 0)

    def score_c(self) -> int:
        return self.scores.get(Category.CHAT.value, 0)

    def score_v(self) -> int:
        return self.scores.get(Category.VERSCHLEIERUNG.value, 0)

    def score_total(self) -> int:
        return sum(self.scores.values())

    def as_dict(self) -> dict:
        return {
            "paket": self.package,
            "uid": self.uid,
            "anzeigename": self.display_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "apk_pfade": self.apk_paths,
            "benutzer": self.users,
            "erstinstallation": self.first_install,
            "letztes_update": self.last_update,
            "installer": self.installer,
            "initiierender_installer": self.initiating_installer,
            "paketquelle": self.package_source,
            "installationsgrund": self.install_reason,
            "signatur_kurzwert": self.signature_hash,
            "herstellersigniert": self.oem_signed,
            "system": self.is_system,
            "aktualisierte_system_app": self.is_updated_system,
            "flags": self.flags,
            "private_flags": self.private_flags,
            "aktiviert": self.enabled,
            "versteckt": self.hidden,
            "suspendiert": self.suspended,
            "gestoppt": self.stopped,
            "nur_daten_behalten": self.only_kept_data,
            "deaktivierte_komponenten": self.disabled_components,
            "launcher_aktivitaeten": self.launcher_activities,
            "nur_zweitprofil": self.second_profile_only,
            "berechtigungen": [p.as_dict() for p in self.permissions],
            "bedienungshilfe": self.accessibility,
            "benachrichtigungszugriff": self.notification_listener,
            "geraeteadmin": self.device_admin,
            "rollen": self.roles,
            "appops": self.appops,
            "zuletzt_genutzt": self.last_used,
            "starts": self.launch_count,
            "empfangen_bytes": self.rx_bytes,
            "gesendet_bytes": self.tx_bytes,
            "benachrichtigungen": self.notification_count,
            "laufende_dienste": self.running_services,
            "foreground_dienste": self.foreground_services,
            "apk_analyse": self.apk.as_dict() if self.apk else None,
            "reputation": self.reputation.as_dict(),
            "befunde": [f.as_dict() for f in self.findings],
            "punkte": self.scores,
            "prioritaet": self.priority.value,
        }


@dataclass
class Profile:
    """Ein Android-Benutzer/Profil auf dem Geraet."""

    user_id: int
    name: str = ""
    type: str = ""  # z. B. primaer, arbeitsprofil, private_space, klon
    running: bool = False

    def as_dict(self) -> dict:
        return {
            "id": self.user_id,
            "name": self.name,
            "typ": self.type,
            "laeuft": self.running,
        }


@dataclass
class DeviceInfo:
    """Geraeteeigenschaften und Rahmendaten des Laufs."""

    serial: str = ""
    model: str = ""
    manufacturer: str = ""
    android_release: str = ""
    sdk: str = ""
    security_patch: str = ""
    fingerprint: str = ""
    build_tags: str = ""  # release-keys / test-keys
    device_time: str = ""
    profiles: list[Profile] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "seriennummer": self.serial,
            "modell": self.model,
            "hersteller": self.manufacturer,
            "android_version": self.android_release,
            "sdk": self.sdk,
            "sicherheitspatch": self.security_patch,
            "fingerprint": self.fingerprint,
            "build_tags": self.build_tags,
            "geraetezeit": self.device_time,
            "profile": [p.as_dict() for p in self.profiles],
        }
