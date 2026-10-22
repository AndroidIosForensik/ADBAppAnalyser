"""Parser fuer ``dumpsys package packages``.

Die Ausgabe besteht aus Bloecken ``  Package [<name>] (<hash>):`` mit
eingerueckten Feldern und je Benutzer einem ``User N:``-Unterblock. Wir lesen
Bloecke robust ein: unbekannte Zeilen werden ignoriert, fehlende Felder bleiben
leer. So bricht ein Formatwechsel einzelner Hersteller den Lauf nicht ab.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Codepfade dieser Praefixe gelten als System-Partition.
SYSTEM_PATH_PREFIXES = (
    "/system/",
    "/system_ext/",
    "/product/",
    "/vendor/",
    "/apex/",
    "/odm/",
    "/oem/",
)

_PKG_HEADER = re.compile(r"^  Package \[(?P<pkg>[^\]]+)\] \(")
_USER_HEADER = re.compile(r"^    User (?P<uid>\d+):\s*(?P<rest>.*)$")


@dataclass
class UserState:
    installed: bool = True
    hidden: bool = False
    suspended: bool = False
    stopped: bool = False
    enabled: bool = True
    first_install: str = ""
    # 0=unbekannt, 1=Richtlinie, 2=Wiederherstellung, 3=Geraeteeinrichtung, 4=Nutzer
    install_reason: str = ""
    disabled_components: list[str] = field(default_factory=list)
    runtime_permissions: dict[str, tuple[bool, str]] = field(default_factory=dict)


@dataclass
class PackageBlock:
    package: str
    uid: str = ""
    code_path: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    signing_version: str = ""
    flags: list[str] = field(default_factory=list)
    private_flags: list[str] = field(default_factory=list)
    last_update: str = ""
    installer: str = ""
    initiating_installer: str = ""
    # True, sobald die Zeile initiatingPackageName= existiert (ab Android 11).
    # Wichtig, um "leer" (System hat installiert) von "unbekannt" zu trennen.
    initiating_recorded: bool = False
    package_source: str = ""
    signature_hash: str = ""
    requested_permissions: list[str] = field(default_factory=list)
    install_permissions: dict[str, bool] = field(default_factory=dict)
    users: dict[int, UserState] = field(default_factory=dict)

    @property
    def is_system(self) -> bool:
        if "SYSTEM" in self.flags:
            return True
        return self.code_path.startswith(SYSTEM_PATH_PREFIXES)

    @property
    def is_updated_system(self) -> bool:
        return "UPDATED_SYSTEM_APP" in self.flags


def parse(text: str) -> dict[str, PackageBlock]:
    """Zerlegt die gesamte Ausgabe in ``{Paketname: PackageBlock}``.

    Wir schneiden zunaechst den Abschnitt ``Packages:`` heraus (davor stehen
    z. B. ``Activity Resolver Table``-Eintraege mit gleicher Einrueckung).
    """
    lines = text.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if line.rstrip() == "Packages:":
            start = i + 1
            break

    blocks: dict[str, PackageBlock] = {}
    current: list[str] | None = None
    name: str | None = None

    def flush() -> None:
        if name is not None and current is not None:
            blocks[name] = _parse_block(name, current)

    for line in lines[start:]:
        header = _PKG_HEADER.match(line)
        if header:
            flush()
            name = header.group("pkg")
            current = []
            continue
        # Ende des Packages-Abschnitts: eine nicht eingerueckte, nicht-leere Zeile.
        if line and not line.startswith(" "):
            flush()
            name = None
            current = None
            continue
        if current is not None:
            current.append(line)
    flush()
    return blocks


def _parse_block(pkg: str, lines: list[str]) -> PackageBlock:
    block = PackageBlock(package=pkg)
    section: str | None = None  # 'requested', 'install', 'runtime', 'disabled'
    current_user: UserState | None = None

    for line in lines:
        stripped = line.strip()

        user = _USER_HEADER.match(line)
        if user:
            uid = int(user.group("uid"))
            current_user = _parse_user_line(user.group("rest"))
            block.users[uid] = current_user
            section = None
            continue

        # Abschnittsueberschriften (Einrueckung 4 Leerzeichen).
        if re.match(r"^    requested permissions:", line):
            section = "requested"
            continue
        if re.match(r"^    install permissions:", line):
            section = "install"
            continue
        if re.match(r"^      runtime permissions:", line):
            section = "runtime"
            continue
        if re.match(r"^      disabledComponents:", line):
            section = "disabled"
            continue
        if re.match(r"^      enabledComponents:", line):
            section = None
            continue
        # declared permissions und andere Unterlisten interessieren uns nicht.
        if re.match(r"^    \w[\w ]*permissions:", line) or re.match(
            r"^    (usesLibraries|usesOptionalLibraries|usesLibraryFiles|"
            r"declared permissions|queries|overlay paths|legacy overlay paths):",
            line,
        ):
            section = "skip"
            continue

        if section == "requested" and line.startswith("      "):
            perm = stripped
            if perm:
                block.requested_permissions.append(perm)
            continue
        if section == "install" and line.startswith("      "):
            m = re.match(r"(?P<name>\S+): granted=(?P<g>true|false)", stripped)
            if m:
                block.install_permissions[m.group("name")] = m.group("g") == "true"
            continue
        if section == "runtime" and current_user is not None and line.startswith("        "):
            m = re.match(
                r"(?P<name>\S+): granted=(?P<g>true|false)(?:, flags=\[(?P<f>[^\]]*)\])?",
                stripped,
            )
            if m:
                current_user.runtime_permissions[m.group("name")] = (
                    m.group("g") == "true",
                    (m.group("f") or "").strip(),
                )
            continue
        if section == "disabled" and current_user is not None and line.startswith("        "):
            if stripped:
                current_user.disabled_components.append(stripped)
            continue
        if current_user is not None and stripped.startswith("firstInstallTime="):
            current_user.first_install = stripped.split("=", 1)[1].strip()
            continue
        if current_user is not None and stripped.startswith("installReason="):
            current_user.install_reason = stripped.split("=", 1)[1].strip()
            continue

        # Einfache Schluessel=Wert-Felder auf oberster Blockebene.
        _apply_field(block, stripped)

    return block


def _apply_field(block: PackageBlock, stripped: str) -> None:
    if stripped.startswith("appId="):
        block.uid = stripped.split("=", 1)[1].strip()
    elif stripped.startswith("codePath="):
        block.code_path = stripped.split("=", 1)[1].strip()
    elif stripped.startswith("versionName="):
        block.version_name = stripped.split("=", 1)[1].strip()
    elif stripped.startswith("versionCode="):
        # Zeile: "versionCode=69139 minSdk=21 targetSdk=35"
        for token in stripped.split():
            if token.startswith("versionCode="):
                block.version_code = token.split("=", 1)[1]
            elif token.startswith("minSdk="):
                block.min_sdk = token.split("=", 1)[1]
            elif token.startswith("targetSdk="):
                block.target_sdk = token.split("=", 1)[1]
    elif stripped.startswith("apkSigningVersion="):
        block.signing_version = stripped.split("=", 1)[1].strip()
    elif stripped.startswith("flags=["):
        block.flags = _flags(stripped)
    elif stripped.startswith("privateFlags=["):
        block.private_flags = _flags(stripped)
    elif stripped.startswith("lastUpdateTime="):
        block.last_update = stripped.split("=", 1)[1].strip()
    elif stripped.startswith("installerPackageName="):
        block.installer = _nullable(stripped.split("=", 1)[1].strip())
    elif stripped.startswith("initiatingPackageName="):
        block.initiating_installer = _nullable(stripped.split("=", 1)[1].strip())
        block.initiating_recorded = True
    elif stripped.startswith("packageSource="):
        block.package_source = stripped.split("=", 1)[1].strip()
    elif stripped.startswith("signatures=PackageSignatures{"):
        m = re.search(r"signatures:\[([0-9a-fA-F, ]*)\]", stripped)
        if m:
            block.signature_hash = m.group(1).split(",")[0].strip()


def _parse_user_line(rest: str) -> UserState:
    state = UserState()

    def flag(key: str) -> bool | None:
        m = re.search(rf"\b{key}=(true|false)", rest)
        return None if m is None else m.group(1) == "true"

    if (v := flag("installed")) is not None:
        state.installed = v
    if (v := flag("hidden")) is not None:
        state.hidden = v
    if (v := flag("suspended")) is not None:
        state.suspended = v
    if (v := flag("stopped")) is not None:
        state.stopped = v
    m = re.search(r"\benabled=(\d+)", rest)
    if m:
        # 0=default, 1=enabled gelten als aktiv; 2/3/4 als deaktiviert.
        state.enabled = m.group(1) in ("0", "1")
    return state


def _flags(stripped: str) -> list[str]:
    m = re.search(r"\[([^\]]*)\]", stripped)
    if not m:
        return []
    return [f for f in m.group(1).split() if f]


def _nullable(value: str) -> str:
    return "" if value == "null" else value
