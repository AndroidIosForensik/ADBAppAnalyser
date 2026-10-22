"""Parser fuer die verschiedenen ``pm list packages``-Varianten.

Die Detailvariante ``pm list packages -f -i -U --show-versioncode`` liefert je
Zeile APK-Pfad, Paketname, versionCode, Installer und UID. Da Android auch
``=`` in Installationspfaden verwendet, matcht der APK-Pfad bewusst gierig bis
zum letzten ``=`` vor dem Paketnamen (wie im PowerShell-Skript).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Format je Zeile: package:<apk>=<pkg><SP><extra>
# Der APK-Pfad kann selbst '=' enthalten (Android nutzt '==' in Pfaden), und mit
# '-i' steht im extra-Teil zusaetzlich 'installer=<x>'. Deshalb NICHT gierig per
# Regex splitten, sondern den Kopf (bis zum ersten Leerzeichen) am LETZTEN '='
# trennen: rechts steht dann sicher der leerzeichenfreie Paketname.
_PKG_TOKEN = re.compile(r"^[A-Za-z0-9_.]+$")


@dataclass
class PmEntry:
    package: str
    apk_path: str = ""
    version_code: str = ""
    installer: str = ""
    uid: str = ""


def parse_detail(text: str) -> tuple[dict[str, PmEntry], list[str]]:
    """Parst die Detailliste. Liefert ``({pkg: PmEntry}, bad_lines)``.

    Ein Paket kann bei mehreren APKs (Splits) mehrfach vorkommen; wir behalten
    den ersten Basis-Eintrag und ergaenzen weitere Pfade nicht hier, weil der
    Pfad aus ``dumpsys`` (codePath) ohnehin fuehrend ist.
    """
    entries: dict[str, PmEntry] = {}
    bad: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith("package:"):
            bad.append(line)
            continue
        body = line[len("package:") :]
        head, _, extra = body.partition(" ")
        apk_path, sep, pkg = head.rpartition("=")
        if not sep or not _PKG_TOKEN.match(pkg):
            bad.append(line)
            continue
        entry = PmEntry(
            package=pkg,
            apk_path=apk_path,
            version_code=_field(extra, r"versionCode:(\d+)"),
            installer=_nullable(_field(extra, r"installer=(\S+)")),
            uid=_field(extra, r"uid:(\d+)"),
        )
        entries.setdefault(entry.package, entry)
    return entries, bad


def parse_names(text: str) -> set[str]:
    """Parst eine einfache ``package:<name>``-Liste zu einer Menge von Namen."""
    names: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            name = line[len("package:") :].split("=")[-1].strip()
            if name:
                names.add(name)
    return names


def _field(text: str, pattern: str) -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else ""


def _nullable(value: str) -> str:
    return "" if value in ("null", "") else value
