"""Erkennung des Code-Typs und Extraktion druckbarer Strings aus Nicht-DEX-Code.

Manche Apps tragen ihre Logik nicht (nur) im DEX, sondern in nativen Bibliotheken
(Flutter), JS-Bundles (React Native, Cordova/Capacitor) oder .NET-Assemblies
(Xamarin). Fuer diese Dateien ziehen wir druckbare ASCII-Strings, damit dieselbe
Mustererkennung (Endpunkte, Protokoll-Signaturen, Chat-Begriffe) greift.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

_PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")


def detect_code_kind(names: list[str]) -> str:
    """Bestimmt den Code-Typ anhand charakteristischer Dateien in der APK."""
    joined = "\n".join(names)
    if "assets/flutter_assets/" in joined or re.search(r"lib/[^/]+/libflutter\.so", joined):
        return "flutter"
    if "assets/index.android.bundle" in joined or re.search(
        r"lib/[^/]+/libhermes\.so", joined
    ):
        return "react-native"
    if "assets/www/" in joined and any("cordova" in n or "capacitor" in n for n in names):
        return "cordova"
    if re.search(r"assemblies/.*\.dll", joined) or re.search(
        r"lib/[^/]+/libmonodroid\.so", joined
    ):
        return "xamarin"
    return "dex"


# Dateien, aus denen wir Nicht-DEX-Strings ziehen (nach Groesse begrenzt).
_CODE_MEMBERS = re.compile(
    r"("
    r"lib/[^/]+/lib.*\.so|"
    r"assets/index\.android\.bundle|"
    r"assets/flutter_assets/.*|"
    r"assets/www/.*\.(?:js|html)|"
    r"assemblies/.*\.dll"
    r")$"
)


def read_native_strings(
    apk_path: str | Path, max_bytes: int = 40_000_000, max_strings: int = 500_000
) -> list[str]:
    """Liest druckbare Strings aus Nicht-DEX-Codedateien der APK.

    ``max_bytes`` begrenzt die insgesamt entpackte Datenmenge, ``max_strings``
    die Anzahl. Beides schuetzt vor sehr grossen oder praeparierten Dateien.
    """
    seen: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for info in zf.infolist():
                if not _CODE_MEMBERS.search(info.filename):
                    continue
                if info.file_size > max_bytes - total:
                    continue
                try:
                    data = zf.read(info.filename)
                except (zipfile.BadZipFile, OSError):
                    continue
                total += len(data)
                for m in _PRINTABLE.findall(data):
                    seen.add(m.decode("ascii", "replace"))
                    if len(seen) >= max_strings:
                        return list(seen)
                if total >= max_bytes:
                    break
    except (zipfile.BadZipFile, OSError):
        return list(seen)
    return list(seen)
