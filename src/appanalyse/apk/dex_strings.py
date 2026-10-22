"""Schneller Leser fuer die String-Tabelle von DEX-Dateien.

Wir dekompilieren nicht, sondern lesen nur die ``string_ids``-Tabelle jedes
``classes*.dex`` in der APK. Das ist um Groessenordnungen schneller als eine
vollstaendige Analyse und liefert genau die Zeichenketten, die wir fuer die
Mustererkennung brauchen: Klassendeskriptoren (z. B. ``Lokhttp3/...;``),
Protokoll-Signaturen, Endpunkte und Chat-Begriffe.

Die String-Daten liegen als MUTF-8 (Java-modifiziertes UTF-8) vor. Fuer unsere
ASCII-lastige Mustersuche genuegt eine tolerante UTF-8-Dekodierung; ungueltige
Sequenzen werden ersetzt, ohne den Lauf zu gefaehrden.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Iterator

_DEX_MAGIC = b"dex\n"
# Offsets im DEX-Header (Little Endian).
_OFF_STRING_IDS_SIZE = 0x38
_OFF_STRING_IDS_OFF = 0x3C


def read_apk_strings(apk_path: str | Path, max_strings: int = 2_000_000) -> list[str]:
    """Liest die de-duplizierten Strings aller DEX-Dateien einer APK.

    ``max_strings`` begrenzt die Gesamtzahl als Schutz gegen praeparierte oder
    ungewoehnlich grosse Dateien.
    """
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(apk_path) as zf:
            dex_names = sorted(
                n for n in zf.namelist() if n.startswith("classes") and n.endswith(".dex")
            )
            for name in dex_names:
                try:
                    data = zf.read(name)
                except (zipfile.BadZipFile, OSError):
                    continue
                for s in iter_dex_strings(data):
                    seen.add(s)
                    if len(seen) >= max_strings:
                        return list(seen)
    except (zipfile.BadZipFile, OSError):
        return list(seen)
    return list(seen)


def iter_dex_strings(data: bytes) -> Iterator[str]:
    """Liefert alle Strings eines einzelnen DEX-Blobs.

    Bei einem beschaedigten oder unerwartet formatierten Header wird still
    abgebrochen (keine Ausnahme), damit die uebrige Analyse weiterlaeuft.
    """
    if len(data) < 112 or data[:4] != _DEX_MAGIC:
        return
    try:
        (count,) = struct.unpack_from("<I", data, _OFF_STRING_IDS_SIZE)
        (ids_off,) = struct.unpack_from("<I", data, _OFF_STRING_IDS_OFF)
    except struct.error:
        return
    n = len(data)
    if ids_off + count * 4 > n or count > 5_000_000:
        return
    for i in range(count):
        try:
            (data_off,) = struct.unpack_from("<I", data, ids_off + i * 4)
        except struct.error:
            continue
        if data_off >= n:
            continue
        # ULEB128-Laenge ueberspringen, dann bis zum Nullbyte lesen.
        pos = _skip_uleb128(data, data_off)
        if pos is None:
            continue
        end = data.find(b"\x00", pos)
        if end < 0:
            end = n
        raw = data[pos:end]
        if raw:
            yield raw.decode("utf-8", "replace")


def _skip_uleb128(data: bytes, pos: int) -> int | None:
    n = len(data)
    for _ in range(5):  # ULEB128 in DEX ist maximal 5 Bytes
        if pos >= n:
            return None
        b = data[pos]
        pos += 1
        if not (b & 0x80):
            return pos
    return None
