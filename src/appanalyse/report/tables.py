"""CSV-Ausgabe nach Excel-freundlicher Konvention.

UTF-8 mit BOM und Semikolon als Trennzeichen, wie im bestehenden
android_export.ps1. Werte werden als Text behandelt; fuehrende Nullen und
Pluszeichen bleiben erhalten, weil wir nichts numerisch umformen.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, Sequence


def write_csv(path: Path, header: Sequence[str], rows: Iterable[Sequence]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig schreibt das BOM, das Excel zur UTF-8-Erkennung braucht.
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh, delimiter=";", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(header)
        for row in rows:
            writer.writerow(["" if c is None else _cell(c) for c in row])


def _cell(value) -> str:
    if isinstance(value, bool):
        return "ja" if value else "nein"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)
