"""Parser fuer ``cmd appops get <pkg>``.

Ausgabe je Zeile ``OP: mode`` (die erste zusaetzlich mit Praefix ``Uid mode: ``).
Modi sind u. a. allow, ignore, deny, foreground, default. Optional folgt ein
``; time=...``-Zusatz mit dem letzten Zugriff, den wir mitnehmen, falls vorhanden.
Wir behalten nur die aussagekraeftigen Operationen (Overlay, Kamera, Mikro,
Standort), um den Bericht schlank zu halten.
"""

from __future__ import annotations

import re

_LINE = re.compile(
    r"^(?:Uid mode: )?(?P<op>[A-Z_]+): (?P<mode>allow|ignore|deny|foreground|default)"
    r"(?:;\s*time=(?P<time>[^;]+))?"
)

# Fuer versteckte Chat-/Spionage-Apps besonders relevante Operationen.
INTERESTING = {
    "SYSTEM_ALERT_WINDOW",
    "CAMERA",
    "RECORD_AUDIO",
    "FINE_LOCATION",
    "COARSE_LOCATION",
    "READ_SMS",
    "RECEIVE_SMS",
    "READ_CONTACTS",
    "READ_CALL_LOG",
}


def parse(text: str, only_interesting: bool = True) -> dict[str, str]:
    """Liefert ``{OP: mode}``; bei ``only_interesting`` nur die relevanten Ops."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        op = m.group("op")
        if only_interesting and op not in INTERESTING:
            continue
        mode = m.group("mode")
        if m.group("time"):
            mode = f"{mode} (zuletzt {m.group('time').strip()})"
        result[op] = mode
    return result
