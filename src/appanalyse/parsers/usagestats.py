"""Parser fuer ``dumpsys usagestats`` (letzte Nutzung, Startzahl je Paket).

Relevante Zeilen enthalten ``package=<pkg> ... lastTimeUsed="YYYY-MM-DD hh:mm:ss"
... appLaunchCount=N``. Da mehrere Zeitfenster (Tag/Woche/Monat/Jahr) vorkommen,
behalten wir je Paket die spaeteste Nutzung und die groesste Startzahl.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_LINE = re.compile(r"package=(?P<pkg>[A-Za-z0-9_.]+)\b")
_LAST = re.compile(r'lastTimeUsed="(?P<t>[^"]*)"')
_LAUNCH = re.compile(r"appLaunchCount=(?P<n>\d+)")

# Platzhalter fuer "nie genutzt": Epoch-Anfang wird ignoriert.
_NEVER = ("1970-01-01",)


@dataclass
class Usage:
    last_used: str = ""
    launch_count: int = 0


def parse(text: str) -> dict[str, Usage]:
    result: dict[str, Usage] = {}
    for line in text.splitlines():
        m = _LINE.search(line)
        if not m:
            continue
        pkg = m.group("pkg")
        usage = result.setdefault(pkg, Usage())
        last = _LAST.search(line)
        if last:
            value = last.group("t").strip()
            if value and not value.startswith(_NEVER) and value > usage.last_used:
                usage.last_used = value
        launch = _LAUNCH.search(line)
        if launch:
            usage.launch_count = max(usage.launch_count, int(launch.group("n")))
    return result
