"""Parser fuer ``dumpsys notification`` - ausschliesslich Zaehlung je Paket.

Datenschutz: Benachrichtigungsinhalte (Absender, Text, Titel) werden bewusst
NICHT gelesen oder gespeichert. Wir zaehlen nur, wie viele aktive
NotificationRecords je Paket vorliegen, als schwaches Aktivitaetssignal.
Der Aufruf erfolgt ohne ``--noredact``.
"""

from __future__ import annotations

import re

_PKG = re.compile(r"NotificationRecord\([^)]*?\bpkg=(?P<pkg>[A-Za-z0-9_.]+)")


def parse(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in text.splitlines():
        m = _PKG.search(line)
        if m:
            counts[m.group("pkg")] = counts.get(m.group("pkg"), 0) + 1
    return counts
