"""Parser fuer ``dumpsys netstats detail`` (Datenverkehr je UID).

Aufbau:
``  ident=[{...}] uid=10198 set=DEFAULT tag=0x0``
``    NetworkStatsHistory: bucketDuration=7200``
``      st=... rb=32598 rp=105 tb=32478 tp=122 op=0``
Wir summieren ``rb`` (empfangen) und ``tb`` (gesendet) nur fuer ``tag=0x0``
(Gesamtverkehr der App, ohne getaggte Teilmengen doppelt zu zaehlen).
"""

from __future__ import annotations

import re

_UID = re.compile(r"\buid=(?P<uid>\d+)\b.*?\btag=(?P<tag>0x[0-9a-fA-F]+)")
_BUCKET = re.compile(r"\brb=(?P<rb>\d+)\b.*?\btb=(?P<tb>\d+)\b")


_LIVE_HEADER = re.compile(r"^\s*uid\s+rxBytes\s+rxPackets\s+txBytes\s+txPackets\s*$")
_LIVE_ROW = re.compile(r"^\s*(?P<uid>\d+)\s+(?P<rx>\d+)\s+\d+\s+(?P<tx>\d+)\s+\d+\s*$")


def parse(text: str) -> dict[str, tuple[int, int]]:
    """Liefert ``{uid: (rx_bytes, tx_bytes)}``.

    Quelle 1: gespeicherter Verlauf (tag=0x0, alle Sets). Er wird nur periodisch
    geschrieben und kann fuer gerade erst genutzte Apps noch leer sein.
    Quelle 2: Live-Zaehler seit Systemstart (Tabelle ``mAppUidStatsMap``).
    Je UID wird pro Richtung der groessere Wert genommen.
    """
    history = _parse_history(text)
    live = _parse_live(text)
    result: dict[str, tuple[int, int]] = {}
    for uid in set(history) | set(live):
        h_rx, h_tx = history.get(uid, (0, 0))
        l_rx, l_tx = live.get(uid, (0, 0))
        result[uid] = (max(h_rx, l_rx), max(h_tx, l_tx))
    return result


def _parse_live(text: str) -> dict[str, tuple[int, int]]:
    live: dict[str, tuple[int, int]] = {}
    in_table = False
    for line in text.splitlines():
        if _LIVE_HEADER.match(line):
            in_table = True
            continue
        if in_table:
            m = _LIVE_ROW.match(line)
            if not m:
                in_table = False
                continue
            live[m.group("uid")] = (int(m.group("rx")), int(m.group("tx")))
    return live


def _parse_history(text: str) -> dict[str, tuple[int, int]]:
    totals: dict[str, list[int]] = {}
    current_uid: str | None = None
    active = False
    for line in text.splitlines():
        m = _UID.search(line)
        if m:
            current_uid = m.group("uid")
            active = m.group("tag") == "0x0"
            continue
        if not active or current_uid is None:
            continue
        b = _BUCKET.search(line)
        if b:
            acc = totals.setdefault(current_uid, [0, 0])
            acc[0] += int(b.group("rb"))
            acc[1] += int(b.group("tb"))
    return {uid: (v[0], v[1]) for uid, v in totals.items()}
