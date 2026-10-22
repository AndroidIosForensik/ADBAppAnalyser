"""ADB-Hilfsfunktionen: Geraeteliste und Shell-Aufrufe.

Die eigentliche Rohdaten-Protokollierung uebernimmt der Recorder; hier liegt
das Quoting fuer die Remote-Shell und die Geraeteerkennung.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

# ADB-Pfad einmalig aufloesen: PATH, dann bekannte WinGet-Installation.
ADB_PATH = shutil.which("adb") or "adb"


@dataclass
class Device:
    serial: str
    state: str
    model: str = ""

    @property
    def usable(self) -> bool:
        return self.state == "device"


def list_devices() -> list[Device]:
    """Listet angeschlossene Geraete (``adb devices -l``)."""
    try:
        proc = subprocess.run(
            [ADB_PATH, "devices", "-l"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    devices: list[Device] = []
    for line in proc.stdout.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        serial, state = parts[0], parts[1]
        model = ""
        for token in parts[2:]:
            if token.startswith("model:"):
                model = token[len("model:") :]
        devices.append(Device(serial, state, model))
    return devices


def quote_arg(value: str) -> str:
    """Quoting fuer ein einzelnes Argument der Remote-Shell.

    Entspricht ``Quote-AndroidArgument``: In einfache Anfuehrungszeichen setzen
    und enthaltene ``'`` durch ``'"'"'`` ersetzen. So bleiben Sonderzeichen fuer
    die Geraete-Shell literal, waehrend die lokale Argumentliste getrennt bleibt.
    """
    return "'" + value.replace("'", "'\"'\"'") + "'"


def shell_args(serial: str, tokens: list[str]) -> list[str]:
    """Baut die ADB-Argumentliste fuer einen ``adb -s <serial> shell -T``-Aufruf.

    ``-T`` deaktiviert die Terminal-Zuweisung, damit Remote-stderr und Exitcode
    getrennt uebertragen werden (wie im PowerShell-Skript begruendet).
    """
    remote = " ".join(quote_arg(t) for t in tokens)
    return ["-s", serial, "shell", "-T", remote]


_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


def valid_serial(serial: str) -> bool:
    return bool(_SERIAL_RE.match(serial))
