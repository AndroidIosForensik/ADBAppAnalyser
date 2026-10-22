"""Lauf-Protokollierung nach dem Muster von android_export.ps1.

Jeder ADB-Aufruf legt seine unveraenderten stdout-/stderr-Bytes in ``rohdaten/``
ab (durchnummeriert), und ``befehle.json`` wird nach jedem Aufruf neu geschrieben,
damit auch ein spaeterer Abbruch nachvollziehbar bleibt. Zusaetzlich fuehren wir
je Schritt einen Status (OK/LEER/TEILWEISE/FEHLER) und sammeln Parse-Hinweise.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# Status-Konstanten (bewusst wie im PowerShell-Skript benannt).
OK = "OK"
LEER = "LEER"
TEILWEISE = "TEILWEISE"
FEHLER = "FEHLER"


@dataclass
class AdbResult:
    """Ergebnis eines einzelnen ADB-Aufrufs."""

    ok: bool
    exit_code: int
    timed_out: bool
    failure: str
    text: str
    error_text: str
    raw_stdout: Path
    raw_stderr: Path

    @property
    def problem(self) -> str:
        """Kurze Problembeschreibung oder leerer String, wenn alles ok ist.

        Bildet die Logik von ``Get-ResultProblem`` nach: Zeitlimit, Startfehler,
        Exitcode und Fehlermeldungen auf stderr bzw. am Anfang von stdout.
        """
        if self.timed_out:
            return "Zeitlimit ueberschritten; Teil-Rohdaten bleiben erhalten."
        if self.failure:
            return self.failure
        if self.exit_code != 0:
            return f"ADB-Exitcode {self.exit_code}; siehe Rohdaten."
        import re

        if re.search(
            r"Exception|Error|Permission Denial|Permission denied|not found|unknown|denied",
            self.error_text,
            re.IGNORECASE,
        ):
            return "Fehlermeldung auf stderr; siehe Rohdaten."
        if re.match(
            r"^\s*(Error\b|Exception\b|java\.\w+\..*?Exception|Permission Denial|"
            r"Permission denied|Security exception|Unknown command|/system/bin/sh:|"
            r"cmd:.*?not found)",
            self.text,
            re.IGNORECASE | re.DOTALL,
        ):
            return "Android meldet einen Fehler; siehe Rohdaten."
        return ""


@dataclass
class StatusRow:
    step: str
    state: str
    count: int
    note: str


@dataclass
class ParseHint:
    step: str
    context: str
    note: str


class Recorder:
    """Verwaltet Ausgabeordner, Rohdaten, Befehlsmanifest und Statuslisten."""

    def __init__(self, out_dir: Path):
        self.run_dir = out_dir
        self.raw_dir = out_dir / "rohdaten"
        self.table_dir = out_dir / "tabellen"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.table_dir.mkdir(parents=True, exist_ok=True)
        self.sequence = 0
        self.commands: list[dict] = []
        self.status: list[StatusRow] = []
        self.hints: list[ParseHint] = []

    # -- ADB-Aufrufe ------------------------------------------------------

    def run(self, name: str, args: list[str], timeout: int = 120) -> AdbResult:
        """Fuehrt einen ADB-Aufruf aus und protokolliert ihn vollstaendig.

        ``args`` sind die ADB-Argumente ohne das fuehrende ``adb`` selbst.
        stdout/stderr werden als reine Bytes gespeichert und erst danach als
        UTF-8 (mit Ersatzzeichen) fuer die Weiterverarbeitung dekodiert.
        """
        from .adb import ADB_PATH

        self.sequence += 1
        stem = f"{self.sequence:04d}_{_safe(name)}"
        out_path = self.raw_dir / f"{stem}.stdout.txt"
        err_path = self.raw_dir / f"{stem}.stderr.txt"
        started = datetime.now(timezone.utc)

        exit_code = -1
        timed_out = False
        failure = ""
        out_bytes = b""
        err_bytes = b""
        try:
            proc = subprocess.run(
                [ADB_PATH, *args],
                capture_output=True,
                timeout=timeout,
            )
            out_bytes, err_bytes = proc.stdout, proc.stderr
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            out_bytes = exc.stdout or b""
            err_bytes = exc.stderr or b""
        except FileNotFoundError:
            failure = "ADB nicht gefunden (adb.exe nicht im PATH)."
        except OSError as exc:
            failure = f"ADB-Prozess konnte nicht gestartet werden: {exc}"

        out_path.write_bytes(out_bytes)
        err_path.write_bytes(err_bytes)

        self.commands.append(
            {
                "name": name,
                "beginn": started.isoformat(),
                "ende": datetime.now(timezone.utc).isoformat(),
                "argumente": args,
                "exitcode": exit_code,
                "zeitlimit": timed_out,
                "fehler": failure,
                "stdout": f"rohdaten/{out_path.name}",
                "stderr": f"rohdaten/{err_path.name}",
            }
        )
        # Manifest nach jedem Befehl schreiben: auch bei spaeterem Abbruch nutzbar.
        (self.run_dir / "befehle.json").write_text(
            json.dumps(self.commands, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        return AdbResult(
            ok=(exit_code == 0 and not timed_out and not failure),
            exit_code=exit_code,
            timed_out=timed_out,
            failure=failure,
            text=out_bytes.decode("utf-8", "replace"),
            error_text=err_bytes.decode("utf-8", "replace"),
            raw_stdout=out_path,
            raw_stderr=err_path,
        )

    # -- Status / Hinweise ------------------------------------------------

    def add_status(self, step: str, state: str, count: int, note: str = "") -> None:
        self.status.append(StatusRow(step, state, count, note))

    def add_hint(self, step: str, context: str, note: str) -> None:
        self.hints.append(ParseHint(step, context, note))

    # -- Abschlussdateien -------------------------------------------------

    def finalize(self) -> int:
        """Schreibt Status- und Hinweislisten sowie SHA256 aller Rohdaten.

        Liefert den Exitcode nach der Konvention: 0 = alles OK/leer,
        2 = Teilfehler/Einschraenkung, 1 = mindestens ein fataler Schritt.
        """
        from .report.tables import write_csv

        write_csv(
            self.table_dir / "status.csv",
            ["schritt", "status", "anzahl", "hinweis"],
            [[s.step, s.state, s.count, s.note] for s in self.status],
        )
        write_csv(
            self.run_dir / "parse_hinweise.csv",
            ["schritt", "kontext", "hinweis"],
            [[h.step, h.context, h.note] for h in self.hints],
        )
        self._write_hashes()

        states = {s.state for s in self.status}
        if FEHLER in states:
            # Ein echter fataler Fehler wird von der CLI gesetzt; einzelne
            # FEHLER-Schritte gelten als Teilfehler.
            return 2
        if TEILWEISE in states:
            return 2
        return 0

    def _write_hashes(self) -> None:
        import hashlib

        from .report.tables import write_csv

        rows = []
        for path in sorted(self.raw_dir.glob("*.txt")):
            data = path.read_bytes()
            rows.append(
                [f"rohdaten/{path.name}", len(data), hashlib.sha256(data).hexdigest()]
            )
        write_csv(self.table_dir / "sha256.csv", ["datei", "bytes", "sha256"], rows)


def _safe(name: str) -> str:
    import re

    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)
