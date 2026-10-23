"""Kommandozeile fuer appanalyse.

Befehle:
  devices        Angeschlossene Geraete auflisten
  scan           Geraet scannen und Bericht erzeugen (rein lesend)
  apk <datei>    Eine einzelne APK offline analysieren
  update-lists   Stalkerware-IOC-Liste aktualisieren
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from . import adb
from .models import PRIORITY_LABEL, Priority


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="appanalyse", description=__doc__)
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("devices", help="Angeschlossene Geraete auflisten")

    sc = sub.add_parser("scan", help="Geraet scannen (rein lesend)")
    sc.add_argument("-s", "--serial", default="", help="Seriennummer des Geraets")
    sc.add_argument("--out", default="", help="Ausgabeverzeichnis (Standard: ausgabe/)")
    sc.add_argument("--offline", action="store_true", help="Keine Online-Abfragen")
    sc.add_argument("--no-apk", action="store_true", help="Keine APKs sichern/analysieren")
    sc.add_argument("--all-apks", action="store_true", help="Auch alle System-Apps sichern")
    sc.add_argument("--keep-all-apks", action="store_true", help="Alle gesicherten APKs behalten")
    sc.add_argument("--vt-key", default=os.environ.get("VT_API_KEY", ""), help="VirusTotal-API-Key")

    ap = sub.add_parser("apk", help="Eine einzelne APK offline analysieren")
    ap.add_argument("file", help="Pfad zur .apk")

    sub.add_parser("update-lists", help="IOC-Liste aktualisieren")

    args = parser.parse_args(argv)
    if args.cmd == "devices":
        return _cmd_devices()
    if args.cmd == "scan":
        return _cmd_scan(args)
    if args.cmd == "apk":
        return _cmd_apk(args)
    if args.cmd == "update-lists":
        return _cmd_update_lists()
    parser.print_help()
    return 0


def _console():
    from rich.console import Console

    return Console()


def _cmd_devices() -> int:
    from rich.table import Table

    console = _console()
    devices = adb.list_devices()
    if not devices:
        console.print("[yellow]Keine Geraete gefunden. USB-Debugging aktiv und Geraet bestaetigt?[/]")
        return 1
    table = Table(title="Angeschlossene Geraete")
    table.add_column("Seriennummer")
    table.add_column("Status")
    table.add_column("Modell")
    for d in devices:
        table.add_row(d.serial, d.state, d.model)
    console.print(table)
    return 0


def _resolve_serial(serial: str, console) -> str | None:
    devices = [d for d in adb.list_devices() if d.usable]
    if serial:
        if any(d.serial == serial for d in devices):
            return serial
        console.print(f"[red]Geraet {serial} nicht gefunden oder nicht bereit.[/]")
        return None
    if not devices:
        console.print("[red]Kein bereites Geraet. USB-Debugging aktiv und bestaetigt?[/]")
        return None
    if len(devices) > 1:
        console.print("[yellow]Mehrere Geraete angeschlossen. Bitte mit -s <Seriennummer> waehlen:[/]")
        for d in devices:
            console.print(f"  {d.serial}  {d.model}")
        return None
    return devices[0].serial


def _cmd_scan(args) -> int:
    from .collect import ScanOptions, run_scan
    from .recorder import Recorder
    from .report import html
    from .reputation.lookup import ReputationChecker

    console = _console()
    if not adb.valid_serial(args.serial or "x"):
        console.print("[red]Ungueltige Seriennummer.[/]")
        return 1
    serial = _resolve_serial(args.serial, console)
    if not serial:
        return 1

    root = Path(args.out) if args.out else Path("ausgabe")
    run_name = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + _safe(serial)
    out_dir = root / run_name
    recorder = Recorder(out_dir)
    _write_liesmich(out_dir)

    options = ScanOptions(
        pull_apk=not args.no_apk,
        all_apks=args.all_apks,
        keep_all_apks=args.keep_all_apks,
    )
    reputation = ReputationChecker(offline=args.offline, vt_key=args.vt_key)

    console.print(f"[bold]Scan startet[/] · Geraet {serial} · Ausgabe: {out_dir}")
    device, apps, fatal = None, [], ""
    try:
        with console.status("[bold]Sammle Daten …[/]") as status:
            device, apps = run_scan(
                recorder, serial, options, reputation, out_dir / "apks",
                progress=lambda m: status.update(f"[bold]{m} …[/]"),
            )
    except Exception as exc:  # Scan robust halten: Teilergebnis sichern statt Absturz.
        fatal = f"{type(exc).__name__}: {exc}"
        recorder.add_status("scan", "FEHLER", 0, fatal)
        console.print(f"[red]Fehler waehrend des Scans:[/] {fatal}")
    finally:
        reputation.close()

    meta = {
        "online": not args.offline,
        "erstellt": datetime.now().isoformat(timespec="seconds"),
        "apk_analyse": not args.no_apk,
        "werkzeug_version": _version(),
        "fehler": fatal,
    }
    report_path = None
    if device is not None:
        try:
            report_path = html.write_all(out_dir, device, apps, meta)
        except Exception as exc:
            console.print(f"[red]Bericht konnte nicht geschrieben werden:[/] {exc}")
        if not args.keep_all_apks:
            _prune_apks(out_dir / "apks", apps)

    exit_code = recorder.finalize()
    if fatal:
        exit_code = 1
    if report_path:
        _print_summary(console, apps, report_path)
    else:
        console.print(f"[yellow]Kein vollstaendiger Bericht. Rohdaten unter:[/] {out_dir}")
    return exit_code


def _cmd_apk(args) -> int:
    from .apk import analyzer
    from .models import AppInfo
    from .scoring import score_app

    console = _console()
    path = Path(args.file)
    if not path.exists():
        console.print(f"[red]Datei nicht gefunden: {path}[/]")
        return 1
    console.print(f"[bold]Analysiere[/] {path.name} …")
    apk = analyzer.analyze(path)
    app = AppInfo(package=apk.label or path.stem, label=apk.label, apk=apk)
    # Reine APK-Analyse ohne Geraetekontext: nur Code-/Zertifikats-/Manifestbefunde.
    score_app(app, context=False)
    console.print(f"\n[bold]{app.display_name}[/]  ({PRIORITY_LABEL[app.priority]})")
    if apk.error:
        console.print(f"[yellow]Hinweis: {apk.error}[/]")
    for f in app.findings:
        w = f"+{f.weight}" if f.weight else " ·"
        console.print(f"  [bold]{w}[/] {f.text}")
        if f.evidence:
            console.print(f"       [dim]{f.evidence}[/]")
    console.print(
        f"\nPunkte — Herkunft {app.score_h()}, Chat {app.score_c()}, Verschleierung {app.score_v()}"
    )
    return 0


def _cmd_update_lists() -> int:
    import requests

    from .reputation.cache import default_cache_dir
    from .reputation.ioc import IOC_FILENAME, IOC_URL, IocDatabase

    console = _console()
    dest = default_cache_dir()
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / IOC_FILENAME
    console.print(f"Lade IOC-Liste von {IOC_URL} …")
    try:
        resp = requests.get(IOC_URL, timeout=60)
        resp.raise_for_status()
    except Exception as exc:
        console.print(f"[red]Download fehlgeschlagen: {exc}[/]")
        return 1
    target.write_bytes(resp.content)
    db = IocDatabase.load(target)
    console.print(f"[green]Gespeichert:[/] {target} · {db.size} Pakete, {len(db.cert_sha1)} Zertifikate")
    return 0


# -- Ausgabe-Hilfen --------------------------------------------------------


def _print_summary(console, apps, report_path: Path) -> None:
    from rich.table import Table

    order = [Priority.UNBEDINGT_PRUEFEN, Priority.PRUEFEN_EMPFOHLEN]
    table = Table(title="Pruefliste")
    table.add_column("Prioritaet")
    table.add_column("App")
    table.add_column("Paket")
    table.add_column("Punkte H/Chat/V", justify="right")
    table.add_column("Wichtigste Gruende")
    shown = 0
    for prio in order:
        for app in sorted((a for a in apps if a.priority == prio), key=lambda a: -a.score_total()):
            reasons = " · ".join(f.text for f in app.findings if f.weight >= 15)[:70]
            style = "red" if prio == Priority.UNBEDINGT_PRUEFEN else "yellow"
            table.add_row(
                f"[{style}]{PRIORITY_LABEL[prio]}[/]",
                app.display_name,
                app.package,
                f"{app.score_h()}/{app.score_c()}/{app.score_v()}",
                reasons,
            )
            shown += 1
    if shown:
        console.print(table)
        console.print(
            "[dim]Legende Punkte: [bold]H[/]=Herkunft (woher die App stammt: Store, "
            "seitlich geladen, Zertifikat) · [bold]Chat[/]=Chat-/Netzwerkfunktion "
            "(WebSocket, Server, Push, Krypto) · [bold]V[/]=Verschleierung/Tarnung "
            "(harmloser Name, versteckt, obfuskiert). Hoehere Werte = verdaechtiger.[/]"
        )
    else:
        console.print("[green]Keine pruefbeduerftigen Apps gefunden.[/]")
    msgs = [a for a in apps if a.priority == Priority.BEKANNTER_MESSENGER]
    console.print(f"\nBekannte Messenger: {len(msgs)} · Apps gesamt: {len(apps)}")
    if shown:
        console.print(
            "[dim]Zu jeder gelisteten App steht im Bericht ein Abschnitt "
            "'Datensicherung' mit dem passenden ADB-Befehl "
            "(run-as ohne Root, sonst Root/Backup).[/]"
        )
    console.print(f"[bold]Bericht:[/] {report_path}")


def _prune_apks(apk_dir: Path, apps) -> None:
    """Behaelt nur die APKs der Pruefliste als Beweismittel; loescht die uebrigen."""
    if not apk_dir.exists():
        return
    keep = {
        a.package
        for a in apps
        if a.priority in (Priority.UNBEDINGT_PRUEFEN, Priority.PRUEFEN_EMPFOHLEN)
    }
    for f in apk_dir.glob("*.apk"):
        if f.stem not in keep:
            try:
                f.unlink()
            except OSError:
                pass


def _write_liesmich(out_dir: Path) -> None:
    text = (
        "APP-ANALYSE\n\n"
        "bericht.html: Hauptbericht mit Pruefliste (offline im Browser oeffnen).\n"
        "pruefliste.csv / befunde.csv / berechtigungen.csv: Tabellen (UTF-8 BOM, ';').\n"
        "tabellen/apps.csv, status.csv, sha256.csv: Uebersicht, Schrittstatus, Pruefsummen.\n"
        "rohdaten/: unveraenderte stdout/stderr aller ADB-Aufrufe.\n"
        "befehle.json: exakte ADB-Argumente, Zeiten, Exitcodes.\n"
        "ergebnis.json: vollstaendiges Ergebnis maschinenlesbar.\n"
        "apks/: gesicherte APKs der Pruefliste (Beweismittel).\n\n"
        "Rein lesende Sammlung: kein Root, keine Grants, keine Aenderungen am Geraet.\n"
    )
    (out_dir / "LIESMICH.txt").write_text(text, encoding="utf-8")


def _safe(serial: str) -> str:
    import re

    return re.sub(r"[^A-Za-z0-9_.-]", "_", serial)


def _version() -> str:
    from . import __version__

    return __version__


if __name__ == "__main__":
    sys.exit(main())
