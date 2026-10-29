"""Erzeugt den HTML-Bericht sowie die CSV-/JSON-Ausgaben eines Scans.

Der HTML-Bericht ist eigenstaendig und offline nutzbar (CSS/JS inline, keine
externen Ressourcen), auf Deutsch und druckbar. Die CSVs folgen der Excel-
Konvention (UTF-8 mit BOM, Semikolon).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ..models import PRIORITY_LABEL, PRIORITY_RANK, AppInfo, DeviceInfo, Priority
from .tables import write_csv

TEMPLATE_DIR = Path(__file__).parent / "templates"


def sort_key(app: AppInfo):
    total = sum(app.scores.values())
    return (-PRIORITY_RANK[app.priority], -total, app.display_name.lower())


def write_all(out_dir: Path, device: DeviceInfo, apps: list[AppInfo], meta: dict) -> Path:
    apps_sorted = sorted(apps, key=sort_key)
    _write_csvs(out_dir, apps_sorted)
    _write_json(out_dir, device, apps_sorted, meta)
    return _write_html(out_dir, device, apps_sorted, meta)


def _write_csvs(out_dir: Path, apps: list[AppInfo]) -> None:
    table_dir = out_dir / "tabellen"

    pruefliste = [
        a
        for a in apps
        if a.priority in (Priority.UNBEDINGT_PRUEFEN, Priority.PRUEFEN_EMPFOHLEN)
    ]
    write_csv(
        out_dir / "pruefliste.csv",
        ["prioritaet", "paket", "anzeigename", "punkte_gesamt", "herkunft", "chat", "verschleierung", "gruende"],
        [
            [
                PRIORITY_LABEL[a.priority],
                a.package,
                a.display_name,
                sum(a.scores.values()),
                a.score_h(),
                a.score_c(),
                a.score_v(),
                " | ".join(f.text for f in a.findings if f.weight > 0)[:500],
            ]
            for a in pruefliste
        ],
    )

    write_csv(
        table_dir / "apps.csv",
        ["paket", "anzeigename", "prioritaet", "version", "installer", "paketquelle", "system", "benutzer", "erstinstallation", "letztes_update", "in_play", "in_fdroid", "sha256"],
        [
            [
                a.package, a.display_name, PRIORITY_LABEL[a.priority], a.version_name,
                a.installer or "null", a.package_source, a.is_system, a.users,
                a.first_install, a.last_update, a.reputation.in_play, a.reputation.in_fdroid,
                a.apk.sha256 if a.apk else "",
            ]
            for a in apps
        ],
    )

    write_csv(
        out_dir / "befunde.csv",
        ["paket", "kategorie", "punkte", "text", "beleg"],
        [
            [a.package, f.category.value, f.weight, f.text, f.evidence]
            for a in apps
            for f in a.findings
        ],
    )

    write_csv(
        out_dir / "berechtigungen.csv",
        ["paket", "berechtigung", "gewaehrt", "laufzeit", "flags"],
        [
            [a.package, p.name, p.granted, p.runtime, p.flags]
            for a in apps
            for p in a.permissions
        ],
    )


def _write_json(out_dir: Path, device: DeviceInfo, apps: list[AppInfo], meta: dict) -> None:
    from ..securing import acquisition_plan

    app_dicts = []
    for a in apps:
        d = a.as_dict()
        d["datensicherung"] = acquisition_plan(a, device.serial).as_dict()
        app_dicts.append(d)
    payload = {
        "meta": meta,
        "geraet": device.as_dict(),
        "apps": app_dicts,
    }
    (out_dir / "ergebnis.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _write_html(out_dir: Path, device: DeviceInfo, apps: list[AppInfo], meta: dict) -> Path:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    from ..securing import acquisition_plan

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    env.filters["bytes_h"] = _human_bytes
    env.globals["secure_plan"] = acquisition_plan
    template = env.get_template("bericht.html.j2")

    buckets = {p: [] for p in Priority}
    for a in apps:
        buckets[a.priority].append(a)

    html = template.render(
        device=device,
        meta=meta,
        apps=apps,
        buckets=buckets,
        labels=PRIORITY_LABEL,
        Priority=Priority,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    path = out_dir / "bericht.html"
    path.write_text(html, encoding="utf-8")
    return path


def _human_bytes(n) -> str:
    if not n:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    value = float(n)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"
