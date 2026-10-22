"""Handlungsempfehlung zur Datensicherung einer verdaechtigen App.

Leitet aus den APK-Merkmalen (debuggable, allowBackup) den passenden, konkreten
Weg ab, um die privaten App-Daten (u. a. SQLite-Datenbanken mit Chatverlauf) zu
sichern - mit fertigen ADB-Befehlen. Das verbindet die Auswertung direkt mit der
naechsten forensischen Massnahme.

Hintergrund:
- ``run-as`` liest die privaten Daten OHNE Root, aber nur bei ``debuggable``-Apps.
- ``adb backup`` geht nur bei ``allowBackup=true`` (und ist auf neueren Android-
  Versionen oft wirkungslos), dafuer ohne Root.
- Sonst hilft nur Root oder eine physikalische/logische Vollextraktion.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import AppInfo


@dataclass
class AcquisitionPlan:
    method: str  # "run-as" | "adb-backup" | "root" | "unbekannt" | "system"
    label: str
    root_required: bool
    commands: list[tuple[str, str]] = field(default_factory=list)  # (befehl, kommentar)
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "methode": self.method,
            "label": self.label,
            "root_noetig": self.root_required,
            "befehle": [{"befehl": c, "kommentar": k} for c, k in self.commands],
            "hinweis": self.note,
        }


def acquisition_plan(app: AppInfo, serial: str = "") -> AcquisitionPlan:
    """Liefert die passende Sicherungsempfehlung fuer eine App."""
    s = serial or "<SERIAL>"
    pkg = app.package
    data_dir = f"/data/data/{pkg}"

    if app.is_system:
        return AcquisitionPlan(
            method="system",
            label="System-App",
            root_required=True,
            note=(
                "System-App: private Daten liegen im geschuetzten Systembereich; "
                "eine Sicherung erfordert Root bzw. eine physikalische Extraktion."
            ),
        )

    apk = app.apk
    debuggable = bool(apk and apk.debuggable)
    # allowBackup ist standardmaessig true; ohne APK-Analyse unbekannt.
    allow_backup = apk.allow_backup if apk else None

    if debuggable:
        return AcquisitionPlan(
            method="run-as",
            label="run-as (ohne Root moeglich, da debuggable)",
            root_required=False,
            commands=[
                (
                    f"adb -s {s} shell run-as {pkg} ls -la databases/",
                    "private Datenbanken auflisten (z. B. verlauf.db)",
                ),
                (
                    f"adb -s {s} exec-out run-as {pkg} tar -c -C {data_dir} . > {pkg}_daten.tar",
                    "gesamte App-Daten binaersicher sichern (Datenbanken, shared_prefs, files)",
                ),
                (
                    f"sha256sum {pkg}_daten.tar",
                    "Pruefsumme fuer die Beweiskette bilden",
                ),
            ],
            note=(
                "Die App ist debuggable - die privaten Daten lassen sich ohne Root "
                "auslesen. tar entpacken und die *.db mit einem SQLite-Werkzeug "
                "(z. B. DB Browser for SQLite) oeffnen. Bei WAL-Modus zusaetzlich "
                "die *.db-wal/-shm mitsichern."
            ),
        )

    if allow_backup:
        return AcquisitionPlan(
            method="adb-backup",
            label="adb backup (ohne Root, aber veraltet)",
            root_required=False,
            commands=[
                (
                    f"adb -s {s} backup -f {pkg}.ab -noapk {pkg}",
                    "logisches Backup anstossen (am Geraet bestaetigen)",
                ),
                (
                    f"sha256sum {pkg}.ab",
                    "Pruefsumme fuer die Beweiskette bilden",
                ),
            ],
            note=(
                "Nicht debuggable, aber allowBackup=true. adb backup kann gehen, "
                "ist auf neueren Android-Versionen aber oft leer/wirkungslos. "
                "Schlaegt es fehl, hilft nur Root oder eine physikalische Extraktion."
            ),
        )

    # Nicht debuggable und (allowBackup=false ODER unbekannt): der schwere Fall.
    hint_backup = "allowBackup=false" if allow_backup is False else "Backup-Status unbekannt"
    return AcquisitionPlan(
        method="root",
        label="Root oder physikalische Extraktion noetig",
        root_required=True,
        commands=[
            (
                f"adb -s {s} shell su -c 'tar -c -C {data_dir} .' > {pkg}_daten.tar",
                "nur mit Root: gesamte App-Daten sichern",
            ),
            (
                f"sha256sum {pkg}_daten.tar",
                "Pruefsumme fuer die Beweiskette bilden",
            ),
        ],
        note=(
            f"Nicht debuggable ({hint_backup}): weder run-as noch adb backup greifen. "
            "Ohne Root bleibt nur eine logische/physikalische Vollsicherung "
            "(z. B. MTK/EDL, Chip-off) durch ein Extraktionswerkzeug."
        ),
    )
