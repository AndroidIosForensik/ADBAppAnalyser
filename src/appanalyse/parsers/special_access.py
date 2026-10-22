"""Parser fuer Sonderzugriffe: Bedienungshilfe, Benachrichtigungszugriff,
Geraeteadministratoren und Rollen (SMS/Telefon/Standard-Launcher/Assistent).

Diese Zugriffe sind fuer versteckte Chat-/Spionage-Apps besonders aussagekraeftig,
weil sie das Mitlesen von Benachrichtigungen oder Fernsteuerung erlauben.
"""

from __future__ import annotations

import re


def parse_component_list(value: str) -> set[str]:
    """Zerlegt eine ``settings``-Liste aus ``pkg/Component``-Eintraegen (mit ':').

    Liefert die Menge der beteiligten Paketnamen. ``null`` ergibt eine leere Menge.
    """
    packages: set[str] = set()
    if not value or value.strip().lower() == "null":
        return packages
    for item in re.split(r"[:\s]+", value.strip()):
        if "/" in item:
            packages.add(item.split("/", 1)[0])
    return packages


def parse_device_admins(text: str) -> set[str]:
    """Extrahiert Pakete aktiver Geraeteadministratoren aus ``dumpsys device_policy``."""
    packages: set[str] = set()
    # Zeilen wie "Admin{com.example/.Receiver}" oder "admin=ComponentInfo{pkg/...}".
    for m in re.finditer(r"(?:Admin|admin=ComponentInfo)\{([A-Za-z0-9_.]+)/", text):
        packages.add(m.group(1))
    return packages


def parse_role_holder(text: str) -> str:
    """Liefert den ersten Paketnamen aus der Ausgabe von ``cmd role get-role-holders``."""
    line = text.strip().splitlines()[0].strip() if text.strip() else ""
    # Ausgabe ist entweder leer oder "pkg" bzw. "pkg;pkg".
    return line.split(";")[0].strip() if line else ""
