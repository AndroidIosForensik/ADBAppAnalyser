"""Parser fuer Launcher-Aktivitaeten und laufende Dienste.

Launcher: ``cmd package query-activities --brief -a MAIN -c LAUNCHER`` liefert
Bloecke mit je einer Komponentenzeile ``<pkg>/<activity>``.
Dienste: ``dumpsys activity services`` liefert ``ServiceRecord{...}``-Bloecke;
je Block bestimmen wir Paket, Benutzer und ob es ein Foreground-Dienst ist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_COMPONENT = re.compile(r"^\s+(?P<pkg>[A-Za-z0-9_.]+)/(?P<act>[A-Za-z0-9_.$]+)\s*$")
_SERVICE_HEADER = re.compile(
    r"ServiceRecord\{\S+ u(?P<user>\d+) (?P<pkg>[A-Za-z0-9_.]+)/(?P<svc>[A-Za-z0-9_.$]+)"
)


def parse_launchers(text: str) -> dict[str, list[str]]:
    """Liefert ``{Paket: [Launcher-Aktivitaeten]}`` aus der brief-Ausgabe."""
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = _COMPONENT.match(line)
        if not m:
            continue
        result.setdefault(m.group("pkg"), []).append(m.group("act"))
    return result


@dataclass
class ServiceInfo:
    packages: set[str] = field(default_factory=set)
    foreground: set[str] = field(default_factory=set)
    services: dict[str, list[str]] = field(default_factory=dict)


def parse_services(text: str) -> ServiceInfo:
    """Parst laufende Dienste; erkennt Foreground-Dienste je Paket.

    Ein Block gilt ab seiner ``ServiceRecord{...}``-Kopfzeile bis zur naechsten.
    Innerhalb suchen wir ``isForeground=true`` bzw. ``foregroundServiceType=``.
    """
    info = ServiceInfo()
    current_pkg: str | None = None
    current_svc: str | None = None
    for line in text.splitlines():
        header = _SERVICE_HEADER.search(line)
        if header:
            current_pkg = header.group("pkg")
            current_svc = header.group("svc")
            info.packages.add(current_pkg)
            info.services.setdefault(current_pkg, []).append(current_svc)
            continue
        if current_pkg is None:
            continue
        if "isForeground=true" in line:
            info.foreground.add(current_pkg)
        elif re.search(r"foregroundServiceType=(?!0x0\b)\S+", line):
            info.foreground.add(current_pkg)
    return info
