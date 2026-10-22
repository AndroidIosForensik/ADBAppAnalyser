"""Parser fuer ``cmd user list -v`` (Android-Benutzer/Profile).

Beispielzeile:
``  0: id=0, name=Eigentuemer, type=full.SYSTEM, flags=ADMIN|FULL|... (running)``
Wir leiten aus ``type`` und ``flags`` einen groben Profiltyp ab (primaer,
arbeitsprofil, private_space, klon), damit der Bericht Zweitprofile benennt.
"""

from __future__ import annotations

import re

from ..models import Profile

_LINE = re.compile(
    r"id=(?P<id>\d+),\s*name=(?P<name>.*?),\s*type=(?P<type>\S+),\s*flags=(?P<flags>\S+)"
)


def parse(text: str) -> list[Profile]:
    profiles: list[Profile] = []
    for line in text.splitlines():
        m = _LINE.search(line)
        if not m:
            continue
        flags = m.group("flags")
        profiles.append(
            Profile(
                user_id=int(m.group("id")),
                name=m.group("name").strip(),
                type=_classify(m.group("type"), flags),
                running="(running)" in line,
            )
        )
    return profiles


def _classify(type_str: str, flags: str) -> str:
    t = type_str.lower()
    f = flags.upper()
    if "PRIMARY" in f or "SYSTEM" in f:
        return "primaer"
    if "profile.managed" in t or "MANAGED_PROFILE" in f:
        return "arbeitsprofil"
    if "profile.private" in t:
        return "private_space"
    if "profile.clone" in t:
        return "klon"
    if "profile" in t:
        return "profil"
    if "restricted" in t:
        return "eingeschraenkt"
    if "guest" in t:
        return "gast"
    return "sekundaer"
