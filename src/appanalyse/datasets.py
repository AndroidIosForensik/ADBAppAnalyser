"""Laedt die mitgelieferten Datenlisten (Installer, Messenger, Mods).

Die YAML-Dateien liegen im Paket unter ``data/``. Das Laden ist tolerant:
fehlt eine Datei, werden leere Mengen zurueckgegeben.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

DATA_DIR = Path(__file__).parent / "data"


@dataclass
class Datasets:
    trusted_installers: set[str] = field(default_factory=set)
    sideload_installers: set[str] = field(default_factory=set)
    messengers: set[str] = field(default_factory=set)
    mods: set[str] = field(default_factory=set)


def _load_yaml(name: str) -> dict:
    try:
        return yaml.safe_load((DATA_DIR / name).read_text("utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}


@lru_cache(maxsize=1)
def load() -> Datasets:
    installer = _load_yaml("installer.yaml")
    messenger = _load_yaml("bekannte_messenger.yaml")
    return Datasets(
        trusted_installers=set(installer.get("vertrauenswuerdig", []) or []),
        sideload_installers=set(installer.get("sideload", []) or []),
        messengers=set(messenger.get("messenger", []) or []),
        mods=set(messenger.get("mods", []) or []),
    )
