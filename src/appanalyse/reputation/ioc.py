"""Abgleich mit der Stalkerware-IOC-Liste (Echap ``ioc.yaml``).

Die Liste enthaelt bekannte Spionage-/Stalkerware-Familien mit Paketnamen und
Zertifikats-SHA1. Wir laden eine lokal zwischengespeicherte Kopie (per
``update-lists`` aktualisierbar) und gleichen Paketname und Signatur-SHA1 ab.
"""

from __future__ import annotations

from pathlib import Path

import yaml

IOC_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
IOC_FILENAME = "stalkerware_ioc.yaml"


class IocDatabase:
    def __init__(self, packages: dict[str, str], cert_sha1: dict[str, str]):
        # package/sha1 (lowercase) -> Familienname
        self.packages = packages
        self.cert_sha1 = cert_sha1

    @classmethod
    def load(cls, path: Path) -> "IocDatabase":
        packages: dict[str, str] = {}
        cert_sha1: dict[str, str] = {}
        try:
            raw = yaml.safe_load(path.read_text("utf-8"))
        except (OSError, yaml.YAMLError):
            return cls({}, {})
        for entry in raw or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or (entry.get("names") or ["?"])[0]
            for pkg in entry.get("packages", []) or []:
                if isinstance(pkg, str):
                    packages[pkg.lower()] = name
            for sha1 in entry.get("certificates", []) or []:
                if isinstance(sha1, str):
                    cert_sha1[sha1.replace(":", "").lower()] = name
        return cls(packages, cert_sha1)

    def match_package(self, package: str) -> str:
        return self.packages.get(package.lower(), "")

    def match_cert(self, sha1_hex: str) -> str:
        if not sha1_hex:
            return ""
        return self.cert_sha1.get(sha1_hex.replace(":", "").lower(), "")

    @property
    def size(self) -> int:
        return len(self.packages)
