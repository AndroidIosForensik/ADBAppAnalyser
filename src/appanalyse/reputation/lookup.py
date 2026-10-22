"""Online-/Listen-Abgleich fuer Pakete: Play Store, F-Droid, VirusTotal, IOC.

Standardmaessig aktiv; mit ``offline=True`` werden keine Netzabfragen gemacht.
Alle Netzergebnisse werden gecacht (7 Tage). Datenschutzhinweis: Beim Play-/
F-Droid-Abgleich gehen Paketnamen an Google bzw. F-Droid; an VirusTotal gehen
nur Hashes und nur mit API-Key.
"""

from __future__ import annotations

import time
from pathlib import Path

from ..models import AppInfo, Reputation
from .cache import Cache
from .ioc import IOC_FILENAME, IocDatabase

PLAY_URL = "https://play.google.com/store/apps/details?id={pkg}&hl=de&gl=DE"
FDROID_URL = "https://f-droid.org/api/v1/packages/{pkg}"
VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"

WEEK = 7 * 24 * 3600
USER_AGENT = "appanalyse/0.1 (Android-App-Analyse; nur Abgleich)"


class ReputationChecker:
    def __init__(
        self,
        offline: bool = False,
        vt_key: str = "",
        cache: Cache | None = None,
        session=None,
    ):
        self.offline = offline
        self.vt_key = vt_key
        self.cache = cache or Cache()
        self._last_play = 0.0
        self._last_vt = 0.0
        self.ioc = IocDatabase.load(self.cache.dir / IOC_FILENAME)
        if session is not None:
            self.session = session
        elif not offline:
            import requests

            self.session = requests.Session()
            self.session.headers["User-Agent"] = USER_AGENT
        else:
            self.session = None

    # -- oeffentliche Schnittstelle --------------------------------------

    def check(self, app: AppInfo, is_candidate: bool) -> Reputation:
        rep = Reputation()
        # IOC- und Messenger-Listen sind lokal und immer aktiv.
        rep.ioc_match = self.ioc.match_package(app.package)
        if not rep.ioc_match and app.apk and app.apk.certificates:
            for cert in app.apk.certificates:
                hit = self.ioc.match_cert(cert.sha1)
                if hit:
                    rep.ioc_match = hit
                    break

        if not self.offline and not app.is_system:
            rep.in_play = self._play(app.package)
            rep.in_fdroid = self._fdroid(app.package)
            # VirusTotal nur fuer Kandidaten und nur mit Schluessel/Hash.
            if is_candidate and self.vt_key and app.apk and app.apk.sha256:
                known, dets = self._vt(app.apk.sha256)
                rep.vt_known = known
                rep.vt_detections = dets
        return rep

    def close(self) -> None:
        self.cache.close()

    # -- Einzelquellen ---------------------------------------------------

    def _play(self, pkg: str) -> bool | None:
        cached = self.cache.get("play", pkg, WEEK)
        if cached is not None:
            return cached.get("exists")
        self._throttle("_last_play", 1.0)
        exists = self._http_exists(PLAY_URL.format(pkg=pkg))
        if exists is not None:
            self.cache.put("play", pkg, {"exists": exists})
        return exists

    def _fdroid(self, pkg: str) -> bool | None:
        cached = self.cache.get("fdroid", pkg, WEEK)
        if cached is not None:
            return cached.get("exists")
        exists = self._http_exists(FDROID_URL.format(pkg=pkg))
        if exists is not None:
            self.cache.put("fdroid", pkg, {"exists": exists})
        return exists

    def _vt(self, sha256: str) -> tuple[bool | None, int | None]:
        cached = self.cache.get("vt", sha256, WEEK)
        if cached is not None:
            return cached.get("known"), cached.get("detections")
        self._throttle("_last_vt", 16.0)  # oeffentliches VT-Limit: 4/min
        try:
            resp = self.session.get(
                VT_URL.format(sha256=sha256),
                headers={"x-apikey": self.vt_key},
                timeout=30,
            )
        except Exception:
            return None, None
        if resp.status_code == 404:
            result = {"known": False, "detections": None}
        elif resp.status_code == 200:
            try:
                stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
                dets = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
            except Exception:
                dets = None
            result = {"known": True, "detections": dets}
        else:
            return None, None
        self.cache.put("vt", sha256, result)
        return result["known"], result["detections"]

    # -- Hilfen ----------------------------------------------------------

    def _http_exists(self, url: str) -> bool | None:
        """True/False je nach 200/404; None bei Netz-/Serverfehler.

        Bei 429 (zu viele Anfragen) wird einmal kurz gewartet und erneut versucht.
        """
        for attempt in range(2):
            try:
                resp = self.session.get(url, timeout=30, allow_redirects=True)
            except Exception:
                return None
            if resp.status_code == 200:
                return True
            if resp.status_code == 404:
                return False
            if resp.status_code == 429 and attempt == 0:
                time.sleep(3.0)
                continue
            return None
        return None

    def _throttle(self, attr: str, min_interval: float) -> None:
        last = getattr(self, attr)
        wait = min_interval - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        setattr(self, attr, time.time())
