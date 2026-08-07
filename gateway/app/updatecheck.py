"""Verificare „există versiune nouă?" — compară versiunea care rulează cu ultimul
tag `vX.Y.Z` de pe GitHub.

Repo public → merge fără niciun secret (API-ul GitHub răspunde neautentificat).
Repo privat → cere un token read-only în `WEBTERM_UPDATE_CHECK_TOKEN` (scope minim:
metadata read); fără el, întrebarea primește 404 și verificarea rămâne „necunoscut".
Tokenul e opțional TOCMAI ca aplicația să nu ajungă să păstreze credențiale GitHub:
cine ajunge la gateway ajunge și la ele.

E singura conexiune pe care gateway-ul o inițiază spre exterior din proprie
inițiativă, deci: se poate opri (`WEBTERM_UPDATE_CHECK=0` sau comutatorul din
Setări), nu trimite nimic despre instanță (doar un GET), și nu blochează UI-ul
dacă GitHub e inaccesibil.

Cadenţa: o dată pe zi (prima cerere după pornirea gateway-ului, apoi la 24h) plus
„verifică acum" din Setări. Mai des n-are rost — versiunile nu apar orar, iar fiecare
cerere e o urmă în plus lăsată la GitHub.
Eşecurile se cache-uiesc separat, o oră: neautentificat GitHub dă 60 de cereri/oră pe
IP, iar panoul de Status face poll des; fără asta, o eroare s-ar transforma în
rate-limit. urllib din stdlib, fără dependenţă nouă.
"""

import asyncio
import json
import re
import time
import urllib.request

from . import config

_SEMVER = re.compile(r"v?(\d+)\.(\d+)\.(\d+)$")
_TTL_OK = 86400        # o dată pe zi
_TTL_ERR = 3600        # reîncercare mai devreme dacă GitHub n-a răspuns
_cache = {"at": 0.0, "data": None, "ttl": _TTL_OK}


def _parse(s: str):
    m = _SEMVER.match((s or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def _fetch_latest_tag() -> str:
    """Ultimul tag semver de pe GitHub (blocant — rulează într-un thread)."""
    url = f"https://api.github.com/repos/{config.UPDATE_REPO}/tags?per_page=100"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "webterm-update-check",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if config.UPDATE_CHECK_TOKEN:          # doar pentru repo privat
        headers["Authorization"] = f"Bearer {config.UPDATE_CHECK_TOKEN}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        tags = json.load(r)
    versions = [(_parse(t.get("name", "")), t.get("name")) for t in tags]
    versions = sorted((v for v in versions if v[0]), reverse=True)
    return versions[0][1] if versions else None


def reset_cache() -> None:
    """Pentru teste și pentru comutarea din Setări (răspuns imediat, nu peste o oră)."""
    _cache.update(at=0.0, data=None, ttl=_TTL_OK)


async def check(force: bool = False, enabled: bool = True) -> dict:
    """`enabled=False` (din setare) → nu atinge rețeaua deloc; UI-ul arată doar versiunea."""
    current = config.GATEWAY_VERSION
    if not enabled or not config.UPDATE_CHECK:
        return {"current": current, "enabled": False}
    now = time.time()
    if not force and _cache["data"] and now - _cache["at"] < _cache["ttl"]:
        return _cache["data"]
    try:
        latest = await asyncio.to_thread(_fetch_latest_tag)
    except Exception as e:
        # nu spargem panoul de Status dacă GitHub e inaccesibil / repo încă privat
        data = {"current": current, "enabled": True, "error": str(e)[:120]}
        _cache.update(at=now, data=data, ttl=_TTL_ERR)
        return data
    cur, lat = _parse(current), _parse(latest or "")
    data = {"current": current, "latest": latest, "enabled": True,
            "update_available": bool(cur and lat and lat > cur)}
    _cache.update(at=now, data=data, ttl=_TTL_OK)
    return data
