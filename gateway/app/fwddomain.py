"""Domeniul de forward (subdomeniile `<slug>.<domeniu>` ale port-forward-urilor).

Implicit = gazda aplicației (din PUBLIC_URL) sau WEBTERM_FORWARD_DOMAIN; poate fi suprascris din
Settings (app_settings['forward_domain']). Valoarea e memoizată aici, reîncărcată la pornire și
la salvare (`load_forward_domain`).

Stă în modul propriu, nu în api.py, ca main/syshealth/certmon s-o poată citi fără să importe
modulul de rute (importurile înapoi în api.py făceau cicluri ascunse prin importuri locale).
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlparse

from . import config, db

DEFAULT_DOMAIN = os.environ.get("WEBTERM_FORWARD_DOMAIN") or urlparse(config.PUBLIC_URL).hostname or "localhost"
_fwd_domain_cache = DEFAULT_DOMAIN


def forward_domain() -> str:
    """Domeniul de forward curent (memoizat; reîncărcat la pornire și la salvare)."""
    return _fwd_domain_cache


async def load_forward_domain() -> None:
    global _fwd_domain_cache
    row = await db.fetchone("SELECT value FROM app_settings WHERE key='forward_domain'")
    _fwd_domain_cache = (row["value"].strip() if row and row["value"] and row["value"].strip()
                         else DEFAULT_DOMAIN)


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def valid_domain(d: str) -> bool:
    return bool(_HOSTNAME_RE.match(d))
