"""SSO / OIDC (ex. Authentik) — flow authorization-code + PKCE, izolat aici.

Login federat OPŢIONAL: activ doar când issuer+client_id+client_secret sunt setate (vezi
`config.OIDC_ENABLED`). Adminul local rămâne break-glass; userii SSO sunt provizionaţi la
primul login şi sunt admin complet pe această instanţă (WebTerm n-are RBAC intern).

Alegeri de securitate, deliberate:
  · `state`  — anti-CSRF pe callback (single-use, TTL scurt, server-side).
  · `nonce`  — anti-replay: legat în `id_token`, verificat la întoarcere.
  · PKCE S256 — chiar cu client_secret, ca un cod interceptat să fie inutil fără verifier.
  · validarea `id_token` cu PyJWT: ALLOWLIST explicit de algoritm (`algorithms=['RS256']` —
    fără `alg:none`, fără confuzie de algoritm), plus aud/iss/exp/iat obligatorii şi nonce.
  · redirect_uri FIX din config (derivat din PUBLIC_URL), niciodată din input de request.

HTTP outbound: `urllib` (ca updatecheck/cloudbackup). JWKS îl aduce `PyJWKClient` (tot urllib,
cu cache). Validarea criptografică o face PyJWT + cryptography (deja dependenţă).
"""
import base64
import hashlib
import json
import os
import time
import urllib.request
from typing import Optional
from urllib.parse import urlencode

import jwt
from jwt import PyJWKClient

from . import config

# tranzacţii OIDC în zbor (state → context), server-side, cu TTL. Ca grant-urile de step-up:
# gateway-ul e o singură instanţă, deci un dict e de-ajuns; se pierde la restart (fereastră
# de câteva minute — irelevant). Single-use: consumat la callback.
_TXN: dict = {}
_TXN_TTL = 600.0        # 10 min între authorize şi callback
_TXN_MAX = 10000        # plafon dur: /login e public, un flood n-are voie să umfle memoria

_disco: Optional[dict] = None
_jwks_client: Optional[PyJWKClient] = None
# algoritmi acceptaţi pentru id_token — allowlist FIX (RS256 e ce emite Authentik implicit).
# Nu citim `alg` din token; îl impunem. Aşa `none` şi confuzia RS/HS sunt imposibile.
_ALGS = ["RS256"]


def _http_json(url: str, data: Optional[bytes] = None, headers: Optional[dict] = None) -> dict:
    req = urllib.request.Request(url, data=data, headers=headers or {},
                                 method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, timeout=10) as r:      # noqa: S310 — issuer din config, TLS
        return json.loads(r.read().decode("utf-8"))


def discovery() -> dict:
    """Documentul OIDC al IdP-ului, cache-uit pe viaţa procesului."""
    global _disco
    if _disco is None:
        doc = _http_json(config.OIDC_ISSUER + "/.well-known/openid-configuration")
        # OIDC cere ca `issuer` din discovery să fie EXACT cel configurat. Verificăm (normalizând
        # slash-ul final) — altfel validarea `iss` a tokenului s-ar face contra unei valori luate
        # din acelaşi document (circular), iar un endpoint greşit/ostil ar putea muta ancora.
        iss = str(doc.get("issuer", "")).rstrip("/")
        if iss != config.OIDC_ISSUER:
            raise OidcError("discovery issuer mismatch: %r != %r" % (iss, config.OIDC_ISSUER))
        _disco = doc
    return _disco


def _jwks() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(discovery()["jwks_uri"], cache_keys=True, lifespan=3600)
    return _jwks_client


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _sweep() -> None:
    now = time.time()
    for k in [k for k, v in _TXN.items() if now - v["ts"] > _TXN_TTL]:
        _TXN.pop(k, None)
    # plafon dur împotriva unui flood pe /login (public, nelimitat de brute-force): dacă tot am
    # depăşit după curăţarea TTL, aruncăm cele mai VECHI intrări. Memoria rămâne mărginită.
    if len(_TXN) >= _TXN_MAX:
        for k in sorted(_TXN, key=lambda k: _TXN[k]["ts"])[:len(_TXN) - _TXN_MAX + 1]:
            _TXN.pop(k, None)


def begin(intent: str = "login", host_id: Optional[int] = None) -> str:
    """Porneşte un flow: generează state/nonce/PKCE, le ţine server-side, întoarce URL-ul de
    authorize. `intent`='login'|'stepup'; `host_id` pentru step-up."""
    _sweep()
    state = _b64url(os.urandom(24))
    nonce = _b64url(os.urandom(24))
    verifier = _b64url(os.urandom(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    _TXN[state] = {"ts": time.time(), "nonce": nonce, "verifier": verifier,
                   "intent": intent, "host_id": host_id}
    params = {
        "response_type": "code",
        "client_id": config.OIDC_CLIENT_ID,
        "redirect_uri": config.OIDC_REDIRECT_URI,
        "scope": config.OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if intent == "stepup":
        params["prompt"] = "login"     # step-up = re-auth proaspăt la IdP
    return discovery()["authorization_endpoint"] + "?" + urlencode(params)


class OidcError(Exception):
    pass


def _claims_groups(claims: dict) -> list:
    g = claims.get("groups")
    if isinstance(g, str):
        return [g]
    return [str(x) for x in g] if isinstance(g, list) else []


def complete(state: str, code: str) -> dict:
    """Consumă state-ul, schimbă codul, validează `id_token`, verifică grupul. Întoarce
    {sub, email, intent, host_id, groups}. Ridică OidcError la orice nepotrivire."""
    txn = _TXN.pop(state, None)      # single-use
    if not txn:
        raise OidcError("unknown or expired state")
    if time.time() - txn["ts"] > _TXN_TTL:
        raise OidcError("expired state")

    d = discovery()
    body = urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.OIDC_REDIRECT_URI,
        "client_id": config.OIDC_CLIENT_ID,
        "client_secret": config.OIDC_CLIENT_SECRET,
        "code_verifier": txn["verifier"],
    }).encode("ascii")
    try:
        tok = _http_json(d["token_endpoint"], data=body,
                         headers={"Content-Type": "application/x-www-form-urlencoded",
                                  "Accept": "application/json"})
    except Exception as e:                          # noqa: BLE001 — orice eșec de rețea/IdP
        raise OidcError("token exchange failed: %s" % e)
    id_token = tok.get("id_token")
    if not id_token:
        raise OidcError("no id_token in token response")

    try:
        signing_key = _jwks().get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token, signing_key.key,
            algorithms=_ALGS,                        # allowlist FIX — anti alg-confusion
            audience=config.OIDC_CLIENT_ID,
            issuer=d["issuer"],
            leeway=30,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except Exception as e:                          # noqa: BLE001 — semnătură/claim invalid
        raise OidcError("id_token validation failed: %s" % e)

    if claims.get("nonce") != txn["nonce"]:
        raise OidcError("nonce mismatch")

    groups = _claims_groups(claims)
    if config.OIDC_ALLOWED_GROUPS and not (set(groups) & set(config.OIDC_ALLOWED_GROUPS)):
        raise OidcError("not in an allowed group")

    sub = claims.get("sub")
    email = (claims.get("email") or "").strip().lower()
    # `email_verified` (OIDC standard): contează la ADOPŢIA unui cont local existent după email —
    # fără el, un IdP care lasă emailuri nevalidate ar permite revendicarea unui cont (ex. adminul).
    # PĂSTRĂM valoarea exactă (True/False/None): None = claim absent, decizia o ia apelantul.
    email_verified = claims.get("email_verified")
    if not sub:
        raise OidcError("no subject in id_token")
    return {"sub": str(sub), "email": email, "email_verified": email_verified,
            "groups": groups, "intent": txn["intent"], "host_id": txn["host_id"]}
