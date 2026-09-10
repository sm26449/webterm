#!/usr/bin/env python3
"""Provisionează (idempotent) aplicaţia OIDC WebTerm într-un Authentik, prin API.

Descoperă singur flow-urile, cheia de semnare şi scope mappings — nu depinde de ID-uri fixe.
Creează: un scope mapping `groups`, grupul `wt-access` (gate de acces), providerul OAuth2
confidenţial cu redirect URI-ul corect, aplicaţia legată de grup. La final tipăreşte blocul
WEBTERM_OIDC_* de pus în .env-ul WebTerm.

Config din mediu (provision.sh le încarcă din .env):
  AUTHENTIK_DOMAIN            (ex: auth.example.com)      — obligatoriu
  WEBTERM_DOMAIN             (ex: term.example.com)      — obligatoriu (redirect URI)
  AUTHENTIK_API_TOKEN sau AUTHENTIK_BOOTSTRAP_TOKEN       — obligatoriu (token de API)
  WEBTERM_OIDC_PROVIDER_NAME (default: Authentik)
"""
import json, os, sys, urllib.request, urllib.error

DOMAIN = os.environ.get("AUTHENTIK_DOMAIN", "").strip()
WT_DOMAIN = os.environ.get("WEBTERM_DOMAIN", "").strip()
TOKEN = os.environ.get("AUTHENTIK_API_TOKEN") or os.environ.get("AUTHENTIK_BOOTSTRAP_TOKEN") or ""
PROVIDER_NAME = os.environ.get("WEBTERM_OIDC_PROVIDER_NAME", "Authentik").strip() or "Authentik"
# AUTHENTIK_URL suprascrie baza (ex: http://127.0.0.1:9100 pentru test local, sau un Authentik
# existent care nu stă pe https://<domeniu>). Implicit https://AUTHENTIK_DOMAIN.
AK = (os.environ.get("AUTHENTIK_URL", "").strip().rstrip("/") or
      (("https://" + DOMAIN) if DOMAIN else ""))

if not AK or not WT_DOMAIN or not TOKEN:
    sys.exit("lipsesc (AUTHENTIK_URL|AUTHENTIK_DOMAIN) / WEBTERM_DOMAIN / (AUTHENTIK_API_TOKEN|AUTHENTIK_BOOTSTRAP_TOKEN)")

REDIRECT = "https://%s/api/oidc/callback" % WT_DOMAIN


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(AK + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"_raw": raw}


def results(path):
    s, d = call("GET", path)
    if s == 403:
        sys.exit("token de API invalid/expirat (HTTP 403). Regenerează-l (vezi provision.sh).")
    return d.get("results", []) if isinstance(d, dict) else []


def one(path, key, val):
    for r in results(path):
        if r.get(key) == val:
            return r
    return None


def need(path, key, val, human):
    r = one(path, key, val)
    if not r:
        sys.exit("nu am găsit %s (%s=%s) în Authentik" % (human, key, val))
    return r


# --- descoperire (robustă la versiuni: slug-urile default s-au schimbat între ediţii) -------
def pick_flow(designation, prefer):
    flows = results("/api/v3/flows/instances/?designation=%s&page_size=100" % designation)
    if not flows:
        sys.exit("nu am găsit niciun flow cu designation=%s în Authentik" % designation)
    for sub in prefer:
        for f in flows:
            if sub in f.get("slug", ""):
                return f["pk"]
    return flows[0]["pk"]

# explicit-consent dacă există, altfel implicit-consent, altfel orice flow de autorizare
auth_flow = pick_flow("authorization", ["explicit-consent", "implicit-consent"])
inval_flow = pick_flow("invalidation", ["default-provider-invalidation", "default-invalidation"])

keys = results("/api/v3/crypto/certificatekeypairs/?has_key=true")
if not keys:
    sys.exit("nu există nicio cheie de semnare cu private key în Authentik")
signing_key = keys[0]["pk"]

scope_pk = {}
for m in results("/api/v3/propertymappings/provider/scope/"):
    if m.get("scope_name") in ("openid", "email", "profile"):
        scope_pk[m["scope_name"]] = m["pk"]
for s in ("openid", "email", "profile"):
    if s not in scope_pk:
        sys.exit("lipseşte scope mapping-ul standard '%s'" % s)

# groups scope mapping (defence-in-depth: tokenul poartă `groups`)
gm = one("/api/v3/propertymappings/provider/scope/?scope_name=groups", "scope_name", "groups")
if gm:
    groups_pk = gm["pk"]
else:
    s, d = call("POST", "/api/v3/propertymappings/provider/scope/", {
        "name": "WebTerm OIDC groups", "scope_name": "groups",
        "description": "User's Authentik groups",
        "expression": "return {\"groups\": [g.name for g in request.user.all_groups()]}"})
    groups_pk = d.get("pk")
    print("scope mapping 'groups': creat" if s == 201 else "scope mapping 'groups': %s %s" % (s, d))

mappings = [scope_pk["openid"], scope_pk["email"], scope_pk["profile"], groups_pk]

# --- grup de acces ----------------------------------------------------------
grp = one("/api/v3/core/groups/?name=wt-access", "name", "wt-access")
if grp:
    group_pk = grp["pk"]
    print("grup wt-access: există")
else:
    s, d = call("POST", "/api/v3/core/groups/", {"name": "wt-access"})
    group_pk = d["pk"]
    print("grup wt-access: creat")

# --- provider OAuth2 --------------------------------------------------------
prov_body = {
    "name": "webterm", "authorization_flow": auth_flow,
    "client_type": "confidential", "signing_key": signing_key,
    # 2026.8 cere grant_types explicit (default gol → „Invalid grant_type" la authorize).
    "grant_types": ["authorization_code", "refresh_token"],
    "redirect_uris": [{"matching_mode": "strict", "url": REDIRECT}],
    "property_mappings": mappings, "sub_mode": "hashed_user_id",
    "include_claims_in_id_token": True,
    "access_code_validity": "minutes=1", "access_token_validity": "minutes=10",
}
if inval_flow:
    prov_body["invalidation_flow"] = inval_flow

prov = one("/api/v3/providers/oauth2/?name=webterm", "name", "webterm")
if prov:
    provider_pk = prov["pk"]
    call("PATCH", "/api/v3/providers/oauth2/%s/" % provider_pk, prov_body)
    s, prov = call("GET", "/api/v3/providers/oauth2/%s/" % provider_pk)
    print("provider webterm: actualizat")
else:
    s, prov = call("POST", "/api/v3/providers/oauth2/", prov_body)
    if s != 201:
        sys.exit("crearea providerului a eşuat: %s %s" % (s, prov))
    provider_pk = prov["pk"]
    print("provider webterm: creat")

client_id = prov.get("client_id")
client_secret = prov.get("client_secret")

# --- aplicaţia + gate pe grup ----------------------------------------------
app_body = {"name": "WebTerm", "slug": "webterm", "provider": provider_pk,
            "meta_launch_url": "https://%s/" % WT_DOMAIN}
if one("/api/v3/core/applications/?slug=webterm", "slug", "webterm"):
    call("PATCH", "/api/v3/core/applications/webterm/", app_body)
    print("aplicaţia webterm: actualizată")
else:
    s, d = call("POST", "/api/v3/core/applications/", app_body)
    print("aplicaţia webterm: creată" if s == 201 else "aplicaţia webterm: %s %s" % (s, d))

s, appobj = call("GET", "/api/v3/core/applications/webterm/")
app_pk = appobj["pk"]
bound = [b for b in results("/api/v3/policies/bindings/?target=%s" % app_pk) if b.get("group") == group_pk]
if bound:
    print("binding wt-access → app: există")
else:
    call("POST", "/api/v3/policies/bindings/", {"target": app_pk, "group": group_pk, "order": 0, "enabled": True})
    print("binding wt-access → app: creat (doar membrii wt-access pot intra)")

print("\n# ---- pune astea în .env-ul WebTerm (apoi: docker compose -f docker-compose.prod.yml up -d app) ----")
print("WEBTERM_OIDC_ISSUER=%s/application/o/webterm/" % AK)
print("WEBTERM_OIDC_CLIENT_ID=%s" % client_id)
print("WEBTERM_OIDC_CLIENT_SECRET=%s" % client_secret)
print("WEBTERM_OIDC_PROVIDER_NAME=%s" % PROVIDER_NAME)
print("#")
print("# Adaugă utilizatorii în grupul 'wt-access' din %s ca să le dai acces la această instanţă." % AK)
