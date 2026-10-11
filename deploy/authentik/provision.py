#!/usr/bin/env python3
"""Provisionează (idempotent) aplicaţia OIDC WebTerm într-un Authentik, prin API.

Descoperă singur flow-urile, cheia de semnare şi scope mappings — nu depinde de ID-uri fixe.
Creează: un scope mapping `groups`, cele CINCI grupuri implicite (3.6.5, „grupuri SSO din
cutie"), providerul OAuth2 confidenţial cu redirect URI-ul corect, aplicaţia legată de FIECARE
grup printr-o politică de expresie `<prefix>-groups` (apartenenţa la ORICARE dintre ele dă voie
la login — un singur grup per om ajunge; modul politicilor aplicaţiei şi celelalte binding-uri
NU se ating). La final tipăreşte blocul WEBTERM_OIDC_* de pus în .env-ul WebTerm, cu maparea
grup → rol.

Grupurile implicite (prefixul `wt` se schimbă cu WT_GROUP_PREFIX, ex. `wt-prod` → `wt-prod-admins`,
ca mai multe instanţe să împartă acelaşi Authentik fără să-şi împartă oamenii):

  wt-access    doar login, NICIUN rol (îl dai de mână în WebTerm)
  wt-admins    → admin @ toate hosturile
  wt-readonly  → viewer @ toate hosturile
  wt-db        → operator @ tag:db
  wt-network   → operator @ tag:network

Owner NU se dă niciodată din grupuri: rămâne contul local break-glass.

Config din mediu (provision.sh le încarcă din .env):
  AUTHENTIK_DOMAIN            (ex: auth.example.com)      — obligatoriu
  WEBTERM_DOMAIN             (ex: term.example.com)      — obligatoriu (redirect URI)
  AUTHENTIK_API_TOKEN sau AUTHENTIK_BOOTSTRAP_TOKEN       — obligatoriu (token de API)
  WEBTERM_OIDC_PROVIDER_NAME (default: Authentik)
  WT_GROUP_PREFIX            (default: wt)
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# (sufix, rol@scope sau None = doar login). Ordinea = ordinea binding-urilor pe aplicaţie.
DEFAULT_GROUPS = (
    ("access", None),
    ("admins", "admin@all"),
    ("readonly", "viewer@all"),
    ("db", "operator@tag:db"),
    ("network", "operator@tag:network"),
)
RECOMMENDED_SESSION_MAX_HOURS = 12
_PREFIX_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9])?$")


class ProvisionError(SystemExit):
    pass


def fail(msg):
    raise ProvisionError(msg)


def group_names(prefix):
    """→ [(nume, rol@scope|None)] cu prefixul aplicat; un prefix ciudat e refuzat (nu ghicim)."""
    prefix = (prefix or "wt").strip()
    if not _PREFIX_RE.match(prefix):
        fail("WT_GROUP_PREFIX=%r: use letters, digits, '.', '_' or '-' (1-64, no leading or "
             "trailing punctuation)" % prefix)
    return [("%s-%s" % (prefix, suffix), role) for suffix, role in DEFAULT_GROUPS]


def policy_expression(names):
    """Politica de expresie Authentik: trece dacă userul e în ORICARE dintre grupuri. Nume
    validate de group_names (fără ghilimele/backslash), puse ca literali Python."""
    lines = ["# WebTerm (provision.py): membru al ORICĂRUIA dintre grupurile WebTerm",
             "for name in (%s,):" % ", ".join(repr(n) for n in names),
             "    if ak_is_group_member(request.user, name=name):",
             "        return True",
             "return False"]
    return "\n".join(lines) + "\n"


def role_map(groups):
    return ",".join("%s=%s" % (g, r) for g, r in groups if r)


class Api:
    """Clientul HTTP real (urllib). Testele îl înlocuiesc cu un Authentik fals."""

    def __init__(self, base, token):
        self.base, self.token = base, token

    def __call__(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.token)
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


def provision(call, *, ak, wt_domain, provider_name="Authentik", prefix="wt", out=print):
    """Idempotent. `call(method, path, body)` → (status, json). Întoarce dict-ul cu ce s-a
    tipărit în blocul .env (pentru teste)."""
    groups = group_names(prefix)
    redirect = "https://%s/api/oidc/callback" % wt_domain

    def results(path):
        s, d = call("GET", path)
        if s == 403:
            fail("token de API invalid/expirat (HTTP 403). Regenerează-l (vezi provision.sh).")
        return d.get("results", []) if isinstance(d, dict) else []

    def one(path, key, val):
        for r in results(path):
            if r.get(key) == val:
                return r
        return None

    # --- descoperire (robustă la versiuni: slug-urile default s-au schimbat între ediţii) ---
    def pick_flow(designation, prefer):
        flows = results("/api/v3/flows/instances/?designation=%s&page_size=100" % designation)
        if not flows:
            fail("nu am găsit niciun flow cu designation=%s în Authentik" % designation)
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
        fail("nu există nicio cheie de semnare cu private key în Authentik")
    signing_key = keys[0]["pk"]

    scope_pk = {}
    for m in results("/api/v3/propertymappings/provider/scope/"):
        if m.get("scope_name") in ("openid", "email", "profile"):
            scope_pk[m["scope_name"]] = m["pk"]
    for s in ("openid", "email", "profile"):
        if s not in scope_pk:
            fail("lipseşte scope mapping-ul standard '%s'" % s)

    # groups scope mapping: tokenul poartă `groups` (WEBTERM_OIDC_ALLOWED_GROUPS + maparea rolurilor)
    gm = one("/api/v3/propertymappings/provider/scope/?scope_name=groups", "scope_name", "groups")
    if gm:
        groups_pk = gm["pk"]
    else:
        s, d = call("POST", "/api/v3/propertymappings/provider/scope/", {
            "name": "WebTerm OIDC groups", "scope_name": "groups",
            "description": "User's Authentik groups",
            "expression": "return {\"groups\": [g.name for g in request.user.all_groups()]}"})
        if s != 201 or not d.get("pk"):
            fail("crearea scope mapping-ului 'groups' a eşuat: %s %s" % (s, d))
        groups_pk = d["pk"]
        out("scope mapping 'groups': creat")

    mappings = [scope_pk["openid"], scope_pk["email"], scope_pk["profile"], groups_pk]

    # --- grupurile implicite (create goale; NU atingem membrii unui grup existent) ----------
    group_pk = {}
    for name, _role in groups:
        grp = one("/api/v3/core/groups/?name=%s" % urllib.parse.quote(name), "name", name)
        if grp:
            group_pk[name] = grp["pk"]
            out("grup %s: există" % name)
        else:
            s, d = call("POST", "/api/v3/core/groups/", {"name": name})
            if s != 201 or not d.get("pk"):
                fail("crearea grupului %s a eşuat: %s %s" % (name, s, d))
            group_pk[name] = d["pk"]
            out("grup %s: creat" % name)

    # --- provider OAuth2 ----------------------------------------------------------------------
    prov_body = {
        "name": "webterm", "authorization_flow": auth_flow,
        "client_type": "confidential", "signing_key": signing_key,
        # 2026.8 cere grant_types explicit (default gol → „Invalid grant_type" la authorize).
        "grant_types": ["authorization_code", "refresh_token"],
        "redirect_uris": [{"matching_mode": "strict", "url": redirect}],
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
        out("provider webterm: actualizat")
    else:
        s, prov = call("POST", "/api/v3/providers/oauth2/", prov_body)
        if s != 201:
            fail("crearea providerului a eşuat: %s %s" % (s, prov))
        provider_pk = prov["pk"]
        out("provider webterm: creat")

    client_id = prov.get("client_id")
    client_secret = prov.get("client_secret")

    # --- aplicaţia + gate pe grupuri -----------------------------------------------------------
    # Modul motorului de politici al aplicaţiei (`policy_engine_mode`) NU se atinge: într-un
    # Authentik existent el decide dacă ALTE binding-uri (MFA, politici de expresie, geo, useri)
    # sunt obligatorii. O singură politică de expresie trece dacă userul e în ORICARE dintre
    # cele cinci grupuri; legată de aplicaţie, merge la fel sub `any` şi sub `all`.
    app_body = {"name": "WebTerm", "slug": "webterm", "provider": provider_pk,
                "meta_launch_url": "https://%s/" % wt_domain}
    if one("/api/v3/core/applications/?slug=webterm", "slug", "webterm"):
        call("PATCH", "/api/v3/core/applications/webterm/", app_body)
        out("aplicaţia webterm: actualizată (modul politicilor neschimbat)")
    else:
        s, d = call("POST", "/api/v3/core/applications/", app_body)
        out("aplicaţia webterm: creată" if s == 201 else "aplicaţia webterm: %s %s" % (s, d))

    s, appobj = call("GET", "/api/v3/core/applications/webterm/")
    if s != 200 or not appobj.get("pk"):
        fail("aplicaţia webterm nu poate fi citită: %s %s" % (s, appobj))
    app_pk = appobj["pk"]

    policy_name = "%s-groups" % groups[0][0].rsplit("-", 1)[0]
    expr = policy_expression([g for g, _r in groups])
    pol = one("/api/v3/policies/expression/?name=%s" % urllib.parse.quote(policy_name),
              "name", policy_name)
    if pol:
        policy_pk = pol["pk"]
        if pol.get("expression") != expr:
            s, d = call("PATCH", "/api/v3/policies/expression/%s/" % policy_pk, {"expression": expr})
            if s != 200:
                fail("actualizarea politicii %s a eşuat: %s %s" % (policy_name, s, d))
            out("politica %s: actualizată" % policy_name)
        else:
            out("politica %s: există" % policy_name)
    else:
        s, d = call("POST", "/api/v3/policies/expression/", {
            "name": policy_name, "expression": expr, "execution_logging": False})
        if s != 201 or not d.get("pk"):
            fail("crearea politicii %s a eşuat: %s %s" % (policy_name, s, d))
        policy_pk = d["pk"]
        out("politica %s: creată" % policy_name)

    existing = results("/api/v3/policies/bindings/?target=%s" % app_pk)
    if any(b.get("policy") == policy_pk for b in existing):
        out("binding %s → app: există" % policy_name)
    else:
        order = max([int(b.get("order") or 0) for b in existing] or [-1]) + 1
        s, d = call("POST", "/api/v3/policies/bindings/", {
            "target": app_pk, "policy": policy_pk, "order": order, "enabled": True})
        if s != 201:
            fail("binding %s → app a eşuat: %s %s" % (policy_name, s, d))
        out("binding %s → app: creat" % policy_name)
    # Binding-ul DIRECT pe `<prefix>-access` (pus de provision înainte de 3.6.5) e cuprins acum în
    # politică. Sub modul `all` ar cere în continuare `<prefix>-access` şi ar refuza un om aflat
    # doar în `<prefix>-db`; îl scoatem — DUPĂ ce politica e legată, deci aplicaţia nu rămâne
    # niciodată fără binding (fără binding, Authentik lasă pe oricine). Alte binding-uri: neatinse.
    access_pk = group_pk[groups[0][0]]
    for b in existing:
        if b.get("group") == access_pk and not b.get("policy") and not b.get("user"):
            s, d = call("DELETE", "/api/v3/policies/bindings/%s/" % b["pk"])
            if s not in (200, 204):
                fail("scoaterea binding-ului direct %s a eşuat: %s %s" % (groups[0][0], s, d))
            out("binding direct %s → app: scos (cuprins în %s)" % (groups[0][0], policy_name))

    # rezumat: operatorul vede ce ALTE condiţii are aplicaţia (rămân cum le-a pus el)
    mode = appobj.get("policy_engine_mode") or "any"
    out("binding-urile aplicaţiei webterm (modul %s — %s):" % (
        mode, "TOATE trebuie să treacă" if mode == "all" else "ajunge UNUL"))
    for b in sorted(results("/api/v3/policies/bindings/?target=%s" % app_pk),
                    key=lambda b: int(b.get("order") or 0)):
        if b.get("policy"):
            what = "politica %s" % ((b.get("policy_obj") or {}).get("name") or b["policy"])
        elif b.get("group"):
            what = "grupul %s" % ((b.get("group_obj") or {}).get("name") or b["group"])
        else:
            what = "userul %s" % ((b.get("user_obj") or {}).get("username") or b.get("user"))
        out("  %3s  %s%s" % (b.get("order"), what, "" if b.get("enabled", True) else " (oprit)"))

    names = [g for g, _r in groups]
    env = {
        "WEBTERM_OIDC_ISSUER": "%s/application/o/webterm/" % ak,
        "WEBTERM_OIDC_CLIENT_ID": client_id,
        "WEBTERM_OIDC_CLIENT_SECRET": client_secret,
        "WEBTERM_OIDC_PROVIDER_NAME": provider_name,
        # TOATE cele cinci: cu doar `<prefix>-access` aici, un om doar în `<prefix>-db` ar fi
        # refuzat de WebTerm deşi Authentik l-a lăsat să intre.
        "WEBTERM_OIDC_ALLOWED_GROUPS": ",".join(names),
        "WEBTERM_OIDC_ROLE_MAP": role_map(groups),
        "WEBTERM_OIDC_SSO_ONLY": "1",
        "WEBTERM_OIDC_SESSION_MAX_HOURS": str(RECOMMENDED_SESSION_MAX_HOURS),
    }
    out("\n# ---- pune astea în .env-ul WebTerm (apoi: docker compose -f docker-compose.prod.yml up -d app) ----")
    for k, v in env.items():
        out("%s=%s" % (k, v))
    out("#")
    out("# Grupuri (%s): pune fiecare om în UNUL dintre ele:" % ak)
    for name, role in groups:
        out("#   %-24s %s" % (name, ("→ " + role) if role else "doar login, fără rol (dai acces de mână în WebTerm)"))
    out("# Owner nu se dă niciodată din grupuri: rămâne contul local (break-glass).")
    return {"env": env, "groups": names}


def main():
    domain = os.environ.get("AUTHENTIK_DOMAIN", "").strip()
    wt_domain = os.environ.get("WEBTERM_DOMAIN", "").strip()
    token = os.environ.get("AUTHENTIK_API_TOKEN") or os.environ.get("AUTHENTIK_BOOTSTRAP_TOKEN") or ""
    provider_name = os.environ.get("WEBTERM_OIDC_PROVIDER_NAME", "Authentik").strip() or "Authentik"
    # AUTHENTIK_URL suprascrie baza (ex: http://127.0.0.1:9100 pentru test local, sau un Authentik
    # existent care nu stă pe https://<domeniu>). Implicit https://AUTHENTIK_DOMAIN.
    ak = (os.environ.get("AUTHENTIK_URL", "").strip().rstrip("/") or
          (("https://" + domain) if domain else ""))
    if not ak or not wt_domain or not token:
        sys.exit("lipsesc (AUTHENTIK_URL|AUTHENTIK_DOMAIN) / WEBTERM_DOMAIN / "
                 "(AUTHENTIK_API_TOKEN|AUTHENTIK_BOOTSTRAP_TOKEN)")
    provision(Api(ak, token), ak=ak, wt_domain=wt_domain, provider_name=provider_name,
              prefix=os.environ.get("WT_GROUP_PREFIX", "wt"))


if __name__ == "__main__":
    main()
