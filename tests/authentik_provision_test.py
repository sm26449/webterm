"""deploy/authentik/provision.py contra unui Authentik FALS, în memorie (3.6.5).

Niciun apel de reţea: `provision()` primeşte clientul ca parametru, iar aici el e un dicţionar
care imită rutele API-ului Authentik folosite de script — plus un EVALUATOR al accesului la
aplicaţie (binding-uri de grup / user / politică, sub modul `any` sau `all`), ca testele să
verifice cine poate intra, nu doar ce obiecte există. Se verifică:
  * cele cinci grupuri implicite create (cu prefix) şi O politică de expresie `<prefix>-groups`
    legată de aplicaţie: un om în ORICARE grup intră, unul în niciunul nu;
  * modul politicilor aplicaţiei NU se schimbă (revizuirea de securitate 3.6.5): o politică MFA
    obligatorie (mod `all`) rămâne obligatorie; un binding de user / altă politică rămân;
  * upgrade de la provision-ul vechi (binding direct pe wt-access): un om doar în wt-db intră
    şi sub modul `all`, binding-ul direct e scos DUPĂ ce politica e legată;
  * idempotenţa: a doua rulare nu creează nimic şi nu schimbă cine intră;
  * blocul .env tipărit: ALLOWED_GROUPS cu TOATE cele cinci grupuri, ROLE_MAP cu prefixul aplicat
    şi fără Owner, SSO_ONLY=1, SESSION_MAX_HOURS=12 — şi WebTerm îl parsează fără erori;
  * un prefix invalid e refuzat înainte de orice scriere; un token invalid opreşte totul;
  * SCIM (3.6.11, opţional): providerul `<prefix>-scim` spre <public URL>/scim/v2 cu tokenul din
    fişier/mediu (niciodată argv), filtrat la membrii grupurilor WebTerm şi la grupurile
    `<prefix>-*`, pus ca backchannel pe aplicaţie fără să scoată alte backchannel-uri;
    idempotent (a doua rulare nu creează nimic); fără token nu se atinge nimic SCIM; un token
    cu altă formă / un fişier ilizibil opresc rularea.
"""
import importlib.util
import os
import re
import sys
from urllib.parse import unquote

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "wt_provision", os.path.join(HERE, "..", "deploy", "authentik", "provision.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
sys.path.insert(0, os.path.join(HERE, "..", "gateway"))

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeAuthentik:
    def __init__(self):
        self.groups = {}            # name -> {"pk", "name", "users"}
        self.policies = {}          # pk -> {"pk","name","expression"} (expression) sau {"kind":"mfa"}
        self.bindings = []          # {"pk","target","group"|"policy"|"user","order","enabled"}
        self.providers = {}
        self.apps = {}
        self.scope_maps = [{"pk": "m-openid", "scope_name": "openid"},
                           {"pk": "m-email", "scope_name": "email"},
                           {"pk": "m-profile", "scope_name": "profile"}]
        self.writes = []
        self.scim_providers = {}
        self.scim_maps = [{"pk": "sm-user", "managed": "goauthentik.io/providers/scim/user",
                           "name": "authentik default SCIM Mapping: User"},
                          {"pk": "sm-group", "managed": "goauthentik.io/providers/scim/group",
                           "name": "authentik default SCIM Mapping: Group"}]
        self.app_bodies = []        # corpurile POST/PATCH pe aplicaţie (modul nu are voie să apară)
        self.n = 0

    def _pk(self, p):
        self.n += 1
        return "%s-%d" % (p, self.n)

    # ── cine intră în aplicaţia webterm (semantica policy engine-ului Authentik) ──
    def allowed(self, user, groups, mfa=True):
        app = self.apps["webterm"]
        bs = [b for b in self.bindings if b["target"] == app["pk"] and b.get("enabled", True)]
        neg = {id(b) for b in bs if b.get("negate")}
        if not bs:
            return True                     # fără binding Authentik lasă pe oricine
        res = []
        for b in bs:
            if b.get("group"):
                res.append(any(g["pk"] == b["group"] and g["name"] in groups
                               for g in self.groups.values()))
            elif b.get("user"):
                res.append(b["user"] == user)
            else:
                pol = self.policies[b["policy"]]
                if pol.get("kind") == "mfa":
                    res.append(mfa)
                else:
                    names = re.findall(r"'([^']+)'", pol["expression"].split("for name in", 1)[1]
                                       .split(":", 1)[0])
                    res.append(any(n in groups for n in names))
            if id(b) in neg:
                res[-1] = not res[-1]
        mode = app.get("policy_engine_mode", "any")
        return all(res) if mode == "all" else any(res)

    def __call__(self, method, path, body=None):
        if method != "GET":
            self.writes.append((method, path))
        base, _, q = path.partition("?")
        qs = {k: unquote(v) for k, v in (x.split("=", 1) for x in q.split("&") if "=" in x)}
        if method == "GET" and base == "/api/v3/flows/instances/":
            d = qs.get("designation")
            slug = {"authorization": "default-provider-authorization-implicit-consent",
                    "invalidation": "default-provider-invalidation-flow"}[d]
            return 200, {"results": [{"pk": "flow-" + d, "slug": slug}]}
        if method == "GET" and base == "/api/v3/crypto/certificatekeypairs/":
            return 200, {"results": [{"pk": "key-1"}]}
        if base == "/api/v3/propertymappings/provider/scope/":
            if method == "GET":
                res = self.scope_maps
                if "scope_name" in qs:
                    res = [m for m in res if m["scope_name"] == qs["scope_name"]]
                return 200, {"results": res}
            m = dict(body, pk=self._pk("map"))
            self.scope_maps.append(m)
            return 201, m
        if base == "/api/v3/core/groups/":
            if method == "GET":
                name = qs.get("name", "")
                return 200, {"results": [g for g in self.groups.values()
                                         if not name or name in g["name"]]}
            g = {"pk": self._pk("grp"), "name": body["name"], "users": []}
            self.groups[g["name"]] = g
            return 201, g
        if base == "/api/v3/policies/expression/":
            if method == "GET":
                name = qs.get("name", "")
                return 200, {"results": [p for p in self.policies.values()
                                         if "expression" in p and (not name or name in p["name"])]}
            pol = dict(body, pk=self._pk("pol"))
            self.policies[pol["pk"]] = pol
            return 201, pol
        if base.startswith("/api/v3/policies/expression/"):
            pk = base.rstrip("/").rsplit("/", 1)[1]
            if method == "PATCH":
                self.policies[pk].update(body)
            return 200, self.policies[pk]
        if base == "/api/v3/providers/oauth2/":
            if method == "GET":
                return 200, {"results": list(self.providers.values())}
            pr = dict(body, pk=self._pk("prov"), client_id="cid", client_secret="csecret")
            self.providers[pr["pk"]] = pr
            return 201, pr
        if base.startswith("/api/v3/providers/oauth2/"):
            pk = base.rstrip("/").rsplit("/", 1)[1]
            if method == "PATCH":
                self.providers[pk].update(body)
            return 200, self.providers[pk]
        if base == "/api/v3/propertymappings/provider/scim/":
            if method == "GET":
                res = self.scim_maps
                if "managed" in qs:
                    res = [m for m in res if m.get("managed") == qs["managed"]]
                if "name" in qs:
                    res = [m for m in res if qs["name"] in m.get("name", "")]
                return 200, {"results": [dict(m) for m in res]}
            m = dict(body, pk=self._pk("smap"))
            self.scim_maps.append(m)
            return 201, m
        if base.startswith("/api/v3/propertymappings/provider/scim/") and method == "PATCH":
            pk = base.rstrip("/").rsplit("/", 1)[1]
            for m in self.scim_maps:
                if m["pk"] == pk:
                    m.update(body)
                    return 200, dict(m)
            return 404, {}
        if base == "/api/v3/providers/scim/":
            if method == "GET":
                name = qs.get("name", "")
                return 200, {"results": [dict(p) for p in self.scim_providers.values()
                                         if not name or name in p["name"]]}
            pr = dict(body, pk=self._pk("scim"))
            self.scim_providers[pr["pk"]] = pr
            return 201, pr
        if base.startswith("/api/v3/providers/scim/") and method == "PATCH":
            pk = base.rstrip("/").rsplit("/", 1)[1]
            self.scim_providers[pk].update(body)
            return 200, dict(self.scim_providers[pk])
        if base.startswith("/api/v3/core/applications/") and method in ("POST", "PATCH"):
            self.app_bodies.append(dict(body or {}))
        if base == "/api/v3/core/applications/":
            if method == "GET":
                return 200, {"results": list(self.apps.values())}
            a = dict(body, pk=self._pk("app"))
            a.setdefault("policy_engine_mode", "any")     # implicitul Authentik
            self.apps[a["slug"]] = a
            return 201, a
        if base == "/api/v3/core/applications/webterm/":
            if method == "PATCH":
                self.apps["webterm"].update(body)
            return 200, self.apps["webterm"]
        if base == "/api/v3/policies/bindings/":
            if method == "GET":
                return 200, {"results": [dict(b) for b in self.bindings
                                         if b["target"] == qs.get("target")]}
            if any(b["target"] == body["target"] and b["order"] == body["order"] for b in self.bindings):
                return 400, {"order": "duplicate"}
            b = dict(body, pk=self._pk("bind"))
            self.bindings.append(b)
            return 201, b
        if base.startswith("/api/v3/policies/bindings/") and method == "PATCH":
            pk = base.rstrip("/").rsplit("/", 1)[1]
            for b in self.bindings:
                if b["pk"] == pk:
                    b.update(body)
                    return 200, dict(b)
            return 404, {}
        if base.startswith("/api/v3/policies/bindings/") and method == "DELETE":
            pk = base.rstrip("/").rsplit("/", 1)[1]
            self.bindings = [b for b in self.bindings if b["pk"] != pk]
            return 204, {}
        return 404, {"detail": "not faked: %s %s" % (method, path)}


def run(ak, prefix="wt"):
    lines = []
    res = P.provision(ak, ak="https://auth.example.test", wt_domain="term.example.test",
                      prefix=prefix, out=lines.append)
    return res, lines


NAMES = ["wt-access", "wt-admins", "wt-readonly", "wt-db", "wt-network"]


def access_matrix(ak, mfa=True):
    return {g: ak.allowed("u", {g}, mfa) for g in NAMES + ["other-team"]}


def main():
    print("── instalare nouă, prefix implicit")
    ak = FakeAuthentik()
    res, lines = run(ak)
    check("cele cinci grupuri create", sorted(ak.groups) == sorted(NAMES), str(sorted(ak.groups)))
    app = ak.apps.get("webterm", {})
    pols = [p for p in ak.policies.values() if p.get("name") == "wt-groups"]
    check("o politică de expresie wt-groups", len(pols) == 1)
    bound = [b for b in ak.bindings if b["target"] == app.get("pk")]
    check("aplicaţia are exact un binding: politica", len(bound) == 1 and bound[0].get("policy") == pols[0]["pk"],
          str(bound))
    check("modul politicilor aplicaţiei nu e trimis de provision",
          ak.app_bodies and all("policy_engine_mode" not in b for b in ak.app_bodies)
          and app.get("policy_engine_mode") == "any", str(ak.app_bodies))
    m = access_matrix(ak)
    check("un om în ORICARE dintre cele cinci grupuri intră", all(m[g] for g in NAMES), str(m))
    check("un om în niciunul NU intră", not m["other-team"])
    check("politica foloseşte ak_is_group_member", "ak_is_group_member(request.user, name=name)"
          in pols[0]["expression"])
    prov = next(iter(ak.providers.values()))
    check("providerul primeşte scope mapping-ul `groups`",
          any(m["scope_name"] == "groups" and m["pk"] in prov["property_mappings"] for m in ak.scope_maps))
    check("redirect URI-ul e cel al instanţei",
          prov["redirect_uris"] == [{"matching_mode": "strict",
                                     "url": "https://term.example.test/api/oidc/callback"}])
    env = res["env"]
    check("ALLOWED_GROUPS listează TOATE cele cinci grupuri (nu doar wt-access)",
          env["WEBTERM_OIDC_ALLOWED_GROUPS"].split(",") == NAMES, env["WEBTERM_OIDC_ALLOWED_GROUPS"])
    check("ROLE_MAP = harta implicită",
          env["WEBTERM_OIDC_ROLE_MAP"] == "wt-admins=admin@all,wt-readonly=viewer@all,"
                                         "wt-db=operator@tag:db,wt-network=operator@tag:network",
          env["WEBTERM_OIDC_ROLE_MAP"])
    check("…fără Owner şi fără wt-access (doar login)",
          "owner" not in env["WEBTERM_OIDC_ROLE_MAP"] and "wt-access" not in env["WEBTERM_OIDC_ROLE_MAP"])
    check("SSO_ONLY=1 şi SESSION_MAX_HOURS=12 recomandate",
          env["WEBTERM_OIDC_SSO_ONLY"] == "1" and env["WEBTERM_OIDC_SESSION_MAX_HOURS"] == "12")
    for k in ("WEBTERM_OIDC_ISSUER", "WEBTERM_OIDC_CLIENT_ID", "WEBTERM_OIDC_CLIENT_SECRET",
              "WEBTERM_OIDC_ALLOWED_GROUPS", "WEBTERM_OIDC_ROLE_MAP", "WEBTERM_OIDC_SSO_ONLY",
              "WEBTERM_OIDC_SESSION_MAX_HOURS"):
        check("blocul .env tipăreşte %s" % k, any(line.startswith(k + "=") for line in lines))
    check("rezumatul binding-urilor aplicaţiei e tipărit",
          any("binding-urile aplicaţiei" in line for line in lines))
    from app import ssomap
    parsed, bad = ssomap.parse_role_map(env["WEBTERM_OIDC_ROLE_MAP"])
    check("WebTerm parsează harta tipărită fără nicio eroare", len(parsed) == 4 and not bad, str(bad))

    print("── a doua rulare: idempotentă")
    ak.groups["wt-db"]["users"] = ["alice"]
    n_posts = len([w for w in ak.writes if w[0] in ("POST", "DELETE")])
    res2, _ = run(ak)
    check("nicio creare / ştergere nouă (doar PATCH-uri de actualizare)",
          len([w for w in ak.writes if w[0] in ("POST", "DELETE")]) == n_posts, str(ak.writes[-6:]))
    check("aceleaşi cinci grupuri, acelaşi binding", len(ak.groups) == 5 and len(ak.bindings) == 1)
    check("membrii unui grup existent nu sunt atinşi", ak.groups["wt-db"]["users"] == ["alice"])
    check("acelaşi bloc .env", res2["env"] == env)
    check("acelaşi acces", access_matrix(ak) == m)

    for mode in ("any", "all"):
        print("── upgrade de la provision-ul vechi (binding direct wt-access), mod %s" % mode)
        old = FakeAuthentik()
        old.groups["wt-access"] = {"pk": "grp-old", "name": "wt-access", "users": ["bob"]}
        old.apps["webterm"] = {"pk": "app-old", "slug": "webterm", "name": "WebTerm",
                               "policy_engine_mode": mode}
        old.bindings.append({"pk": "b0", "target": "app-old", "group": "grp-old", "order": 0,
                             "enabled": True})
        run(old)
        mm = access_matrix(old)
        check("[%s] un om doar în wt-db intră (nu mai e blocat de binding-ul vechi)" % mode, mm["wt-db"], str(mm))
        check("[%s] wt-access intră în continuare" % mode, mm["wt-access"])
        check("[%s] niciun grup → refuzat" % mode, not mm["other-team"])
        check("[%s] binding-ul direct pe wt-access e scos, politica legată" % mode,
              [b.get("policy") is not None for b in old.bindings] == [True], str(old.bindings))
        check("[%s] modul aplicaţiei neschimbat" % mode, old.apps["webterm"]["policy_engine_mode"] == mode)
        ok_order = ("POST", "/api/v3/policies/bindings/") in old.writes and \
            old.writes.index(("POST", "/api/v3/policies/bindings/")) < \
            old.writes.index(("DELETE", "/api/v3/policies/bindings/b0/"))
        check("[%s] politica e legată ÎNAINTE de scoaterea binding-ului vechi (niciodată zero binding-uri)"
              % mode, ok_order, str(old.writes))

    for flag in ("enabled", "negate"):
        print("── binding-ul politicii %s de un admin, apoi re-rulare" % ("oprit" if flag == "enabled" else "negat"))
        dis = FakeAuthentik()
        run(dis)
        app_pk = dis.apps["webterm"]["pk"]
        grp = dis.groups["wt-access"]["pk"]
        pb = next(b for b in dis.bindings if b.get("policy"))
        pb[flag] = flag != "enabled"
        dis.bindings.append({"pk": "bd", "target": app_pk, "group": grp, "order": 9, "enabled": True})
        run(dis)
        check("[%s] binding-ul politicii e reactivat" % flag,
              pb.get("enabled", True) and not pb.get("negate"), str(pb))
        check("[%s] niciun grup → refuzat (aplicaţia nu rămâne deschisă)" % flag,
              not dis.allowed("u", {"other-team"}))
        check("[%s] wt-db intră" % flag, dis.allowed("u", {"wt-db"}))

    print("── binding direct al ALTEI aplicaţii (răspuns nefiltrat) nu e atins")
    oth = FakeAuthentik()
    run(oth)
    grp = oth.groups["wt-access"]["pk"]
    oth.bindings.append({"pk": "bx", "target": "app-other", "group": grp, "order": 0, "enabled": True})
    real_call = oth.__call__
    def leaky(method, path, body=None):
        if method == "GET" and path.startswith("/api/v3/policies/bindings/"):
            return 200, {"results": [dict(b) for b in oth.bindings]}
        return real_call(method, path, body)
    P.provision(leaky, ak="https://auth.example.test", wt_domain="term.example.test",
                prefix="wt", out=lambda *_: None)
    check("binding-ul altei aplicaţii rămâne", any(b["pk"] == "bx" for b in oth.bindings))

    print("── aplicaţie cu o politică MFA obligatorie (mod all) şi un binding de user")
    mfa = FakeAuthentik()
    mfa.policies["pol-mfa"] = {"pk": "pol-mfa", "name": "require-mfa", "kind": "mfa"}
    mfa.apps["webterm"] = {"pk": "app-m", "slug": "webterm", "name": "WebTerm",
                           "policy_engine_mode": "all"}
    mfa.bindings.append({"pk": "bm", "target": "app-m", "policy": "pol-mfa", "order": 0, "enabled": True})
    run(mfa)
    check("modul `all` rămas neschimbat (niciun corp nu-l trimite)",
          mfa.apps["webterm"]["policy_engine_mode"] == "all"
          and all("policy_engine_mode" not in b for b in mfa.app_bodies))
    check("binding-ul MFA e intact", any(b["pk"] == "bm" for b in mfa.bindings))
    check("membru wt-db CU MFA → intră", mfa.allowed("u", {"wt-db"}, mfa=True))
    check("membru wt-db FĂRĂ MFA → refuzat (MFA rămâne obligatorie)", not mfa.allowed("u", {"wt-db"}, mfa=False))
    check("fără grup, cu MFA → refuzat", not mfa.allowed("u", {"x"}, mfa=True))
    run(mfa)
    check("re-rulare: tot 2 binding-uri, MFA încă obligatorie",
          len(mfa.bindings) == 2 and not mfa.allowed("u", {"wt-db"}, mfa=False))
    usr = FakeAuthentik()
    usr.apps["webterm"] = {"pk": "app-u", "slug": "webterm", "name": "WebTerm", "policy_engine_mode": "any"}
    usr.bindings.append({"pk": "bu", "target": "app-u", "user": "ops-bot", "order": 0, "enabled": True})
    run(usr)
    check("un binding de user existent e păstrat", any(b["pk"] == "bu" for b in usr.bindings)
          and usr.allowed("ops-bot", set()))

    print("── prefix per instanţă")
    ak3 = FakeAuthentik()
    res3, _ = run(ak3, prefix="wt-prod")
    check("grupurile poartă prefixul", sorted(ak3.groups) == sorted(
        "wt-prod-" + s for s in ("access", "admins", "readonly", "db", "network")), str(sorted(ak3.groups)))
    check("politica se numeşte wt-prod-groups", any(p.get("name") == "wt-prod-groups" for p in ak3.policies.values()))
    check("un om în wt-db (alt prefix) NU intră pe instanţa wt-prod", not ak3.allowed("u", {"wt-db"}))
    check("ROLE_MAP şi ALLOWED_GROUPS folosesc prefixul",
          res3["env"]["WEBTERM_OIDC_ROLE_MAP"].startswith("wt-prod-admins=admin@all")
          and "wt-prod-network" in res3["env"]["WEBTERM_OIDC_ALLOWED_GROUPS"]
          and "wt-access" not in res3["env"]["WEBTERM_OIDC_ALLOWED_GROUPS"].split(","))
    for badp in ("wt prod", "wt-", "-wt", "a" * 80, "wt,x", "wt=x", "wt'x", "wt\\x"):
        ak4 = FakeAuthentik()
        try:
            run(ak4, prefix=badp)
            refused = False
        except SystemExit:
            refused = True
        check("prefix %r refuzat înainte de orice scriere" % badp[:20], refused and not ak4.writes,
              str(ak4.writes[:3]))

    print("── SCIM (3.6.11): provider + backchannel, idempotent, token din fişier/mediu")
    tok = "wtscim_" + "A" * 43
    ak5 = FakeAuthentik()
    run(ak5)
    check("fără token SCIM: nimic SCIM creat", not ak5.scim_providers
          and not any("/scim/" in w[1] for w in ak5.writes))
    ak5.apps["webterm"]["backchannel_providers"] = ["other-bc"]
    lines = []
    res5 = P.provision(ak5, ak="https://auth.example.test", wt_domain="term.example.test",
                       prefix="wt", out=lines.append, scim_token=tok)
    provs = list(ak5.scim_providers.values())
    check("un provider SCIM wt-scim", len(provs) == 1 and provs[0]["name"] == "wt-scim", str(provs))
    pr = provs[0] if provs else {}
    check("URL-ul = https://<WEBTERM_DOMAIN>/scim/v2 şi tokenul dat", pr.get("url") ==
          "https://term.example.test/scim/v2" and pr.get("token") == tok)
    check("certificate verificate, conturile de serviciu excluse",
          pr.get("verify_certificates") is True and pr.get("exclude_users_service_account") is True)
    umaps = [m for m in ak5.scim_maps if m["pk"] in pr.get("property_mappings", [])]
    gmaps = [m for m in ak5.scim_maps if m["pk"] in pr.get("property_mappings_group", [])]
    uf = next((m for m in umaps if "expression" in m), {})
    gf = next((m for m in gmaps if "expression" in m), {})
    check("useri: maparea implicită + filtrul WebTerm", "sm-user" in pr.get("property_mappings", [])
          and "raise SkipObject" in uf.get("expression", ""))
    check("…filtrul trece DOAR membrii celor cinci grupuri",
          all(repr(n) in uf.get("expression", "") for n in NAMES)
          and "ak_is_group_member(request.user, name=name)" in uf.get("expression", ""))
    check("grupuri: maparea implicită + doar wt-*", "sm-group" in pr.get("property_mappings_group", [])
          and "startswith('wt-')" in gf.get("expression", "") and "raise SkipObject" in gf.get("expression", ""))
    check("backchannel pe aplicaţia webterm, cel existent păstrat",
          ak5.apps["webterm"].get("backchannel_providers") == ["other-bc", pr.get("pk")],
          str(ak5.apps["webterm"].get("backchannel_providers")))
    check("modul politicilor tot neatins", all("policy_engine_mode" not in b for b in ak5.app_bodies))
    check("tokenul NU apare în ce se tipăreşte", not any(tok in ln for ln in lines))
    check("rezultatul spune URL-ul SCIM", res5["scim"]["url"] == "https://term.example.test/scim/v2")
    n = len([w for w in ak5.writes if w[0] in ("POST", "DELETE")])
    P.provision(ak5, ak="https://auth.example.test", wt_domain="term.example.test", prefix="wt",
                out=lambda *_: None, scim_token=tok)
    check("a doua rulare: nicio creare (idempotent)", len([w for w in ak5.writes if w[0] in ("POST", "DELETE")]) == n
          and len(ak5.scim_providers) == 1
          and ak5.apps["webterm"]["backchannel_providers"].count(pr.get("pk")) == 1)
    tok2 = "wtscim_" + "B" * 43
    P.provision(ak5, ak="https://auth.example.test", wt_domain="term.example.test", prefix="wt",
                out=lambda *_: None, scim_token=tok2, scim_url="https://wt.internal:8443/scim/v2/")
    check("token rotit + URL explicit → providerul actualizat (PATCH)",
          pr["pk"] in ak5.scim_providers and ak5.scim_providers[pr["pk"]]["token"] == tok2
          and ak5.scim_providers[pr["pk"]]["url"] == "https://wt.internal:8443/scim/v2")
    ak6 = FakeAuthentik()
    P.provision(ak6, ak="https://auth.example.test", wt_domain="term.example.test", prefix="wt-prod",
                out=lambda *_: None, scim_token=tok)
    p6 = next(iter(ak6.scim_providers.values()))
    g6 = next(m for m in ak6.scim_maps if m["pk"] in p6["property_mappings_group"] and "expression" in m)
    check("prefix wt-prod: providerul wt-prod-scim, doar grupurile wt-prod-*",
          p6["name"] == "wt-prod-scim" and "startswith('wt-prod-')" in g6["expression"])
    import tempfile
    d = tempfile.mkdtemp()
    fpath = os.path.join(d, "scim-token")
    with open(fpath, "w") as f:
        f.write(tok + "\n")
    check("tokenul din WEBTERM_SCIM_TOKEN_FILE (rândul nou final tăiat)",
          P.read_scim_token({"WEBTERM_SCIM_TOKEN_FILE": fpath}) == tok)
    check("…sau din WEBTERM_SCIM_TOKEN", P.read_scim_token({"WEBTERM_SCIM_TOKEN": tok}) == tok)
    check("niciunul setat → fără SCIM", P.read_scim_token({}) is None)
    for what, env in (("fişier inexistent", {"WEBTERM_SCIM_TOKEN_FILE": fpath + ".nope"}),
                      ("token de automatizare (wt_…)", {"WEBTERM_SCIM_TOKEN": "wt_" + "x" * 43}),
                      ("token scurt", {"WEBTERM_SCIM_TOKEN": "wtscim_x"}),
                      ("token cu spaţii", {"WEBTERM_SCIM_TOKEN": "wtscim_" + "a" * 20 + " " + "b" * 20})):
        try:
            P.read_scim_token(env)
            stopped = False
        except SystemExit:
            stopped = True
        check("SCIM: %s → oprire" % what, stopped)
    os.remove(fpath)
    os.rmdir(d)
    src = open(os.path.join(HERE, "..", "deploy", "authentik", "provision.py"), encoding="utf-8").read()
    check("main() citeşte tokenul doar din mediu/fişier (argv neatins)",
          "sys.argv" not in src and "read_scim_token()" in src)

    print("── un token invalid opreşte totul")
    try:
        P.provision(lambda m, p, b=None: (403, {}), ak="https://x", wt_domain="y", out=lambda s: None)
        stopped = False
    except SystemExit:
        stopped = True
    check("HTTP 403 → oprire cu mesaj", stopped)

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
