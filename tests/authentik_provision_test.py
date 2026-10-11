"""deploy/authentik/provision.py contra unui Authentik FALS, în memorie (3.6.5).

Niciun apel de reţea: `provision()` primeşte clientul ca parametru, iar aici el e un dicţionar
care imită cele câteva rute ale API-ului Authentik folosite de script. Se verifică:
  * cele cinci grupuri implicite create (cu prefix), fiecare legat de aplicaţie, aplicaţia în
    policy_engine_mode=any (un singur grup per om ajunge);
  * idempotenţa: a doua rulare nu creează nimic; un grup / binding existent nu e duplicat, iar
    membrii unui grup existent nu sunt atinşi;
  * blocul .env tipărit: ALLOWED_GROUPS cu TOATE cele cinci grupuri, ROLE_MAP cu prefixul aplicat
    şi fără Owner, SSO_ONLY=1, SESSION_MAX_HOURS=12 — şi că WebTerm îl parsează fără erori;
  * un prefix invalid e refuzat înainte de orice scriere.
"""
import asyncio
import importlib.util
import os
import sys

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
        self.bindings = []          # {"pk","target","group","order","enabled"}
        self.providers = {}
        self.apps = {}
        self.scope_maps = [{"pk": "m-openid", "scope_name": "openid"},
                           {"pk": "m-email", "scope_name": "email"},
                           {"pk": "m-profile", "scope_name": "profile"}]
        self.writes = []
        self.n = 0

    def _pk(self, p):
        self.n += 1
        return "%s-%d" % (p, self.n)

    def __call__(self, method, path, body=None):
        if method != "GET":
            self.writes.append((method, path))
        base, _, q = path.partition("?")
        qs = dict(x.split("=", 1) for x in q.split("&") if "=" in x)
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
                from urllib.parse import unquote
                name = unquote(qs.get("name", ""))
                return 200, {"results": [g for g in self.groups.values()
                                         if not name or name in g["name"]]}
            g = {"pk": self._pk("grp"), "name": body["name"], "users": []}
            self.groups[g["name"]] = g
            return 201, g
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
        if base == "/api/v3/core/applications/":
            if method == "GET":
                return 200, {"results": list(self.apps.values())}
            a = dict(body, pk=self._pk("app"))
            self.apps[a["slug"]] = a
            return 201, a
        if base == "/api/v3/core/applications/webterm/":
            if method == "PATCH":
                self.apps["webterm"].update(body)
            return 200, self.apps["webterm"]
        if base == "/api/v3/policies/bindings/":
            if method == "GET":
                return 200, {"results": [b for b in self.bindings if b["target"] == qs.get("target")]}
            if any(b["target"] == body["target"] and b["order"] == body["order"] for b in self.bindings):
                return 400, {"order": "duplicate"}
            b = dict(body, pk=self._pk("bind"))
            self.bindings.append(b)
            return 201, b
        return 404, {"detail": "not faked: %s %s" % (method, path)}


def run(ak, prefix="wt"):
    lines = []
    res = P.provision(ak, ak="https://auth.example.test", wt_domain="term.example.test",
                      prefix=prefix, out=lines.append)
    return res, lines


def main():
    print("── prima rulare, prefix implicit")
    ak = FakeAuthentik()
    res, lines = run(ak)
    names = ["wt-access", "wt-admins", "wt-readonly", "wt-db", "wt-network"]
    check("cele cinci grupuri create", sorted(ak.groups) == sorted(names), str(sorted(ak.groups)))
    app = ak.apps.get("webterm", {})
    bound = {b["group"] for b in ak.bindings if b["target"] == app.get("pk")}
    check("fiecare grup e legat de aplicaţie", bound == {ak.groups[n]["pk"] for n in names}, str(bound))
    check("ordinile binding-urilor sunt distincte", len({b["order"] for b in ak.bindings}) == 5)
    check("aplicaţia cere ORICARE grup (policy_engine_mode=any)", app.get("policy_engine_mode") == "any")
    prov = next(iter(ak.providers.values()))
    check("providerul primeşte scope mapping-ul `groups`",
          any(m["scope_name"] == "groups" and m["pk"] in prov["property_mappings"] for m in ak.scope_maps))
    check("redirect URI-ul e cel al instanţei",
          prov["redirect_uris"] == [{"matching_mode": "strict",
                                     "url": "https://term.example.test/api/oidc/callback"}])
    env = res["env"]
    check("ALLOWED_GROUPS listează TOATE cele cinci grupuri (nu doar wt-access)",
          env["WEBTERM_OIDC_ALLOWED_GROUPS"].split(",") == names, env["WEBTERM_OIDC_ALLOWED_GROUPS"])
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
    check("…issuer-ul corect", env["WEBTERM_OIDC_ISSUER"] == "https://auth.example.test/application/o/webterm/")
    from app import ssomap
    parsed, bad = ssomap.parse_role_map(env["WEBTERM_OIDC_ROLE_MAP"])
    check("WebTerm parsează harta tipărită fără nicio eroare", len(parsed) == 4 and not bad, str(bad))

    print("── a doua rulare: idempotentă")
    ak.groups["wt-db"]["users"] = ["alice"]
    n_writes = len([w for w in ak.writes if w[0] == "POST"])
    res2, _ = run(ak)
    check("nicio creare nouă (doar PATCH-uri de actualizare)",
          len([w for w in ak.writes if w[0] == "POST"]) == n_writes,
          str(ak.writes[-6:]))
    check("aceleaşi cinci grupuri, aceleaşi cinci binding-uri", len(ak.groups) == 5 and len(ak.bindings) == 5)
    check("membrii unui grup existent nu sunt atinşi", ak.groups["wt-db"]["users"] == ["alice"])
    check("acelaşi bloc .env", res2["env"] == env)

    print("── upgrade: un Authentik provizionat înainte de 3.6.5 (doar wt-access, binding la 0)")
    old = FakeAuthentik()
    old.groups["wt-access"] = {"pk": "grp-old", "name": "wt-access", "users": ["bob"]}
    old.apps["webterm"] = {"pk": "app-old", "slug": "webterm", "name": "WebTerm"}
    old.bindings.append({"pk": "b0", "target": "app-old", "group": "grp-old", "order": 0, "enabled": True})
    run(old)
    check("se adaugă cele patru grupuri noi", len(old.groups) == 5)
    check("binding-ul vechi rămâne, cele noi primesc ordini libere",
          len(old.bindings) == 5 and len({b["order"] for b in old.bindings}) == 5)
    check("aplicaţia existentă trece pe policy_engine_mode=any",
          old.apps["webterm"].get("policy_engine_mode") == "any")

    print("── prefix per instanţă")
    ak3 = FakeAuthentik()
    res3, _ = run(ak3, prefix="wt-prod")
    check("grupurile poartă prefixul", sorted(ak3.groups) == sorted(
        "wt-prod-" + s for s in ("access", "admins", "readonly", "db", "network")), str(sorted(ak3.groups)))
    check("ROLE_MAP şi ALLOWED_GROUPS folosesc prefixul",
          res3["env"]["WEBTERM_OIDC_ROLE_MAP"].startswith("wt-prod-admins=admin@all")
          and "wt-prod-network" in res3["env"]["WEBTERM_OIDC_ALLOWED_GROUPS"]
          and "wt-access" not in res3["env"]["WEBTERM_OIDC_ALLOWED_GROUPS"].split(","))
    for badp in ("", "wt prod", "wt-", "-wt", "a" * 80, "wt,x", "wt=x"):
        ak4 = FakeAuthentik()
        try:
            run(ak4, prefix=badp)
            refused = badp == ""          # gol = implicit „wt", nu e o eroare
        except SystemExit:
            refused = True
        check("prefix %r refuzat înainte de orice scriere (sau implicit)" % badp[:20],
              refused and (badp == "" or not ak4.writes), str(ak4.writes[:3]))

    print("── un token invalid opreşte totul")
    ak5 = FakeAuthentik()
    try:
        P.provision(lambda m, p, b=None: (403, {}), ak="https://x", wt_domain="y", out=lambda s: None)
        stopped = False
    except SystemExit:
        stopped = True
    check("HTTP 403 → oprire cu mesaj", stopped and not ak5.writes)

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    asyncio.set_event_loop(asyncio.new_event_loop())
    raise SystemExit(0 if main() else 1)
