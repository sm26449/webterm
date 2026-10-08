"""Docker: statistici per container + „Logs" live (3.5.10). Ermetic — niciun demon docker real:
agentul e un FakeAgent (ca în docker_sudo_test), iar comanda sesiunii de loguri se rulează cu un
`docker`/`sudo` FALS pus primul în PATH.

  * parserul unităţilor lui docker (B, kB, KiB, MB, MiB, GB, GiB, %, „--", gol, gunoi);
  * GET /api/hosts/{id}/docker/stats: aceleaşi reguli ca docker_list (cookie; tokenul de
    automatizare → 401; host 2FA fără step-up → 403), host inexistent, erori docker, timeout
    → „indisponibil" (nu eroare), cache + o singură rulare în zbor pe host;
  * sesiunea „Logs": id validat cu _DOCKER_ID, shell-quotat, fallback `sudo -n`, fără prompt.
"""
import asyncio
import os
import json
import shlex
import stat
import subprocess
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0
PW = "parolabuna1"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeAgent(core.AgentConnection):
    """AgentConnection fals: răspunde la run_command după un scenariu (cmd prefix → resp)."""
    def __init__(self, host_id, script, delay=0.0):
        self.host_id = host_id
        self.forwards = {}
        self._script = script
        self._delay = delay
        self.calls = []

    async def run_command(self, cmd, timeout):
        self.calls.append((cmd, timeout))
        if self._delay:
            await asyncio.sleep(self._delay)
        for prefix, resp in self._script:
            if cmd.startswith(prefix):
                return resp
        return {"ok": True, "exit_code": 127, "stdout": "", "stderr": "not scripted"}


STATS_OUT = "\n".join([
    '{"BlockIO":"12.3MB / 4.1kB","CPUPerc":"12.34%","Container":"3f2a1b4c5d6e","ID":"3f2a1b4c5d6e",'
    '"MemPerc":"0.16%","MemUsage":"12.3MiB / 7.6GiB","Name":"web","NetIO":"1.2kB / 0B","PIDs":"3"}',
    "WARNING: something docker printed on stdout",
    '{"BlockIO":"-- / --","CPUPerc":"--","ID":"aaaaaaaaaaaa","MemPerc":"--",'
    '"MemUsage":"-- / --","Name":"starting","NetIO":"-- / --","PIDs":"--"}',
    '{"BlockIO":"0B / 0B","CPUPerc":"250.5%","ID":"bbbbbbbbbbbb","MemPerc":"",'
    '"MemUsage":"512MiB / 1GiB","Name":"busy","NetIO":"1.5GB / 2GB","PIDs":"40"}',
])
STATS_OK = {"ok": True, "exit_code": 0, "stdout": STATS_OUT, "stderr": ""}


def test_parser():
    P = api._parse_size
    check("B", P("0B") == 0 and P("512B") == 512)
    check("kB (zecimal)", P("1.2kB") == 1200)
    check("KB tolerat ca kB", P("2KB") == 2000)
    check("KiB (binar)", P("1KiB") == 1024 and P("1.5KiB") == 1536)
    check("MB", P("12.3MB") == 12_300_000)
    check("MiB", P("12.3MiB") == round(12.3 * 1024 ** 2))
    check("GB", P("1.5GB") == 1_500_000_000)
    check("GiB", P("7.6GiB") == round(7.6 * 1024 ** 3))
    check("TB / TiB", P("1TB") == 10 ** 12 and P("1TiB") == 1024 ** 4)
    check("spaţii în jur + între număr şi unitate", P("  3 MiB ") == 3 * 1024 ** 2)
    check("număr gol fără unitate = octeţi", P("42") == 42)
    check("„--” → None", P("--") is None)
    check("gol / None / non-string → None", P("") is None and P(None) is None and P(12) is None)
    check("unitate necunoscută → None, nu un număr inventat", P("12XB") is None)
    check("gunoi → None", P("abc") is None and P("1.2.3MB") is None and P("-5MB") is None)

    Q = api._parse_pct
    check("% → float", Q("12.34%") == 12.34)
    check("CPU > 100% (mai multe nuclee) e păstrat", Q("250.5%") == 250.5)
    check("„--” / gol / gunoi → None", Q("--") is None and Q("") is None and Q("x%") is None)
    check("NaN / inf → None", Q("NaN%") is None and Q("inf%") is None)
    check("negativ → None", Q("-3%") is None)

    R = api._parse_pair
    check("pereche used / limit", R("12.3MiB / 7.6GiB") == (round(12.3 * 1024 ** 2), round(7.6 * 1024 ** 3)))
    check("pereche „-- / --”", R("-- / --") == (None, None))
    check("jumătate lipsă", R("1kB / --") == (1000, None))
    check("fără „/”", R("--") == (None, None))

    rows = api._parse_docker_stats(STATS_OUT)
    check("linia non-JSON e sărită, restul parsate", len(rows) == 3, str(len(rows)))
    w = rows[0]
    check("rând complet: numere, nu text",
          w["id"] == "3f2a1b4c5d6e" and w["name"] == "web" and w["cpu_pct"] == 12.34
          and w["mem_used"] == round(12.3 * 1024 ** 2) and w["mem_limit"] == round(7.6 * 1024 ** 3)
          and w["mem_pct"] == 0.16 and w["net_rx"] == 1200 and w["net_tx"] == 0
          and w["block_read"] == 12_300_000 and w["block_write"] == 4100 and w["pids"] == 3, str(w))
    s = rows[1]
    check("container care porneşte: toate „--” → None",
          all(s[k] is None for k in ("cpu_pct", "mem_used", "mem_limit", "mem_pct", "net_rx",
                                     "net_tx", "block_read", "block_write", "pids")), str(s))
    b = rows[2]
    check("MemPerc lipsă → calculat din used/limit", b["mem_pct"] == 50.0, str(b))
    check("ieşire goală → listă goală", api._parse_docker_stats("") == [])


def test_logs_cmd():
    cmd = api._docker_logs_cmd("web-1.prod_x")
    check("comanda e `sh -c <quoted>`", cmd.startswith("sh -c '"))
    inner = shlex.split(cmd)[2]
    check("docker logs --tail 500 --timestamps -f <id>",
          "docker logs --tail 500 --timestamps -f web-1.prod_x" in inner, inner)
    check("fallback `sudo -n`, niciodată sudo cu prompt",
          "exec sudo -n docker logs" in inner and "sudo docker" not in inner, inner)
    # quoting-ul: chiar dacă regex-ul ar lăsa vreodată să treacă ceva periculos, argumentul rămâne UN cuvânt
    evil = api._docker_logs_cmd("x; touch /tmp/pwn")
    check("un id cu `;` rămâne un singur argument quotat (apărare în adâncime)",
          "-f 'x; touch /tmp/pwn'" in shlex.split(evil)[2], evil)

    # rulăm REAL comanda cu un `docker` fals primul în PATH: sintaxa sh e validă, argv-ul ajunge
    # exact, iar ramura sudo se alege când `docker version` pică (fără demon real)
    d = tempfile.mkdtemp()
    fake_docker = os.path.join(d, "docker")
    with open(fake_docker, "w") as f:
        f.write('#!/bin/sh\n'
                'if [ "$1" = version ]; then [ "$DOCKER_OK" = 1 ] || [ "$VIA_SUDO" = 1 ]; exit $?; fi\n'
                'for a in "$@"; do printf "<%s>" "$a"; done; echo "|sudo=${VIA_SUDO:-0}"\n')
    fake_sudo = os.path.join(d, "sudo")
    with open(fake_sudo, "w") as f:
        f.write('#!/bin/sh\n[ "$1" = -n ] && shift\n[ "$SUDO_OK" = 1 ] || exit 1\n'
                'VIA_SUDO=1 exec "$@"\n')
    for p in (fake_docker, fake_sudo):
        os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
    base = {"PATH": d + ":/usr/bin:/bin"}

    def run(c, **env):
        return subprocess.run(c, shell=True, env={**base, **env}, capture_output=True,
                              text=True, timeout=10).stdout

    out = run(cmd, DOCKER_OK="1")
    check("acces direct: argv exact, fără sudo",
          out.strip() == "<logs><--tail><500><--timestamps><-f><web-1.prod_x>|sudo=0", out)
    out = run(cmd, SUDO_OK="1")
    check("fără acces la socket + sudo passwordless → rulează prin `sudo -n`",
          out.strip() == "<logs><--tail><500><--timestamps><-f><web-1.prod_x>|sudo=1", out)
    out = run(cmd)
    check("fără niciun acces: comanda simplă (eroarea reală) + indicaţia WebTerm",
          "<logs>" in out and "[WebTerm]" in out and "|sudo=0" in out, out)
    out = run(evil, DOCKER_OK="1")
    check("injecţia nu rulează: `;` ajunge ca text în argv",
          "<x; touch /tmp/pwn>" in out, out)

    # ── 3.5.15: „Shell" (docker exec) — acelaşi direct → sudo -n → simplu + indicaţie ──
    ex = api._docker_exec_cmd("web-1.prod_x")
    check("exec: tot `sh -c <quoted>`, cu fallback `sudo -n` şi fără sudo cu prompt",
          ex.startswith("sh -c '") and "exec sudo -n docker exec -it" in shlex.split(ex)[2]
          and "sudo docker" not in shlex.split(ex)[2], ex)
    inner_sh = "<sh><-c><command -v bash >/dev/null 2>&1 && exec bash || exec sh>"
    out = run(ex, DOCKER_OK="1")
    check("exec, acces direct: argv exact (bash dacă există, altfel sh), fără sudo",
          out.strip() == "<exec><-it><web-1.prod_x>" + inner_sh + "|sudo=0", out)
    out = run(ex, SUDO_OK="1")
    check("exec, fără socket + sudo passwordless → prin `sudo -n`",
          out.strip() == "<exec><-it><web-1.prod_x>" + inner_sh + "|sudo=1", out)
    out = run(ex)
    check("exec, fără niciun acces: comanda simplă (eroarea reală) + indicaţia WebTerm",
          "<exec>" in out and "[WebTerm]" in out and "|sudo=0" in out, out)
    out = run(api._docker_exec_cmd("x; touch /tmp/pwn"), DOCKER_OK="1")
    check("exec: injecţia nu rulează, `;` rămâne text într-un singur argument",
          "<x; touch /tmp/pwn>" in out, out)


async def test_api():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW, "setup_token": "test-setup"})
        hid = (await c.post("/api/hosts", json={"name": "normal"})).json()["id"]
        hid2 = (await c.post("/api/hosts", json={"name": "errs"})).json()["id"]
        hid3 = (await c.post("/api/hosts", json={"name": "slow"})).json()["id"]
        hid2fa = (await c.post("/api/hosts", json={"name": "critic", "require_2fa": True})).json()["id"]
        tok = (await c.post("/api/tokens", json={"name": "mon", "scopes": ["read", "run"], "days": 1,
                                                 "current_password": PW})).json()["token"]

        # ── succes: numere parsate, comanda corectă, timeout scurt ──
        core.sources[hid] = FakeAgent(hid, [("docker stats", STATS_OK)])
        r = await c.get(f"/api/hosts/{hid}/docker/stats")
        j = r.json()
        check("stats: 200 + available", r.status_code == 200 and j.get("available") is True, r.text[:200])
        check("stats: rândurile sunt numere", j["rows"][0]["mem_used"] == round(12.3 * 1024 ** 2)
              and j["rows"][0]["cpu_pct"] == 12.34)
        cmd, to = core.sources[hid].calls[0]
        check("stats: rulează `docker stats --no-stream --format '{{json .}}'`",
              cmd == "docker stats --no-stream --format '{{json .}}'", cmd)
        check("stats: timeout de câteva secunde, nu 20", to == api._DOCKER_STATS_TIMEOUT and to <= 10, str(to))
        await c.get(f"/api/hosts/{hid}/docker/stats")
        check("stats: a doua cerere în TTL vine din cache (o singură rulare)",
              len(core.sources[hid].calls) == 1, str(len(core.sources[hid].calls)))

        # ── 3.5.15: nucleele hostului, pentru CPU% relativ la host ──
        check("stats: fără snapshot de diagnostic → host_cpus null (UI: brut, „per nucleu”)",
              j.get("host_cpus") is None, str(j.get("host_cpus")))
        await db.execute("UPDATE hosts SET diagnostics=? WHERE id=?",
                         json.dumps({"cpu": {"cores": 8, "model": "x"}}), hid)
        api._docker_stats_cache.pop(hid, None)
        j = (await c.get(f"/api/hosts/{hid}/docker/stats")).json()
        check("stats: host_cpus din snapshot-ul de diagnostic din DB", j.get("host_cpus") == 8, str(j)[:200])
        core.sources[hid].diagnostics = {"cpu": {"cores": 4}}
        api._docker_stats_cache.pop(hid, None)
        j = (await c.get(f"/api/hosts/{hid}/docker/stats")).json()
        check("stats: snapshot-ul din memorie (cel mai proaspăt) are prioritate", j.get("host_cpus") == 4, str(j)[:200])
        for bad in (0, -2, "8", True, 10 ** 6):
            core.sources[hid].diagnostics = {"cpu": {"cores": bad}}
            api._docker_stats_cache.pop(hid, None)
            j = (await c.get(f"/api/hosts/{hid}/docker/stats")).json()
            check(f"stats: cores invalid {bad!r} → null", j.get("host_cpus") is None, str(j.get("host_cpus")))
        core.sources[hid].diagnostics = None

        # ── timeout → „indisponibil", nu eroare; NU se cache-uieşte ──
        core.sources[hid3] = FakeAgent(hid3, [("docker stats", {"ok": True, "exit_code": None,
                                                                 "timed_out": True, "stdout": "", "stderr": ""})])
        r = await c.get(f"/api/hosts/{hid3}/docker/stats")
        check("timeout → 200 {available:false, reason:timeout}",
              r.status_code == 200 and r.json() == {"available": False, "reason": "timeout", "rows": []}, r.text)
        await c.get(f"/api/hosts/{hid3}/docker/stats")
        check("timeout-ul nu e cache-uit (următorul tick reîncearcă)", len(core.sources[hid3].calls) == 2)

        # ── o singură rulare în zbor pentru cereri simultane ──
        api._docker_stats_cache.pop(hid, None)
        core.sources[hid] = FakeAgent(hid, [("docker stats", STATS_OK)], delay=0.2)
        rs = await asyncio.gather(*[c.get(f"/api/hosts/{hid}/docker/stats") for _ in range(3)])
        check("3 cereri simultane → o singură rulare pe host",
              all(x.status_code == 200 for x in rs) and len(core.sources[hid].calls) == 1,
              str(len(core.sources[hid].calls)))

        # ── erori docker: aceleaşi coduri ca docker_list ──
        for name, stderr, code in (
                ("absent", "sh: docker: command not found", "docker.absent"),
                ("demon oprit", "Cannot connect to the Docker daemon at unix:///run/x.sock. Is the docker daemon running?",
                 "docker.failed")):
            api._docker_stats_cache.pop(hid2, None)
            core.sources[hid2] = FakeAgent(hid2, [("docker", {"ok": True, "exit_code": 1, "stdout": "", "stderr": stderr})])
            r = await c.get(f"/api/hosts/{hid2}/docker/stats")
            check(f"eroare docker ({name}) → 400 {code}",
                  r.status_code == 400 and r.headers.get("X-WebTerm-Error") == code, f"{r.status_code} {r.headers.get('X-WebTerm-Error')}")
        core.sources[hid2] = FakeAgent(hid2, [("sudo -n docker", {"ok": True, "exit_code": 1, "stdout": "",
                                                                  "stderr": "sudo: a password is required"}),
                                              ("docker", {"ok": True, "exit_code": 1, "stdout": "",
                                                          "stderr": "permission denied ... /var/run/docker.sock"})])
        r = await c.get(f"/api/hosts/{hid2}/docker/stats")
        check("fără acces (nici sudo) → docker.denied", r.headers.get("X-WebTerm-Error") == "docker.denied")

        # ── host inexistent / fără agent ──
        r = await c.get("/api/hosts/99999/docker/stats")
        check("host inexistent → 409 host.offline (nu 500)",
              r.status_code == 409 and r.headers.get("X-WebTerm-Error") == "host.offline", r.text)

        # ── host 2FA fără step-up → 403, fără să atingă agentul ──
        core.sources[hid2fa] = FakeAgent(hid2fa, [("docker stats", STATS_OK)])
        r = await c.get(f"/api/hosts/{hid2fa}/docker/stats")
        check("host 2FA fără step-up → 403", r.status_code == 403, str(r.status_code))
        r2 = await c.get(f"/api/hosts/{hid2fa}/docker?kind=containers")
        check("…exact ca docker_list", r2.status_code == r.status_code
              and r2.headers.get("X-WebTerm-Error") == r.headers.get("X-WebTerm-Error"))
        check("agentul nu a fost atins fără step-up", core.sources[hid2fa].calls == [])

        # ── sesiunea „Logs" live ──
        captured = {}

        async def fake_create(host_id, title, rows, cols, tz, cmd, db_pw=None):
            captured.update(host_id=host_id, title=title, cmd=cmd)
            return {"id": "s-logs", "host_id": host_id, "title": title}
        orig = api.core.create_session
        api.core.create_session = fake_create
        try:
            r = await c.post(f"/api/hosts/{hid}/sessions", json={"docker_logs": "3f2a1b4c5d6e", "title": "logs: web"})
            check("sesiune logs: 200", r.status_code == 200, r.text[:200])
            check("sesiune logs: comanda e _docker_logs_cmd(id)", captured.get("cmd") == api._docker_logs_cmd("3f2a1b4c5d6e"))
            check("sesiune logs: titlul trimis de client e păstrat", captured.get("title") == "logs: web")
            captured.clear()
            r = await c.post(f"/api/hosts/{hid}/sessions", json={"docker_container": "3f2a1b4c5d6e"})
            check("3.5.15: sesiune Shell: comanda e _docker_exec_cmd(id) (fallback sudo -n)",
                  r.status_code == 200 and captured.get("cmd") == api._docker_exec_cmd("3f2a1b4c5d6e"),
                  f"{r.status_code} {captured}")
            captured.clear()
            await c.post(f"/api/hosts/{hid}/sessions", json={"docker_logs": "web"})
            check("sesiune logs fără titlu → „logs: <id>”", captured.get("title") == "logs: web", str(captured))
            for bad in ("web; rm -rf /", "$(id)", "-f", "a b", "", "x" * 200):
                captured.clear()
                r = await c.post(f"/api/hosts/{hid}/sessions", json={"docker_logs": bad})
                if bad == "":
                    continue    # gol = sesiune normală, nu logs
                check(f"id invalid {bad[:16]!r} → 400 docker.badContainer, nicio sesiune",
                      r.status_code == 400 and r.headers.get("X-WebTerm-Error") == "docker.badContainer"
                      and not captured, f"{r.status_code} {captured}")
            await db.execute("UPDATE hosts SET connection_type='telnet-jump' WHERE id=?", hid3)
            captured.clear()
            r = await c.post(f"/api/hosts/{hid3}/sessions", json={"docker_logs": "web"})
            check("host fără agent → 400, nicio sesiune", r.status_code == 400 and not captured, r.text[:120])
            r = await c.post(f"/api/hosts/{hid2fa}/sessions", json={"docker_logs": "web"})
            check("host 2FA fără step-up → 403 (sesiunea cere step-up)", r.status_code == 403, str(r.status_code))
        finally:
            api.core.create_session = orig

    # ── tokenul de automatizare: endpoint-ul NU e pe lista albă → 401 ──
    async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                 headers={"Authorization": "Bearer " + tok}) as t:
        r = await t.get(f"/api/hosts/{hid}/docker/stats")
        check("token de automatizare → 401 (ca docker_list)", r.status_code == 401, str(r.status_code))
        r2 = await t.get(f"/api/hosts/{hid}/docker?kind=containers")
        check("…exact ca docker_list", r2.status_code == 401)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as anon:
        r = await anon.get(f"/api/hosts/{hid}/docker/stats")
        check("fără sesiune → 401", r.status_code == 401)

    await db.close()


test_parser()
test_logs_cmd()
asyncio.run(test_api())
print(f"\n{ok}/{total} checks passed")
if ok != total:
    raise SystemExit(1)
