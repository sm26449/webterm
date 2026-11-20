"""Listele allow / deny pe care gateway-ul le scrie pentru Traefik (edgelists.py, 3.6.38).

Fără Traefik real (comportamentul lui e verificat separat pe 3.7.10 / 3.7.19, vezi docstring-ul
modulului). Verificăm fişierul produs:
  * doar routere pe calea EXACTĂ /agent/ws, ClientIP câte unul, înlănţuite cu ||;
  * allow: agent conectat → intră; deconectat → rămâne ALLOW_TTL, apoi iese; prioritate peste deny;
  * deny: exact adresele blocate acum de agentgate; IPv6 pe /64; cheia „unknown" nu intră niciodată;
  * plafoane, scriere atomică, JSON valid, rescriere periodică (expirările dispar fără activitate);
  * repornire: allow-ul revine din fişier, deny-ul nu (îl decide agentgate);
  * `off` → nu scrie nimic.
"""
import json
import os
import re
import sys
import tempfile

D = tempfile.mkdtemp()
os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "https://wt.example.org"
os.environ["WEBTERM_AGENT_LISTS_DIR"] = D
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import agentgate, config, edgelists  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


def read():
    with open(os.path.join(D, edgelists.FILE_NAME)) as f:
        return json.load(f)


def cidrs(rule):
    return re.findall(r"ClientIP\(`([^`]+)`\)", rule)


T = 1_900_000_000.0
agentgate.reset_for_tests()
edgelists.reset_for_tests()

print("== empty")
check("writes even when empty (Traefik sees a valid, empty file)", edgelists.write(now=T, force=True))
check("an EMPTY document when both lists are empty (Traefik rejects an empty routers map)", read() == {}, read())

print("== allow")
edgelists.note_agent_connected(1, "203.0.113.10", now=T)
edgelists.note_agent_connected(2, "2001:db8:5:6::77", now=T)
edgelists.note_agent_connected(3, "?", now=T)                      # sursă nedeterminată: nu intră
edgelists.write(now=T + 11)
r = read()["http"]["routers"]
al = r.get("webterm-agent-allow", {})
check("allow router on our host names and the exact path", al.get("rule", "").startswith("(Host(`wt.example.org`) || HostRegexp(`^[a-z0-9-]+\\.wt\\.example\\.org$`)) && Path(`/agent/ws`) && ("), al.get("rule"))
check("one ClientIP per address, IPv4 /32 and IPv6 /64", sorted(cidrs(al["rule"])) == ["2001:db8:5:6::/64", "203.0.113.10/32"],
      cidrs(al["rule"]))
check("allow outranks deny (priority 3000 > 2000) and goes to the gateway",
      al["priority"] == 3000 and al["service"] == "webterm@docker" and al["entryPoints"] == ["websecure"])
check("allow keeps the global limit and the 529 marker after its own wide limit",
      al["middlewares"] == ["webterm-agent-allow-rl@file", "webterm-agent-mark@docker", "webterm-agent-bucket@docker",
                            "webterm-agent-all@docker"], al["middlewares"])
check("the wide per-address limit is defined in the same file",
      read()["http"]["middlewares"]["webterm-agent-allow-rl"]["rateLimit"]["burst"] == config.AGENT_ALLOW_BURST)

print("== deny")
for _ in range(agentgate.STRIKES):
    agentgate.strike("198.51.100.66", now=T + 20)
for _ in range(agentgate.STRIKES):
    agentgate.strike("?", now=T + 20)                               # cheia comună „unknown"
edgelists.write(now=T + 31)
dn = read()["http"]["routers"].get("webterm-agent-deny", {})
check("a blocked address is denied at Traefik", cidrs(dn.get("rule", "")) == ["198.51.100.66/32"], dn)
check("the shared 'unknown' key never reaches the file", "unknown" not in json.dumps(read()))
check("deny is refused by an allow-nothing ipAllowList, before the gateway",
      dn["middlewares"] == ["webterm-agent-deny-all@file"] and dn["priority"] == 2000
      and read()["http"]["middlewares"]["webterm-agent-deny-all"] == {"ipAllowList": {"sourceRange": ["0.0.0.0/32"]}})

print("== review round 2")
check("an address that EVER had a valid agent is never denied at the proxy, even if blocked",
      not any("203.0.113.10" in c for c in cidrs(read()["http"]["routers"].get("webterm-agent-deny", {}).get("rule", ""))))
for _ in range(agentgate.STRIKES):
    agentgate.strike("203.0.113.10", now=T + 25)                    # adresa agentului 1, blocată în gateway
edgelists.write(now=T + 42, force=True)
check("…checked: 203.0.113.10 blocked in the gateway but absent from the proxy deny",
      agentgate.blocked("203.0.113.10", now=T + 42)
      and "203.0.113.10/32" not in cidrs(read()["http"]["routers"].get("webterm-agent-deny", {}).get("rule", "")))
for rnd in range(4):                                                 # recidivă: blocarea în gateway urcă la ore
    for _ in range(agentgate.STRIKES):
        agentgate.strike("198.51.100.99", now=T + 30 + rnd)
    agentgate._state[agentgate.ip_key("198.51.100.99")][2] = T + 30 + 5 * 3600   # blocat 5 h în gateway
edgelists.write(now=T + 30 + edgelists.PROXY_DENY_MAX + 60, force=True)
check("the proxy deny lasts at most PROXY_DENY_MAX after the last strike",
      "198.51.100.99/32" not in cidrs(read().get("http", {}).get("routers", {}).get("webterm-agent-deny", {}).get("rule", "")))
m_old = edgelists.note_agent_connected(7, "192.0.2.70", now=T)
m_new = edgelists.note_agent_connected(7, "192.0.2.71", now=T + 1)
edgelists.note_agent_disconnected(7, m_old)                          # vechea conexiune se închide DUPĂ
check("an old connection closing after a new one keeps the new one's address", edgelists._connected.get(7, (None,))[0] == "192.0.2.71")
edgelists.note_agent_disconnected(7, m_new)
check("…and the new one removes it when it closes", 7 not in edgelists._connected)
config.TRUSTED_PROXY_HOPS = 2
check("behind another proxy (hops 2) the lists are not written at all", edgelists.render(now=T + 50) == {})
config.TRUSTED_PROXY_HOPS = 1
config.TRUST_CF_CONNECTING_IP = True
check("…nor with CF-Connecting-IP trusted", edgelists.render(now=T + 50) == {})
config.TRUST_CF_CONNECTING_IP = False

print("== TTL")
edgelists.write(now=T + 20 + agentgate.BLOCK_BASE + 70)            # blocarea a expirat
check("deny disappears when the block ends", "webterm-agent-deny" not in read().get("http", {}).get("routers", {}))
edgelists.note_agent_disconnected(1)
edgelists.write(now=T + config.AGENT_ALLOW_TTL - 100, force=True)
check("a disconnected agent's address stays allowed until ALLOW_TTL",
      "203.0.113.10/32" in cidrs(read()["http"]["routers"]["webterm-agent-allow"]["rule"]))
edgelists.write(now=edgelists._allow["203.0.113.10"] + 100, force=True)   # TTL-ul curge de la ultima vedere a agentului conectat
al = read()["http"]["routers"].get("webterm-agent-allow", {})
check("…and leaves after it", "203.0.113.10/32" not in cidrs(al.get("rule", "")), al)
check("a still-connected agent's address is extended, not expired", "2001:db8:5:6::/64" in cidrs(al.get("rule", "")), al)

print("== rewrite cadence")
n0 = edgelists._last_write_at
check("no rewrite within MIN_WRITE", not edgelists.write(now=n0 + 1))
check("unchanged content is not rewritten before REWRITE", not edgelists.write(now=n0 + edgelists.MIN_WRITE + 1))
check("…but is rewritten after REWRITE (expiries drop without activity)", edgelists.write(now=n0 + edgelists.REWRITE + 1))
check("no temporary file left behind", sorted(os.listdir(D)) == [edgelists.FILE_NAME], os.listdir(D))
check("readable by Traefik (0644)", oct(os.stat(os.path.join(D, edgelists.FILE_NAME)).st_mode & 0o777) == "0o644")

print("== caps")
edgelists.reset_for_tests()
for i in range(edgelists.MAX_ALLOW + 50):
    edgelists.note_agent_connected(1000 + i, "10.9.%d.%d" % (i // 256, i % 256), now=T)
agentgate.reset_for_tests()
for i in range(edgelists.MAX_DENY + 50):
    for _ in range(agentgate.STRIKES):
        agentgate.strike("192.0.2.%d" % (i % 250) if i < 250 else "198.18.%d.%d" % (i // 256, i % 256), now=T)
edgelists.write(now=T + 1, force=True)
r = read()["http"]["routers"]
check("allow capped at MAX_ALLOW", len(cidrs(r["webterm-agent-allow"]["rule"])) <= edgelists.MAX_ALLOW)
check("deny capped at MAX_DENY", len(cidrs(r["webterm-agent-deny"]["rule"])) <= edgelists.MAX_DENY)

print("== restart")
edgelists.reset_for_tests()
agentgate.reset_for_tests()
edgelists.note_agent_connected(1, "203.0.113.10", now=T)
for _ in range(agentgate.STRIKES):
    agentgate.strike("198.51.100.66", now=T)
edgelists.write(now=T + 1, force=True)
edgelists.reset_for_tests()                                          # gateway repornit
agentgate.reset_for_tests()
edgelists.write(now=T + 2, force=True)
r = read().get("http", {}).get("routers", {})
check("allow comes back from the file after a restart", "203.0.113.10/32" in cidrs(r.get("webterm-agent-allow", {}).get("rule", "")), r)
check("deny does not (agentgate decides it, and starts empty)", "webterm-agent-deny" not in r, r)

print("== review round 3")
import asyncio
from app import db as _db, fwddomain as _fd
async def _persist_case():
    await _db.connect()
    edgelists.reset_for_tests()
    edgelists.note_agent_connected(9, "198.51.100.200", now=T)
    await edgelists.persist_ever_valid(now=T + 1)
    edgelists.reset_for_tests()                                      # gateway repornit: memoria goală
    await edgelists.persist_ever_valid(now=T + 3 * 86400)            # 3 zile mai târziu, fără allow în fişier
    ok1 = "198.51.100.200" in edgelists._ever_valid
    agentgate.reset_for_tests()
    for _ in range(agentgate.STRIKES):
        agentgate.strike("198.51.100.200", now=T + 3 * 86400)
    edgelists.write(now=T + 3 * 86400 + 1, force=True)
    denied = "198.51.100.200/32" in cidrs(read().get("http", {}).get("routers", {}).get("webterm-agent-deny", {}).get("rule", ""))
    await _db.close()
    return ok1, denied
ok1, denied = asyncio.run(_persist_case())
check("the 'had a valid agent' exemption survives a gateway restart (kept in the DB)", ok1)
check("…so 3 days later that address is still not denied at the proxy", not denied)
_fd.DEFAULT_DOMAIN = "env-fwd.example.org"
edgelists.note_agent_connected(1, "203.0.113.10", now=T)
edgelists.write(now=T + 3 * 86400 + 20, force=True)
rule = read()["http"]["routers"]["webterm-agent-allow"]["rule"]
check("the file routers cover the forward domain from .env as well as the one from Settings",
      "env-fwd\\.example\\.org" in rule and "wt\\.example\\.org" in rule, rule[:200])
config.TRUST_CF_CONNECTING_IP = True
edgelists.write(now=T + 3 * 86400 + 90, force=True)
check("behind a proxy the status says why the lists are off", edgelists.status["supported"] is False and edgelists.status["off_reason"] == "proxy")
config.TRUST_CF_CONNECTING_IP = False

print("== off")
edgelists.reset_for_tests()
config.AGENT_LISTS_DIR = "off"
check("off → nothing written", not edgelists.write(now=T + 5, force=True) and edgelists.status["enabled"] is False)

print("\n%d/%d passed" % (ok, total))
sys.exit(0 if ok == total else 1)
