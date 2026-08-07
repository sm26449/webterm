"""Anti-clone: a host token is fenced to one machine (instance id).
Pin on first connect; a different instance on the same token is refused;
the same instance may reconnect. Once pinned, a connection that drops the
header can't dodge the fence — it's refused too. A host that has only ever
seen header-less agents stays unpinned and keeps working (backward compat).
Runs against a gateway on :8010 (dev stack). Creates + deletes its own hosts."""
import asyncio
import re
import sys

import httpx
import websockets

BASE = "http://localhost:8010"
WS = "ws://localhost:8010/agent/ws"
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


async def ws_try(token, instance):
    """Return 'accepted' if the handshake completes, else 'refused'."""
    headers = {"Authorization": "Bearer " + token}
    if instance is not None:
        headers["X-Webterm-Instance"] = instance
    try:
        conn = await websockets.connect(WS, additional_headers=headers, open_timeout=8)
        await conn.close()
        return "accepted"
    except websockets.exceptions.InvalidStatus:
        return "refused"
    except Exception as e:  # 403 rejection surfaces variously across versions
        return "refused" if "403" in str(e) or "rejected" in str(e).lower() else "error:" + str(e)


async def make_host(http, name):
    """Create an agent host and return (id, enroll token)."""
    r = await http.post("/api/hosts", json={"name": name, "connection_type": "agent"})
    host = r.json()
    enroll = re.search(r"/install/([A-Za-z0-9_-]+)\.sh", host["install_command"]).group(1)
    script = (await http.get("/install/%s.sh" % enroll)).text
    token = re.search(r'TOKEN="([^"]+)"', script).group(1)
    return host["id"], token


async def main():
    async with httpx.AsyncClient(base_url=BASE) as http:
        r = await http.post("/api/login", json={"email": "admin@example.com",
                                                "password": "parola-buna-123"})
        cookie = r.cookies.get("wt_session") or http.cookies.get("wt_session")
        assert cookie, "login failed"

        # host 1: pinned to instance A, then probed with clones / header drop
        hid, token = await make_host(http, "fence-test")
        # host 2: only ever sees header-less agents (genuine old agent)
        hid2, token2 = await make_host(http, "fence-test-legacy")
        try:
            check("first connect (instance A) accepted → pins A", await ws_try(token, "AAA") == "accepted")
            check("different machine (instance B), same token → refused",
                  await ws_try(token, "BBB") == "refused")
            check("same machine (instance A) may reconnect", await ws_try(token, "AAA") == "accepted")
            # the fix: once pinned, dropping the header can't dodge the fence
            check("pinned host, header dropped → refused (no downgrade bypass)",
                  await ws_try(token, None) == "refused")

            # backward compat: a host that has only ever seen header-less agents
            # stays unpinned and keeps accepting them
            check("legacy host, no header → accepted (stays unpinned)",
                  await ws_try(token2, None) == "accepted")
            check("legacy host, no header, reconnect → still accepted",
                  await ws_try(token2, None) == "accepted")
        finally:
            await http.delete("/api/hosts/%d" % hid)
            await http.delete("/api/hosts/%d" % hid2)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)


asyncio.run(main())
