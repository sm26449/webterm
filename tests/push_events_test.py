"""Push lifecycle: current host authorization and OSC events independent of transport chunks."""
import asyncio
import io
import time

import rbac_util as U
from app import authz, core, db, osc133, push

check = U.Checker()


def event_hub(callback):
    h = core.SessionHub.__new__(core.SessionHub)
    h.closed = False
    h.agent_offset = h._unpersisted = h.out_pos = 0
    h.out_f = io.BytesIO()
    h.clients = []
    h._cast_event = lambda *args: None
    async def checkpoint():
        pass
    h._checkpoint = checkpoint
    h._owner_id = 123
    h.sid = "event-fixture"
    h._task_started_at = None
    h._last_push_at = 0
    h._push_task_failed = callback
    h.osc = osc133.Osc133Scanner(on_mark=h._detect_task_event)
    return h


async def parser_tests():
    b = b"\x1b]133;B\x07"
    c = b"\x1b]133;E;false\x07\x1b]133;C\x07"
    d = b"\x1b]133;D;1\x07"
    prompt = b"\x1b]133;A\x07" + b
    raw = b + c + d + prompt

    async def chunks(groups, gap=False):
        got = []
        async def record(code, duration):
            got.append((code, duration))
        h = event_hub(record)
        for chunk in groups:
            await h._process_output(chunk)
            if gap:
                h.osc.gap()
            await asyncio.sleep(0)
        check("output bytes are preserved", h.out_f.getvalue() == b"".join(groups))
        return got, h

    for groups in [[b, c, d, prompt], [b, c, d + prompt], [raw], [bytes([v]) for v in raw]]:
        got, _ = await chunks(groups)
        check("one failure detected regardless of chunking", len(got) == 1 and got[0][0] == 1, str(got))
    # Every possible boundary, including splitting an OSC introducer or terminator.
    good = True
    for cut in range(len(raw) + 1):
        got = []
        async def record(code, duration):
            got.append(code)
        h = event_hub(record)
        await h._process_output(raw[:cut]); await h._process_output(raw[cut:]); await asyncio.sleep(0)
        good = good and got == [1]
    check("all two-chunk partitions detect the same event", good)
    got, _ = await chunks([b + c, d], gap=True)
    check("gap invalidates pending command", not got)
    for ending in [b"\x1b]133;D;0\x07", b"\x1b]133;D\x07", b"\x1b]133;D;garbage\x07"]:
        got, _ = await chunks([b + c, ending + prompt])
        check("success/unknown exit does not send failure", not got)
    got, _ = await chunks([d + prompt])
    check("D without command does not notify", not got)
    got, _ = await chunks([raw + raw])
    check("flood rate-limit remains in effect", len(got) == 1)
    got = []
    async def record(code, duration):
        got.append(duration)
    h = event_hub(record)
    await h._process_output(b + c)
    h._task_started_at -= 60
    await h._process_output(d + prompt); await asyncio.sleep(0)
    check("long command duration survives coalesced prompt", len(got) == 1 and got[0] >= 60)
    # An observer failure must not prevent security/guardrail parsing from completing.
    def broken(*args):
        raise RuntimeError("fixture observer")
    scanner = osc133.Osc133Scanner(on_mark=broken)
    scanner.feed(raw, 0)
    check("observer error cannot interrupt parsing", scanner.last == "B" and scanner.integrated)


async def authorization_tests():
    await U.boot()
    original_enabled, original_send = push.enabled, push.send
    sent = []
    push.enabled = lambda: True
    push.send = lambda *args, **kw: sent.append(args) or []
    owner = None
    try:
        owner = await U.owner_client()
        hid = await U.add_host(owner, "private-host-fixture", folder="prod")
        uid = await U.add_user("notify@example.invalid", bindings=[("operator", "host", str(hid))])
        await db.execute("UPDATE users SET push_task_enabled=1,push_task_min_seconds=1 WHERE id=?", uid)
        await db.execute("INSERT INTO push_subscriptions(user_id,endpoint,p256dh,auth,created) VALUES(?,?,?,?,?)",
                         uid, "https://fcm.googleapis.com/fixture", "fixture-key", "fixture-auth", time.time())
        h = core.SessionHub.__new__(core.SessionHub)
        h._owner_id, h.host_id, h.sid = uid, hid, "notify-fixture"
        async def sends():
            sent.clear()
            await h._push_task_failed(1, 60)
            return len(sent)
        check("authorized owner receives notification", await sends() == 1)
        await U.unbind_all(uid)
        check("revoked user receives nothing", await sends() == 0)
        bid = await U.bind(uid, "operator", "host", str(hid))
        await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", time.time() + 0.03, bid)
        authz.bump_epoch()
        await authz.grants_for_user(uid)
        await asyncio.sleep(0.05)
        check("expired role is rejected even after cached permission", await sends() == 0)
        await U.unbind_all(uid)
        await U.bind(uid, "operator", "folder", "prod")
        check("folder-scoped owner receives notification", await sends() == 1)
        await db.execute("UPDATE hosts SET folder='lab' WHERE id=?", hid)
        check("host moved out of scope stops notifications", await sends() == 0)
        await U.bind(uid, "operator", "host", str(hid))
        await db.execute("UPDATE users SET disabled=1 WHERE id=?", uid); authz.bump_epoch()
        check("disabled user receives nothing", await sends() == 0)
        await db.execute("UPDATE users SET disabled=0,push_task_enabled=0 WHERE id=?", uid); authz.bump_epoch()
        check("disabled preference receives nothing", await sends() == 0)
        await db.execute("UPDATE users SET push_task_enabled=1 WHERE id=?", uid)
        await db.execute("DELETE FROM hosts WHERE id=?", hid)
        check("deleted host receives no notification", await sends() == 0)
        await db.execute("DELETE FROM users WHERE id=?", uid); authz.bump_epoch()
        check("deleted user receives nothing", await sends() == 0)
    finally:
        push.enabled, push.send = original_enabled, original_send
        if owner:
            await owner.aclose()
        await db.close()


async def main():
    await parser_tests()
    await authorization_tests()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
