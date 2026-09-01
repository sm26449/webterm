"""Supersede de agent: reconectarea aceleiaşi maşini (dual-WAN) nu trebuie să îngheţe
terminalele deschise, nici să dea alarmă falsă de „shared token".

Bug real (server cu 2 WAN-uri): agentul se reconectează peste celălalt WAN înainte ca vechea
conexiune să moară → gateway-ul o SUPRASCRIE (`superseded`). `_shutdown` al conexiunii vechi
rulează pe un tick ulterior, când `sources[host_id]` e deja noua conexiune, deci `was_current`
iese False şi `on_detached` NU rulează. Hub-urile rămân `attached=True`, reconcile-ul noii
conexiuni face `ensure_attached` = no-op → sesiunile vii nu se re-ataşează: agent conectat,
terminale îngheţate. Fix: `register_agent` detaşează explicit hub-urile hostului la supersede.
Plus: pe un host PINNED, un supersede e garantat aceeaşi maşină (fence-ul refuză alta), deci
alarma „two machines / shared token" nu mai are sens acolo.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, core, db  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class StubOld:
    """Vechea conexiune de agent, ca `register_agent` să vadă un supersede."""
    def __init__(self):
        self._stop_reason = ""
        self.disconnected = False

    async def disconnect(self):
        self.disconnected = True


class StubHub:
    def __init__(self, host_id):
        self.host_id = host_id
        self.attached = True          # ataşat la sursa VECHE

    def on_detached(self):
        self.attached = False


async def main():
    config.ensure_dirs()
    await db.connect()

    HID = 4242
    # un hub „viu" pe hostul ăsta, ataşat la sursa veche
    hub = StubHub(HID)
    core.hubs["a" * 32] = hub
    core.sources[HID] = StubOld()

    try:
        # ── 1. supersede pe host PINNED (dual-WAN): hub detaşat, fără alarmă de conflict ──
        # tripăm întâi pragul de conflict, ca să dovedim că `pinned` chiar suprimă alarma
        core.replacements[HID] = [__import__("time").time()] * 5
        events_before = (await db.fetchone(
            "SELECT COUNT(*) c FROM agent_events WHERE host_id=? AND event='conflict'", HID))["c"]
        conn = await core.register_agent(object(), HID, pinned=True)
        check("noua conexiune devine sursa curentă", core.sources.get(HID) is conn)
        check("hub-urile hostului sunt DETAŞATE la supersede (re-attach la reconcile)",
              hub.attached is False)
        events_after = (await db.fetchone(
            "SELECT COUNT(*) c FROM agent_events WHERE host_id=? AND event='conflict'", HID))["c"]
        check("host pinned: NU se dă alarma falsă de conflict (dual-WAN, nu shared token)",
              events_after == events_before, (events_before, events_after))

        # ── 2. supersede pe host NEPINNED cu replacements repetate: conflict RĂMÂNE ──
        # (acolo fence-ul e oprit, deci două maşini chiar pot alterna → alarma e reală)
        hub.attached = True
        core.sources[HID] = StubOld()
        core.replacements[HID] = [__import__("time").time()] * 5
        await core.register_agent(object(), HID, pinned=False)
        ev = (await db.fetchone(
            "SELECT COUNT(*) c FROM agent_events WHERE host_id=? AND event='conflict'", HID))["c"]
        check("host nepinned cu replacements repetate: conflictul RĂMÂNE semnalat", ev >= 1)
        check("…iar hub-urile tot se detaşează", hub.attached is False)
    finally:
        core.hubs.pop("a" * 32, None)
        core.sources.pop(HID, None)
        await db.close()

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
