"""Resync-ul de resume/unlock nu mai pierde fereastra neflush-uită a transcriptului.

Bug real (raportat pe taburi cu Claude Code): la revenirea pe un tab pauzat, tail-ul
citea doar octeții FLUSH-uiți (checkpoint la 2s/64KiB), deci până la ~2s de output se
pierdeau. Un shell „converge" la următorul output, dar un TUI nu-și mai redesenează
chenarul static — prompterul rămânea cu linii lipsă până la un redraw forțat (A±/reload).

Fixul: `_resync` face drain → flush → tell (atomic, sincron) și mărginește `read_tail`
la offsetul de la flush. Tot ce e ≤ cutoff vine din tail, tot ce e > cutoff vine din
coadă — nici gaură, nici dublură. Pur unit pe BrowserClient — fără gateway/agent.
"""
import asyncio
import json
import os
import sys
import tempfile
import time

TMP = tempfile.mkdtemp()
os.environ["WEBTERM_DATA_DIR"] = TMP
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, core  # noqa: E402

config.ensure_dirs()
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeWs:
    """Reține tot ce se trimite, în ordine: JSON-urile ca dict, binarul ca bytes."""
    def __init__(self):
        self.sent = []

    async def send_text(self, s):
        self.sent.append(json.loads(s))

    async def send_bytes(self, b):
        self.sent.append(bytes(b))

    async def close(self, code=1000):
        pass


def make_hub(sid):
    row = {"id": sid, "host_id": 1, "rows": 24, "cols": 80,
           "agent_epoch": None, "agent_offset": 0, "created": time.time()}
    return core.SessionHub(row)


def stream_bytes(ws):
    return b"".join(x for x in ws.sent if isinstance(x, bytes))


async def run_sender_briefly(client, secs=0.2):
    task = asyncio.create_task(client.sender())
    await asyncio.sleep(secs)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def t1_read_tail_end_bound():
    sid = "e" * 32
    out, _ = core.transcript_paths(sid)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"AAAA" + b"BBBB")
    check("end=None citește tot (comportamentul de attach, neschimbat)",
          core.read_tail(sid) == b"AAAABBBB")
    check("end taie exact la offset", core.read_tail(sid, end=4) == b"AAAA")
    check("end + limit: fereastra se termină la end",
          core.read_tail(sid, limit=2, end=4) == b"AA")
    check("end peste mărimea fișierului nu strică nimic",
          core.read_tail(sid, end=10 ** 9) == b"AAAABBBB")


async def t2_resume_includes_unflushed():
    sid = "f" * 32
    hub = make_hub(sid)
    ws = FakeWs()
    client = core.BrowserClient(ws, hub)
    hub.clients.add(client)

    # tab-ul intră în fundal; între timp TUI-ul desenează chenarul prompterului.
    # Octeții ajung în transcript DOAR în bufferul Python (sub pragul de checkpoint
    # de 64KiB/2s) — exact fereastra care înainte se pierdea la resume.
    client.pause()
    frame = b"\xe2\x95\xad\xe2\x94\x80\xe2\x94\x80chenar\xe2\x95\xae"   # ╭──chenar╮
    hub.out_f.write(frame)              # scris, NEflush-uit (ca în _process_output)
    client.push(frame)                  # pauzat → doar marchează _missed_while_paused

    client.resume()
    await run_sender_briefly(client)

    types = [x.get("type") for x in ws.sent if isinstance(x, dict)]
    check("la resume se trimite resync", "resync" in types, str(types))
    check("tail-ul CONȚINE octeții neflush-uiți (gaura închisă)",
          frame in stream_bytes(ws), repr(stream_bytes(ws)[-80:]))
    hub.out_f.close(); hub.cast_f.close()


async def t3_concurrent_checkpoint_no_duplication():
    sid = "c0ffee" + "0" * 26
    hub = make_hub(sid)
    ws = FakeWs()
    client = core.BrowserClient(ws, hub)
    hub.clients.add(client)

    before = b"inainte-de-pauza\n"
    hub.out_f.write(before)
    client.pause()
    client.push(before)                 # pauzat → pierdut din coadă, dar e în transcript

    late = b"sosit-cat-citeam-tail-ul\n"
    real_read_tail = core.read_tail

    def racing_read_tail(s, limit=config.BROWSER_TAIL_BYTES, end=None):
        # simulează checkpoint-ul concurent: cât „citim pe thread", sosește un chunk
        # care apucă să fie și FLUSH-uIT pe disc, și pus în coada clientului. Fără
        # marginea `end`, ar apărea și în tail, și din coadă — dublat pe ecran.
        hub.out_f.write(late)
        hub.out_f.flush()
        client.push(late)
        return real_read_tail(s, limit=limit, end=end)

    core.read_tail = racing_read_tail
    try:
        client.resume()
        await run_sender_briefly(client)
    finally:
        core.read_tail = real_read_tail

    data = stream_bytes(ws)
    check("chunk-ul din cursă ajunge EXACT o dată (nu dublat, nu pierdut)",
          data.count(late) == 1, repr(data[-120:]))
    check("conținutul dinaintea pauzei vine din tail", before in data)
    hub.out_f.close(); hub.cast_f.close()


def main():
    t1_read_tail_end_bound()
    asyncio.run(t2_resume_includes_unflushed())
    asyncio.run(t3_concurrent_checkpoint_no_duplication())
    ok = sum(1 for _, c in results if c)
    print(f"\n{ok}/{len(results)} passed")
    return ok == len(results)


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
