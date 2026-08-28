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


async def t4_resume_requests_full_redraw():
    # tmux trimite doar DIFF-uri: tail-ul redă ce s-a transmis, nu ce e pe ecran, deci
    # chenarele statice ale unui TUI (prompterul Claude Code) lipsesc din orice replay
    # dacă n-au mai fost retransmise de mult. La resume, hub-ul trebuie să ceară sursei
    # un `refresh-client` — repaint complet, sosit prin flux DUPĂ tail (post-cutoff).
    sid = "d00d" + "0" * 28
    hub = make_hub(sid)
    ws = FakeWs()
    client = core.BrowserClient(ws, hub)
    hub.clients.add(client)

    redraws = []

    class FakeSource:
        async def redraw(self, s):
            redraws.append(s)

    hub._source = lambda: FakeSource()

    client.pause()
    client.push(b"x")                   # marchează _missed → resume va face resync
    client.resume()
    await run_sender_briefly(client, secs=0.5)   # peste debounce-ul de 0.2s

    check("resume-ul cere sursei un redraw complet", redraws == [sid], str(redraws))
    hub.out_f.close(); hub.cast_f.close()


async def t5_lossy_resync_keeps_old_behaviour():
    # Resync-ul de CLIENT LENT (backlog depășit) NU e cel de resume: clientul poate fi
    # abia atașat, de altă mărime — fereastra neflush-uită NU se redă (coliziunea cu
    # redraw-ul de resize), iar un repaint cerut aici s-ar declanșa în buclă la un client
    # cronic lent. Verificăm ambele: fără flush (octeții neflush-uiți lipsesc din tail)
    # și fără redraw.
    sid = "10552" + "0" * 27
    hub = make_hub(sid)
    ws = FakeWs()
    client = core.BrowserClient(ws, hub)
    hub.clients.add(client)

    redraws = []

    class FakeSource:
        async def redraw(self, s):
            redraws.append(s)

    hub._source = lambda: FakeSource()

    flushed = b"e-pe-disc\n"
    hub.out_f.write(flushed); hub.out_f.flush()
    unflushed = b"doar-in-buffer\n"
    hub.out_f.write(unflushed)                    # NEflush-uit
    # simulează overflow-ul: push() peste limită → drain + _RESYNC (lossy)
    client.buffered = config.CLIENT_BUFFER_LIMIT + 1
    client.push(b"x")
    client.buffered = 0
    await run_sender_briefly(client, secs=0.5)

    data = stream_bytes(ws)
    check("lossy: octeții flush-uiți sunt în tail", flushed in data)
    check("lossy: fereastra neflush-uită NU se redă (comportamentul istoric)",
          unflushed not in data, repr(data[-60:]))
    check("lossy: nu se cere repaint", redraws == [], str(redraws))
    hub.out_f.close(); hub.cast_f.close()


async def t6_cap_rewrite_invalidates_cutoff():
    # _maybe_cap poate RESCRIE fișierul cât citim tail-ul pe thread: offseturile se mută
    # sub noi. Detecția e prin CONTORUL de generație (out_gen), nu prin mărime — revizia
    # a arătat că rescrierea poate LUNGI fișierul (GAP_MARKER + tot conținutul), iar
    # varianta veche a testului nici măcar nu atingea ramura stale (cutoff-ul ieșea sub
    # noua mărime → trecea vacuu). Acum: gen bump → drain → chunk-ul din coadă e ARUNCAT,
    # nu redat — count(late) == 0 pică dacă cineva șterge ramura stale (redevine 1).
    sid = "cabbed" + "0" * 26
    hub = make_hub(sid)
    ws = FakeWs()
    client = core.BrowserClient(ws, hub)
    hub.clients.add(client)

    out_path, _ = core.transcript_paths(sid)
    hub.out_f.write(b"istoric-lung\n")
    client.pause()
    client.push(b"istoric-lung\n")

    late = b"dupa-cap\n"
    real_read_tail = core.read_tail

    def capping_read_tail(s, limit=config.BROWSER_TAIL_BYTES, end=None):
        # simulează exact ce face _maybe_cap: rescrie fișierul (aici mai LUNG — cazul
        # care păcălea comparația de mărime), redeschide handle-ul, bumpează generația;
        # apoi sosește un chunk flush-uit în fișierul nou ȘI pus în coada clientului
        hub.out_f.close()
        out_path.write_bytes(b"[GAP-mai-lung-decat-originalul]\n")
        hub.out_f = open(out_path, "ab")
        hub.out_gen += 1
        hub.out_f.write(late); hub.out_f.flush()
        client.push(late)
        return real_read_tail(s, limit=limit, end=end)

    core.read_tail = capping_read_tail
    try:
        client.resume()
        await run_sender_briefly(client, secs=0.5)
    finally:
        core.read_tail = real_read_tail

    data = stream_bytes(ws)
    check("cap-rewrite: gen bump → coada drenată, chunk-ul nici dublat, nici redat",
          data.count(late) == 0, repr(data[-100:]))
    hub.out_f.close(); hub.cast_f.close()


async def t7_overflow_cannot_downgrade_full():
    # Intenția de resync e stare pe client, nu element de coadă: un overflow de client
    # lent (cere lossy) sosit DUPĂ un unlock (a cerut full) nu mai degradează full-ul —
    # nivelurile se combină prin max, iar drain-ul nu le atinge.
    sid = "f011" + "0" * 28
    hub = make_hub(sid)
    ws = FakeWs()
    client = core.BrowserClient(ws, hub)
    hub.clients.add(client)

    redraws = []

    class FakeSource:
        async def redraw(self, s):
            redraws.append(s)

    hub._source = lambda: FakeSource()

    unflushed = b"scris-cat-era-blocat\n"
    client.lock()
    hub.out_f.write(unflushed)          # NEflush-uit — doar un resync FULL îl livrează
    client.push(unflushed)              # blocat → doar marchează
    client.unlock()                     # cere FULL
    client.buffered = config.CLIENT_BUFFER_LIMIT + 1
    client.push(b"x")                   # overflow → cere LOSSY; nu are voie să degradeze
    client.buffered = 0
    await run_sender_briefly(client, secs=0.5)

    data = stream_bytes(ws)
    check("overflow după unlock: resync-ul rămâne FULL (octeții neflush-uiți vin)",
          unflushed in data, repr(data[-80:]))
    check("…și repaint-ul tot se cere", redraws == [sid], str(redraws))
    hub.out_f.close(); hub.cast_f.close()


async def t8_unlock_pause_resume_keeps_intent():
    # unlock → pause (drain) → resume fără output nou: sentinela din coadă a fost drenată,
    # dar INTENȚIA supraviețuiește pe client — la resume se retrezește și resync-ul vine.
    # Cu sentinelele-ca-date (2.0.9), output-ul pierdut cât era blocat nu mai sosea deloc.
    sid = "0b0e" + "0" * 28
    hub = make_hub(sid)
    ws = FakeWs()
    client = core.BrowserClient(ws, hub)
    hub.clients.add(client)

    missed = b"pierdut-cat-era-blocat\n"
    client.lock()
    hub.out_f.write(missed)
    client.push(missed)
    client.unlock()                     # cere FULL (sentinelă în coadă)
    client.pause()                      # drain: sentinela dispare, intenția rămâne
    client.resume()                     # fără output nou între timp
    await run_sender_briefly(client, secs=0.5)

    types = [x.get("type") for x in ws.sent if isinstance(x, dict)]
    check("intenția supraviețuiește pause-ului: resync-ul tot se face",
          "resync" in types, str(types))
    check("…și livrează output-ul pierdut cât era blocat",
          missed in stream_bytes(ws), repr(stream_bytes(ws)[-80:]))
    hub.out_f.close(); hub.cast_f.close()


async def t9_locked_client_gets_no_resync():
    # Audit de securitate 2026-08: un client BLOCAT (idle-lock 2FA / invitat share fără
    # owner) putea smulge scrollback prin calea de recuperare pong-timeout, care cheamă
    # _resync DIRECT (ocolind garda din sender). _resync trebuie să refuze el însuși.
    sid = "10cced" + "0" * 26
    hub = make_hub(sid)
    ws = FakeWs()
    client = core.BrowserClient(ws, hub)
    hub.clients.add(client)

    secret = b"parola-din-scrollback\n"
    hub.out_f.write(secret); hub.out_f.flush()
    client.lock()                        # sesiune blocată
    await client._resync(full=True)      # exact ce face _flow_control după pong-timeout

    data = stream_bytes(ws)
    check("client blocat: _resync NU trimite scrollback", secret not in data, repr(data[:60]))
    check("client blocat: nici măcar mesajul resync", not any(
        isinstance(x, dict) and x.get("type") == "resync" for x in ws.sent))
    hub.out_f.close(); hub.cast_f.close()


def main():
    t1_read_tail_end_bound()
    asyncio.run(t2_resume_includes_unflushed())
    asyncio.run(t3_concurrent_checkpoint_no_duplication())
    asyncio.run(t4_resume_requests_full_redraw())
    asyncio.run(t5_lossy_resync_keeps_old_behaviour())
    asyncio.run(t6_cap_rewrite_invalidates_cutoff())
    asyncio.run(t7_overflow_cannot_downgrade_full())
    asyncio.run(t8_unlock_pause_resume_keeps_intent())
    asyncio.run(t9_locked_client_gets_no_resync())
    ok = sum(1 for _, c in results if c)
    print(f"\n{ok}/{len(results)} passed")
    return ok == len(results)


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
