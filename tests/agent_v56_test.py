"""Agent v56 — gardă de tip pe frame-ul de control (anti-crash).

Un review independent a găsit că un frame de control care e JSON VALID dar NU e obiect (`[]`, `42`,
`"x"`) ajungea la handler: `handle_ctrl` face `msg.get("op")` CHIAR LA ÎNCEPUT, înainte de try-ul
lui intern, deci ridica AttributeError, care urca din `_drain_inbox` în bucla principală şi oprea
procesul (systemd reporneşte, dar e un crash — crash-loop dacă gateway-ul repetă frame-ul).

Fix (v56): după `json.loads`, dispatch-ul verifică `isinstance(msg, dict)` şi prinde per-frame
ValueError/TypeError/KeyError/AttributeError/UnicodeDecodeError → log + skip, nu fatal (oglinda
gărzii de pe gateway, core.py). Un frame valid trece neschimbat.

Hermetic: fără gateway, fără pty, fără socketul tmux de producţie. HOME e sandboxat ÎNAINTE de
import; agentul e construit cu `object.__new__` (fără `__init__`, care ar scrie tmux.conf), exact
ca agent_v54/v55_test.
"""
import json
import os
import queue
import sys
import tempfile

os.environ["HOME"] = tempfile.mkdtemp(prefix="v56-home-")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import ptyd  # noqa: E402

os.makedirs(ptyd.WEBTERM_DIR, exist_ok=True)
ok_n = 0
total = 0


def check(name, cond, detail=""):
    global ok_n, total
    total += 1
    ok_n += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


def fake_agent():
    ag = object.__new__(ptyd.Agent)
    ag.inbox = queue.Queue()
    ag.replies = []
    ag.send_ctrl = ag.replies.append
    ag._hb_sent_at = {}
    return ag


def ctrl(obj_or_bytes):
    """Corpul unui FRAME_CTRL (dispatch-ul decupează octetul de tip înainte de handler)."""
    if isinstance(obj_or_bytes, (bytes, bytearray)):
        body = bytes(obj_or_bytes)
    else:
        body = json.dumps(obj_or_bytes).encode()
    return ptyd.FRAME_CTRL + body


# ───────────────────────── versiune ─────────────────────────
# pin pe „cel puţin 56" (ca agent_v54/v55_test): garda de tip există din v56 încolo, deci testul
# nu trebuie să se spargă la fiecare creştere de AGENT_VERSION (ex. bump-ul la 57).
check("AGENT_VERSION >= 56", ptyd.AGENT_VERSION >= 56, ptyd.AGENT_VERSION)
check("FRAME_CTRL == b'J'", ptyd.FRAME_CTRL == b"J", ptyd.FRAME_CTRL)

# ═════════════════════════ 1. bug-ul brut: handle_ctrl pe un non-obiect crapă ═════════════════════════
# Confirmăm că garda chiar e portantă: fără ea, un JSON valid ne-obiect ridică AttributeError la
# `msg.get(...)` din capul lui handle_ctrl (înainte de try-ul lui intern).
for bad in ([], 42, "x", None):
    raised = False
    try:
        ptyd.Agent.handle_ctrl(fake_agent(), bad)
    except AttributeError:
        raised = True
    except Exception:          # orice altceva e tot „nu e dict", dar vrem specific .get()
        raised = True
    check("handle_ctrl(%r) brut ridică (de aia avem garda)" % (bad,), raised)

# handle_ctrl pe un dict VALID funcţionează (hb_ack → setează _last_hb_ack, nu crapă)
ag = fake_agent()
ptyd.Agent.handle_ctrl(ag, {"type": "hb_ack", "seq": 0})
check("handle_ctrl pe dict valid (hb_ack) merge", getattr(ag, "_last_hb_ack", None) is not None)

# ═════════════════════════ 2. dispatch-ul (_drain_inbox) prinde frame-urile corupte ═════════════════════════
# Mock pe handle_ctrl: numărăm CE ajunge la handler. Non-obiectele şi JSON-ul invalid NU trebuie
# să ajungă (garda le respinge înainte); un obiect valid trebuie să ajungă neschimbat.
ag = fake_agent()
seen = []
ag.handle_ctrl = seen.append

malformed = [
    ("listă []", ctrl([])),
    ("număr 42", ctrl(42)),
    ("string \"x\"", ctrl("x")),
    ("bool true", ctrl(True)),
    ("null", ctrl(None)),
    ("JSON trunchiat", ctrl(b'{"op":')),
    ("ne-JSON", ctrl(b"not json at all")),
    ("UTF-8 invalid", ctrl(b"\xff\xfe\x00")),
    ("corp gol", ctrl(b"")),
]
for _name, frame in malformed:
    ag.inbox.put(frame)
ag.inbox.put(ctrl({"op": "whatever", "id": "r1"}))   # UN frame valid printre cele corupte

crashed = False
try:
    ptyd.Agent._drain_inbox(ag)
except Exception as e:                                # pragma: no cover
    crashed = True
    print("    EXC: %r" % e)

check("_drain_inbox NU crapă pe niciun frame corupt", not crashed)
check("niciun frame corupt n-a ajuns la handle_ctrl", len(seen) == 1, "au ajuns: %r" % seen)
check("frame-ul valid a ajuns la handle_ctrl, ca dict neschimbat",
      seen == [{"op": "whatever", "id": "r1"}], seen)

# ═════════════════════════ 3. end-to-end cu handler-ul REAL: corupt sărit, valid procesat ═════════════════════════
# Fără mock: dispatch-ul + handle_ctrl real. Frame-urile corupte sunt log+skip; un hb_ack valid
# tot setează _last_hb_ack (dovadă că frame-ul bun nu e „pierdut" odată cu cele rele).
ag = fake_agent()
for _name, frame in malformed:
    ag.inbox.put(frame)
ag.inbox.put(ctrl({"type": "hb_ack", "seq": 7}))
crashed = False
try:
    ptyd.Agent._drain_inbox(ag)
except Exception as e:                                # pragma: no cover
    crashed = True
    print("    EXC: %r" % e)
check("end-to-end cu handler real: NU crapă", not crashed)
check("end-to-end: frame-ul valid (hb_ack) a fost procesat",
      getattr(ag, "_last_hb_ack", None) is not None)

print("\n%d/%d checks passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
