"""Per-session transcript cap: once .out passes MAX it is head-truncated to the
last KEEP bytes (gap-marked), and .cast stays a valid asciicast (header + tail).
Pure unit test on SessionHub — no gateway/agent."""
import json
import os
import sys
import tempfile
import time

TMP = tempfile.mkdtemp()
os.environ["WEBTERM_DATA_DIR"] = TMP
os.environ["WEBTERM_TRANSCRIPT_MAX_BYTES"] = "20000"
os.environ["WEBTERM_TRANSCRIPT_KEEP_BYTES"] = "8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, core  # noqa: E402

config.ensure_dirs()
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


sid = "a" * 32
row = {"id": sid, "host_id": 1, "rows": 24, "cols": 80,
       "agent_epoch": None, "agent_offset": 0, "created": time.time()}
hub = core.SessionHub(row)

# write well past MAX (30 KB) directly into the transcript
for _ in range(300):
    hub.out_f.write(b"X" * 100)
    hub._cast_event("o", b"X" * 100)
hub._flush()
out_path, cast_path = core.transcript_paths(sid)
check("grows past the cap before truncation", out_path.stat().st_size > 20000)

hub._maybe_cap()

out_size = out_path.stat().st_size
check("capped: .out <= KEEP + gap slack", out_size <= 8000 + len(core.GAP_MARKER) + 200)
data = out_path.read_bytes()
check("capped: .out starts with the gap marker", data.startswith(core.GAP_MARKER))

# .cast must still be a valid asciicast: header line + parseable tail events
lines = [l for l in cast_path.read_bytes().splitlines() if l.strip()]
hdr = json.loads(lines[0])
check("cast header intact (version 2)", hdr.get("version") == 2)
check("cast tail lines parse as events", all(isinstance(json.loads(l), list) for l in lines[1:5]))

# hub still usable after cap: further output appends, read_tail works
hub.out_f.write(b"AFTER_CAP_MARKER\r\n")
hub._flush()
tail = core.read_tail(sid)
check("read_tail works after cap and sees new output", b"AFTER_CAP_MARKER" in tail)

hub.teardown()
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
