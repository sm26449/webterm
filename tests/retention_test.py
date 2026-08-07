"""Retenția transcripturilor: arhivare la ștergere + purge după 120 zile."""
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_ARCHIVE_DAYS", "120")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, core  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    print(f"  {'PASS' if cond else 'FAIL'} {name}")
    ok += 1 if cond else 0
    assert cond, name


config.ensure_dirs()
sid = "b" * 32
out, cast = core.transcript_paths(sid)
out.write_bytes(b"salut")
cast.write_text('[0,"o","hi"]')

core.archive_transcript(sid)
check("fișierele nu mai sunt în transcripts", not out.exists() and not cast.exists())
check("ambele au ajuns în arhivă", len(list(config.ARCHIVE_DIR.iterdir())) == 2)

check("purge nu atinge arhiva proaspătă", core.purge_archive() == 0)

old = time.time() - 121 * 86400
for p in config.ARCHIVE_DIR.iterdir():
    os.utime(p, (old, old))
check("purge șterge fișierele > retenție", core.purge_archive() == 2)
check("arhiva e goală după purge", list(config.ARCHIVE_DIR.iterdir()) == [])

# arhivarea unei sesiuni fără fișiere nu crapă
core.archive_transcript("c" * 32)
check("arhivare fără fișiere e no-op sigur", True)

print(f"\n{ok} passed")
