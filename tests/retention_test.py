"""Retenția transcripturilor: arhivare la ștergere + purge după 120 zile."""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_ARCHIVE_DAYS", "120")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, core, db  # noqa: E402

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



# ── sesiunile ÎNCHISE îşi arhivează transcriptul, nu doar cele şterse cu mâna ──
# `archive_transcript` era chemat dintr-un singur loc: `DELETE /api/sessions/{sid}`. Deci
# `purge_archive` păzea un director în care nimic nu intra de la sine, iar o sesiune pur şi
# simplu închisă îşi păstra cele două fişiere la nesfârşit — până la 64 MiB fiecare. Un audit
# extern a măsurat 120 de sesiuni închise = 240 de fişiere pe care nimeni nu le mai atingea:
# singura creştere nemărginită din produs.
async def test_closed_sessions_get_archived():
    await db.connect()
    config.ensure_dirs()
    now = time.time()
    old_sid, fresh_sid = "a" * 32, "b" * 32
    for sid, closed in ((old_sid, now - 60 * 86400), (fresh_sid, now - 3600)):
        await db.execute(
            "INSERT INTO sessions(id, host_id, state, created, closed_at) VALUES(?,?,?,?,?)",
            sid, 1, "closed", closed, closed)
        for p in core.transcript_paths(sid):
            p.write_bytes(b"x" * 100)

    moved = await core.archive_closed_transcripts(now)
    check("sesiunea închisă de mult e arhivată", moved == 1)
    check("fişierele ei au plecat din directorul activ",
          not any(p.exists() for p in core.transcript_paths(old_sid)))
    check("şi au ajuns în arhivă",
          (config.ARCHIVE_DIR / (old_sid + ".out")).exists())
    check("sesiunea închisă RECENT rămâne neatinsă",
          all(p.exists() for p in core.transcript_paths(fresh_sid)))
    check("rândul din DB rămâne (istoricul e util, doar octeţii pleacă)",
          (await db.fetchone("SELECT id FROM sessions WHERE id=?", old_sid)) is not None)
    # a doua trecere nu mai are ce muta — janitorul rulează la fiecare oră
    check("a doua rulare nu mai mişcă nimic", (await core.archive_closed_transcripts(now)) == 0)
    await db.close()


asyncio.run(test_closed_sessions_get_archived())
print(f"\n{ok} passed")

