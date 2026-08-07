"""Regresie pentru reparațiile dintr-un audit de securitate intern (2026-07):
  M3 — token-urile de port-forward se invalidează la bump-ul de epoch (logout/schimbare parolă);
  L2 — sesiunile web au idle-expiry (nu doar TTL absolut), cu slide throttled;
  L4 — cheia de semnare a flotei intră în snapshot-ul de backup.
Rulează hermetic, in-process (fără uvicorn / agent / browser)."""
import asyncio
import io
import os
import tarfile
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import backup, config, db, security  # noqa: E402

ok = 0
total = 0


def check(name, cond):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


def test_m3_forward_epoch():
    security.init_crypto(b"x" * 32)
    tok = security.make_forward_token("myslug")
    check("M3: token de forward proaspăt e valid", security.verify_forward_token(tok, "myslug"))
    check("M3: token legat de slug (alt slug respins)", not security.verify_forward_token(tok, "altslug"))
    security.bump_forward_epoch()      # logout / schimbare parolă
    check("M3: după bump de epoch, tokenul vechi e invalid", not security.verify_forward_token(tok, "myslug"))
    tok2 = security.make_forward_token("myslug")
    check("M3: un token nou (post-bump) e valid", security.verify_forward_token(tok2, "myslug"))


async def test_l2_idle_expiry():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await db.execute(
        "INSERT INTO users(email, password_hash, created) VALUES(?,?,?)",
        "a@b.co", security.hash_password("parolabuna1"), time.time())
    uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]

    tok = await security.create_web_session(uid)
    check("L2: sesiune proaspătă → user găsit", (await security.user_for_token(tok)) is not None)

    # împinge last_seen dincolo de fereastra de idle
    th = security.sha256_hex(tok)
    await db.execute("UPDATE web_sessions SET last_seen=? WHERE token_hash=?",
                     time.time() - security.WEB_SESSION_IDLE - 100, th)
    check("L2: sesiune inactivă prea mult → invalidată", (await security.user_for_token(tok)) is None)
    gone = await db.fetchone("SELECT 1 FROM web_sessions WHERE token_hash=?", th)
    check("L2: sesiunea expirată e ștearsă din DB", gone is None)

    # TTL absolut respectat independent
    tok2 = await security.create_web_session(uid)
    await db.execute("UPDATE web_sessions SET expires=? WHERE token_hash=?",
                     time.time() - 1, security.sha256_hex(tok2))
    check("L2: TTL absolut expirat → user None", (await security.user_for_token(tok2)) is None)
    await db.close()


def test_l4_signing_key_in_backup():
    (config.DATA_DIR / "agent-signing.key").write_bytes(b"-----BEGIN PRIVATE KEY-----\nfake\n")
    (config.DATA_DIR / "agent-signing.pub").write_text("deadbeef")
    snap = backup.make_snapshot(include_transcripts=False)
    with tarfile.open(fileobj=io.BytesIO(snap), mode="r:gz") as tar:
        names = tar.getnames()
    check("L4: cheia privată de semnare e în snapshot", "agent-signing.key" in names)
    check("L4: cheia publică de semnare e în snapshot", "agent-signing.pub" in names)
    check("L4: seiful (secret) rămâne în snapshot", "secret" in names)


async def main():
    test_m3_forward_epoch()
    await test_l2_idle_expiry()
    test_l4_signing_key_in_backup()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
