"""db.execute_returning sub scrieri concurente (3.7.0-rc2, producţie): o instrucţiune `… RETURNING`
lăsată deschisă între două await-uri făcea commit-ul altei corutine să eşueze cu „cannot commit
transaction - SQL statements in progress". Rafală mixtă RETURNING + scrieri simple: zero erori,
iar fiecare UPDATE s-a aplicat o singură dată."""
import asyncio
import os
import sqlite3
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp(prefix="wt-dbconc-")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, db  # noqa: E402

ok_n = total = 0


def check(name, cond, detail=""):
    global ok_n, total
    total += 1
    ok_n += bool(cond)
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


async def main():
    await db.connect()
    try:
        await db.execute("CREATE TABLE IF NOT EXISTS conc_t (id INTEGER PRIMARY KEY, n INTEGER NOT NULL)")
        for _ in range(20):
            await db.execute("INSERT INTO conc_t(n) VALUES(0)")
        errors, returned = [], []

        async def ret(i):
            try:
                row = await db.execute_returning("UPDATE conc_t SET n=n+1 WHERE id=? RETURNING id", i % 20 + 1)
                returned.append(row["id"] if row else None)
            except Exception as e:          # noqa: BLE001
                errors.append(repr(e))

        async def wr(i):
            try:
                await db.execute("UPDATE conc_t SET n=n+1 WHERE id=?", i % 20 + 1)
            except Exception as e:          # noqa: BLE001
                errors.append(repr(e))

        n = 300
        await asyncio.gather(*[ret(i) if i % 2 else wr(i) for i in range(n)])
        check("no 'SQL statements in progress' under a mixed burst", not errors, errors[:2])
        check("every RETURNING got its row", len(returned) == n // 2 and None not in returned)
        total_n = (await db.fetchone("SELECT SUM(n) s FROM conc_t"))["s"]
        check("every UPDATE applied exactly once", total_n == n, total_n)
        none = await db.execute_returning("UPDATE conc_t SET n=n WHERE id=-1 RETURNING id")
        check("no matching row → None", none is None)

        # 3.8 (repetiţia e2e a activării): o scriere eşuată nu lasă tranzacţia implicită a conexiunii
        # partajate deschisă. Altfel ţinea lock-ul de scriere (conexiunea Store-ului bloca), iar cu un
        # snapshot fixat de o citire şi un commit extern, orice scriere următoare pica pe loc.
        await db.execute("CREATE TABLE IF NOT EXISTS uniq_t (x INTEGER UNIQUE)")
        await db.execute("INSERT INTO uniq_t VALUES(1)")
        failed = False
        try:
            await db.execute("INSERT INTO uniq_t VALUES(1)")
        except sqlite3.IntegrityError:
            failed = True
        check("a failing write raises", failed)
        check("no dangling transaction after a failed execute", not db._conn.in_transaction)
        try:
            await db.execute_returning("INSERT INTO uniq_t VALUES(1) RETURNING x")
        except sqlite3.IntegrityError:
            pass
        check("no dangling transaction after a failed execute_returning", not db._conn.in_transaction)
        await db.fetchall("SELECT * FROM conc_t")
        ext = sqlite3.connect(str(config.DB_PATH), isolation_level=None, timeout=1)
        try:
            ext.execute("INSERT INTO uniq_t VALUES(2)")         # alt conector (Store) poate scrie
            ext_ok = True
        except sqlite3.OperationalError:
            ext_ok = False
        finally:
            ext.close()
        check("another connection can write after the failure", ext_ok)
        try:
            await db.execute("INSERT INTO uniq_t VALUES(3)")
            after = True
        except sqlite3.OperationalError:
            after = False
        check("the gateway writes again after an external commit", after)

        # 3.8 (producţie, rc5): un SELECT al altei corutine, între `execute` şi `fetchone`, ţine un
        # snapshot pe conexiunea partajată; cât timp alt conector (Store-ul) ţine lock-ul de scriere,
        # o scriere a gateway-ului era refuzată PE LOC („database is locked", fără busy_timeout) şi
        # agentul care scria la hello era deconectat. Acum scrierea aşteaptă şi reuşeşte.
        import threading
        import time as _t
        hold = threading.Event()

        def store_txn(v=10, secs=0.3):
            con = sqlite3.connect(str(config.DB_PATH), isolation_level=None, timeout=5)
            try:
                con.execute("BEGIN IMMEDIATE")
                con.execute("INSERT INTO uniq_t VALUES(?)", (v,))
            finally:
                hold.set()
            _t.sleep(secs)
            con.execute("COMMIT")
            con.close()
        th = threading.Thread(target=store_txn)
        th.start()
        await asyncio.to_thread(hold.wait, 5)
        reader = await db._conn.execute("SELECT id FROM conc_t")     # snapshot deschis (cursor activ)
        await reader.fetchone()

        async def finish_reader():
            await asyncio.sleep(0.1)
            await reader.fetchall()
            await reader.close()
        fin = asyncio.ensure_future(finish_reader())
        t0 = _t.monotonic()
        try:
            await db.execute("INSERT INTO uniq_t VALUES(11)")         # o scriere de hello / reconcile
            busy_ok, err = True, ""
        except sqlite3.OperationalError as e:
            busy_ok, err = False, repr(e)
        await fin
        await asyncio.to_thread(th.join)
        check("a write racing another connection's lock while a read snapshot is open waits and succeeds",
              busy_ok and (await db.fetchone("SELECT COUNT(*) n FROM uniq_t WHERE x IN (10, 11)"))["n"] == 2
              and not db._conn.in_transaction, err)
        check("…within the retry budget", _t.monotonic() - t0 < db.BUSY_RETRY_SECS)
        reader = await db._conn.execute("SELECT id FROM conc_t")
        await reader.fetchone()
        try:
            hold.clear()
            th = threading.Thread(target=store_txn, args=(20, 0.6))
            th.start()
            await asyncio.to_thread(hold.wait, 5)
            old = db.BUSY_RETRY_SECS
            db.BUSY_RETRY_SECS = 0.2
            try:
                await db.execute("INSERT INTO uniq_t VALUES(12)")
                bounded = False
            except sqlite3.OperationalError:
                bounded = True
            finally:
                db.BUSY_RETRY_SECS = old
        finally:
            await reader.close()
            await asyncio.to_thread(th.join)
        check("a refusal that does not clear is still raised after the budget (bounded, nothing applied)",
              bounded and (await db.fetchone("SELECT COUNT(*) n FROM uniq_t WHERE x=12"))["n"] == 0)
        await _agent_loop_classifies_operational_errors()
    finally:
        await db.close()


def _genuine_errors():
    """(busy, schema) OperationalErrors ridicate de SQLite însuşi (cu sqlite_errorcode)."""
    path = os.path.join(os.environ["WEBTERM_DATA_DIR"], "codes.db")
    a = sqlite3.connect(path, isolation_level=None)
    b = sqlite3.connect(path, isolation_level=None, timeout=0)
    try:
        a.execute("CREATE TABLE IF NOT EXISTS t (x)")
        a.execute("BEGIN IMMEDIATE")
        try:
            b.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as e:
            busy = e
        try:
            b.execute("SELECT * FROM no_such_table")
        except sqlite3.OperationalError as e:
            schema = e
        a.execute("ROLLBACK")
    finally:
        a.close()
        b.close()
    return busy, schema


async def _agent_loop_classifies_operational_errors():
    # Codex L2 (2026-11-27): bucla de recepţie a agentului trata ORICE OperationalError drept
    # „database busy". Doar busy/locked (codul primar SQLite) e non-fatal; restul se comportă ca
    # înainte de 10e7bcb (urcă din run(), conexiunea se închide, eroarea se vede).
    from app import core
    busy, schema = _genuine_errors()
    check("genuine SQLite errors carry their result code",
          getattr(busy, "sqlite_errorcode", None) == db.SQLITE_BUSY
          and getattr(schema, "sqlite_errorcode", 0) & 0xFF not in (db.SQLITE_BUSY, db.SQLITE_LOCKED),
          (getattr(busy, "sqlite_errorcode", None), getattr(schema, "sqlite_errorcode", None)))
    check("is_contention: busy yes, schema / disk I/O / non-sqlite no",
          db.is_contention(busy) and not db.is_contention(schema)
          and db.is_contention(sqlite3.OperationalError("database is locked"))
          and db.is_contention(sqlite3.OperationalError("database table is locked"))
          and not db.is_contention(sqlite3.OperationalError("disk I/O error (test)"))
          and not db.is_contention(ValueError("database is locked")))
    # Un mesaj „database is locked" pe o eroare al cărei COD spune altceva nu e busy (codul decide).
    fake = sqlite3.OperationalError("database is locked")
    fake.sqlite_errorcode = 10                     # SQLITE_IOERR
    check("the result code wins over the message", not db.is_contention(fake) and not db._is_busy(fake))

    class _WS:
        def __init__(self, frames):
            self.frames = list(frames)

        async def receive_bytes(self):
            if self.frames:
                return self.frames.pop(0)
            raise ConnectionError("agent gone (test)")

    async def drive(err):
        seen = []
        conn = core.AgentConnection(_WS([core.FRAME_CTRL + b'{"event":"a"}',
                                         core.FRAME_CTRL + b'{"event":"b"}']), 987654)

        async def on_ctrl(msg):
            seen.append(msg["event"])
            if len(seen) == 1:
                raise err
        conn._on_ctrl = on_ctrl
        core.sources[987654] = conn
        try:
            await conn.run()
            out = None
        except BaseException as e:                 # noqa: BLE001
            out = e
        finally:
            core.sources.pop(987654, None)
        return seen, out

    seen, out = await drive(busy)
    check("busy in control-frame bookkeeping: the link stays, the next frame is processed",
          seen == ["a", "b"] and isinstance(out, ConnectionError), (seen, repr(out)))
    seen, out = await drive(schema)
    check("a non-busy OperationalError keeps its old behaviour: it ends run(), nothing after it",
          seen == ["a"] and out is schema, (seen, repr(out)))


asyncio.run(main())
print("\n%d/%d passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
