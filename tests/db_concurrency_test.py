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
    finally:
        await db.close()


asyncio.run(main())
print("\n%d/%d passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
