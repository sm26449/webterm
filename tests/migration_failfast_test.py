"""G-16: o migraţie care eşuează cu altceva decât „duplicate column" OPREŞTE boot-ul.

Înainte era doar un WARNING şi gateway-ul pornea cu o coloană lipsă: fiecare cerere care o
atingea dădea 500, fără niciun semnal clar la pornire. Acum `db.connect()` ridică
`MigrationError` cu instrucţiunea vinovată în mesaj şi lasă `_conn` None (nimic nu rulează
pe o schemă parţială). „duplicate column" (migraţie aditivă re-rulată) rămâne ignorat.
Pur unit pe un DB temporar."""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, db  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


async def main():
    config.ensure_dirs()
    orig = list(db.MIGRATIONS)

    # 1. boot normal: migraţiile reale trec (inclusiv re-rularea lor pe un DB deja migrat)
    await db.connect()
    check("boot normal: connect() reuşeşte", db.connected())
    await db.close()
    await db.connect()
    check("re-boot pe acelaşi DB: „duplicate column” e ignorat în continuare", db.connected())
    await db.close()

    # 2. o migraţie care pică REAL (tabel inexistent) → MigrationError, fără conexiune
    db.MIGRATIONS[:] = orig + ["ALTER TABLE tabela_inexistenta ADD COLUMN x TEXT"]
    raised = None
    try:
        await db.connect()
    except db.MigrationError as e:
        raised = e
    except Exception as e:      # noqa: BLE001
        check("tipul excepţiei", False, repr(e))
    check("migraţie eşuată (non-duplicate) → MigrationError (boot refuzat)", raised is not None)
    check("… mesajul numeşte instrucţiunea vinovată",
          raised is not None and "tabela_inexistenta" in str(raised), str(raised))
    check("… nu rămâne o conexiune pe o schemă parţială (_conn None)", not db.connected())

    # 3. o instrucţiune cu „duplicate column" explicit → ignorată (boot-ul merge)
    db.MIGRATIONS[:] = orig + ["ALTER TABLE hosts ADD COLUMN name TEXT"]   # coloană deja existentă
    try:
        await db.connect()
        check("„duplicate column” → ignorat, connect() reuşeşte", db.connected())
        await db.close()
    except Exception as e:      # noqa: BLE001
        check("duplicate column ignorat", False, repr(e))

    db.MIGRATIONS[:] = orig
    print(f"\n{ok}/{total} teste trecute")
    sys.stdout.flush()
    os._exit(0 if ok == total else 1)


asyncio.run(main())
