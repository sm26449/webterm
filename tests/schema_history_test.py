"""Amprenta schemei pentru comenzile admin doar-DB (db._schema_of / connect_maintenance), RC-M2.

1. Regresie istorică: baze create cu SCHEMA + MIGRATIONS ale unor versiuni vechi (extrase din git în
   tests/fixtures/db-schema/<tag>.json: `git show <tag>:gateway/app/db.py`, doar listele SCHEMA,
   MIGRATIONS şi DDL-ul rulat de connect() după ele), aduse la zi de db.connect() de acum, trebuie
   să aibă EXACT amprenta unei baze noi — inclusiv cu ordinea coloanelor diferită (coloanele
   adăugate prin ALTER stau la coadă). Altfel break-glass-ul (`app.admin passwd` …) ar refuza o
   instalare veche, migrată corect.
2. Ce prinde amprenta: DEFAULT, CHECK, COLLATE (şi pe UNIQUE-urile implicite, prin index_xinfo),
   literalii exacţi; ce ignoră: spaţii, comentarii, majusculele cuvintelor-cheie.
3. Amprenta se ia pe ACEEAŞI conexiune pe care o foloseşte apoi comanda (o singură deschidere).
Fără reţea, doar directoare temporare.
"""
import asyncio
import json
import os
import pathlib
import shutil
import sqlite3
import sys
import tempfile

BASE = tempfile.mkdtemp(prefix="wt-schema-hist-")
os.environ["WEBTERM_DATA_DIR"] = BASE
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "gateway"))

import aiosqlite  # noqa: E402

from app import config, db  # noqa: E402

FIXTURES = HERE / "fixtures" / "db-schema"
ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {str(detail)[:400]}"))


def run(coro):
    return asyncio.run(coro)


def fresh_dir():
    for n in os.listdir(BASE):
        p = os.path.join(BASE, n)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.unlink(p)


def build_old(fx):
    con = sqlite3.connect(str(config.DB_PATH))
    con.executescript(fx["schema"])
    for stmt in fx["migrations"]:
        try:
            con.execute(stmt)
        except sqlite3.Error as e:
            if "duplicate column" not in str(e).lower():
                raise
    for stmt in fx["post"]:
        con.execute(stmt)
    con.commit()
    con.close()


def fingerprint(path):
    con = sqlite3.connect(str(path))
    try:
        return db._schema_of(con)
    finally:
        con.close()


def maint_ok():
    try:
        run(db.connect_maintenance())
        res = True
    except db.MaintenanceRefused:
        res = False
    opened = db._conn is not None
    run(db.close())
    return res, opened


def history():
    print("── RC-M2: historical upgrades → the fresh fingerprint")
    want = db.expected_schema()
    # ordinea coloanelor unei baze NOI (SCHEMA + MIGRATIONS), per tabelă
    con = sqlite3.connect(":memory:")
    con.executescript(db.SCHEMA)
    for stmt in db.MIGRATIONS:
        try:
            con.execute(stmt)
        except sqlite3.Error:
            pass
    fresh_order = {t: [r[1] for r in con.execute('PRAGMA table_info("%s")' % t)]
                   for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    differed = []
    tags = sorted(p.stem for p in FIXTURES.glob("*.json"))
    check("cel puţin 3 versiuni istorice în fixtures", len(tags) >= 3, tags)
    reordered = []
    for tag in tags:
        fx = json.loads((FIXTURES / (tag + ".json")).read_text())
        fresh_dir()
        build_old(fx)
        before = fingerprint(config.DB_PATH)
        run(db.connect())
        run(db.close())
        live = fingerprint(config.DB_PATH)
        bad = sorted(t for t in set(want) | set(live) if want.get(t) != live.get(t))
        check(f"{tag}: upgrade prin db.connect() → amprenta = cea a unei baze noi", not bad, bad[:5])
        if before != want:
            differed.append(tag)
        con = sqlite3.connect(str(config.DB_PATH))
        for t, fo in fresh_order.items():
            order = [r[1] for r in con.execute('PRAGMA table_info("%s")' % t)]
            if order != fo and sorted(order) == sorted(fo):
                reordered.append("%s:%s" % (tag, t))
        con.close()
        check(f"{tag}: connect_maintenance acceptă baza migrată", maint_ok() == (True, True))
    check("cel puţin o versiune veche avea altă schemă înainte de upgrade (testul vede ceva)",
          len(differed) >= 2, differed)
    check("cel puţin o versiune are coloanele în altă ordine (ALTER la coadă)", reordered, reordered)


def detections():
    print("── RC-M2: what the fingerprint sees (and ignores)")
    fresh_dir()
    run(db.connect())
    run(db.close())
    good = config.DB_PATH.read_bytes()

    def attempt(sql):
        fresh_dir()
        config.DB_PATH.write_bytes(good)
        if sql:
            con = sqlite3.connect(str(config.DB_PATH))
            con.executescript(sql)
            con.commit()
            con.close()
        return maint_ok()

    check("baza creată de boot → acceptată", attempt("") == (True, True))
    # o tabelă refăcută cu aceeaşi structură, dar cu o diferenţă pe care PRAGMA index_info / numele nu o văd
    def rebuild(table, transform):
        con = sqlite3.connect(str(config.DB_PATH))
        sql = con.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0]
        # indexurile explicite pleacă odată cu tabela veche: le refacem, ca singura diferenţă să fie cea testată
        idx = [r[0] for r in con.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? "
                                         "AND sql IS NOT NULL", (table,))]
        con.close()
        new = transform(sql)
        assert new != sql, "transformarea nu a schimbat nimic"
        return ("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON; ALTER TABLE %s RENAME TO _old_t; %s; "
                "INSERT INTO %s SELECT * FROM _old_t; DROP TABLE _old_t; %s" % (table, new, table, "".join(i + ";" for i in idx)))

    for table in ("users", "app_settings"):
        got = attempt(rebuild(table, lambda s: s.replace("(", " (  ", 1).replace("TEXT", "text")))
        check(f"control: {table} refăcută cu alte spaţii / majuscule (aceeaşi schemă) → acceptată",
              got == (True, True), got)

    con = sqlite3.connect(":memory:")
    con.executescript(db.SCHEMA)
    users_sql = con.execute("SELECT sql FROM sqlite_master WHERE name='users'").fetchone()[0]
    con.close()
    check("(premisa) users are `email TEXT UNIQUE NOT NULL`", "email TEXT UNIQUE NOT NULL" in users_sql, users_sql[:200])
    for label, table, fn in (
            ("COLLATE NOCASE pe UNIQUE-ul implicit (index_info identic, index_xinfo nu)", "users",
             lambda s: s.replace("email TEXT UNIQUE NOT NULL", "email TEXT UNIQUE NOT NULL COLLATE NOCASE", 1)),
            ("un CHECK pe coloană", "users",
             lambda s: s.replace("email TEXT UNIQUE NOT NULL", "email TEXT UNIQUE NOT NULL CHECK (length(email) > 3)", 1)),
            ("un CHECK la nivel de tabelă", "app_settings",
             lambda s: s.rstrip().rstrip(")") + ", CHECK (key <> 'x'))"),
            ("STRICT", "app_settings", lambda s: s.rstrip() + " STRICT")):
        got = attempt(rebuild(table, fn))
        check(f"RC-M2: {label} → refuz, nicio conexiune deschisă", got == (False, False), got)
    # DEFAULT: unul diferit (literal) → refuz; acelaşi DEFAULT scris altfel (spaţii, majuscule) → acceptat
    con = sqlite3.connect(":memory:")
    con.executescript(db.SCHEMA)
    dfl = [(t, r[1], r[4]) for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
           for r in con.execute('PRAGMA table_info("%s")' % t) if r[4] and r[4].startswith("'")]
    con.close()
    t, col, lit = dfl[0]

    def swap_default(s, new):
        i = s.index(lit, s.index(col))
        return s[:i] + new + s[i + len(lit):]
    got = attempt(rebuild(t, lambda s: swap_default(s, "'X'" if lit != "'X'" else "'Y'")))
    check(f"RC-M2: DEFAULT {t}.{col} {lit} → alt literal → refuz", got == (False, False), got)
    # literalii se păstrează EXACT: doar majusculele literalului diferă
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE a(x TEXT DEFAULT 'abc', y TEXT CHECK (y <> 'Q'))")
    con.execute("CREATE TABLE b(x TEXT DEFAULT 'ABC', y TEXT CHECK (y <> 'q'))")
    con.execute("CREATE TABLE c(x   text   default   'abc' ,  y TEXT check(y<>'Q')) -- comentariu")
    fa, fb, fc = (db._schema_of(con)[n] for n in ("a", "b", "c"))
    con.close()
    check("RC-M2: literalii nu se normalizează ('abc' ≠ 'ABC', 'Q' ≠ 'q')", fa != fb)
    check("RC-M2: spaţii, comentarii şi majusculele cuvintelor-cheie nu contează", fa == fc, (fa, fc))
    check("RC-M2: _norm_sql păstrează literalul şi scoate IF NOT EXISTS",
          db._norm_sql("create  index if not exists i ON t(x) WHERE y = 'Ab  c'")
          == "CREATE INDEX I ON T ( X ) WHERE Y = 'Ab  c'", db._norm_sql("create index if not exists i ON t(x) WHERE y = 'Ab  c'"))
    # o diferenţă de ordine DESC / colaţie pe un index explicit
    got = attempt("DROP INDEX idx_sessions_share; CREATE INDEX idx_sessions_share ON sessions(share_token DESC) "
                  "WHERE share_token IS NOT NULL;")
    check("RC-M2: indexul parţial cu altă ordine (DESC) → refuz", got == (False, False), got)


def same_connection():
    print("── RC-M2: the fingerprint is taken on the connection the command uses")
    fresh_dir()
    run(db.connect())
    run(db.close())
    opened = []
    real_aio, real_sql = aiosqlite.connect, sqlite3.connect

    def aio(*a, **k):
        opened.append(("aiosqlite", a[0]))
        return real_aio(*a, **k)

    def sq(*a, **k):
        if a and str(config.DB_PATH) in str(a[0]):
            opened.append(("sqlite3", a[0]))
        return real_sql(*a, **k)
    db.aiosqlite.connect, db.sqlite3.connect = aio, sq
    try:
        res = maint_ok()
    finally:
        db.aiosqlite.connect, db.sqlite3.connect = real_aio, real_sql
    # sqlite3.connect apare o dată: chiar deschiderea făcută de aiosqlite pe firul ei
    check("o singură deschidere a fişierului DB (aceeaşi conexiune pentru amprentă şi comandă)",
          res == (True, True) and sorted(k for k, _u in opened) == ["aiosqlite", "sqlite3"], opened)
    # tranzacţia amprentei s-a încheiat: conexiunea păstrată nu ţine niciun lacăt
    run(db.connect_maintenance())
    try:
        busy = db._conn._conn.in_transaction
        other = sqlite3.connect(str(config.DB_PATH), timeout=0.2)
        other.execute("BEGIN IMMEDIATE")
        other.rollback()
        other.close()
        free = True
    except sqlite3.OperationalError:
        free = False
    finally:
        run(db.close())
    check("după verificare conexiunea nu ţine tranzacţia deschisă (gateway-ul poate scrie)",
          busy is False and free, (busy, free))


def main():
    try:
        history()
        detections()
        same_connection()
    finally:
        shutil.rmtree(BASE, ignore_errors=True)
    print(f"\n{ok}/{total} passed")
    raise SystemExit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
