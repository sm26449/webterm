"""The 3.7 vault inventory and the FK_legacy proof (3.8, encryption at rest; H4, R-H2).

One place for "does this 32-byte legacy key really open this database": the boot's migration
(bootkeys.prove_legacy_key on the live volume and on a 3.7 staged set) and every restore of a
pre-3.8 archive (backup: the legacy import onto a protected volume, a 3.7 restore onto a legacy
volume, and the host-side `hostops verify`) run exactly this code on exactly the database they
will publish. A low module (config, keys only): backup.py and security.py import it, bootkeys
re-exports it.

INV-14 (docs/design/INVARIANTS.md): a foreign 32-byte file never becomes FK_legacy.
"""
import base64
import json
import os
import re
import sqlite3
import stat
import urllib.parse

from cryptography.fernet import Fernet, InvalidToken

from . import config, keys

DB_NAME = "webterm.db"
# 3.8 (ENCRYPTION-AT-REST.md §12.2): prefixul numeşte cheia valorii (security le re-exportă)
FK_PREFIX = "FK:"
FK_LEGACY_PREFIX = "FKL:"
# Un token Fernet: versiunea 0x80 → base64 url-safe începe cu „gA”; minim ~100 de caractere.
_FERNET_RE = re.compile(r"^gA[A-Za-z0-9_-]{60,}={0,2}$")
# H4: INVENTARUL e complet (fiecare rând al fiecărei coloane `*_encrypted` şi al app_settings,
# citit în flux, fără LIMIT înaintea clasificării); doar DECRIPTAREA are buget. Plafonul
# inventarului e un refuz explicit, niciodată „no-ciphertext”.
_DECRYPT_BUDGET = 256         # valori încercate cel mult (regula „măcar una se decriptează”)
_FIRST_PER_SOURCE = 4         # primele valori ale fiecărei surse intră în buget înaintea restului
_MAX_VAULT_VALUES = 500_000   # valori de seif clasificate; peste → refuz legacy-db-inventory-too-large
_JSON_DEPTH = 16

# ── item 3: FK_legacy proven on the database ────────────────────────────────


def _db_uri(dir_fd, base_path=None) -> str:
    # prin fd-ul fixat al directorului (nu printr-o nouă rezolvare a căii): acelaşi director pe
    # care l-a inventariat lock-ul. immutable=1: SQLite nu creează -wal/-shm şi nu ia lock-uri,
    # deci proba nu scrie nimic în volum (garanţia „refuz = nimic schimbat”). Fiindcă immutable
    # ignoră WAL-ul, un WAL nevid e refuzat ÎNAINTE de citire (H4).
    base = "/proc/self/fd/%d" % dir_fd
    path = os.path.join(base if os.path.isdir(base) else str(base_path or config.DATA_DIR), DB_NAME)
    return "file:%s?mode=ro&immutable=1" % urllib.parse.quote(path, safe="/")


class _Unclassifiable(Exception):
    def __init__(self, reason, where):
        super().__init__(where)
        self.reason = reason
        self.where = where


class VaultInventory:
    """H4: what the 3.7 schema can hold encrypted, classified exhaustively. `count` = every
    vault-shaped value seen; `candidates` = the decryption budget (first values of each source
    first, then the rest in order). A `FK:` value anywhere, an unclassifiable value or an
    inventory over the cap raise _Unclassifiable while scanning."""

    def __init__(self):
        self.count = 0
        self.candidates = []
        self._rest = []
        self._per_source = {}

    def add(self, v, where):
        self.count += 1
        if self.count > _MAX_VAULT_VALUES:
            raise _Unclassifiable("legacy-db-inventory-too-large", "more than %d encrypted values"
                                  % _MAX_VAULT_VALUES)
        n = self._per_source.get(where, 0)
        self._per_source[where] = n + 1
        if n < _FIRST_PER_SOURCE:
            if len(self.candidates) < _DECRYPT_BUDGET:
                self.candidates.append(v)
        elif len(self.candidates) + len(self._rest) < _DECRYPT_BUDGET:
            self._rest.append(v)

    def budget(self):
        return (self.candidates + self._rest)[:_DECRYPT_BUDGET]


def _vault_value(v: str):
    """Classify one string: "fk" (3.8 FK: prefix), "candidate" (a Fernet token, optionally with
    the FKL: prefix), "bad" (vault-shaped but not a token: a broken FKL: value or a damaged
    token), or None (not a vault value: a placeholder, plain text)."""
    if v.startswith(FK_PREFIX):
        return "fk"
    if v.startswith(FK_LEGACY_PREFIX):
        return "candidate" if _FERNET_RE.match(v[len(FK_LEGACY_PREFIX):]) else "bad"
    if _FERNET_RE.match(v):
        return "candidate"
    return None


def _classify_column(inv, v, where):
    if v is None or v == "":
        return
    if not isinstance(v, str):
        # 3.7 scrie doar text în coloanele *_encrypted: un BLOB/număr nu se poate clasifica
        raise _Unclassifiable("legacy-db-unclassifiable", where)
    kind = _vault_value(v)
    if kind == "fk":
        raise _Unclassifiable("legacy-db-has-protected-values", where)
    if kind == "candidate":
        inv.add(v, where)
    elif kind == "bad" or v.startswith("gA"):
        # „arată” a token (prefixul versiunii Fernet) dar nu e unul întreg: nu ştim ce e → refuz
        raise _Unclassifiable("legacy-db-unclassifiable", where)
    # altfel: placeholder / text fără formă de seif — nu dovedeşte şi nu infirmă cheia


def _walk_json(inv, doc, where, depth=0):
    if depth > _JSON_DEPTH:
        raise _Unclassifiable("legacy-db-unclassifiable", where)
    if isinstance(doc, dict):
        items = doc.values()
    elif isinstance(doc, list):
        items = doc
    else:
        items = (doc,)
    for x in items:
        if isinstance(x, (dict, list)):
            _walk_json(inv, x, where, depth + 1)
        elif isinstance(x, str):
            _classify_setting_str(inv, x, where)


def _classify_setting_str(inv, v, where):
    kind = _vault_value(v.strip())
    if kind == "fk":
        raise _Unclassifiable("legacy-db-has-protected-values", where)
    if kind == "bad":
        raise _Unclassifiable("legacy-db-unclassifiable", where)
    if kind == "candidate":
        inv.add(v.strip(), where)


def _classify_setting(inv, key, value):
    where = "app_settings[%s]" % str(key)[:64]
    if value is None or value == "":
        return
    if isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
        if b"gA" in b or FK_PREFIX.encode() in b:
            raise _Unclassifiable("legacy-db-unclassifiable", where)
        return
    if not isinstance(value, str):
        return                                  # număr: nu e valoare de seif
    v = value.strip()
    if v[:1] in ("{", "["):
        try:
            doc = json.loads(v)
        except ValueError:
            doc = None
        if doc is None and v not in ("null",):
            # nu se parsează, dar poate ascunde un token / un FK: → nu-l putem clasifica
            if "gA" in v or FK_PREFIX in v:
                raise _Unclassifiable("legacy-db-unclassifiable", where)
            return
        _walk_json(inv, doc, where)
        return
    _classify_setting_str(inv, v, where)


def legacy_inventory(con) -> VaultInventory:
    """H4: every encrypted value the 3.7 schema can hold, without knowing the schema version:
    each `*_encrypted` column of each table (every non-empty row, streamed) and every
    app_settings value that is, or holds as JSON at any depth, a Fernet token (SMTP password,
    cloud credentials, the agents' CA key). Raises _Unclassifiable (see VaultInventory)."""
    inv = VaultInventory()
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for t in tables:
        qt = '"%s"' % t.replace('"', '""')
        cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % qt)]
        for c in cols:
            if not str(c).endswith("_encrypted"):
                continue
            qc = '"%s"' % str(c).replace('"', '""')
            where = "%s.%s" % (t, c)
            # fără LIMIT: cursorul curge rând cu rând, clasificarea vede tot
            for (v,) in con.execute("SELECT %s FROM %s WHERE %s IS NOT NULL" % (qc, qt, qc)):
                _classify_column(inv, v, where)
    if "app_settings" in tables:
        for k, v in con.execute("SELECT key, value FROM app_settings"):
            _classify_setting(inv, k, v)
    return inv


def legacy_candidates(con) -> list:
    """The decryption budget of legacy_inventory (kept for callers and tests)."""
    return legacy_inventory(con).budget()


def _side_file_pending(dir_fd, name) -> bool:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_size > 0
    except FileNotFoundError:
        return False
    except OSError:
        return True                     # nu ştim → tratat ca nescris în fişier (mai strict)


def prove_legacy_key(dir_fd, secret: bytes, kind: str = keys.KIND_INVALID_KEY, base_path=None) -> str:
    """§12.9 checklist item 3 + 9, H4. Before `secret` becomes FK_legacy:
      - a non-empty `webterm.db-wal` (or a hot `-journal`) → refuse (`legacy-db-wal-pending`)
        BEFORE any read: the probe reads the file only (immutable, writes nothing), so values
        still in the WAL would be invisible. Stop the 3.7 gateway cleanly first (a clean stop
        checkpoints the WAL), or start once without the key and stop it;
      - the complete inventory (legacy_inventory): a value with the 3.8 FK prefix → refuse
        (`legacy-db-has-protected-values`, a mixed set is never migrated); an unclassifiable
        value → `legacy-db-unclassifiable`; over the cap → `legacy-db-inventory-too-large`;
      - encrypted values present → at least one of the decryption budget must decrypt with
        `secret` ("proven"); none → refuse (`legacy-key-unproven`): a foreign 32-byte file
        never becomes FK_legacy;
      - no encrypted value at all → eligible ("no-ciphertext").
    Returns "proven" or "no-ciphertext"; refuses with BootRefused(kind)."""
    try:
        st = os.stat(DB_NAME, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        if _side_file_pending(dir_fd, DB_NAME + "-wal"):
            raise keys.BootRefused("legacy-db-wal-pending", DB_NAME + "-wal", kind) from None
        return "no-ciphertext"
    except OSError as e:
        raise keys.BootRefused("legacy-db-unreadable", "%s: %s" % (DB_NAME, e.strerror), kind) from None
    if not stat.S_ISREG(st.st_mode):
        raise keys.BootRefused("legacy-db-not-regular", DB_NAME, kind)
    for side in ("-wal", "-journal"):
        if _side_file_pending(dir_fd, DB_NAME + side):
            raise keys.BootRefused("legacy-db-wal-pending", DB_NAME + side, kind)
    try:
        con = sqlite3.connect(_db_uri(dir_fd, base_path), uri=True, timeout=2)
        try:
            inv = legacy_inventory(con)
        finally:
            con.close()
    except _Unclassifiable as e:
        raise keys.BootRefused(e.reason, e.where, kind) from None
    except sqlite3.Error:
        raise keys.BootRefused("legacy-db-unreadable", DB_NAME, kind) from None
    if not inv.count:
        return "no-ciphertext"
    f = Fernet(base64.urlsafe_b64encode(secret))
    tried = inv.budget()
    for v in tried:
        if v.startswith(FK_LEGACY_PREFIX):
            v = v[len(FK_LEGACY_PREFIX):]
        try:
            f.decrypt(v.encode())
            return "proven"
        except (InvalidToken, ValueError, TypeError):
            continue
    raise keys.BootRefused("legacy-key-unproven", "%s does not decrypt any of %d (of %d) encrypted "
                           "value(s)" % (keys.LEGACY_SECRET, len(tried), inv.count), kind)
