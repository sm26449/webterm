"""Snapshot container `WTS1` (3.8 encryption at rest, docs/design/ENCRYPTION-AT-REST.md §12.10).

Pure codec: no config, no DB, no files of its own; it reads from and writes to file objects the
caller gives it, in bounded memory (one 1 MiB chunk at a time). `backup.py` decides what goes
inside (a tar.gz with an authenticated content manifest) and where the bytes live.

Layout (integers little-endian unless marked BE):

    header (60 B)  "WTS1" | ver u8 = 1 | flags u8 | reserved u16 = 0 | installation_id 16 B
                   | created_ms u64 | keyring epoch u64 | mk_id 16 B | content u8 = 1 (tar.gz)
                   | reserved 3 B = 0
    envelopes      local (if flags & 1), then portable (if flags & 2); each 83 B:
                   kind u8 (1 local, 2 portable) | kek_id 16 B | wlen u16 = 64
                   | AES-KWP(KEK, "WTS1" ‖ kind ‖ kek_id ‖ CK 32 B)
                   local KEK = SNK; portable KEK = HKDF(MK, "wt/v1/portable")
    header MAC     HMAC-SHA-256(HKDF(CK, "wt/v1/snap-hdr"), header ‖ envelopes)   32 B
    frames         flag u8 (0 data, 1 final) | ct_len u32 | AES-256-GCM ciphertext ‖ tag
                   key = HKDF(CK, "wt/v1/snap-body"), nonce = 8 zero bytes ‖ counter u32 BE,
                   AAD = header MAC ‖ counter u32 BE ‖ flag u8
                   data frames: 1 MiB of plaintext each, only the last one shorter (never empty)
                   final frame: exactly one, plaintext = data-frame count u64 ‖ plaintext len u64
    EOF            nothing after the final frame

CK (the content key) is random, fresh for every Writer (a retry after an ambiguous write is a new
Writer, hence a new CK: the counter-based nonces are never reused under one key). A Writer takes
one caller at a time, reserves the counter before encrypting and requires every sink write to
confirm its full length; anything else breaks it for good.
"""
import hashlib
import hmac
import secrets
import struct
import threading
import time
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap_with_padding,
)

from . import keyring as kr

MAGIC = b"WTS1"
VERSION = 1
FLAG_LOCAL = 1
FLAG_PORTABLE = 2
CONTENT_TAR_GZ = 1
ENV_LOCAL = 1
ENV_PORTABLE = 2

CHUNK = 1 << 20
TAG = 16
FINAL_PT = 16
_HDR = struct.Struct("<4sBBH16sQQ16sB3s")
HDR_LEN = _HDR.size                     # 60
ENV_WRAPPED_LEN = 64                    # KWP(53 B) = 56 padded + 8
ENV_LEN = 1 + kr.ID_LEN + 2 + ENV_WRAPPED_LEN
MAC_LEN = 32
_FRAME = struct.Struct("<BI")

LBL_PORTABLE = b"wt/v1/portable"
LBL_HDR = b"wt/v1/snap-hdr"
LBL_BODY = b"wt/v1/snap-body"

# Bugete implicite ale cititorului. Un snapshot real e mic (DB + transcripturi comprimate);
# plafonul există ca un fişier ostil să nu ne ţină ocupaţi / să nu umple discul.
MAX_PLAINTEXT = 4 << 30                 # 4 GiB de tar.gz
MAX_COUNTER = (1 << 32) - 1


class SnapshotError(ValueError):
    """Any refusal. ValueError, so the API maps it to 400 like every other bad backup."""

    def __init__(self, reason, detail=""):
        self.reason = reason
        super().__init__(f"corrupt or tampered encrypted backup ({reason})" + (f": {detail}" if detail else ""))


class SnapshotWrongKey(SnapshotError):
    """`mk_id` (16 B) when the refusal is "this needs master key <id>" (L1: its own API code)."""

    def __init__(self, reason, detail="", mk_id=None):
        self.reason = reason
        self.mk_id = mk_id
        ValueError.__init__(self, f"this backup cannot be opened with this installation's keys ({reason})"
                            + (f": {detail}" if detail else ""))


class SnapshotTooLarge(SnapshotError):
    def __init__(self, reason, detail=""):
        self.reason = reason
        ValueError.__init__(self, f"encrypted backup too large ({reason})" + (f": {detail}" if detail else ""))


def portable_key(mk):
    """KEK of the portable envelope: HKDF(MK, "wt/v1/portable") (a key used for nothing else)."""
    return kr.derive(mk, LBL_PORTABLE)


def _key32(k, name):
    if not isinstance(k, (bytes, bytearray)) or len(k) != kr.KEY_LEN:
        raise SnapshotError("bad-key", name)
    return bytes(k)


def _nonce(counter):
    return b"\x00" * 8 + struct.pack(">I", counter)


def _aad(mac, counter, final):
    return mac + struct.pack(">IB", counter, 1 if final else 0)


def _wrap(kek, kind, ck):
    kid = kr.key_id(kek)
    w = aes_key_wrap_with_padding(kek, MAGIC + bytes([kind]) + kid + ck)
    if len(w) != ENV_WRAPPED_LEN:   # nu assert: dispare sub python -O
        raise SnapshotError("bad-envelope-length")
    return bytes([kind]) + kid + struct.pack("<H", len(w)) + w


def _unwrap(kek, env, kind):
    if env[0] != kind:
        raise SnapshotError("bad-envelope-kind")
    kid = env[1:1 + kr.ID_LEN]
    if not hmac.compare_digest(kid, kr.key_id(kek)):
        raise SnapshotWrongKey("wrong-snk" if kind == ENV_LOCAL else "wrong-mk")
    (wlen,) = struct.unpack_from("<H", env, 1 + kr.ID_LEN)
    if wlen != ENV_WRAPPED_LEN:
        raise SnapshotError("bad-envelope-length")
    try:
        inner = aes_key_unwrap_with_padding(kek, env[1 + kr.ID_LEN + 2:])
    except InvalidUnwrap:
        raise SnapshotError("unwrap-failed") from None
    # antetul exterior al plicului nu e acoperit de KWP; doar copia lui din interior este
    if len(inner) != 4 + 1 + kr.ID_LEN + kr.KEY_LEN or inner[:5 + kr.ID_LEN] != MAGIC + bytes([kind]) + kid:
        raise SnapshotError("envelope-inner-mismatch")
    return inner[5 + kr.ID_LEN:]


def _fresh_ck():
    """CK nou pentru fiecare Writer. Singurul punct de injecţie pentru vectorul de test (testul
    înlocuieşte funcţia modulului); niciun parametru public nu poate fixa CK-ul (H4)."""
    return secrets.token_bytes(kr.KEY_LEN)


class Writer:
    """File-like sink: `write(bytes)` … `close()`. Single use: any error breaks it for good (the
    caller discards the output and starts a new Writer, i.e. a new content key).

    Like txformat.Writer: one caller at a time (a non-blocking lock; a concurrent or re-entrant
    call breaks the writer instead of waiting), the frame counter is reserved BEFORE encryption,
    and every sink write must confirm its full length (None, short or an exception → broken)."""

    def __init__(self, out, *, installation_id, epoch, mk_id, snk=None, mk=None, created_ms=None,
                 max_plaintext=MAX_PLAINTEXT):
        if snk is None and mk is None:
            raise SnapshotError("no-envelope")
        if not isinstance(installation_id, bytes) or len(installation_id) != kr.ID_LEN:
            raise SnapshotError("bad-installation-id")
        if not isinstance(mk_id, bytes) or len(mk_id) != kr.ID_LEN:
            raise SnapshotError("bad-mk-id")
        if mk is not None and not hmac.compare_digest(kr.key_id(mk), mk_id):
            raise SnapshotError("mk-id-mismatch")
        if not isinstance(epoch, int) or not 0 <= epoch < 1 << 64:
            raise SnapshotError("bad-epoch")
        created_ms = int(time.time() * 1000) if created_ms is None else created_ms
        ck = _fresh_ck()
        flags = (FLAG_LOCAL if snk is not None else 0) | (FLAG_PORTABLE if mk is not None else 0)
        hdr = _HDR.pack(MAGIC, VERSION, flags, 0, installation_id, created_ms, epoch, mk_id,
                        CONTENT_TAR_GZ, b"\x00" * 3)
        envs = b""
        if snk is not None:
            envs += _wrap(_key32(snk, "snk"), ENV_LOCAL, ck)
        if mk is not None:
            envs += _wrap(portable_key(mk), ENV_PORTABLE, ck)
        self._mac = hmac.new(kr.derive(ck, LBL_HDR), hdr + envs, hashlib.sha256).digest()
        self._aead = AESGCM(kr.derive(ck, LBL_BODY))
        del ck
        self._out = out
        self._buf = bytearray()
        self._ctr = 0
        self._total = 0
        self._max = max_plaintext
        self._state = "open"
        self._lock = threading.Lock()
        self._enter()
        try:
            self._emit(hdr + envs + self._mac)
        finally:
            self._leave()

    def _enter(self):
        # neblocant: un al doilea apelant (alt thread sau sinkul reintrând) NU aşteaptă; strică
        # writerul, ca nicio pereche cheie/nonce să nu poată fi folosită de două ori
        if not self._lock.acquire(blocking=False):
            self._state = "broken"
            raise SnapshotError("writer-concurrent")
        if self._state != "open":
            self._lock.release()
            raise SnapshotError("writer-" + self._state)

    def _leave(self):
        self._lock.release()

    def _emit(self, b):
        try:
            n = self._out.write(b)
        except BaseException:
            self._state = "broken"
            raise
        if self._state != "open":            # sinkul a reintrat (şi a stricat writerul)
            raise SnapshotError("writer-" + self._state)
        if n is None or n != len(b):
            # rezultat ambiguu: nu ştim ce a ajuns pe disc → containerul e abandonat
            self._state = "broken"
            raise SnapshotError("short-write", "%r of %d" % (n, len(b)))

    def _frame(self, pt, final):
        ctr = self._ctr
        if ctr > MAX_COUNTER:
            self._state = "broken"
            raise SnapshotTooLarge("too-many-chunks")
        # contorul e rezervat ÎNAINTE de criptare: orice eşec de aici încolo lasă writerul
        # stricat, iar nonce-ul ctr nu mai poate fi reluat sub aceeaşi CK
        self._ctr = ctr + 1
        try:
            ct = self._aead.encrypt(_nonce(ctr), bytes(pt), _aad(self._mac, ctr, final))
        except BaseException:
            self._state = "broken"
            raise
        self._emit(_FRAME.pack(1 if final else 0, len(ct)) + ct)

    def write(self, data):
        self._enter()
        try:
            if self._total + len(self._buf) + len(data) > self._max:
                self._state = "broken"
                raise SnapshotTooLarge("plaintext-budget")
            self._buf += data
            while len(self._buf) >= CHUNK:
                self._frame(self._buf[:CHUNK], False)
                del self._buf[:CHUNK]
                self._total += CHUNK
            return len(data)
        finally:
            self._leave()

    def flush(self):
        pass

    def close(self):
        """Writes the last data frame and the final frame. Idempotent once closed."""
        if self._state == "closed":
            return
        self._enter()
        try:
            if self._buf:
                n = len(self._buf)
                self._frame(self._buf, False)
                self._total += n
                self._buf = bytearray()
            data_frames = self._ctr
            self._frame(struct.pack("<QQ", data_frames, self._total), True)
            self._state = "closed"
        finally:
            self._leave()

    @property
    def plaintext_len(self):
        return self._total + len(self._buf)


class Reader:
    """Parses the header on construction (no key needed), `unlock(...)` recovers CK and checks
    the header MAC; `read(n)` / `chunks()` then stream the authenticated plaintext. The final
    frame and EOF are checked when the stream ends; `finish()` forces that check."""

    def __init__(self, src, max_plaintext=MAX_PLAINTEXT):
        self._src = src
        self._max = max_plaintext
        head = self._exact(HDR_LEN, "truncated-header")
        (magic, ver, flags, rsv, inst, created, epoch, mk_id, content, rsv3) = _HDR.unpack(head)
        if magic != MAGIC:
            raise SnapshotError("bad-magic")
        if ver != VERSION:
            raise SnapshotError("bad-version")
        if flags not in (1, 2, 3) or rsv != 0 or rsv3 != b"\x00" * 3:
            raise SnapshotError("bad-flags")
        if content != CONTENT_TAR_GZ:
            raise SnapshotError("bad-content-type")
        self.flags, self.installation_id, self.created_ms = flags, inst, created
        self.epoch, self.mk_id = epoch, mk_id
        self._envs = {}
        envs = b""
        for kind, bit in ((ENV_LOCAL, FLAG_LOCAL), (ENV_PORTABLE, FLAG_PORTABLE)):
            if flags & bit:
                e = self._exact(ENV_LEN, "truncated-header")
                self._envs[kind] = e
                envs += e
        self._signed = head + envs
        self._mac = self._exact(MAC_LEN, "truncated-header")
        self._aead = None
        self._ctr = 0
        self._total = 0
        self._short_seen = False
        self._done = False
        self._pending = b""

    @property
    def local(self):
        return ENV_LOCAL in self._envs

    @property
    def portable(self):
        return ENV_PORTABLE in self._envs

    def _exact(self, n, reason):
        out = bytearray()
        while len(out) < n:
            b = self._src.read(n - len(out))
            if not b:
                raise SnapshotError(reason)
            out += b
        return bytes(out)

    def unlock(self, *, snk=None, installation_id=None, mk=None):
        """Recover CK: the local envelope with `snk` (only for the same `installation_id`), else
        the portable one with `mk` (its id must be the header's MK id). Then the header MAC."""
        if self._aead is not None:
            raise SnapshotError("already-unlocked")
        ck = None
        if snk is not None and self.local and (
                installation_id is None or hmac.compare_digest(installation_id, self.installation_id)):
            ck = _unwrap(_key32(snk, "snk"), self._envs[ENV_LOCAL], ENV_LOCAL)
        elif mk is not None and self.portable:
            if not hmac.compare_digest(kr.key_id(mk), self.mk_id):
                raise SnapshotWrongKey("wrong-mk", "the backup needs master key " + self.mk_id.hex(),
                                       mk_id=self.mk_id)
            ck = _unwrap(portable_key(mk), self._envs[ENV_PORTABLE], ENV_PORTABLE)
        else:
            raise SnapshotWrongKey("no-usable-envelope",
                                   "portable" if self.portable else "local to installation "
                                   + self.installation_id.hex())
        want = hmac.new(kr.derive(ck, LBL_HDR), self._signed, hashlib.sha256).digest()
        if not hmac.compare_digest(want, self._mac):
            raise SnapshotError("bad-header-mac")
        self._aead = AESGCM(kr.derive(ck, LBL_BODY))

    def _next(self):
        """One authenticated frame → its plaintext; b"" once the final frame and EOF are checked."""
        if self._aead is None:
            raise SnapshotError("locked")
        if self._done:
            return b""
        flag, clen = _FRAME.unpack(self._exact(_FRAME.size, "truncated"))
        if flag not in (0, 1):
            raise SnapshotError("bad-frame-flag")
        final = flag == 1
        # bugetele ÎNAINTE de a citi corpul cadrului: un ct_len uriaş nu se citeşte niciodată
        if final:
            if clen != FINAL_PT + TAG:
                raise SnapshotError("bad-final-length")
        else:
            if not TAG < clen <= CHUNK + TAG:
                raise SnapshotError("bad-frame-length")
            if self._short_seen:
                raise SnapshotError("non-canonical-chunking")
            if self._ctr >= MAX_COUNTER:
                raise SnapshotTooLarge("too-many-chunks")
            if self._total + clen - TAG > self._max:
                raise SnapshotTooLarge("plaintext-budget")
        ct = self._exact(clen, "truncated")
        try:
            pt = self._aead.decrypt(_nonce(self._ctr), ct, _aad(self._mac, self._ctr, final))
        except Exception:
            raise SnapshotError("bad-chunk", str(self._ctr)) from None
        if final:
            count, total = struct.unpack("<QQ", pt)
            if count != self._ctr or total != self._total:
                raise SnapshotError("bad-final-count")
            if self._src.read(1):
                raise SnapshotError("trailing-bytes")
            self._done = True
            return b""
        if len(pt) < CHUNK:
            self._short_seen = True
        self._ctr += 1
        self._total += len(pt)
        return pt

    def chunks(self):
        while True:
            b = self._next()
            if not b:
                return
            yield b

    def read(self, n=-1):
        """File-like read over the plaintext (bounded: never more than one frame buffered)."""
        if n is None or n < 0:
            raise SnapshotError("unbounded-read")
        while not self._pending and not self._done:
            self._pending = self._next()
        out, self._pending = self._pending[:n], self._pending[n:]
        return out

    def finish(self):
        """Drain to the final frame + EOF; any plaintext left unread is an error (the caller's
        parser must have consumed everything it accepts)."""
        if self._pending:
            raise SnapshotError("unconsumed-plaintext")
        while not self._done:
            if self._next():
                raise SnapshotError("unconsumed-plaintext")

    @property
    def plaintext_len(self):
        return self._total


class BoundedGunzip:
    """File-like gunzip over `src.read` with two budgets: an absolute cap on the output and a
    ratio cap (output ≤ max(floor, ratio × compressed input so far)), checked after every step,
    so a compression bomb is refused after at most one bounded step. One gzip member, nothing
    after it."""

    STEP = 64 * 1024

    def __init__(self, src, max_out, ratio=1024, floor=64 << 20):
        self._src = src
        self._max = max_out
        self._ratio = ratio
        self._floor = floor
        self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self._in = 0
        self._out = 0
        self._tail = b""
        self._eof = False

    def _check(self):
        if self._out > self._max:
            raise SnapshotTooLarge("unpacked-budget", "possible compression bomb")
        if self._out > max(self._floor, self._ratio * self._in):
            raise SnapshotTooLarge("compression-ratio", "possible compression bomb")

    def read(self, n=-1):
        if n is None or n < 0:
            raise SnapshotError("unbounded-read")
        out = bytearray()
        while len(out) < n and not self._eof:
            if not self._tail:
                self._tail = self._src.read(self.STEP)
                self._in += len(self._tail)
                if not self._tail:
                    raise SnapshotError("truncated-gzip")
            try:
                b = self._d.decompress(self._tail, min(n - len(out), self.STEP))
            except zlib.error:
                raise SnapshotError("bad-gzip") from None
            self._tail = self._d.unconsumed_tail
            self._out += len(b)
            self._check()
            out += b
            if self._d.eof:
                # un al doilea membru gzip sau orice octet după el = refuz, nu ignorat
                if self._d.unused_data or self._tail or self._src.read(1):
                    raise SnapshotError("trailing-gzip-data")
                self._eof = True
        return bytes(out)

    @property
    def out_len(self):
        """Decompressed bytes delivered so far (the whole stream once EOF was reached)."""
        return self._out

    def drain_zeros(self):
        """After the tar end marker: only zero padding may remain (tar record blocking)."""
        while True:
            b = self.read(self.STEP)
            if not b:
                return
            if b.strip(b"\x00"):
                raise SnapshotError("data-after-archive")
