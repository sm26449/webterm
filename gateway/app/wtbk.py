"""Streamed passphrase layer `WTBK2` (3.8, docs/design/ENCRYPTION-AT-REST.md §12.10.1).

The host-side archive (`scripts/backup.sh` → `hostops backup`) of a protected volume: the
portable WTS1 under a passphrase, written and read in bounded memory (two 1 MiB chunks at most),
whatever the size of the volume. WTBK1 (backup.encrypt / decrypt: one AES-GCM over the whole
archive) stays the format of in-app downloads and uploads, and is still read everywhere.

Pure codec like snapshot.py: no config, no files of its own. Layout (integers little-endian
unless marked BE):

    header (56 B)  "WTBK2" | ver u8 = 1 | kdf u8 = 1 (scrypt) | log2_n u8 | r u8 | p u8
                   | chunk_log2 u8 = 20 | content u8 = 1 (WTS1) | salt 16 B | nonce_prefix 8 B
                   | plain_len u64 | unpacked_len u64 | reserved 4 B = 0
    header MAC     HMAC-SHA-256(HKDF(K, "wt/v1/wtbk2-hdr"), header)                   32 B
    chunks         n = max(1, ceil(plain_len / 2^chunk_log2)); chunk i = AES-256-GCM
                   ciphertext ‖ tag of plaintext bytes [i·C, min((i+1)·C, plain_len)),
                   key = HKDF(K, "wt/v1/wtbk2-body"), nonce = nonce_prefix ‖ i u32 BE,
                   AAD = header MAC ‖ i u32 BE ‖ final u8 (1 only for i = n − 1)
    EOF            nothing after chunk n − 1

K = scrypt(passphrase UTF-8, salt, N = 2^log2_n, r, p, 32 B). `plain_len` is the exact length of
the plaintext (so every chunk boundary, and the last chunk, follow from the authenticated header:
a truncated, extended, reordered, duplicated or dropped chunk fails its tag or the length);
`unpacked_len` is the exact decompressed size of the WTS1's tar stream, declared so a reader can
refuse before it extracts anything (free space) and enforce it while extracting.
"""
import hashlib
import hmac
import secrets
import struct
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import keyring as kr

MAGIC = b"WTBK2"
VERSION = 1
KDF_SCRYPT = 1
CONTENT_WTS1 = 1
CHUNK_LOG2 = 20
CHUNK = 1 << CHUNK_LOG2
TAG = 16
MAC_LEN = 32
_HDR = struct.Struct("<5sBBBBBBB16s8sQQ4s")
HDR_LEN = _HDR.size                     # 56

LBL_HDR = b"wt/v1/wtbk2-hdr"
LBL_BODY = b"wt/v1/wtbk2-body"

# Parametrii scrypt ai scriitorului (64 MiB, ~0,2 s) şi ce acceptă cititorul: un antet ostil nu
# ne poate cere sute de MiB sau minute de CPU înainte ca MAC-ul să fie verificat
LOG2_N = 16
SCRYPT_R = 8
SCRYPT_P = 1
LOG2_N_RANGE = (15, 20)
SCRYPT_MAX_MEM = 256 << 20              # 128 · r · N
SCRYPT_MAX_P = 4
MAX_CHUNKS = 1 << 32                    # contorul nonce-ului e u32
MAX_LEN = MAX_CHUNKS * CHUNK


class WtbkError(ValueError):
    """Any refusal (ValueError: the callers map it like every other bad backup)."""

    def __init__(self, reason, detail=""):
        self.reason = reason
        super().__init__(f"corrupt or tampered encrypted backup ({reason})" + (f": {detail}" if detail else ""))


class WtbkWrongPassphrase(WtbkError):
    def __init__(self):
        self.reason = "bad-header-mac"
        ValueError.__init__(self, "wrong passphrase, or the file is corrupt")


def _fresh_salt():
    """Singurele puncte de injecţie pentru vectorul de test (testul înlocuieşte funcţiile modulului)."""
    return secrets.token_bytes(16)


def _fresh_prefix():
    return secrets.token_bytes(8)


def _kdf(passphrase, salt, log2n, r, p):
    if not isinstance(passphrase, str) or not passphrase:
        raise WtbkError("no-passphrase")
    return Scrypt(salt=salt, length=kr.KEY_LEN, n=1 << log2n, r=r, p=p).derive(passphrase.encode("utf-8"))


def _chunks_for(plain_len):
    return max(1, -(-plain_len // CHUNK))


def _aad(mac, i, final):
    return mac + struct.pack(">IB", i, 1 if final else 0)


class Writer:
    """File-like sink for exactly `plain_len` bytes: `write(bytes)` … `close()`. Single use: any
    error (more or fewer bytes than declared, a short or failed sink write, a concurrent call)
    breaks it for good; the caller discards the output. The header is written at construction."""

    def __init__(self, out, passphrase, *, plain_len, unpacked_len, log2n=LOG2_N, r=SCRYPT_R, p=SCRYPT_P):
        for v in (plain_len, unpacked_len):
            if type(v) is not int or not 0 <= v < 1 << 64:
                raise WtbkError("bad-length")
        if plain_len > MAX_LEN:
            raise WtbkError("too-large")
        salt, self._prefix = _fresh_salt(), _fresh_prefix()
        hdr = _HDR.pack(MAGIC, VERSION, KDF_SCRYPT, log2n, r, p, CHUNK_LOG2, CONTENT_WTS1, salt,
                        self._prefix, plain_len, unpacked_len, b"\x00" * 4)
        _check_params(log2n, r, p, CHUNK_LOG2)
        k = _kdf(passphrase, salt, log2n, r, p)
        self._mac = hmac.new(kr.derive(k, LBL_HDR), hdr, hashlib.sha256).digest()
        self._aead = AESGCM(kr.derive(k, LBL_BODY))
        del k
        self._out = out
        self._len = plain_len
        self._n = _chunks_for(plain_len)
        self._buf = bytearray()
        self._ctr = 0
        self._done = 0                  # octeţi de text clar deja criptaţi
        self._state = "open"
        self._lock = threading.Lock()
        self._enter()
        try:
            self._emit(hdr + self._mac)
        finally:
            self._lock.release()

    def _enter(self):
        # neblocant, ca la snapshot.Writer: un al doilea apelant strică writerul (nonce unic)
        if not self._lock.acquire(blocking=False):
            self._state = "broken"
            raise WtbkError("writer-concurrent")
        if self._state != "open":
            self._lock.release()
            raise WtbkError("writer-" + self._state)

    def _emit(self, b):
        try:
            n = self._out.write(b)
        except BaseException:
            self._state = "broken"
            raise
        if self._state != "open":
            raise WtbkError("writer-" + self._state)
        if n is None or n != len(b):
            self._state = "broken"
            raise WtbkError("short-write", "%r of %d" % (n, len(b)))

    def _chunk(self, pt):
        i = self._ctr
        final = i == self._n - 1
        # contorul e rezervat ÎNAINTE de criptare: un eşec lasă writerul stricat, nonce-ul nefolosit
        self._ctr = i + 1
        try:
            ct = self._aead.encrypt(self._prefix + struct.pack(">I", i), bytes(pt), _aad(self._mac, i, final))
        except BaseException:
            self._state = "broken"
            raise
        self._done += len(pt)
        self._emit(ct)

    def write(self, data):
        self._enter()
        try:
            if self._done + len(self._buf) + len(data) > self._len:
                self._state = "broken"
                raise WtbkError("more-than-declared")
            self._buf += data
            # ultimul chunk (cel cu final = 1) aşteaptă close(): numai acolo ştim că nu mai vine nimic
            while len(self._buf) >= CHUNK and self._done + CHUNK < self._len:
                self._chunk(self._buf[:CHUNK])
                del self._buf[:CHUNK]
            return len(data)
        finally:
            self._lock.release()

    def flush(self):
        pass

    def close(self):
        if self._state == "closed":
            return
        self._enter()
        try:
            if self._done + len(self._buf) != self._len:
                self._state = "broken"
                raise WtbkError("less-than-declared", "%d of %d" % (self._done + len(self._buf), self._len))
            while len(self._buf) > CHUNK:           # doar la plain_len multiplu exact (n ≥ 2)
                self._chunk(self._buf[:CHUNK])
                del self._buf[:CHUNK]
            self._chunk(self._buf)
            self._buf = bytearray()
            if self._ctr != self._n:
                self._state = "broken"
                raise WtbkError("chunk-count")
            self._state = "closed"
        finally:
            self._lock.release()


def _check_params(log2n, r, p, chunk_log2):
    if not LOG2_N_RANGE[0] <= log2n <= LOG2_N_RANGE[1] or not 1 <= r or not 1 <= p <= SCRYPT_MAX_P:
        raise WtbkError("bad-kdf-params")
    if 128 * r * (1 << log2n) > SCRYPT_MAX_MEM:
        raise WtbkError("bad-kdf-params")
    if chunk_log2 != CHUNK_LOG2:
        raise WtbkError("bad-chunk-size")


def parse_header(head):
    """The 56-byte header → dict (no key needed); any malformed field → WtbkError."""
    if len(head) != HDR_LEN:
        raise WtbkError("truncated-header")
    (magic, ver, kdf, log2n, r, p, clog, content, salt, prefix, plain_len, unpacked_len, rsv) = _HDR.unpack(head)
    if magic != MAGIC:
        raise WtbkError("bad-magic")
    if ver != VERSION:
        raise WtbkError("bad-version")
    if kdf != KDF_SCRYPT:
        raise WtbkError("bad-kdf")
    _check_params(log2n, r, p, clog)
    if content != CONTENT_WTS1:
        raise WtbkError("bad-content-type")
    if rsv != b"\x00" * 4:
        raise WtbkError("bad-reserved")
    if plain_len > MAX_LEN:
        raise WtbkError("too-large")
    return {"log2n": log2n, "r": r, "p": p, "salt": salt, "prefix": prefix, "plain_len": plain_len,
            "unpacked_len": unpacked_len}


class Reader:
    """Parses the header and checks its MAC with the passphrase on construction (a wrong
    passphrase is refused before any body byte is read); `read(n)` then streams the
    authenticated plaintext, one chunk at a time. The end (last chunk, then EOF of `src`) is
    checked before `read` first returns b"" — the caller sees the end only once it is proven."""

    def __init__(self, src, passphrase, max_plain=None):
        self._src = src
        head = self._exact(HDR_LEN, "truncated-header")
        h = parse_header(head)
        if max_plain is not None and h["plain_len"] > max_plain:
            raise WtbkError("too-large", "declared %d bytes" % h["plain_len"])
        mac = self._exact(MAC_LEN, "truncated-header")
        k = _kdf(passphrase, h["salt"], h["log2n"], h["r"], h["p"])
        want = hmac.new(kr.derive(k, LBL_HDR), head, hashlib.sha256).digest()
        if not hmac.compare_digest(want, mac):
            raise WtbkWrongPassphrase()
        self._aead = AESGCM(kr.derive(k, LBL_BODY))
        del k
        self._mac = mac
        self._prefix = h["prefix"]
        self.plain_len = h["plain_len"]
        self.unpacked_len = h["unpacked_len"]
        self._n = _chunks_for(self.plain_len)
        self._ctr = 0
        self._pending = b""
        self._done = False

    def _exact(self, n, reason):
        out = bytearray()
        while len(out) < n:
            b = self._src.read(n - len(out))
            if not b:
                raise WtbkError(reason)
            out += b
        return bytes(out)

    def _next(self):
        i = self._ctr
        final = i == self._n - 1
        size = min(CHUNK, self.plain_len - i * CHUNK)
        ct = self._exact(size + TAG, "truncated")
        try:
            pt = self._aead.decrypt(self._prefix + struct.pack(">I", i), ct, _aad(self._mac, i, final))
        except Exception:
            raise WtbkError("bad-chunk", str(i)) from None
        self._ctr = i + 1
        if final:
            # nimic după ultimul chunk; citirea lui EOF e şi momentul în care sursa îşi poate face
            # propriile verificări de capăt (hostops: SHA-256 fixat)
            if self._src.read(1):
                raise WtbkError("trailing-bytes")
            self._done = True
        return pt

    def read(self, n=-1):
        if n is None or n < 0:
            raise WtbkError("unbounded-read")
        while not self._pending and not self._done:
            self._pending = self._next()
        out, self._pending = self._pending[:n], self._pending[n:]
        return out

    def finish(self):
        """Every chunk read and the end proven; plaintext left unread is an error."""
        if self._pending:
            raise WtbkError("unconsumed-plaintext")
        while not self._done:
            if self._next():
                raise WtbkError("unconsumed-plaintext")

    @property
    def done(self):
        return self._done
