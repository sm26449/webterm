"""Containerul WTS1 (gateway/app/snapshot.py, docs/design/ENCRYPTION-AT-REST.md §12.10).

Vector fix, roundtrip local/portabil, orice octet modificat / trunchiere / reordonare / octeţi
în plus refuzate, cheie greşită (SNK, MK, instalare), bugete verificate ÎNAINTE de citire,
bombă de compresie oprită devreme, memorie mărginită în flux, cheie de conţinut nouă la fiecare
scriere, şi stratul cu parolă (WTBK1) care cere ambele secrete. Pur: fără DB, fără reţea."""
import io
import os
import struct
import sys
import tempfile
import tracemalloc
import zlib

os.environ.setdefault("WEBTERM_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from app import backup  # noqa: E402
from app import keyring as kr  # noqa: E402
from app import snapshot as wts  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


SNK = bytes(range(0xC0, 0xE0))
MK = bytes(range(0x40, 0x60))
CK = bytes(range(0xE0, 0x100))
INST = bytes(range(0xA0, 0xB0))
CREATED = 1795305600000

# Vectorul v1: aceleaşi valori ca în anexa documentului de design. Orice octet schimbat aici e o
# schimbare a formatului de pe disc.
V_PORTABLE_KEY = "8cf0b68c716729fd2f2861bf8232e1411b37dc6eec228c11cba070073072e309"
V_HELLO = (
    "5754533101030000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00748d00a2010000010000000000000052062057e5bb"
    "b03e34bb12c0d05de4340100000001ed9b1d5549111099b6ed05e8bfca4f01400026fb1d7fa012d28c4c5427d099"
    "44e1fe698511c3c9c10b25e9d3e14464345fc93946edfef0bff8ec4f7b57cbeca807f6990734678749226331d245"
    "a7c94f9b9602bd94d0405378ffd3483fbc61aeb726b04000d078ded7e9a4c9494594450817cf72703278eb90a778"
    "effd81bd782c2675d36374f0d948bcea715e31fb16d4e5d5feac48077dc11ced6e0250c07656e5edfeed2c198530"
    "94b2dfe59e48df9db07f26fd87f554dcae070f090acbdb32e522dca80015000000a57126689e1a2bfed1114598dc"
    "410836ab394337a0012000000015adc832ed8bcdf93ea3b74295134b8817cba9764076dfea902388a32d8c32d8")


def make(data, snk=SNK, mk=MK, ck=None, epoch=1):
    buf = io.BytesIO()
    w = wts.Writer(buf, installation_id=INST, epoch=epoch, mk_id=kr.key_id(MK), snk=snk, mk=mk,
                   created_ms=CREATED, _ck=ck)
    for i in range(0, len(data), 300_000):
        w.write(data[i:i + 300_000])
    w.close()
    return buf.getvalue()


def opened(blob, how="local", max_plaintext=wts.MAX_PLAINTEXT):
    r = wts.Reader(io.BytesIO(blob), max_plaintext)
    if how == "local":
        r.unlock(snk=SNK, installation_id=INST)
    else:
        r.unlock(mk=MK)
    return b"".join(r.chunks())


def refused(fn, exc=wts.SnapshotError):
    try:
        fn()
        return False
    except exc:
        return True


def hdr_len(blob):
    n = (blob[5] & 1) + ((blob[5] >> 1) & 1)
    return wts.HDR_LEN + n * wts.ENV_LEN + wts.MAC_LEN


def frames(blob):
    """[(offset, flag, ct_len)] of the body frames."""
    out, off = [], hdr_len(blob)
    while off < len(blob):
        flag, clen = struct.unpack_from("<BI", blob, off)
        out.append((off, flag, clen))
        off += 5 + clen
    return out


def forge(data_chunks, final_count=None, final_total=None, snk=SNK):
    """Container valid până la header, cu cadre construite de mână sub CK cunoscut (pentru
    cazurile pe care Writer-ul nu le poate produce: chunking necanonic, final greşit)."""
    head = make(b"", snk=snk, mk=None, ck=CK)
    head = head[:hdr_len(head)]
    mac = head[-32:]
    aead = AESGCM(kr.derive(CK, wts.LBL_BODY))
    body = b""
    total = 0
    for i, pt in enumerate(data_chunks):
        ct = aead.encrypt(b"\0" * 8 + struct.pack(">I", i), pt, mac + struct.pack(">IB", i, 0))
        body += struct.pack("<BI", 0, len(ct)) + ct
        total += len(pt)
    n = len(data_chunks)
    fin = struct.pack("<QQ", n if final_count is None else final_count, total if final_total is None else final_total)
    ct = aead.encrypt(b"\0" * 8 + struct.pack(">I", n), fin, mac + struct.pack(">IB", n, 1))
    return head + body + struct.pack("<BI", 1, len(ct)) + ct


class CountingSrc(io.BytesIO):
    def __init__(self, b):
        super().__init__(b)
        self.n = 0

    def read(self, n=-1):
        b = super().read(n)
        self.n += len(b)
        return b


def main():
    # 1) vectori
    check("vector: portable KEK = HKDF(MK, wt/v1/portable)", wts.portable_key(MK).hex() == V_PORTABLE_KEY)
    v = make(b"hello", ck=CK)
    check("vector: container 'hello' (local + portable) octet cu octet", v.hex() == V_HELLO, v.hex())
    check("vector: lungime header 60 B, plic 83 B", wts.HDR_LEN == 60 and wts.ENV_LEN == 83)
    check("vector: se deschide local şi portabil", opened(v) == b"hello" and opened(v, "mk") == b"hello")

    # 2) roundtrip multi-chunk, la limitele de chunk
    for size in (0, 1, wts.CHUNK - 1, wts.CHUNK, wts.CHUNK + 1, 2 * wts.CHUNK + 12345):
        data = os.urandom(size)
        b = make(data)
        check(f"roundtrip {size} B (local)", opened(b) == data)
        check(f"roundtrip {size} B (portable)", opened(b, "mk") == data)
        expect_frames = (size + wts.CHUNK - 1) // wts.CHUNK + 1
        check(f"cadre canonice pentru {size} B", len(frames(b)) == expect_frames)

    # 3) cheie de conţinut nouă la fiecare Writer (o reîncercare nu refoloseşte nonce-uri)
    a, b2 = make(b"same"), make(b"same")
    check("CK nou per scriere: plicuri diferite", a[60:60 + 83] != b2[60:60 + 83])
    check("CK nou per scriere: corp diferit", a[hdr_len(a):] != b2[hdr_len(b2):])

    # 4) modificări de un octet: header, plicuri, MAC, cadre, final
    base = make(os.urandom(2 * wts.CHUNK + 777))
    fr = frames(base)
    spots = {
        "magic": 0, "versiune": 4, "flags": 5, "rezervat": 6, "installation id": 9,
        "created": 25, "epoch": 33, "mk_id": 41, "content": 56, "rezervat 3B": 58,
        "plic local (kind)": 60, "plic local (kek_id)": 62, "plic local (wrapped)": 100,
        "plic portabil (wrapped)": 60 + 83 + 50, "MAC header": 60 + 2 * 83 + 3,
        "cadru 0: flag": fr[0][0], "cadru 0: lungime": fr[0][0] + 2, "cadru 0: ct": fr[0][0] + 100,
        "cadru 1: tag": fr[1][0] + 5 + fr[1][2] - 1, "cadru final: ct": fr[-1][0] + 7,
        "cadru final: flag": fr[-1][0],
    }
    for label, off in spots.items():
        t = bytearray(base)
        t[off] ^= 0x01
        check(f"octet modificat refuzat: {label}", refused(lambda: opened(bytes(t))) and
              refused(lambda: opened(bytes(t), "mk")))

    # 5) trunchieri, octeţi în plus, reordonare, cadre lipsă / dublate
    for cut in (10, 59, 60 + 83, hdr_len(base) - 1, hdr_len(base), fr[1][0], fr[-1][0], len(base) - 1):
        check(f"trunchiat la {cut} refuzat", refused(lambda: opened(base[:cut])))
    check("octeţi după final refuzaţi", refused(lambda: opened(base + b"\0")))
    check("al doilea container lipit după final refuzat", refused(lambda: opened(base + base)))
    f0 = base[fr[0][0]:fr[1][0]]
    f1 = base[fr[1][0]:fr[2][0]]
    check("cadre reordonate refuzate",
          refused(lambda: opened(base[:fr[0][0]] + f1 + f0 + base[fr[2][0]:])))
    check("cadru din mijloc lipsă refuzat", refused(lambda: opened(base[:fr[1][0]] + base[fr[2][0]:])))
    check("cadru dublat refuzat", refused(lambda: opened(base[:fr[1][0]] + f0 + base[fr[1][0]:])))
    check("final lipsă refuzat", refused(lambda: opened(base[:fr[-1][0]])))
    check("final dublat refuzat", refused(lambda: opened(base + base[fr[-1][0]:])))
    other = make(os.urandom(2 * wts.CHUNK + 777))
    of = frames(other)
    check("cadru din alt container (alt CK) refuzat",
          refused(lambda: opened(base[:fr[1][0]] + other[of[1][0]:of[2][0]] + base[fr[2][0]:])))
    check("header din alt container refuzat", refused(lambda: opened(other[:hdr_len(other)] + base[hdr_len(base):])))

    # 6) final cu număr / lungime greşite, chunking necanonic, flag de cadru necunoscut
    check("forge valid se deschide (control)", opened(forge([b"x" * wts.CHUNK, b"y"])) == b"x" * wts.CHUNK + b"y")
    check("final cu count greşit refuzat", refused(lambda: opened(forge([b"a"], final_count=2))))
    check("final cu lungime greşită refuzat", refused(lambda: opened(forge([b"a"], final_total=5))))
    check("chunk scurt urmat de alt chunk refuzat", refused(lambda: opened(forge([b"a", b"b"]))))
    bad = bytearray(forge([b"a"]))
    bad[hdr_len(bad)] = 2
    check("flag de cadru 2 refuzat", refused(lambda: opened(bytes(bad))))

    # 7) cheie greşită: SNK, MK, instalare, plic absent
    check("SNK greşit refuzat", refused(lambda: wts.Reader(io.BytesIO(base)).unlock(
        snk=os.urandom(32), installation_id=INST), wts.SnapshotWrongKey))
    check("MK greşit refuzat", refused(lambda: wts.Reader(io.BytesIO(base)).unlock(mk=os.urandom(32)),
                                       wts.SnapshotWrongKey))
    check("local cu alt installation id refuzat (nici un plic utilizabil)",
          refused(lambda: wts.Reader(io.BytesIO(base)).unlock(snk=SNK, installation_id=os.urandom(16)),
                  wts.SnapshotWrongKey))
    loc = make(b"x", mk=None)
    check("container doar local: MK-ul nu-l deschide",
          refused(lambda: wts.Reader(io.BytesIO(loc)).unlock(mk=MK), wts.SnapshotWrongKey))
    port = make(b"x", snk=None)
    check("container doar portabil: SNK nu-l deschide",
          refused(lambda: wts.Reader(io.BytesIO(port)).unlock(snk=SNK, installation_id=INST),
                  wts.SnapshotWrongKey))
    check("container doar portabil: MK-ul îl deschide", opened(port, "mk") == b"x")
    check("Writer fără niciun plic refuzat", refused(lambda: wts.Writer(io.BytesIO(), installation_id=INST,
                                                                          epoch=1, mk_id=kr.key_id(MK))))
    check("Writer cu MK care nu e mk_id-ul din header refuzat",
          refused(lambda: wts.Writer(io.BytesIO(), installation_id=INST, epoch=1, mk_id=b"\0" * 16, mk=MK)))
    check("citire înainte de unlock refuzată", refused(lambda: wts.Reader(io.BytesIO(base)).read(10)))
    r = wts.Reader(io.BytesIO(base))
    r.unlock(mk=MK)
    check("read() nemărginit refuzat", refused(lambda: r.read()))

    # 8) bugete: verificate ÎNAINTE de a citi corpul cadrului
    check("buget de plaintext depăşit refuzat", refused(lambda: opened(base, max_plaintext=wts.CHUNK),
                                                         wts.SnapshotTooLarge))
    h = make(b"", mk=None, ck=CK)[:hdr_len(make(b"", mk=None, ck=CK))]
    huge = h + struct.pack("<BI", 0, 0xFFFFFFFF) + b"\0" * 64
    src = CountingSrc(huge)
    rr = wts.Reader(src)
    rr.unlock(snk=SNK, installation_id=INST)
    check("ct_len uriaş refuzat fără a citi corpul", refused(lambda: rr.read(1)) and src.n <= len(h) + 5,
          src.n)
    src = CountingSrc(h + struct.pack("<BI", 1, 4096) + b"\0" * 4096)
    rr = wts.Reader(src)
    rr.unlock(snk=SNK, installation_id=INST)
    check("final cu lungime greşită refuzat fără a-l citi", refused(lambda: rr.read(1)) and src.n <= len(h) + 5)
    src = CountingSrc(h + struct.pack("<BI", 0, wts.CHUNK + 4096) + b"\0" * 64)
    rr = wts.Reader(src, max_plaintext=10 << 20)
    rr.unlock(snk=SNK, installation_id=INST)
    check("cadru > 1 MiB refuzat fără a-l citi", refused(lambda: rr.read(1)) and src.n <= len(h) + 5)

    # 9) bombă de compresie: oprită după un pas mărginit, nu după ce s-a umflat
    bomb = zlib.compressobj(9, zlib.DEFLATED, 31)
    zb = bomb.compress(b"\0" * (300 << 20)) + bomb.flush()
    src = CountingSrc(zb)
    g = wts.BoundedGunzip(src, max_out=2 << 30)
    out = 0
    try:
        while True:
            b = g.read(1 << 20)
            if not b:
                break
            out += len(b)
        check("bombă (raport) refuzată", False, out)
    except wts.SnapshotTooLarge:
        check("bombă (raport) refuzată", True)
    check("bomba oprită devreme (< 80 MiB decomprimat)", out < 80 << 20, out)
    g = wts.BoundedGunzip(io.BytesIO(zb), max_out=1 << 20, ratio=10 ** 9)
    check("plafon absolut de decompresie", refused(lambda: [g.read(1 << 16) for _ in range(64)],
                                                   wts.SnapshotTooLarge))
    gz2 = zlib.compressobj(6, zlib.DEFLATED, 31)
    one = gz2.compress(b"abc") + gz2.flush()
    check("gzip: date după membru refuzate",
          refused(lambda: [wts.BoundedGunzip(io.BytesIO(one + one), 1 << 20).read(100) for _ in range(3)]))
    check("gzip: trunchiat refuzat", refused(lambda: wts.BoundedGunzip(io.BytesIO(one[:-4]), 1 << 20).read(100)))

    # 10) memorie mărginită în flux: 24 MiB scrişi şi citiţi cu vârf mult sub mărimea arhivei
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "big.wts")
        piece = os.urandom(256 * 1024)
        tracemalloc.start()
        with open(p, "wb") as f:
            w = wts.Writer(f, installation_id=INST, epoch=1, mk_id=kr.key_id(MK), snk=SNK)
            maxbuf = 0
            for _ in range(96):
                w.write(piece)
                maxbuf = max(maxbuf, len(w._buf))
            w.close()
        _, peak_w = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        n = 0
        with open(p, "rb") as f:
            r = wts.Reader(f)
            r.unlock(snk=SNK, installation_id=INST)
            while True:
                b = r.read(64 * 1024)
                if not b:
                    break
                n += len(b)
        _, peak_r = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        check("flux: buffer-ul Writer-ului nu depăşeşte un chunk", maxbuf < wts.CHUNK, maxbuf)
        check("flux: scriere 24 MiB cu vârf < 6 MiB", peak_w < 6 << 20, peak_w)
        check("flux: citire 24 MiB cu vârf < 6 MiB", peak_r < 6 << 20, peak_r)
        check("flux: toţi octeţii citiţi", n == 96 * len(piece))

    # 11) stratul cu parolă (WTBK1 peste WTS1): cere AMBELE secrete
    inner = make(b"secret payload", snk=None)
    outer = backup.encrypt(inner, "parola-lunga-1")
    check("parolă greşită refuzată", refused(lambda: backup.decrypt(outer, "alta-parola-x"), ValueError))
    got = backup.decrypt(outer, "parola-lunga-1")
    check("parola singură nu ajunge (fără MK)",
          refused(lambda: wts.Reader(io.BytesIO(got)).unlock(mk=os.urandom(32)), wts.SnapshotWrongKey))
    check("MK-ul singur nu ajunge (fără parolă)", b"secret payload" not in outer and
          refused(lambda: wts.Reader(io.BytesIO(outer)), wts.SnapshotError))
    check("parolă + MK deschid", opened(got, "mk") == b"secret payload")

    print(f"\n{ok}/{total} passed")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
