"""WTX1 codec (gateway/app/txformat.py, ENCRYPTION-AT-REST.md §12.1): fixed test vectors, an
independent re-derivation of every byte with raw primitives, and the reader rules (succession,
watermark, SEAL, limits, index). Pure: no DB, no gateway process, files only in memory.

Vectorii sunt şi în docs/design/ENCRYPTION-AT-REST.md, "Appendix: Test vectors (v1)": o
schimbare de octet aici e o schimbare de format pe disc, deci trebuie făcută în ambele locuri."""
import hashlib
import hmac
import io
import os
import struct
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))
from app import txformat as tx  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


def raises(fn, exc, reason=None):
    try:
        fn()
    except exc as e:
        return reason is None or getattr(e, "reason", None) == reason
    except Exception as e:  # noqa: BLE001
        print(f"      (unexpected {type(e).__name__}: {e})")
        return False
    return False


# ── fixed inputs (Appendix: Test vectors (v1)) ──
RK = bytes(range(32))
GEN = bytes(range(0x10, 0x20))
SID = bytes.fromhex("00112233445566778899aabbccddeeff")
CREATED = 1795305600000
P0, P1 = b"hello\r\n", b"$ ls\r\n"

V_K_HDR = "98614479f133a6f48d9474d9b18b32c6629e5523d5695e6e06a68fd56dec24c1"
V_K_REC = "cc213e3065fa21cfa24a4d84c53470c50aeea39e37e4c05040cc4cd61ca3e6cc"
V_K_IDX = "e7e93680d905ca244d72c0644a416f312075221060263a1fed418a154d2d763d"
V_PREFIX = ("5754583101010000101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeeff"
            "00748d00a201000000000000000000000000000000000000"
            "bba285dcda26b655a9f417b309c4cda2ff8d317dca59ed35b7278f8612f7d304")
V_REC0 = "010700000000000000783d8f7570bd6378c394721f88db2f579d9755a88dc4e7"
V_REC1 = "01060000000100000056ae7534a5ee15608a5306ee3be7eb3240d764b7d95a"
V_SEAL = ("023000000002000000ecf2a2207beb5e68abd6e36b09d2357a84609519de2ef0f48cba731ebedf29a5"
          "078aeacbe294bb286be63aeb32653aa8fff6ae47f122908b04b44595f25d057a")
V_EMPTY = ("5754583101020000101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeeff"
           "00748d00a201000000000000000000000000000000000000"
           "b431b09f12712547f8d74193369016de7b8b883dad7a3ceeba47335213466b5c"
           "0230000000000000001f49d8f9d7956aadb2c7207cce695467662a48cd8359662e0287d2205e2e1322"
           "c8e8a9dc5f178b3305a6540d98895fe535262c337f54526386817f15925faf89")
# Index (kind 1, data_count 2, intrări pentru ambele recorduri DATA de mai sus).
V_INDEX = ("5754493101010000101112131415161718191a1b1c1d1e1f0200000000000000020000000000000000000000000000006000000000000000"
           "01000000070000000000000080000000000000004d1d98fab4e55f31a7430c27fafb843ac8aeaeb6869afbff8be106b89cbe86e9")


def make(kind=1, payloads=(P0, P1), seal=True, gen=GEN, sid=SID, **kw):
    f = io.BytesIO()
    w = tx.Writer(f, RK, kind=kind, sid=sid, gen_id=gen, created_ms=CREATED, **kw)
    for p in payloads:
        w.append(p)
    info = w.seal() if seal else None
    return f.getvalue(), w, info


def read(blob, data_count, kind=1, gen=GEN, sid=SID, **kw):
    r = tx.Reader(io.BytesIO(blob), RK, kind=kind, sid=sid, gen_id=gen, data_count=data_count, **kw)
    return list(r.records())


def full(blob, kind=1, gen=GEN, sid=SID, **kw):
    return tx.verify_full(io.BytesIO(blob), RK, kind=kind, sid=sid, gen_id=gen, **kw)


print("== vectors ==")
keys = tx.generation_keys(RK, 1, GEN)
check("K_hdr vector", keys.hdr.hex() == V_K_HDR)
check("K_rec vector", keys.rec.hex() == V_K_REC)
check("K_idx vector", keys.idx.hex() == V_K_IDX)
blob, w, info = make()
check("header + hdr_mac vector (96 B)", blob[:96].hex() == V_PREFIX)
check("DATA record seq 0 vector", blob[96:128].hex() == V_REC0)
check("DATA record seq 1 vector", blob[128:159].hex() == V_REC1)
check("SEAL vector", blob[159:].hex() == V_SEAL)
check("total length 232 = 96 + (25+7) + (25+6) + 73", len(blob) == 232 == tx.phys_len(2, 13, True))
check("writer phys_len matches the file", w.phys_len == len(blob) == info.phys_len)
e_blob, _, e_info = make(kind=2, payloads=())
check("zero-DATA generation vector (kind 2, SEAL only)", e_blob.hex() == V_EMPTY)
check("zero-DATA SEAL carries count 0, len 0, SHA-256('')",
      (e_info.data_count, e_info.plain_len, e_info.tags_hash) == (0, 0, hashlib.sha256().digest()))

print("== independent re-derivation with raw primitives ==")


def hk(label, kind):
    info = label + b"\x00" + bytes([kind]) + GEN
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=info).derive(RK)


check("HKDF info = label ‖ 00 ‖ kind ‖ gen_id, salt 32×00",
      (hk(b"wt/v1/hdr", 1), hk(b"wt/v1/rec", 1), hk(b"wt/v1/idx", 1)) == (keys.hdr, keys.rec, keys.idx))
check("kind changes every key", tx.generation_keys(RK, 2, GEN).rec != keys.rec)
check("gen_id changes every key", tx.generation_keys(RK, 1, bytes(16)).hdr != keys.hdr)
hdr = b"WTX1" + bytes([1, 1]) + b"\x00\x00" + GEN + SID + CREATED.to_bytes(8, "little") + bytes(16)
check("header layout: 64 B, created u64 LE", blob[:64] == hdr and len(hdr) == 64)
mac = hmac.new(keys.hdr, hdr, hashlib.sha256).digest()
check("hdr_mac = HMAC-SHA-256(K_hdr, header)", blob[64:96] == mac)
check("nonce = 8×00 ‖ seq u32 BE", tx.nonce(0x01020304) == bytes(8) + b"\x01\x02\x03\x04")
rh = bytes([1]) + (7).to_bytes(4, "little") + (0).to_bytes(4, "little")
check("record head: type u8 | len u32 LE | seq u32 LE", blob[96:105] == rh)
ct = AESGCM(keys.rec).encrypt(bytes(12), P0, mac + rh)
check("record 0 = AES-GCM(nonce(0), AAD = hdr_mac ‖ head)", blob[105:128] == ct)
rh1 = bytes([1]) + (6).to_bytes(4, "little") + (1).to_bytes(4, "little")
check("record 1 nonce counter is big-endian (00..00 00000001)",
      blob[137:159] == AESGCM(keys.rec).encrypt(bytes(11) + b"\x01", P1, mac + rh1))
tags = blob[128 - 16:128] + blob[159 - 16:159]
seal_pt = struct.pack("<QQ", 2, 13) + hashlib.sha256(tags).digest()
sh = bytes([2]) + (48).to_bytes(4, "little") + (2).to_bytes(4, "little")
check("SEAL: seq = data_count, pt = count u64 LE ‖ len u64 LE ‖ SHA-256(tags)",
      blob[159:] == sh + AESGCM(keys.rec).encrypt(bytes(8) + (2).to_bytes(4, "big"), seal_pt, mac + sh))
dec = AESGCM(keys.rec).decrypt(tx.nonce(2), blob[168:], mac + sh)
check("SEAL plaintext round-trips", struct.unpack("<QQ32s", dec) == (2, 13, info.tags_hash))

print("== round trip ==")
recs = read(blob, 2, plain_len=13, hdr_mac=info.hdr_mac)
check("reader returns both DATA records", [r.data for r in recs] == [P0, P1])
check("logical and file offsets", [(r.seq, r.logical_offset, r.file_offset) for r in recs] == [(0, 0, 96), (1, 7, 128)])
check("verify_full ok + matches descriptor values",
      full(blob, data_count=2, plain_len=13, phys_len=232, hdr_mac=info.hdr_mac) == info)
check("zero-DATA generation: verify_full ok", full(e_blob, kind=2) == e_info)
check("zero-DATA generation: reader with watermark 0 returns nothing", read(e_blob, 0, kind=2) == [])
big = os.urandom(150000)
f = io.BytesIO()
bw = tx.Writer(f, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED)
bw.write(big)
check("write() splits into 65 536-byte records", bw.data_count == 3 and read(f.getvalue(), 3)[0].data == big[:65536])
check("write() bytes come back identical", b"".join(r.data for r in read(f.getvalue(), 3)) == big)

print("== header tamper and identity ==")
for name, pos, reason in (("magic", 0, "bad-magic"), ("version", 4, "bad-version"), ("kind", 5, "wrong-kind"),
                          ("reserved u16", 6, "bad-reserved"), ("gen_id", 8, "wrong-gen"), ("sid", 24, "wrong-sid"),
                          ("created", 40, "bad-hdr-mac"), ("reserved 16 B", 50, "bad-reserved"),
                          ("hdr_mac", 70, "bad-hdr-mac")):
    t = bytearray(blob)
    t[pos] ^= 0x01
    check(f"header {name} flipped → {reason}", raises(lambda: read(bytes(t), 2), tx.CorruptError, reason))
check("short header → short-header", raises(lambda: read(blob[:95], 0), tx.CorruptError, "short-header"))
check("expected hdr_mac from descriptor differs → hdr-mac-mismatch",
      raises(lambda: read(blob, 2, hdr_mac=bytes(32)), tx.CorruptError, "hdr-mac-mismatch"))
other_gen = bytes(range(0x20, 0x30))
other_sid = bytes(16)
g2, _, _ = make(gen=other_gen)
check("another generation's file under this gen_id → wrong-gen", raises(lambda: read(g2, 2), tx.CorruptError, "wrong-gen"))
s2, _, _ = make(sid=other_sid)
check("another session's file under this sid → wrong-sid", raises(lambda: read(s2, 2), tx.CorruptError, "wrong-sid"))
k2, _, _ = make(kind=2)
check("the .cast file read as .out → wrong-kind", raises(lambda: read(k2, 2, kind=1), tx.CorruptError, "wrong-kind"))
# Antetul unei generaţii + recordurile alteia (acelaşi sid/kind): tagurile pică, AAD şi cheia diferă.
spliced = blob[:96] + g2[96:]
check("records of another generation spliced under this header → bad-tag",
      raises(lambda: read(spliced, 1), tx.CorruptError, "bad-tag"))
spliced_k = blob[:96] + k2[96:]
check("records of the other kind spliced under this header → bad-tag",
      raises(lambda: read(spliced_k, 1), tx.CorruptError, "bad-tag"))
wrong_rk = bytes(32)
check("wrong RK → bad-hdr-mac", raises(lambda: tx.Reader(io.BytesIO(blob), wrong_rk, kind=1, sid=SID, gen_id=GEN, data_count=2),
                                       tx.CorruptError, "bad-hdr-mac"))

print("== records: reorder, duplicate, drop, tamper ==")
h, r0, r1, sl = blob[:96], blob[96:128], blob[128:159], blob[159:]
check("swapped records → bad-seq", raises(lambda: read(h + r1 + r0 + sl, 2), tx.CorruptError, "bad-seq"))
check("duplicated record → bad-seq", raises(lambda: read(h + r0 + r0 + r1, 2), tx.CorruptError, "bad-seq"))
check("dropped record → bad-seq", raises(lambda: read(h + r1 + sl, 1), tx.CorruptError, "bad-seq"))
# seq rescris în antetul recordului: AAD-ul îl include, deci tagul pică.
r1_as0 = r1[:5] + struct.pack("<I", 0) + r1[9:]
check("record 1 relabelled as seq 0 → bad-tag", raises(lambda: read(h + r1_as0, 1), tx.CorruptError, "bad-tag"))
t = bytearray(blob)
t[110] ^= 0x80
check("ciphertext bit flip → bad-tag", raises(lambda: read(bytes(t), 2), tx.CorruptError, "bad-tag"))
t = bytearray(blob)
t[127] ^= 0x01
check("tag bit flip → bad-tag", raises(lambda: read(bytes(t), 2), tx.CorruptError, "bad-tag"))
t = bytearray(blob)
t[96] = 3
check("unknown record type → bad-type", raises(lambda: read(bytes(t), 2), tx.CorruptError, "bad-type"))
t = bytearray(blob)
t[96:97] = b"\x02"
check("DATA relabelled as SEAL (len 7) → bad-len", raises(lambda: read(bytes(t), 2), tx.CorruptError, "bad-len"))
t = bytearray(blob)
t[97:101] = struct.pack("<I", 0)
check("DATA len 0 → bad-len", raises(lambda: read(bytes(t), 2), tx.CorruptError, "bad-len"))
t = bytearray(blob)
t[97:101] = struct.pack("<I", 65537)
check("DATA len 65 537 → bad-len", raises(lambda: read(bytes(t), 2), tx.CorruptError, "bad-len"))

print("== watermark ==")
live, lw, _ = make(payloads=(P0, P1, b"third"), seal=False)
check("reader stops at the watermark (2 of 3)", [r.data for r in read(live, 2)] == [P0, P1])
check("authentic records after the watermark ignored", [r.data for r in read(live + os.urandom(50), 1)] == [P0])
check("torn last record beyond the watermark ignored", [r.data for r in read(live[:-5], 2)] == [P0, P1])
check("garbage beyond the watermark ignored", [r.data for r in read(live[:128] + b"\xff" * 40, 1)] == [P0])
check("watermark 0 reads nothing even with data present", read(live, 0) == [])
check("truncation inside the watermark → short-record",
      raises(lambda: read(live[:-5], 3), tx.CorruptError, "short-record"))
check("file ends exactly at a record boundary inside the watermark → short-record",
      raises(lambda: read(live[:128], 2), tx.CorruptError, "short-record"))
check("SEAL below the watermark → bad-type (descriptor claims more than the generation has)",
      raises(lambda: read(blob, 3), tx.CorruptError, "bad-type"))
check("descriptor plain_len differs → plain-len-mismatch",
      raises(lambda: read(blob, 2, plain_len=14), tx.CorruptError, "plain-len-mismatch"))
check("negative watermark refused", raises(lambda: read(blob, -1), tx.CorruptError, "bad-watermark"))
check("watermark above the record limit refused",
      raises(lambda: read(blob, tx.MAX_DATA_RECORDS + 1), tx.CorruptError, "bad-watermark"))
check("plain_len impossible for the count refused", raises(lambda: read(blob, 2, plain_len=1), tx.CorruptError, "bad-watermark"))
r = tx.Reader(io.BytesIO(blob), RK, kind=1, sid=SID, gen_id=GEN, data_count=2)
check("read_all = concatenated plaintext", r.read_all(max_bytes=13) == P0 + P1)
check("a reader cannot be consumed twice", raises(lambda: list(r.records()), tx.StateError, "consumed"))

print("== SEAL rules (verify_full) ==")
check("unsealed generation → missing-seal", raises(lambda: full(live), tx.CorruptError, "missing-seal"))
check("byte after SEAL → trailing-bytes", raises(lambda: full(blob + b"\x00"), tx.CorruptError, "trailing-bytes"))
check("second SEAL appended → trailing-bytes", raises(lambda: full(blob + sl), tx.CorruptError, "trailing-bytes"))
check("truncated SEAL → short-record", raises(lambda: full(blob[:-1]), tx.CorruptError, "short-record"))
check("truncated mid-DATA → short-record", raises(lambda: full(blob[:100]), tx.CorruptError, "short-record"))


def forge_seal(count, plain, th, seq=None):
    head = bytes([2]) + struct.pack("<II", 48, count if seq is None else seq)
    return head + AESGCM(keys.rec).encrypt(tx.nonce(count if seq is None else seq),
                                           struct.pack("<QQ", count, plain) + th, mac + head)


check("forged SEAL with wrong count → bad-seal", raises(lambda: full(h + r0 + r1 + forge_seal(3, 13, info.tags_hash, 2)), tx.CorruptError, "bad-seal"))
check("forged SEAL with wrong plain_len → bad-seal", raises(lambda: full(h + r0 + r1 + forge_seal(2, 12, info.tags_hash)), tx.CorruptError, "bad-seal"))
check("forged SEAL with wrong tag hash → bad-seal", raises(lambda: full(h + r0 + r1 + forge_seal(2, 13, bytes(32))), tx.CorruptError, "bad-seal"))
check("valid forge reference passes (the forger is correct)", full(h + r0 + r1 + forge_seal(2, 13, info.tags_hash)).data_count == 2)
check("SEAL after a dropped record → bad-seq", raises(lambda: full(h + r0 + sl), tx.CorruptError, "bad-seq"))
check("descriptor count differs from SEAL → count-mismatch", raises(lambda: full(blob, data_count=3), tx.CorruptError, "count-mismatch"))
check("descriptor phys_len differs → phys-len-mismatch", raises(lambda: full(blob, phys_len=231), tx.CorruptError, "phys-len-mismatch"))
check("descriptor plain_len differs → plain-len-mismatch", raises(lambda: full(blob, plain_len=12), tx.CorruptError, "plain-len-mismatch"))
check("the watermark reader ignores the SEAL itself", [x.data for x in read(blob, 2)] == [P0, P1])

print("== writer state ==")
check("append after SEAL refused", raises(lambda: w.append(b"x"), tx.StateError, "sealed"))
check("second SEAL refused", raises(lambda: w.seal(), tx.StateError, "sealed"))
_, w3, _ = make(seal=False)
check("empty append refused", raises(lambda: w3.append(b""), tx.StateError, "bad-argument"))
check("65 537-byte append refused", raises(lambda: w3.append(b"x" * 65537), tx.StateError, "bad-argument"))
check("65 536-byte append accepted", w3.append(b"x" * 65536) == 2)


class Failing(io.BytesIO):
    def __init__(self):
        super().__init__()
        self.fail = False

    def write(self, b):
        if self.fail:
            return len(b) // 2  # scriere parţială
        return super().write(b)


ff = Failing()
w4 = tx.Writer(ff, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED)
ff.fail = True
check("short write raises ambiguous-write", raises(lambda: w4.append(b"abc"), tx.WriteError, "ambiguous-write"))
ff.fail = False
check("after a write error the writer is broken (no append)", raises(lambda: w4.append(b"abc"), tx.StateError, "broken"))
check("after a write error the writer is broken (no SEAL)", raises(lambda: w4.seal(), tx.StateError, "broken"))
check("limits can only be lowered", raises(lambda: tx.Writer(io.BytesIO(), RK, kind=1, sid=SID, gen_id=GEN, created_ms=0,
                                                              max_records=tx.MAX_DATA_RECORDS + 1), tx.StateError))
check("unknown kind refused", raises(lambda: tx.Writer(io.BytesIO(), RK, kind=3, sid=SID, gen_id=GEN, created_ms=0), tx.StateError))
check("short gen_id refused", raises(lambda: tx.Writer(io.BytesIO(), RK, kind=1, sid=SID, gen_id=b"x" * 15, created_ms=0), tx.StateError))
check("spec limits: 1 048 576 records, 64 GiB", (tx.MAX_DATA_RECORDS, tx.MAX_PLAIN_BYTES) == (1048576, 64 * 2 ** 30))

print("== limits and should_roll ==")
f5 = io.BytesIO()
w5 = tx.Writer(f5, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED, max_records=10)
for i in range(8):
    w5.append(b"r")
check("should_roll false at 80 %", not w5.should_roll())
w5.append(b"r")
check("should_roll true at 90 % of records", w5.should_roll())
w5.append(b"r")
check("append past the record limit refused", raises(lambda: w5.append(b"r"), tx.LimitError))
check("a full generation can still be sealed and verified", (w5.seal(), full(f5.getvalue()).data_count)[1] == 10)
f6 = io.BytesIO()
w6 = tx.Writer(f6, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED, max_plain=100)
w6.append(b"x" * 89)
check("should_roll false at 89 % of bytes", not w6.should_roll())
w6.append(b"x")
check("should_roll true at 90 % of bytes", w6.should_roll())
before = w6.phys_len
check("write() past the byte limit refused, all or nothing", raises(lambda: w6.write(b"x" * 11), tx.LimitError) and w6.phys_len == before)
w6.write(b"x" * 10)
check("writing exactly up to the limit is allowed", w6.plain_len == 100)

print("== H1: single owner, seq reserved before encryption ==")
check("the stateless record encoder is private", not hasattr(tx, "encode_record") and not hasattr(tx, "encode_seal"))


class Reenter(io.BytesIO):
    """write() re-enters append once (the reviewer's reproduction)."""

    def __init__(self, swallow):
        super().__init__()
        self.w, self.swallow, self.inner = None, swallow, None

    def write(self, b):
        if self.w is not None and self.inner is None:
            w, self.w = self.w, None
            try:
                w.append(b"inner")
                self.inner = "accepted"
            except tx.StateError as e:
                self.inner = e.reason
                if not self.swallow:
                    raise
        return super().write(b)


def seqs(blob):
    # Toate seq-urile din flux, parcurse după câmpul len (fără chei): o dublură s-ar vedea aici.
    out, p = [], 96
    while p + 9 <= len(blob):
        _t, n, sq = struct.unpack_from("<BII", blob, p)
        out.append(sq)
        p += 9 + n + 16
    return out


ra = Reenter(swallow=False)
wr = tx.Writer(ra, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED)
ra.w = wr
check("re-entrant append from write() refused with busy (propagated)",
      raises(lambda: wr.append(b"outer"), tx.StateError, "busy") and ra.inner == "busy")
check("…no record written, so no duplicate seq", seqs(ra.getvalue()) == [] and len(ra.getvalue()) == 96)
check("…the outer writer is broken for good", raises(lambda: wr.append(b"x"), tx.StateError, "broken")
      and raises(lambda: wr.seal(), tx.StateError, "broken"))
check("…counters still describe the last full record", (wr.data_count, wr.plain_len, wr.phys_len) == (0, 0, 96))
rs = Reenter(swallow=True)
ws = tx.Writer(rs, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED)
rs.w = ws
check("re-entrant append swallowed by the sink: inner refused, outer completes", ws.append(b"outer") == 0 and rs.inner == "busy")
check("…stream has seq 0 exactly once and reads back",
      seqs(rs.getvalue()) == [0] and [x.data for x in read(rs.getvalue(), 1)] == [b"outer"])
check("…but the writer is now broken for good (strict: any concurrent attempt ends the generation)",
      raises(lambda: ws.append(b"next"), tx.StateError) and seqs(rs.getvalue()) == [0])


class Gate(io.BytesIO):
    def __init__(self):
        super().__init__()
        self.hold = False
        self.entered, self.go = threading.Event(), threading.Event()

    def write(self, b):
        if self.hold:
            self.entered.set()
            self.go.wait(5)
        return super().write(b)


gt = Gate()
wg = tx.Writer(gt, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED)
gt.hold = True
th = threading.Thread(target=lambda: wg.append(b"from-thread"))
th.start()
gt.entered.wait(5)
check("concurrent append from another thread → busy", raises(lambda: wg.append(b"main"), tx.StateError, "busy"))
check("concurrent seal from another thread → busy", raises(lambda: wg.seal(), tx.StateError, "busy"))
check("concurrent write() → busy", raises(lambda: wg.write(b"main"), tx.StateError, "busy"))
gt.hold = False
gt.go.set()
th.join(5)
check("the owner's append completed; refused calls left no trace (one record, seq 0)",
      wg.data_count == 1 and seqs(gt.getvalue()) == [0])
check("…and the writer is broken after the concurrent attempts (strict), so it cannot be sealed",
      raises(lambda: wg.seal(), tx.StateError, "broken"))

print("== M1: write() must confirm the whole buffer ==")


class Sink(io.BytesIO):
    def __init__(self):
        super().__init__()
        self.mode = None

    def write(self, b):
        m = self.mode
        if m == "none":
            return None
        if m == "short":
            super().write(b[:len(b) - 1])
            return len(b) - 1
        if m == "float":
            super().write(b)
            return float(len(b))
        if m == "raise":
            raise OSError("disk gone")
        return super().write(b)


for mode, exc, reason in (("none", tx.WriteError, "ambiguous-write"), ("short", tx.WriteError, "ambiguous-write"),
                          ("float", tx.WriteError, "ambiguous-write"), ("raise", OSError, None)):
    sk = Sink()
    wk = tx.Writer(sk, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED)
    wk.append(P0)
    before = (wk.data_count, wk.plain_len, wk.phys_len)
    sk.mode = mode
    check(f"write() → {mode}: refused", raises(lambda: wk.append(P1), exc, reason))
    check(f"write() → {mode}: counters not advanced past the last full record",
          (wk.data_count, wk.plain_len, wk.phys_len) == before == (1, 7, 128))
    sk.mode = None
    check(f"write() → {mode}: writer broken (append and seal refused)",
          raises(lambda: wk.append(b"x"), tx.StateError, "broken") and raises(lambda: wk.seal(), tx.StateError, "broken"))
sk = Sink()
sk.mode = "none"
check("header write returning None → constructor refuses",
      raises(lambda: tx.Writer(sk, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED), tx.WriteError, "ambiguous-write"))
sk = Sink()
wk = tx.Writer(sk, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED)
wk.append(P0)
sk.mode = "none"
check("SEAL write returning None → refused, not sealed", raises(lambda: wk.seal(), tx.WriteError) and not wk.sealed)
sk.mode = None
check("…and no second SEAL attempt (broken)", raises(lambda: wk.seal(), tx.StateError, "broken"))
sk = Sink()
wk = tx.Writer(sk, RK, kind=1, sid=SID, gen_id=GEN, created_ms=CREATED)
wk.append(P0)
sk.mode = "short"
check("multi-record write() failing mid-way breaks the writer",
      raises(lambda: wk.write(b"z" * 70000), tx.WriteError) and raises(lambda: wk.append(b"x"), tx.StateError, "broken"))

print("== M3: budgets ==")


def reader(b, **kw):
    return tx.Reader(io.BytesIO(b) if isinstance(b, bytes) else b, RK, kind=1, sid=SID, gen_id=GEN, data_count=2, **kw)


check("read_all needs an explicit budget", raises(lambda: reader(blob).read_all(), TypeError))
check("read_all over budget → LimitError", raises(lambda: reader(blob).read_all(max_bytes=12), tx.LimitError, "budget"))


class Counting(io.BytesIO):
    def __init__(self, b):
        super().__init__(b)
        self.reads = 0

    def read(self, n=-1):
        self.reads += 1
        return super().read(n)


cf = Counting(blob)
rc = reader(cf, plain_len=13)
n_hdr = cf.reads
check("read_all refuses from the descriptor's plain_len before reading any record",
      raises(lambda: rc.read_all(max_bytes=12), tx.LimitError, "budget") and cf.reads == n_hdr)
check("read_all with a bool budget refused", raises(lambda: reader(blob).read_all(max_bytes=True), tx.StateError, "bad-argument"))
check("verify_full stops early past the expected data_count",
      raises(lambda: full(h + r0 + r1 + r0 + r1 + sl, data_count=1), tx.CorruptError, "count-mismatch"))
cf = Counting(live + os.urandom(10))
check("verify_full stops at the first record past expected plain_len (no further reads)",
      raises(lambda: tx.verify_full(cf, RK, kind=1, sid=SID, gen_id=GEN, plain_len=7), tx.CorruptError, "plain-len-mismatch")
      and cf.reads == 7)  # antet 1 + 2 recorduri × 3 citiri, nimic după
check("verify_full stops past expected phys_len", raises(lambda: full(blob, phys_len=100), tx.CorruptError, "phys-len-mismatch"))
check("verify_full refuses a bool expected value", raises(lambda: full(blob, data_count=True), tx.CorruptError, "bad-watermark"))


class Greedy(io.BytesIO):
    def read(self, n=-1):
        return super().read(-1)  # dă mai mult decât s-a cerut


check("file object returning more than asked → bad-read", raises(lambda: reader(Greedy(blob)), tx.CorruptError, "bad-read"))

print("== L1: API input types ==")
check("bool kind refused", raises(lambda: tx.generation_keys(RK, True, GEN), tx.StateError, "bad-argument"))
check("bool created_ms refused", raises(lambda: tx.Writer(io.BytesIO(), RK, kind=1, sid=SID, gen_id=GEN, created_ms=True), tx.StateError))
check("bool limit refused",
      raises(lambda: tx.Writer(io.BytesIO(), RK, kind=1, sid=SID, gen_id=GEN, created_ms=0, max_records=True), tx.StateError))
check("int as sid refused (no bytes(16) zero sid)",
      raises(lambda: tx.Writer(io.BytesIO(), RK, kind=1, sid=16, gen_id=GEN, created_ms=0), tx.StateError, "bad-argument"))
check("int as DATA refused (no bytes(n) allocation)", raises(lambda: w3.append(10 ** 9), tx.StateError, "bad-argument"))
check("str as DATA refused", raises(lambda: w3.append("text"), tx.StateError, "bad-argument"))
check("float kind refused", raises(lambda: tx.generation_keys(RK, 1.0, GEN), tx.StateError, "bad-argument"))
check("unhashable kind refused with the module error", raises(lambda: tx.generation_keys(RK, [1], GEN), tx.StateError, "bad-argument"))
check("bool watermark refused", raises(lambda: read(blob, True), tx.CorruptError, "bad-watermark"))
check("int hdr_mac refused (no bytes(32) zero MAC)", raises(lambda: read(blob, 2, hdr_mac=32), tx.StateError, "bad-argument"))
check("int sid on read refused", raises(lambda: read(blob, 2, sid=16), tx.StateError, "bad-argument"))
check("nonce(seq) refuses bool / out of range",
      raises(lambda: tx.nonce(True), tx.StateError) and raises(lambda: tx.nonce(1 << 32), tx.StateError))
check("index entry with bool fields refused on encode",
      raises(lambda: tx.encode_index(RK, kind=1, gen_id=GEN, data_count=3, entries=[tx.IndexEntry(True, 1, 122)]), tx.StateError))
check("index entries that are not entries refused",
      raises(lambda: tx.encode_index(RK, kind=1, gen_id=GEN, data_count=3, entries=[5]), tx.StateError, "bad-argument"))
check("index blob that is an int refused", raises(lambda: tx.verify_index(10 ** 9, RK, kind=1, gen_id=GEN, data_count=3), tx.StateError))
check("GenKeys repr hides the keys", keys.rec.hex() not in repr(keys) and "rec=" not in repr(keys) and "rec=" not in f"{keys}")

print("== index ==")
vidx = tx.encode_index(RK, kind=1, gen_id=GEN, data_count=2, entries=[tx.IndexEntry(0, 0, 96), tx.IndexEntry(1, 7, 128)])
check("index vector (kind 1, data_count 2, both records)", vidx.hex() == V_INDEX)
vbody = (b"WTI1" + bytes([1, 1, 0, 0]) + GEN + struct.pack("<QI", 2, 2) + struct.pack("<IQQ", 0, 0, 96)
         + struct.pack("<IQQ", 1, 7, 128))
check("index vector = layout + HMAC-SHA-256(K_idx, body)", vidx == vbody + hmac.new(keys.idx, vbody, hashlib.sha256).digest())
ents = [tx.IndexEntry(r.seq, r.logical_offset, r.file_offset) for r in read(live, 3)]
idx = tx.encode_index(RK, kind=1, gen_id=GEN, data_count=3, entries=ents)
check("index round trip", tx.verify_index(idx, RK, kind=1, gen_id=GEN, data_count=3) == ents)
check("index size = 36 + 20×n + 32", len(idx) == 36 + 20 * 3 + 32)
check("index for another watermark → stale-index (MAC still ok)", raises(lambda: tx.verify_index(
    tx.encode_index(RK, kind=1, gen_id=GEN, data_count=2, entries=ents[:2]), RK, kind=1, gen_id=GEN, data_count=3),
    tx.CorruptError, "stale-index"))
check("index under another gen_id → bad-index-mac", raises(lambda: tx.verify_index(idx, RK, kind=1, gen_id=other_gen, data_count=3),
                                                             tx.CorruptError, "bad-index-mac"))
check("index under another kind → bad-index-mac", raises(lambda: tx.verify_index(idx, RK, kind=2, gen_id=GEN, data_count=3),
                                                           tx.CorruptError, "bad-index-mac"))
t = bytearray(idx)
t[40] ^= 1
check("entry byte flipped → bad-index-mac", raises(lambda: tx.verify_index(bytes(t), RK, kind=1, gen_id=GEN, data_count=3),
                                                   tx.CorruptError, "bad-index-mac"))
check("truncated index → bad-index-mac", raises(lambda: tx.verify_index(idx[:-1], RK, kind=1, gen_id=GEN, data_count=3),
                                                tx.CorruptError, "bad-index-mac"))
check("index with wrong RK → bad-index-mac", raises(lambda: tx.verify_index(idx, bytes(32), kind=1, gen_id=GEN, data_count=3),
                                                    tx.CorruptError, "bad-index-mac"))
check("sparse index accepted", tx.verify_index(tx.encode_index(RK, kind=1, gen_id=GEN, data_count=3, entries=[ents[0], ents[2]]),
                                               RK, kind=1, gen_id=GEN, data_count=3) == [ents[0], ents[2]])
bad = [tx.IndexEntry(1, 7, 128 + 1)]
check("encode refuses an inconsistent file offset", raises(lambda: tx.encode_index(RK, kind=1, gen_id=GEN, data_count=3, entries=bad), tx.StateError))
check("encode refuses an entry at/after the watermark",
      raises(lambda: tx.encode_index(RK, kind=1, gen_id=GEN, data_count=1, entries=ents[:2]), tx.StateError))
check("encode refuses unordered entries",
      raises(lambda: tx.encode_index(RK, kind=1, gen_id=GEN, data_count=3, entries=[ents[1], ents[0]]), tx.StateError))
# Un index cu MAC valid dar intrări incoerente (cheie compromisă / bug) e prins de verificarea
# structurală de după MAC.
body = idx[:36] + struct.pack("<IQQ", 0, 0, 96) + struct.pack("<IQQ", 1, 7, 999) + idx[76:96]
forged = body + hmac.new(keys.idx, body, hashlib.sha256).digest()
check("authentic MAC but impossible offsets → bad-index", raises(lambda: tx.verify_index(forged, RK, kind=1, gen_id=GEN, data_count=3),
                                                                 tx.CorruptError, "bad-index"))
check("oversized index refused before the MAC", raises(lambda: tx.verify_index(b"\x00" * (36 + 20 * (tx.MAX_DATA_RECORDS + 1) + 32),
                                                                                RK, kind=1, gen_id=GEN, data_count=3),
                                                        tx.CorruptError, "bad-index"))
check("index above max_entries refused by size, before the MAC",
      raises(lambda: tx.verify_index(idx, RK, kind=1, gen_id=GEN, data_count=3, max_entries=2), tx.CorruptError, "bad-index"))
check("index at exactly max_entries accepted", tx.verify_index(idx, RK, kind=1, gen_id=GEN, data_count=3, max_entries=3) == ents)
check("default index budget is 65 536 entries", tx.DEFAULT_MAX_INDEX_ENTRIES == 65536
      and raises(lambda: tx.verify_index(b"\x00" * (36 + 20 * 65537 + 32), RK, kind=1, gen_id=GEN, data_count=3), tx.CorruptError, "bad-index"))
check("max_entries above the record limit refused", raises(lambda: tx.verify_index(idx, RK, kind=1, gen_id=GEN, data_count=3,
                                                                                   max_entries=tx.MAX_DATA_RECORDS + 1), tx.StateError))

print("== RecordCursor (verified forward parse from a record boundary, PR5) ==")
VB = bytes.fromhex(V_PREFIX + V_REC0 + V_REC1 + V_SEAL)
HM = VB[64:96]


def cur(**kw):
    a = dict(kind=1, gen_id=GEN, hdr_mac=HM, data_count=2)
    a.update(kw)
    fp = io.BytesIO(VB)
    fp.seek(a.get("file_offset", tx.PREFIX_LEN))
    return tx.RecordCursor(fp, RK, **a)


c = cur()
r0, r1, end = c.next(), c.next(), c.next()
check("from seq 0: both DATA records with offsets, None at the watermark",
      (r0.data, r0.logical_offset, r1.data, r1.logical_offset, r1.file_offset, end) == (P0, 0, P1, 7, 128, None))
check("seal() after a full parse matches the SEAL", c.seal().phys_len == len(VB))
c = cur(seq=1, logical_offset=7, file_offset=128)
check("from an index entry (seq 1)", c.next().data == P1 and c.next() is None)
check("seal() refused when the parse did not start at seq 0", raises(lambda: c.seal(), tx.StateError))
check("inconsistent start position refused before decrypting", raises(lambda: cur(seq=1, logical_offset=7, file_offset=129), tx.StateError))
check("watermark 1 stops before seq 1 (bytes past it never read)", (lambda c: (c.next(), c.next())[1] is None)(cur(data_count=1)))
check("watermark above the DATA records → SEAL below the watermark refused",
      raises(lambda: [cur(data_count=3).next() for _ in range(3)] and (lambda c: [c.next() for _ in range(3)])(cur(data_count=3)), tx.CorruptError, "bad-type"))
t = bytearray(VB)
t[110] ^= 1
check("tampered record → bad-tag", raises(lambda: tx.RecordCursor(io.BytesIO(bytes(t[96:])), RK, kind=1, gen_id=GEN, hdr_mac=HM, data_count=2).next(),
                                         tx.CorruptError, "bad-tag"))
check("wrong hdr_mac (AAD) → bad-tag", raises(lambda: cur(hdr_mac=bytes(32)).next(), tx.CorruptError, "bad-tag"))
c = cur(data_count=1)
c.next()
check("seal() at a watermark below the real count → DATA where SEAL expected", raises(lambda: c.seal(), tx.CorruptError))

# ── version 2: compressed records (§12.11.14, Appendix "Test vectors (v2)") ──
print("== v2: compressed records ==")
import random  # noqa: E402
import zlib  # noqa: E402

V2_PREFIX = ("5754583102010000101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeeff"
             "00748d00a201000000000000000000000000000000000000"
             "dda37ab88527feb900800c264bee47f9ae79f022ba61d8b3ce05aea584fb31e7")
V2_REC0 = "0311000000000000001758e319d5f8a4775ec94fccae0688673cb85e492f82b4c6c2f883a643d76e12f0"
V2_REC1 = "041000000001000000748e1947fab51f3bace0012ab87070c690dad18b9389712dff3a700b0e2b5af0"
V2_SEAL = ("023000000002000000ecf2a2207beb5e68abd6e36b09d2357ad3da2733712fa18e39c627b63c5e20d8"
           "a67b3c1f05fcb3b7eee7d733e5e0a56858543e78cf7f6d64a7c5f820a938c43a")
V2_INDEX = ("5754493102010000101112131415161718191a1b1c1d1e1f02000000000000000100000000000000"
            "0000000000000000600000000000000049d125530ea11ec7d6e08a784a97b75ce7803fb8b5534e54de6fd37eb69177fb")
# z-ul vectorilor (o codare deflate validă, nu normativă: alt zlib poate da alţi octeţi, la fel de valizi)
V2_Z0, V2_Z1 = "ca48cdc9c9e7e502000000ffff", "5251c829e6e502000000ffff"
VB2 = bytes.fromhex(V2_PREFIX + V2_REC0 + V2_REC1 + V2_SEAL)
HM2 = VB2[64:96]
keys = tx.generation_keys(RK, 1, GEN)
aes = AESGCM(keys.rec)


def make2(payloads=(P0, P1), seal=True, resets=(), gen=GEN, **kw):
    f = io.BytesIO()
    w = tx.Writer(f, RK, kind=1, sid=SID, gen_id=GEN if gen is None else gen, created_ms=CREATED,
                  ver=tx.VERSION_Z, **kw)
    for i, p in enumerate(payloads):
        w.append(p, reset=i in resets)
    info = w.seal() if seal else None
    return f.getvalue(), w, info


def rec2(rtype, seq, ulen, z, hm=HM2):
    return tx._encode_record(aes, hm, rtype, seq, struct.pack("<I", ulen) + z)


def cur2(blob, data_count, **kw):
    a = dict(kind=1, gen_id=GEN, hdr_mac=blob[64:96], data_count=data_count, ver=tx.VERSION_Z)
    a.update(kw)
    fp = io.BytesIO(blob)
    fp.seek(a.get("file_offset", tx.PREFIX_LEN))
    return tx.RecordCursor(fp, RK, **a)


def all2(blob, data_count, **kw):
    c = cur2(blob, data_count, **kw)
    out = []
    while True:
        r = c.next()
        if r is None:
            return out, c
        out.append(r)


# vectori: cititorul îi decodează mereu; writer-ul îi reproduce când zlib-ul local dă acelaşi z
check("v2 header vector (ver byte 2 under hdr_mac)", VB2[:96].hex() == V2_PREFIX)
c = zlib.compressobj(tx.Z_LEVEL, zlib.DEFLATED, tx.Z_WBITS)
same_z = (c.compress(P0) + c.flush(zlib.Z_SYNC_FLUSH)).hex() == V2_Z0 and \
    (c.compress(P1) + c.flush(zlib.Z_SYNC_FLUSH)).hex() == V2_Z1
b2, w2, i2 = make2()
if same_z:
    check("v2 writer reproduces the vectors byte for byte (same deflate output)", b2 == VB2)
else:
    print("  NOTE local zlib emits other (valid) deflate bytes; writer vector skipped")
check("v2 vector: record plaintexts are ulen ‖ z (raw deflate, Z_SYNC_FLUSH)",
      aes.decrypt(tx.nonce(0), VB2[105:105 + 17 + 16], HM2 + VB2[96:105]) == struct.pack("<I", 7) + bytes.fromhex(V2_Z0))
recs, c = all2(VB2, 2, plain_len=13)
check("v2 vector decodes: ZSTART then ZCONT, logical offsets on plaintext",
      [(r.data, r.logical_offset, r.reset) for r in recs] == [(P0, 0, True), (P1, 7, False)])
check("v2 vector: SEAL counts the decompressed length", (c.seal().plain_len, c.seal.__self__.file_offset) == (13, len(VB2)))
check("v2 vector: verify_full with the descriptor's values", tx.verify_full(
    io.BytesIO(VB2), RK, kind=1, sid=SID, gen_id=GEN, data_count=2, plain_len=13, phys_len=len(VB2),
    hdr_mac=HM2, ver=2).phys_len == 252)
check("v2 index vector", tx.encode_index(RK, kind=1, gen_id=GEN, data_count=2,
                                         entries=[tx.IndexEntry(0, 0, 96)], ver=2).hex() == V2_INDEX)
check("v2 index vector verifies (ver 2 expected)", tx.verify_index(bytes.fromhex(V2_INDEX), RK, kind=1, gen_id=GEN,
                                                                   data_count=2, ver=2) == [tx.IndexEntry(0, 0, 96)])
check("v2 index refused where a v1 index is expected (and the reverse)",
      raises(lambda: tx.verify_index(bytes.fromhex(V2_INDEX), RK, kind=1, gen_id=GEN, data_count=2), tx.CorruptError)
      and raises(lambda: tx.verify_index(bytes.fromhex(V_INDEX), RK, kind=1, gen_id=GEN, data_count=2, ver=2), tx.CorruptError))
check("Reader (whole generation) reads v2", [r.data for r in tx.Reader(io.BytesIO(VB2), RK, kind=1, sid=SID, gen_id=GEN,
                                                                     data_count=2, ver=2).records()] == [P0, P1])

# versiunea: header şi descriptor, ambele autentificate
check("v2 file read as v1 → bad-version (expected version from the descriptor)",
      raises(lambda: tx.verify_full(io.BytesIO(VB2), RK, kind=1, sid=SID, gen_id=GEN), tx.CorruptError, "bad-version"))
check("v1 file read as v2 → bad-version", raises(lambda: tx.verify_full(io.BytesIO(VB), RK, kind=1, sid=SID, gen_id=GEN, ver=2),
                                                 tx.CorruptError, "bad-version"))
t = bytearray(VB2)
t[4] = 1
check("header version byte stripped 2 → 1 → bad-hdr-mac (even when v1 is expected)",
      raises(lambda: tx.verify_full(io.BytesIO(bytes(t)), RK, kind=1, sid=SID, gen_id=GEN), tx.CorruptError, "bad-hdr-mac"))
check("unknown version (3) refused as an argument", raises(lambda: tx.Writer(
    io.BytesIO(), RK, kind=1, sid=SID, gen_id=GEN, created_ms=0, ver=3), tx.StateError))
check("bool version refused", raises(lambda: tx.verify_header(VB2[:96], keys, kind=1, sid=SID, gen_id=GEN, ver=True), tx.StateError))

# tipuri de record încrucişate: refuz înainte de decriptare
v1_in_v2 = VB2[:96] + tx._encode_record(aes, HM2, tx.TYPE_DATA, 0, P0)
check("a v1 DATA record inside a v2 generation → bad-type", raises(lambda: cur2(v1_in_v2, 1).next(), tx.CorruptError, "bad-type"))
z0 = bytes.fromhex(V2_Z0)
v2_in_v1 = VB[:96] + tx._encode_record(AESGCM(keys.rec), HM, tx.TYPE_ZSTART, 0, struct.pack("<I", 7) + z0)
check("a v2 ZSTART record inside a v1 generation → bad-type",
      raises(lambda: tx.RecordCursor(io.BytesIO(v2_in_v1[96:]), RK, kind=1, gen_id=GEN, hdr_mac=HM, data_count=1).next(),
             tx.CorruptError, "bad-type"))

# alterări
for pos, what in ((96 + 9 + 3, "ciphertext"), (96 + 1, "length field"), (96, "type byte"), (len(VB2) - 1, "SEAL tag")):
    t = bytearray(VB2)
    t[pos] ^= 1
    check(f"flipped byte ({what}) → refused", raises(lambda t=t: tx.verify_full(io.BytesIO(bytes(t)), RK, kind=1, sid=SID,
                                                                               gen_id=GEN, ver=2), tx.CorruptError))
check("truncated record → short-record", raises(lambda: all2(VB2[:96 + 30], 1), tx.CorruptError, "short-record"))
big = zlib.compressobj(6, zlib.DEFLATED, -15)
zb = big.compress(b"A" * 5000) + big.flush(zlib.Z_SYNC_FLUSH)
check("oversize output (z inflates past ulen) → bad-zlen, output capped at ulen",
      raises(lambda: all2(VB2[:96] + rec2(tx.TYPE_ZSTART, 0, 100, zb), 1), tx.CorruptError, "bad-zlen"))
check("short output (ulen above what z yields) → bad-zlen",
      raises(lambda: all2(VB2[:96] + rec2(tx.TYPE_ZSTART, 0, 8, z0), 1), tx.CorruptError, "bad-zlen"))
fin = zlib.compressobj(6, zlib.DEFLATED, -15)
zf = fin.compress(P0) + fin.flush(zlib.Z_FINISH)
check("a record that ends the deflate stream (BFINAL) → bad-zlen",
      raises(lambda: all2(VB2[:96] + rec2(tx.TYPE_ZSTART, 0, 7, zf), 1), tx.CorruptError, "bad-zlen"))
check("ulen 0 → bad-zlen", raises(lambda: all2(VB2[:96] + rec2(tx.TYPE_ZSTART, 0, 0, z0), 1), tx.CorruptError, "bad-zlen"))
check("ulen above 65 536 → bad-zlen", raises(lambda: all2(VB2[:96] + rec2(tx.TYPE_ZSTART, 0, 65537, z0), 1), tx.CorruptError, "bad-zlen"))
check("z longer than ulen + 64 → bad-zlen (before inflating)",
      raises(lambda: all2(VB2[:96] + rec2(tx.TYPE_ZSTART, 0, 7, z0 + b"\x00" * 60), 1), tx.CorruptError, "bad-zlen"))
check("garbage deflate → bad-deflate", raises(lambda: all2(VB2[:96] + rec2(tx.TYPE_ZSTART, 0, 7, b"\xff" * 12), 1),
                                              tx.CorruptError, "bad-deflate"))
check("a continuation record at seq 0 (no block open) → bad-block",
      raises(lambda: all2(VB2[:96] + rec2(tx.TYPE_ZCONT, 0, 7, z0), 1), tx.CorruptError, "bad-block"))
check("descriptor plain_len below the decoded total → refused while reading",
      raises(lambda: all2(VB2, 2, plain_len=12), tx.CorruptError, "plain-len-mismatch"))
check("descriptor plain_len above the decoded total → refused at the watermark",
      raises(lambda: all2(VB2, 2, plain_len=14), tx.CorruptError, "plain-len-mismatch"))
check("record length past the v2 maximum → bad-len before the body is read",
      raises(lambda: all2(VB2[:96] + struct.pack("<BII", tx.TYPE_ZSTART, tx.MAX_ZREC_LEN + 1, 0), 1), tx.CorruptError, "bad-len"))
check("writer refuses a record length the reader would refuse (encoder bound)",
      raises(lambda: tx._encode_record(aes, HM2, tx.TYPE_ZSTART, 0, b"\x00" * 4), tx.StateError))

# reseturi şi căutare de la fiecare intrare de index
rng = random.Random(7)
words = [b"ls -la", b"drwxr-xr-x", b"root", b"stefan", b"\x1b[0;32m", b"\x1b[0m", b"total 48", b"Makefile",
         b"README.md", b"gateway", b"frontend", b"$ ", b"\r\n", b"  ", b"2026-11-27", b"12:00", b"4096"]


def term_like(n):
    out = bytearray()
    while len(out) < n:
        out += b" ".join(rng.choice(words) for _ in range(rng.randint(3, 12))) + b"\r\n"
    return bytes(out[:n])


data = term_like(3 * 1024 * 1024 + 12345)
pieces = []
pos = 0
while pos < len(data):
    n = rng.choice((1, 7, 300, 4096, 65536, 20000))
    pieces.append(data[pos:pos + n])
    pos += n
starts = {i for i in range(len(pieces)) if i % 37 == 5}
b3, w3, i3 = make2(pieces, resets=starts)
recs, c = all2(b3, w3.data_count, plain_len=len(data))
check("v2 round trip of 3 MiB terminal-like output in mixed record sizes",
      b"".join(r.data for r in recs) == data and c.seal().plain_len == len(data))
check("seq 0, every reset=True record and every 1 MiB block start are ZSTART",
      recs[0].reset and all(recs[i].reset for i in starts)
      and all(any(r.reset for r in recs if lo <= r.logical_offset < lo + tx.Z_BLOCK + tx.MAX_DATA_LEN)
              for lo in range(0, len(data) - tx.Z_BLOCK - tx.MAX_DATA_LEN, tx.Z_BLOCK)))
blocks = [r for r in recs if r.reset]
gap = max(b.logical_offset - a.logical_offset for a, b in zip(blocks, blocks[1:]))
check("no block holds more than Z_BLOCK + one record of plaintext", gap <= tx.Z_BLOCK + tx.MAX_DATA_LEN)
ents = [tx.IndexEntry(r.seq, r.logical_offset, r.file_offset) for r in blocks]
ix = tx.encode_index(RK, kind=1, gen_id=GEN, data_count=w3.data_count, entries=ents, ver=2)
ents = tx.verify_index(ix, RK, kind=1, gen_id=GEN, data_count=w3.data_count, ver=2)
ok_all = True
for e in ents:
    got, _c = all2(b3, w3.data_count, seq=e.seq, logical_offset=e.logical_offset, file_offset=e.file_offset)
    ok_all = ok_all and b"".join(r.data for r in got) == data[e.logical_offset:]
check(f"seeking from every index entry ({len(ents)}) decodes on its own, byte-identical", ok_all and len(ents) >= 5)
cont = next(r for r in recs if not r.reset)
check("a cursor started at a continuation record → bad-block (index may only name block starts)",
      raises(lambda: all2(b3, w3.data_count, seq=cont.seq, logical_offset=cont.logical_offset,
                          file_offset=cont.file_offset), tx.CorruptError, "bad-block"))
check("an index naming a continuation record verifies but the reader refuses it",
      raises(lambda: (lambda e: all2(b3, w3.data_count, seq=e.seq, logical_offset=e.logical_offset,
                                     file_offset=e.file_offset))(tx.verify_index(tx.encode_index(
                                         RK, kind=1, gen_id=GEN, data_count=w3.data_count,
                                         entries=[tx.IndexEntry(cont.seq, cont.logical_offset, cont.file_offset)], ver=2),
                                         RK, kind=1, gen_id=GEN, data_count=w3.data_count, ver=2)[0]), tx.CorruptError, "bad-block"))
check("v2 start position outside the per-record bounds refused before decrypting",
      raises(lambda: cur2(b3, w3.data_count, seq=10, logical_offset=10, file_offset=96 + 10), tx.StateError))
lo, hi = tx.phys_bounds(2, w3.data_count, len(data), True)
check("phys_len of the v2 file lies within phys_bounds", lo <= len(b3) <= hi)
check("phys_bounds v1 is exact", tx.phys_bounds(1, 2, 13, True) == (tx.phys_len(2, 13, True),) * 2)
check("verify_full: a v2 generation with trailing bytes → refused",
      raises(lambda: tx.verify_full(io.BytesIO(b3 + b"\x00"), RK, kind=1, sid=SID, gen_id=GEN, ver=2), tx.CorruptError, "trailing-bytes"))
# incompresibil: o limită de 64 octeţi peste ulen ajunge (zlib alege blocuri stored)
rnd = os.urandom(65536 * 3)
b4, w4, _ = make2([rnd[i:i + 65536] for i in range(0, len(rnd), 65536)] + [os.urandom(1), os.urandom(2)])
got4 = all2(b4, w4.data_count)[0]
check("incompressible input stays within ulen + 64 per record and round-trips",
      b"".join(r.data for r in got4[:3]) == rnd and len(b4) <= tx.phys_bounds(2, 5, len(rnd) + 3, True)[1])
check("incompressible: verify_full passes", tx.verify_full(io.BytesIO(b4), RK, kind=1, sid=SID, gen_id=GEN, ver=2).data_count == 5)

# raport de compresie pe ieşire de terminal (prompturi, ls, culori), cu recorduri de 64 KiB
b5, w5, _ = make2([data[i:i + 65536] for i in range(0, len(data), 65536)])
ratio = len(data) / len(b5)
print(f"      (terminal-like ratio {ratio:.1f}x: {len(data)} → {len(b5)} bytes)")
check("compression ratio on terminal-like output ≥ 5×", ratio >= 5)
v1b, _w, _ = make(payloads=[data[i:i + 65536] for i in range(0, len(data), 65536)])
check("the same stream as v1 is ≥ 5× larger", len(v1b) >= 5 * len(b5))

# writer: o eroare după comprimare strică writer-ul (contextul a avansat)


class Boom:
    def __init__(self):
        self.n = 0
        self.buf = bytearray()

    def write(self, b):
        self.n += 1
        if self.n == 3:
            raise OSError("disk")
        self.buf += b
        return len(b)


bw = tx.Writer(Boom(), RK, kind=1, sid=SID, gen_id=GEN, created_ms=0, ver=2)
bw.append(P0)
check("v2 writer: I/O error after compressing → raised", raises(lambda: bw.append(P1), OSError))
check("v2 writer: broken afterwards (the deflate context moved on)", raises(lambda: bw.append(P1), tx.StateError, "broken"))
check("v2 writer: counters describe the last full record", (bw.data_count, bw.plain_len) == (1, 7))

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
