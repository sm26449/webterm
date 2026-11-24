# Encryption at rest (design, 3.8)

Status: **proposal v4**, revised after three independent reviews (Codex, 2026-11-22; reports kept
locally in `.audit/`). §12 is normative and wins over any earlier wording. No code yet. Owner decision 2026-11-22: session recordings and everything
about clients and users are encrypted at rest, on every installation.

## 1. Where we are today (3.7.1)

Encrypted: individual secrets in SQLite with Fernet (`security.encrypt_secret`): host credentials
and agent tokens, deploy keys, connection credentials, TOTP secrets, SMTP and cloud-backup secrets,
the agent CA private key. Backup downloads and cloud uploads: scrypt + AES-GCM with a passphrase.
Tokens (API, web sessions, share and replay links) are stored as hashes.

Not encrypted:

| Data | Where | Sensitivity |
|---|---|---|
| Session recordings `transcripts/<sid>.out` / `.cast`, `transcripts/arhiva/`, cap temp files | data volume | highest: everything the terminal showed |
| SQLite file + WAL: emails, names, IPs, user agents, titles, notes, command history, audit details, alerts, snippets, host notes and addresses, push subscriptions | data volume | high: personal data and an infrastructure map |
| Scheduled local snapshots `backups/*.wtsnap` and pre-restore `.keep` (DB + vault key + recordings) | data volume | highest: a full plaintext copy |
| `agent-signing.key` (fleet update signing key, when no passphrase), `vapid.key`, `setup-token` | data volume | high (signing key: affects the whole fleet) / medium |

And the Fernet key (`data/secret`) **lives in the same volume** and inside every backup, so today's
field encryption protects only a leaked database file on its own.

## 2. Threat model and what we promise

The promise depends on where the key is. The UI and docs show the installation's **protection
state**, not a blanket claim.

| Capture | Key in the volume (legacy) | Key file on the same host | Key off-host (KMS / mounted at boot from elsewhere) |
|---|---|---|---|
| Copy of the data volume only | readable | **protected** | **protected** |
| A backup / snapshot archive alone (new scheme) | protected | protected | protected |
| That archive **plus** a copy of the volume | readable (the MK is in the volume) | protected | protected |
| Full disk image / VM snapshot of the host | readable | readable (key file is on that disk) | **protected** |
| VM snapshot including RAM, swap, core dumps | readable | readable | readable (key in memory) |
| Code running in the gateway / root on the live host (N1) | readable | readable | readable |

Operator wording: *"A copy of the data volume can be read only with the master key. To be protected
against a copy of the whole host, keep the master key off that host."*

Not protected, stated in the docs: N1 a running compromised gateway or host root; N2 the operator
(self-hosted: the operator is the customer); N3 live traffic (TLS/mTLS); N4 metadata leaks that
survive encryption: file names (session ids), sizes, mtimes and write rhythm, the Traefik edge
files (IPs of connected agents), and with the DB not yet encrypted (phase 1) everything in it; N5
an attacker who can replace the **whole** state (DB, files and index together) with an older
authentic copy (rollback, §4.4); N6 data outside the gateway (managed hosts, the operator's own
exports, proxy logs, the backup provider's own copies).

## 3. Keys

### 3.1 Hierarchy

```
Master key  MK (32 B)                      key file / env / (legacy) volume
 ├─ K_man = HKDF(MK, "wt/v1/manifest")    authenticates keys.wtk (§12.2)
 ├─ K_mw  = HKDF(MK, "wt/v1/mkwrap")       wraps the stable keys below (AES-KWP, §12.2)
 ├─ KWK   random 32 B, stable              wraps the data keys and per-session RKs (AES-KWP)
 ├─ SNK   random 32 B, stable              local snapshot containers (§6, §12.6)
 └─ keyring (in the key manifest file, not in the DB — §12.2):
     ├─ DBK       random 32 B              SQLCipher key (phase 2)
     ├─ FK_legacy = today's data/secret     existing Fernet fields, unchanged until re-encrypted
     ├─ FK        random 32 B              new Fernet fields
     └─ per-session RK (random 32 B, wrapped by KWK, row in `session_keys`)
          └─ per generation: K_hdr, K_rec, K_idx = HKDF(RK, …)    (§12.1)
```

- **Independent keys per purpose**, so DB rekey, Fernet migration and MK rotation are separate
  operations. Today's 32-byte `data/secret` is kept **as a wrapped data key** (`FK_legacy`), not
  re-derived: existing secrets keep decrypting; they are re-encrypted under `FK` by a verified,
  resumable migration and `FK_legacy` is retired only after a full coverage check. The
  forward-token HMAC sub-key keeps its current derivation from `FK_legacy` until then.
- **Envelope binding:** AES-KWP has no AAD, so the key type and the wrapping-key id are wrapped
  together with the key (§12.2); the binding to the installation comes from the manifest MAC, and
  for a session's RK from the descriptor MAC (`rk_hash`). A wrapped key cannot be replayed into
  another slot.
- **Wrapping** is AES-KWP (RFC 5649), deterministic, so there is no wrap nonce budget; the exact
  byte rules are in §12.2.

### 3.2 Sources and the boot contract

Sources, by precedence: `WEBTERM_MASTER_KEY_FILE` (default `/run/secrets/webterm_master_key`) →
`WEBTERM_MASTER_KEY` (env; warned: visible in container metadata) → legacy in-volume key.

- File content is canonical: exactly 32 bytes after base64 decoding; mode must not be group/world
  readable; never logged.
- **An installation manifest** (in the volume: installation id, MK id = HMAC(MK, "id"), keyring
  version, format versions, migration state; authenticated with KWK) is checked **before** the DB
  schema runs and before any writer opens:
  - no manifest, no data → bootstrap (§3.3);
  - manifest present and MK matches → start;
  - a source is **configured but missing or invalid**, or the MK does not match the manifest →
    **refuse to start**, change nothing on disk (no new key, no fallback to another source). The
    error names the problem without the key. Restarting twice with a wrong key leaves the disk
    byte-identical.
- **New installations:** refuse to start without an external key source, unless the operator
  explicitly sets `WEBTERM_KEY_IN_VOLUME=1` (shown as "reduced protection" in System health).
  `install.sh` and the production compose create the key file, so the default path just works.
- **Existing installations (upgrade to 3.8):** start in a declared *legacy* state with the old key;
  `upgrade.sh` creates the key file, the app wraps the keyring under it, verifies, then removes the
  in-volume key (atomic, fsynced). Until then System health shows "master key stored next to the
  data".

### 3.3 Bootstrap, rotation, recovery

- Bootstrap writes the keyring and the manifest atomically (create with restrictive mode at open,
  `O_NOFOLLOW`, fsync of file and directory).
- **MK rotation:** resumable re-wrap of the keyring (dual-read: old and new KWK; single-write: new),
  audited; the old MK is retired only after a coverage check; old MKs needed for older backups are
  listed (ids, dates) so the operator can keep them offline for the backup retention. Rotation does
  **not** help if the old MK was copied together with the old envelopes; the docs say so.
- **Recovery kit:** the MK is never shown by default. An Owner can export it after re-auth (no-store
  response) or the operator exports it with the CLI. The kit holds the installation id, MK id,
  versions, a checksum and validated restore instructions; never sent by email. "Kit confirmed"
  requires a check of the material (paste it back / CLI verify), not just closing a dialog.

## 4. Recordings: segments `WTX1`

### 4.1 Segments and keys (no nonce reuse, by construction)

A recording is a sequence of **segments**. Each writer start (session start, reattach after a
gateway restart, after a crash, after a restore, after the size cap, after any ambiguous write
error) opens a **new segment** with a fresh random 128-bit `gen_id` and its own keys (§12.1). A
segment is never reopened for writing. Nonces, limits and the roll-over point are fixed in §12.1. One writer per (sid, kind) at a time, enforced by a per-session lease
(§5).

### 4.2 Byte format (overview; the bytes are in §12.1)

```
header: see §12.1 (64 B immutable + HMAC-SHA-256, no AEAD nonce spent on it)
record: see §12.1 (type u8 | len u32 LE | seq u32 LE | ciphertext | tag)
seal: a record of type SEAL (superseded in detail by §12.1)
```

- Readers require `seq` to be exactly the previous seq + 1, starting at 0: a moved, duplicated or
  dropped record fails.
- A sealed segment's seal proves completeness (count and length).
- The **live** segment has no seal; the writer publishes a **commit watermark** (seq, plain length)
  in the session's row after each fsync. Records beyond the watermark that fail to authenticate are
  a torn write (dropped silently, the writer has already moved to a new segment); a bad tag or a gap
  *below* the watermark is corruption (error, alarm).
- Once a session has been migrated, a plaintext file for it is **refused** (no downgrade); the
  session row records the format.
- `.cast`: records are opaque bytes; readers rebuild lines across records (bounded line length).
  No event is ever rewritten or split: a download stays byte-identical to the plaintext file.

### 4.3 Index and readers

- An optional `<sid>.<kind>.<gen>.idx` (offsets per record), authenticated with a key derived from
  the segment key, bound to gen_id, record count and the watermark. It is a cache: missing or stale
  → bounded rebuild by scanning record lengths, then authentication before returning bytes.
- All readers go through one module (`txstore.py`) and pin a (segment list, watermark) snapshot at
  open; on a concurrent cap or migration they retry from a fresh snapshot, never mixing inodes.
- Behaviour kept exactly as today (each with a test): fresh attach reads up to the flushed boundary;
  resume/unlock reads from an exact logical offset; preview, search (bounded, last 4 MiB per
  session, 128 MiB per query) and OSC 133 offsets use **logical plaintext offsets**, separate from
  ciphertext positions and from the agent's offsets.
- Downloads keep their RBAC, step-up, token and no-store preconditions. Byte ranges are served on
  plaintext offsets. Public redacted replay keeps redacting on the decrypted stream, across record
  boundaries; caches are keyed by segment, redaction policy and revocation.
- Budgets: index rebuild, concurrent readers and bytes inspected per request are bounded.

### 4.4 Size cap, retention, deletion

- Cap (64 MiB → keep 16 MiB): seal the current segment, copy the kept tail into a new segment
  (decrypt + re-encrypt off the loop), publish, delete the old segments.
- Archive moves sealed segments; purge deletes them.
- **Three different operations, documented separately:** archive (recoverable), logical deletion
  (gone from the app), erasure (RK destroyed). After erasure the recording is unreadable *through the
  app* at once; ciphertext copies in backups taken earlier, WAL pages and storage remanence remain
  until their retention (WAL checkpoint/truncate reduces it; SSD/CoW gives no physical guarantee). A
  **deletion journal** kept outside snapshots is re-applied after any restore, before access is
  served again.
- Rollback of the whole state to an older authentic copy (N5) is not detected in 3.8; detecting it
  would need a monotonic marker outside the volume. Stated as a limit.

### 4.5 Migration of existing recordings

- New segments from the first boot of 3.8. Existing plaintext files are converted in the background,
  under the session lease: closed sessions first, a live session only when it closes or at a writer
  restart (before the writer opens). Write new segment → fsync file and directory → record format in
  the row → delete plaintext. Sessions in `lost` state and archive files without a row are converted
  with an explicit "orphan" key row or reported, never silently dropped.
- Readers accept both formats until a session is marked migrated. Progress and errors in System
  health; any failure leaves the plaintext in place and retries.

## 5. Coordination: per-session lease and dataset manifest

- One in-process lease per sid serialises writer open, cap, migration, archive and purge.
- A backup takes a **coherent dataset generation**: it records, under the leases, the DB snapshot
  (`VACUUM INTO`), the keyring version and the committed (segment, watermark) of every session, then
  copies exactly those committed prefixes off the loop. The manifest binds them together.

## 6. Backups, snapshots and restore

- **One versioned container for every path** (local scheduled snapshot, download, manual and
  scheduled cloud/SFTP/FTPS, pre-restore safety copy): authenticated manifest, a random data key per
  snapshot, that key wrapped by SNK (local) and, for portable backups, also by a **recovery
  envelope** derived from the MK; the passphrase (scrypt) stays as an optional outer layer for
  downloads and remote uploads. Streaming with bounded memory and decompression limits (today's
  path builds the archive in memory).
- **Backups never contain the MK.** They contain the wrapped keyring. Restoring on the same host
  uses the host's MK; on a new host the operator mounts the recovered MK as the key file before
  the restore (or uses an offline CLI import that re-wraps to the new host's MK). The MK is never
  written to `restore-pending/`, headers, audit or markers.
- Restore verifies, **before any swap**: manifest, key ids, DB integrity, that every session row's
  key and segments are present and consistent; then swaps atomically, re-applies the deletion
  journal, then serves.
- Old (pre-3.8) backups: explicit import that converts on the way in, never leaving plaintext in
  staging.

## 7. The database

**Decision proposed: SQLCipher (whole-file, phase 2)**, through the `sqlcipher3` binding
(PyPI 0.6.5 has CPython 3.12 manylinux_2_28 wheels for x86_64 and aarch64, without provenance).
Gate before adoption: pinned hashes or our own reproducible build, an SBOM of the bundled SQLCipher,
SQLite and crypto backend, review of the native components (a Python scanner does not see them),
and smoke + cross-restore tests on amd64 and arm64. If the gate fails, the DB stays out of the
promise and the protection state says so.

Implementation notes: one adapter for gateway, CLI (`admin.py`), backup, restore and verify
(row factory and driver exceptions included); key before first access; check `cipher_version` and an
authenticated read; WAL kept; temp store in memory; migration with `sqlcipher_export` into a keyed
target under exclusivity, then schema, `user_version`, integrity, foreign-key and representative
query checks; no decrypted copy on disk at any step.

Field-level encryption with blind indexes is kept only as a fallback; its leaks (schema,
frequencies, equality) and its per-field rules are listed in the review.

## 8. Invariant (INV-14, to add with the code)

*For every asset declared protected, every persistent copy the gateway produces (including temp
files, snapshots and staging) needs the separately held key; the protection state and coverage are
visible. A missing, wrong or divergent key, an invalid envelope or a tampered committed area causes
a refusal before any mutation or disclosure. Every (key, nonce) pair is unique across all write
attempts, including interrupted ones. A reader accepts only a coherent segment set and its committed
prefix. Limits are explicit for legacy data, whole-state rollback, memory captures and existing
copies; until SQLCipher ships, the DB and WAL are outside this invariant.*

Acceptance tests are **gated by phase** (review V2-L1/V3-L1): in phase 1, protected recordings
and snapshots must not contain the plaintext marker or any key, while DB and WAL are expected to
still contain metadata markers. Summary (the full list is in the review): fixed vectors; crash and resume at every
header/record/index/commit boundary; parallel writers and clones after restore; counter limits;
missing/duplicate/reordered records; cross-sid/kind/gen swaps; stale index and header; downgrade;
byte-identical downloads; cap and migration concurrent with attach, resume, OSC 133, preview, range
download, search and redacted replay; markers absent from DB, WAL, temp, transcripts, archives and
pre-restore files, plus positive opening with the right key and refusal without it; crash, disk-full
and I/O errors during migration, cap, rotation, snapshot and restore; new-host recovery; deletions
re-applied before serving; multi-arch golden files and amd64↔arm64 cross-restore; a wrong key file
leaves the disk unchanged across two restarts.

## 9. Operations and performance

- `install.sh` and the production compose create `secrets/webterm_master_key` and mount it;
  `upgrade.sh` creates it for existing installations and runs the legacy → protected transition.
- System health: protection state per asset (recordings, snapshots, DB, signing key), key source,
  migration and re-wrap progress, recovery-kit status.
- Performance is measured, not promised: flush-to-visible latency, CPU, p95/p99 of tail and search,
  RSS, sparse-output sessions, cap and restore, on amd64 and arm64. Numbers go into this document
  after the gate.

## 10. Phasing

1. **3.8.0:** key hierarchy, manifest and boot contract; `WTX1` segments + migration; the unified
   backup/snapshot container; per-session lease and dataset manifest; deletion journal; protection
   state in System health; INV-14 for recordings and snapshots. The fleet signing key moves under
   the keyring (or keeps its passphrase) in the same release.
2. **3.8.x:** SQLCipher after its supply-chain gate; `vapid.key` and `setup-token` under the keyring.

## 11. Owner decisions (2026-11-22)

1. **New installations without an external key refuse to start**; the explicit opt-out
   `WEBTERM_KEY_IN_VOLUME=1` runs with "reduced protection" shown in System health.
2. **Production keeps the master key in a key file on the same host** (`/opt/webterm/secrets/`,
   mounted read-only): it protects copies of the data volume and of backups; protection against a
   copy of the whole host (key off-host, supplied at boot) stays an option documented for
   operators who need it.
3. **Recovery kit: both** an Owner export in the UI after re-auth (no-store, never by email) and a
   CLI export/verify for operators.
4. **Erasure wording accepted:** "unreadable through the app at once; copies in backups expire with
   their retention", with the deletion journal re-applied after any restore.

## 12. Normative details (v3, after the second review)

These rules close the review's open points. Where an earlier section is vaguer, this one wins.

### 12.1 `WTX1` generation format

- **KDF:** HKDF-SHA-256, salt = 32 zero bytes, `info` = ASCII label ‖ 0x00 ‖ kind (1 B) ‖ gen_id
  (16 B). Labels: `wt/v1/hdr`, `wt/v1/rec`, `wt/v1/idx`. Three independent keys per generation.
- **Header** (fixed 64 B, immutable, never rewritten): `"WTX1"` | ver u8 = 1 | kind u8 | reserved
  u16 = 0 | gen_id 16 B | sid 16 B | created u64 LE (unix ms) | reserved 16 B = 0 ‖ followed by
  `hdr_mac` = HMAC-SHA-256(K_hdr, header 64 B) (32 B). No AEAD is used for the header, so no nonce
  is spent on it.
- **Record:** `type u8` (1 = DATA, 2 = SEAL) | `len u32 LE` (DATA: 1..65 536; SEAL: 48) | `seq u32
  LE` | ciphertext (`len` bytes) | tag 16 B. Cipher AES-256-GCM under K_rec; nonce = 8 zero bytes ‖
  seq as u32 big-endian; AAD = `hdr_mac` ‖ type ‖ len ‖ seq. `seq` starts at 0 and increases by 1
  for every record of either type; readers require exact succession.
- **Limits:** at most 1 048 576 DATA records and 64 GiB of plaintext per generation (far above the
  64 MiB cap, so in practice a generation ends by cap or writer restart); the writer starts a new
  generation at 90 % of either limit and refuses to write past it.
- **SEAL:** written at most once, at `seq = data_count`, plaintext = data_count u64 ‖ plain_len u64
  ‖ SHA-256 over the concatenated DATA tags (32 B). No byte may follow a SEAL. A generation that
  ended by crash is **never sealed afterwards**: its readable prefix is recorded in the descriptor
  as `recovered` (§12.3) and, if it must stay, copied into a new generation by the next cap.
- **Uniqueness:** `gen_id` = 16 bytes from `os.urandom`; the file is created with `O_CREAT|O_EXCL`
  under a name containing the gen_id, after the gen_id is reserved in the descriptor. A collision
  (or an orphan file with that name) aborts and retries with a new id. A clone of a VM with RAM can
  still repeat randomness: stated as a limit (N1-class capture).
- **Index** (`.idx`, a cache): entries (seq u32, logical offset u64, file offset u64), authenticated
  with HMAC-SHA-256 under K_idx over (gen_id, entries, data_count); readers verify it against the
  descriptor and the records they return, and rebuild by a bounded length scan when it is missing
  or stale.
- **Test vectors** (fixed RK, gen_id, plaintexts → exact bytes) are part of the first PR.
- **Implementation notes (first PR, `gateway/app/txformat.py`):** the AAD's record fields are the
  9 record-header bytes exactly as written (type u8, len u32 LE, seq u32 LE). SEAL integers are
  u64 LE; a generation with zero DATA records is valid and sealed with count 0, length 0 and
  SHA-256 of the empty string. Physical length = 96 + Σ(25 + len) over DATA, + 73 once sealed.
  Kinds: 1 = `.out`, 2 = `.cast`; any other value is refused. Index file: `"WTI1"` | ver u8 = 1 |
  kind u8 | reserved u16 = 0 | gen_id 16 B | data_count u64 LE | n u32 LE | n × (seq u32,
  logical offset u64, file offset u64, all LE) | HMAC-SHA-256(K_idx, all bytes before); entries
  strictly ascending, below the watermark, with file offset = 96 + logical offset + 25 × seq.
  Vectors: Appendix "Test vectors (v1)".
- **Writer and budgets (PR1 review fixes):** `Writer` has a single owner: append / write / seal
  take a non-blocking lock, so a concurrent or re-entrant call (e.g. from the file object's
  `write`) is refused with `busy` before any encryption; each seq is reserved before it is
  encrypted, and any failure after a reservation breaks the writer for good. `write()` on the
  file object must return exactly the buffer length; `None`, a short count, a non-int or an
  exception is an ambiguous write: the writer is broken and its counters stay at the last fully
  written record (the integration abandons the generation and keeps only the last durable
  watermark). The record encoder is private. Budgets: `Reader.read_all(max_bytes=…)` has no
  default; `verify_full` stops as soon as the generation exceeds the descriptor's expected
  count / plain length / physical length; `verify_index` refuses more than `max_entries`
  (default 65 536) by size before copying or MAC-ing; types and sizes are checked before any
  copy, and `bool` is never accepted as an integer.

### 12.2 Key manifest, bootstrap and boot

- The keyring lives in **one file**, `DATA_DIR/keys.wtk`, not in the database (the SQLCipher key
  cannot live inside the database it opens). Content: installation id, epoch u64, MK ids it accepts,
  envelopes (`FK_legacy`, `FK`, `DBK`, `KWK`-checks), each envelope = AES-256 key wrap with padding
  (RFC 5649, deterministic, no caller nonce) under KWK, with a type tag; the whole file is
  authenticated by HMAC-SHA-256 under `K_man = HKDF(MK, "wt/v1/manifest")` (a key used for nothing
  else). Per-session RKs stay in the `session_keys` table, wrapped the same way; their binding to
  the session is the descriptor MAC (§12.3).
- **Encodings (first PR, `gateway/app/keyring.py`; draft until §12.8 contracts 1 and 6 are
  closed, nothing is written to disk yet):** MK-level and KWK-level derivations use the §12.1 HKDF
  with `info` = label ‖ 0x00 (`K_man` "wt/v1/manifest", `K_mw` "wt/v1/mkwrap", `K_desc`
  "wt/v1/desc", journal "wt/v1/erase"). Key id = HMAC-SHA-256(key, "id")[:16] (the MK id of §3.2,
  also used for wrapping keys). Envelope = ver u8 = 1 | type u8 | kek_id 16 B | wlen u16 LE = 64 |
  AES-KWP(KEK, ver ‖ type ‖ kek_id ‖ key 32 B); the inner copy binds type and wrapping key, so a
  relabelled or moved envelope fails to unwrap. Types: 1 KWK, 2 SNK (under `K_mw`), 3 FK_legacy,
  4 FK, 5 DBK, 6 RK (under KWK). Manifest = `"WTKM"` | ver u8 = 1 | 3 reserved zero bytes |
  installation id 16 B | epoch u64 LE (≥ 1) | current MK id 16 B | n u8 + retired MK ids
  (strictly ascending, ≤ 64) | n u8 + (len u16 LE ‖ envelope) strictly ascending by type, one per
  type, KWK required, RK forbidden (≤ 16) | HMAC-SHA-256(K_man, all bytes before); at most 16 KiB.
  Decoding compares the MK id first (a wrong key is reported as such), then the MAC, then parses
  strictly (trailing bytes, order, reserved bits refused). The manifest does not yet carry
  migration or format state (§3.2 lists them); that is part of contract 6.
- **Opening (PR1 review fixes):** the only public way to open the manifest is
  `open_keyring_bytes(blob, mk, profile)`: size/type gate → MK id → MAC → strict parse → envelope
  types checked against a `Profile` (required types present; any type outside `allowed`, even
  authentic, is refused) → unwrap of every envelope. The structural parser is private
  (`_parse_manifest_unauthenticated`). Profile `v1` requires KWK and allows SNK, FK_legacy, FK
  and DBK; later phases declare their own profiles. Key bytes never appear in `repr`.
- **Publication:** write `keys.wtk.tmp` (O_EXCL, 0600, O_NOFOLLOW), fsync, rename over `keys.wtk`,
  fsync the directory. One file = one atomic switch; the epoch increases on every change.
- **Routine MK rotation (v4, review V3-H1):** KWK, SNK and the keys derived from KWK (`K_desc`,
  the journal key) are random and **stable**; only their wrapping under `K_mw` and the manifest MAC
  depend on the MK. Rotating the MK therefore publishes **one** new `keys.wtk` (new epoch) with the
  same stable keys re-wrapped under the new MK; descriptors, `session_keys` and the journal do not
  change. Boot needs exactly one MK: the one whose id the current `keys.wtk` names. A crash leaves
  the old or the new file, never a mix. Old MK ids stay listed in the recovery-kit inventory for as
  long as backups made under them are retained.
- **Rotating KWK itself** (after a suspected compromise of the stable keys) is a separate, offline
  maintenance protocol with its own design, out of scope for 3.8.0.
- **Boot order** (before `db.connect`, before any writer): take the **process lock**
  (`fcntl.flock` on `DATA_DIR/.lock`, exclusive, non-blocking: a second process refuses) → resolve
  the key source → verify `keys.wtk` (MAC, MK id, unwrap of every envelope, an open probe of the DB
  in phase 2) → only then schema, migrations and writers.
  - `keys.wtk` absent and the data directory empty → bootstrap.
  - `keys.wtk` absent and data present → refused, except the one declared legacy migration (a 3.7
    volume: `data/secret` present, no `keys.wtk`, format markers all legacy).
  - A source that is **explicitly configured** (`WEBTERM_MASTER_KEY_FILE` or `WEBTERM_MASTER_KEY`
    set) but missing or invalid → refused. The default path (`/run/secrets/webterm_master_key`) only
    counts as configured once a `keys.wtk` exists that expects an external key; a migrated volume
    never falls back to the in-volume key.
- Every Fernet value written from 3.8 carries a version prefix naming its key (`FK` or
  `FK_legacy`); the migration re-encrypts every producer's values (hosts, connections, deploy keys,
  TOTP, SMTP, cloud, agent CA) and the forward-token HMAC moves to a key derived from `FK`.

### 12.3 Descriptors and commit

- Each (sid, kind) has a **descriptor** in the database: version u64, list of generations
  `{gen_id, state live|sealed|recovered, data_count, plain_len, phys_len, hdr_mac}`, the hash of the
  session's wrapped RK, authenticated with HMAC-SHA-256 under `K_desc = HKDF(KWK, "wt/v1/desc")`
  over (installation id, sid, kind, everything above).
- **Encoding (first PR, `gateway/app/txdesc.py`; draft until §12.8 contract 1 is closed):**
  `"WTD1"` | ver u8 = 1 | kind u8 | reserved u16 = 0 | installation id 16 B | sid 16 B (the uuid4
  bytes) | version u64 LE | SHA-256 of the wrapped-RK envelope | n u16 LE (≤ 4096) | n ×
  (gen_id 16 B | state u8: 1 live, 2 sealed, 3 recovered | data_count u64 | plain_len u64 |
  phys_len u64 | hdr_mac 32 B) | HMAC-SHA-256(K_desc, all bytes before). The list is in recording
  order; gen_ids unique; at most one `live`, and only last; phys_len is the committed prefix for
  live and recovered, the whole file with its SEAL for sealed. The decoder also checks the
  expected installation, sid and kind and the RK envelope: `rk_envelope` is a required
  argument, must be an RK envelope, and its hash must match before the generation list is
  parsed (an authentic RK envelope of another session under the same KWK would unwrap fine).
- **Commit order per checkpoint:** append records to `.out` and `.cast` → fsync both → one DB
  transaction that updates both descriptors (`data_count` = exclusive watermark) **and** the
  upstream agent offset. A reader trusts exactly the committed prefix: bytes after it are ignored,
  even if they authenticate; inside it, a short file, a bad tag or a gap is corruption.
- Range reads guarantee the records they return plus the descriptor; the seal (sealed generations)
  or the watermark (live) guarantees completeness of the whole generation.
- Detection limits: a MAC stops edits, not the replay of an older authentic descriptor together
  with older files (whole-state rollback, N5); a monotonic epoch in `keys.wtk` catches a database
  rolled back alone against a newer key file, nothing more.

### 12.4 Concurrency, backup boundary, restore

- Cross-process exclusivity: the boot lock (§12.2). In process, one async **commit barrier** that
  every checkpoint takes for its fsync + DB transaction.
- **Backup boundary:** take the barrier (milliseconds), `VACUUM INTO` the DB, read all descriptors,
  **pin** the listed generations (cap, archive and purge defer unlinking pinned files), release the
  barrier, then copy exactly the committed prefixes off the loop, then unpin. No long lease blocks a
  live terminal.
- **Restore** builds the complete new state in `DATA_DIR/.restore/<epoch>/` (DB, keys.wtk check,
  generations), verifies manifest, key ids, DB integrity and every descriptor against its files,
  applies the erasure journal (§12.5), then switches with a resumable rename journal at the next
  boot (each step idempotent; a crash resumes or rolls back, never a half state). A backup without
  recordings restores with recordings marked "not in this backup"; a pair where `.out` is migrated
  and `.cast` is not is migrated together before the switch; orphans are listed in System health.

### 12.5 Erasure journal

- Order of an erasure: append a tombstone (sid, installation id, monotonic erasure number, time; no
  personal data) to `DATA_DIR/erasures.wtj` (HMAC-chained under `HKDF(KWK, "wt/v1/erase")`, fsync)
  → revoke share and replay links, close open readers of that session (exports already started are
  cut at the next record) and drop caches → destroy the wrapped RK.
- The journal is copied into **every** backup and, when an off-host backup destination is
  configured, also written there as its own small object after each erasure.
- A restore applies the freshest journal it can find (volume, backup, destination). When the
  backup is older than the newest erasure it can see, those erasures are re-applied before access.
  When no source newer than the backup is reachable (restore from a downloaded file on a new host),
  the restore stays in staging until an Owner confirms "erasures after <backup date> cannot be
  re-applied"; the confirmation is audited.

### 12.6 Snapshot container

*Sketch; the normative bytes and rules are §12.10 (where they differ, §12.10 wins: the portable
envelope is keyed by `HKDF(MK, "wt/v1/portable")`, AAD uses the header MAC, and the passphrase is
mandatory for every archive that leaves the host).*

- Header (magic, version, installation id, MK id, created, flags), a random snapshot key wrapped by
  `SNK` (local) and, for portable copies, by the historical **MK id** recorded in the header
  (recovery uses the recovery kit for that MK; kits list every MK id still needed by retained
  backups). No independent recovery key: one root of trust, documented.
- Chunked AES-256-GCM (1 MiB chunks, nonce = chunk counter, AAD = header hash ‖ counter ‖ final
  flag), a final chunk with count and total length; truncated or reordered streams fail.
- The scrypt passphrase layer is required for downloads, optional for configured remote
  destinations (their credentials are a second factor), with bounded scrypt parameters on input.
- The local snapshot is "protected" only when the MK is outside the volume (§2 table).

### 12.7 First pull request (infrastructure, nothing user-visible)

`keys.py` (key manifest, sources, boot contract, process lock, rotation skeleton), `txformat.py`
(the §12.1 codec with test vectors, no writer wired in), descriptor schema + MAC, commit barrier
and pinning API, INV-14 text with its phase matrix, and the contract tests: wrong key twice leaves
the disk byte-identical; crash at every publication point; vectors; succession, seal and watermark
rules. Writers, migration, backups and the protection promise stay **inactive** until the next PRs
pass their own gates.

### 12.8 Open contracts before any writer is enabled (review v3)

Notes from the PR1 code review: any concurrent or re-entrant writer call breaks the writer for good
(the generation ends, a new one starts); `encode_manifest` refuses a manifest its profile would not
open; contract 1 must also prove that every Writer starts on a fresh (RK, kind, gen_id), since the
codec restarts at seq 0; request-path callers pass the descriptor's data_count, plain_len and
phys_len to `verify_full` as budgets.

The first PR ships the codec and internal types only. These contracts must be written here and
reviewed before the PR that turns writers, migration, backup or erasure on:

1. **Publication (V3-H2):** private reservation of a generation (not visible to readers) → create
   with `O_EXCL` → fsync file and directory → publish the authenticated descriptor and the upstream
   offset in one transaction; exact canonical encoding and list order; at most one live generation
   per kind; `phys_len` per state (SEAL included once sealed); a recovery table for every
   interruption point; the rollback guarantee limited to "across a key-manifest epoch change"
   unless a per-commit monotonic marker outside the restorable set is added. *Descriptor part
   designed in §12.11.1 (PR5, under review).*
2. **Range vs full integrity (V3-H3):** a range read is served only through an authentic index bound
   to the exact descriptor, or after a verified parse of the needed prefix within a budget; a full
   integrity check (all records, SEAL, size) is a separate operation (System health, backup,
   restore); rules for `recovered` generations and for a live prefix inside a backup. *Designed in §12.11.2.*
3. **Erasure continuity (V3-H4):** a journal head attested off-volume, backups bound to the head
   they contain, continuity checks, tombstones re-applied at every boot before readers; without
   proof of continuity, the recordings that could be affected stay quarantined; an Owner "recover
   anyway" is a recovery mode with the erasure guarantee suspended, recent re-auth, restricted
   access and audit. *Designed in §12.11.4.*
4. **Snapshot container bytes (V3-M1):** per-envelope algorithm and purpose key, canonical AAD,
   nonce and strict counter, frame and decompression limits, single final frame, new key on retry
   after an ambiguous write; the passphrase is mandatory for downloads and for any remote profile
   that promises "two secrets". *Written in §12.10 (PR3).*
5. **Backup snapshot coherence (V3-M2):** descriptors and keyring read from the same snapshot as the
   DB; the list of mutations that take the barrier; pins on immutable references (fds), released
   only after the worker really finished; all I/O off the loop with budgets. *Designed in
   §12.11.3.*
6. **Boot inventory (V3-M3):** accepted artefacts for bootstrap, lock taken without changing the
   classification, leftover `keys.wtk.tmp` handled, `fstat` on the same fd, regular file, no
   symlinks, canonical encodings and size limits for manifest, envelopes and descriptors; the
   wrong-key refusal also with a restore in staging. *Written in §12.9 (PR2), together with the
   key-manifest part of contract 1; the descriptor part of contract 1 stays open. The boot is not
   wired until the §12.9 "Wiring checklist" is closed (preflight before ensure_dirs/restore,
   3.7 staged restore, FK_legacy proven on real data, FK vs FK_legacy selection, legacy raw-key
   copies, backup/restore on `keys.wtk`).*

### 12.9 Boot and key-manifest publication (PR2)

Normative. Closes contract 6 and the key-manifest part of contract 1 (§12.8). Implemented in
`gateway/app/keys.py`, tested in `tests/keys_test.py`. **Wired into the real boot in PR4**
through `gateway/app/bootkeys.py` (`prepare()`, first step of `main.lifespan`), before anything
that mutates `DATA_DIR` (the clean-up in `config.ensure_dirs()`, the staged-restore apply), before
the vault and before `db.connect`; tested end to end in `tests/boot_keys_test.py`. See the
*Wiring checklist* and its *Status (PR4)* at the end of this section.

**Order.** Lock → inventory → key source → open or create the keyring → (later PRs) restore apply,
schema, writers. Every step before "open" only reads; a refusal at any of them leaves the data
directory as it was (see *Guarantee*).

**Process lock.** `DATA_DIR` is opened once (`O_RDONLY|O_DIRECTORY`; the path itself is the
operator's, already resolved by `config`), and every later name is reached relative to that
descriptor. The lock file is `DATA_DIR/.lock`, opened `O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC`, mode
0600, never truncated and never written; `fstat` on that fd must show a regular file, otherwise
refuse. `fcntl.flock(LOCK_EX|LOCK_NB)`; if it is taken, refuse ("another process holds the data
directory"); never wait, never remove the file. The lock is held for the life of the process (the
lock object keeps both fds open) and is released only by process exit. `.lock` belongs to the
tolerated set below, so taking the lock cannot change the classification.

- **Trust domain.** `flock` excludes only processes that use the same inode and follow the
  protocol: whoever can write `DATA_DIR` can unlink or replace `.lock`, and a second `open` then
  locks another inode. `DATA_DIR` and its ancestors are therefore a trust domain: no other user
  may write them, and no 3.7 process may run against the same volume. Checked at lock time, on
  the fds (refuse, never repair): `fstat(DATA_DIR)` owner = effective uid or root and
  `mode & 0o022 == 0` (`data-dir-bad-owner`, `data-dir-bad-mode`); the same for `.lock`
  (`lock-bad-owner`, `lock-bad-mode`). The ancestors are the operator's (the container image
  creates `/data` 0755 owned by the service user). This does not exclude an actor who is allowed
  to rewrite the volume; it makes an accidental second writer fail loudly.
- **`.lock` is never deleted** — not by boot, restore, backup, clean-up or an operator procedure.
  Deleting it while a process holds it is exactly the race above.
- **Supported filesystems:** local filesystems with working BSD `flock` (ext4, xfs, btrfs, zfs,
  overlayfs on those; a Docker named volume is one of them). NFS and other network or FUSE
  filesystems are not supported for `DATA_DIR`: `flock` there may be emulated per client or be a
  no-op, and the single-writer guarantee would silently disappear.

**Inventory.** The top level of `DATA_DIR` is listed without following symlinks (`lstat`
semantics). Entries are sorted into:

| Group | Entries | Rule |
|---|---|---|
| tolerated | `.lock` and `.maint.lock` (regular files), `lost+found` (directory, content not inspected: it is filesystem metadata and may be unreadable), `transcripts/` that is empty or holds only an empty `arhiva/` (what `config.ensure_dirs` creates before boot) | never change the class |
| key artefacts | `secret` (3.7 key), `keys.wtk`, `keys.wtk.tmp`, `master.key`, `master.key.tmp`, `migrating.wtm` (migration intent), `migrating.wtm.tmp` | each must be a regular file (a symlink, directory, FIFO… → `ambiguous`); `secret` must be exactly 32 bytes |
| staged restore | `restore-pending/` + `.restore-flag` (3.7 mechanism), `.restore/` (3.8, §12.4) | reported as `staged_restore`; never read, applied or removed by PR2 code |
| new-format markers | `erasures.wtj`, `.restore/`, any other top-level name of the reserved `.wt*` family (`*.wtk`, `*.wtj`, `*.wtx`, `*.wtd`…; only `migrating.wtm` is exempt, and only as the pre-commit/migration marker), and under `transcripts/` (its top level and one level of subdirectories such as `arhiva/`) any name ending in `.wtx`, `.wtd`, `.idx` or of the `.wt*` family | data that only exists once a `keys.wtk` exists. 3.7 never writes these names (its snapshots `*.wtsnap` live in `backups/`, not at the top level). A directory in the scanned set that cannot be opened or listed counts as a marker (absence not proven) → refuse |

**The reserved namespace has one definition**, in `keys.py`: `RESERVED_TOP_NAMES`, the `.wt*`
family, `TRANSCRIPT_MARKER_EXT`, `RESERVED_DIR = "transcripts"` and `RESERVED_SCAN_DEPTH = 1`,
behind `is_reserved_name(name, where)` and `find_reserved(dir_fd, exempt)`. The inventory uses it
now; the 3.8 writers, the cap and restore must import it rather than restate it, so nothing can
write a name the inventory does not see. **Supported depth:** the top level of `DATA_DIR`, the top
level of `transcripts/` and one level of subdirectories below it. The storage format creates
nothing deeper; a writer that needs more must raise `RESERVED_SCAN_DEPTH` (and the tests) first.
A reserved name deeper than that is not inspected (tested, so the limit is explicit).
| data | everything else | — |

Classes, first match wins:

1. `protected`: `keys.wtk` is present. Sub-state `in_volume` when `master.key` is present,
   `migrating` when `migrating.wtm` is present (the migration's last steps, below); if `secret` is
   also present, `secret_leftover`. `secret` + `keys.wtk` **without** `migrating.wtm` is not a
   state the migration produces → `ambiguous`.
2. `ambiguous`: no `keys.wtk`, and a new-format marker is present. This scan runs **before** the
   pre-commit exception below, with only `migrating.wtm` exempt (the other artefacts legitimately
   present in that state — `secret`, `keys.wtk.tmp`, `master.key*` for in-volume, `.lock` — are
   not in the namespace). A restore-mixed set (`secret` + marker + tmp + a WTX1 segment or a new
   journal) is refused, never migrated (tested with `transcripts/record.wtx`).
3. `ambiguous`: no `keys.wtk` and `migrating.wtm` present ("migration published but keys.wtk
   missing"), **except** the structurally matching pre-commit state: `secret`, `migrating.wtm` and a
   `keys.wtk.tmp` whose SHA-256 equals the marker's manifest digest, and the marker's secret digest
   equals `secret` → `legacy-3.7` with `migrating` (below). These digests are unauthenticated:
   they only select the class; the migration authenticates the tmp with the MK before any write.
4. `legacy-3.7`: no `keys.wtk`, `secret` present (anything else may be present: DB, transcripts,
   keys, a 3.7 `restore-pending/`).
5. `empty`: nothing outside the tolerated set, `keys.wtk.tmp`, `master.key.tmp` and `master.key`
   (the last three are leftovers of an interrupted bootstrap).
6. `ambiguous`: anything else (data without `secret`, a staged restore without any key, a
   non-regular key artefact). **Refuse**, naming the first offending entry.

**Key sources.** Read from the environment; a variable counts as *set* only when it is non-empty
after stripping whitespace (compose passes `${VAR:-}` as present-and-empty). The strip only
decides *set*: the value used is the original one (a `WEBTERM_MASTER_KEY` with spaces, a CR or a
second newline is refused like the same bytes in a file; a `WEBTERM_MASTER_KEY_FILE` path is not
trimmed either).

| Source | Name in `ProtectionState.source` | Configured when |
|---|---|---|
| `WEBTERM_MASTER_KEY_FILE` (a path) | `file` | set |
| `WEBTERM_MASTER_KEY` (the base64 value; warned: visible in container metadata) | `env` | set |
| `WEBTERM_KEY_IN_VOLUME=1` → `DATA_DIR/master.key` | `volume` | set to `1` (`0` = unset, any other value refused) |
| `/run/secrets/webterm_master_key` | `default-file` | the class is `protected` without `master.key` (the manifest expects an external key), **or** the file exists |

- Exactly one source may be configured. `file` + `env`, or `volume` + any external source → refuse
  ("conflicting key sources"). (Stricter than "precedence": a second configured source is an
  operator error, and guessing which one wins is how a key gets silently replaced.) When no
  explicit source is set, the default path is consulted. The default path is a **fallback**, not
  a configured source: with `WEBTERM_MASTER_KEY_FILE` or `WEBTERM_MASTER_KEY` set, a file at the
  default path is not read and is not a conflict (tested).
- **A key file must not be inside the data tree** (`file`, `default-file`, and the new file of a
  rotation). The location is decided on the **opened file**, not on a second resolution of its
  path: the path is walked from `/` one component at a time, each directory opened with
  `O_RDONLY|O_DIRECTORY|O_NOFOLLOW` relative to the previous fd (pinned), and the key file is
  opened relative to the last one with `O_NOFOLLOW`. The `(st_dev, st_ino)` of every pinned
  directory is compared with the `DATA_DIR` fd's; a match → refuse with `key-in-data-dir`
  ("…is inside the data directory; use `WEBTERM_KEY_IN_VOLUME=1` explicitly"). The same fds are
  then read, so a parent swapped between read and check cannot change the verdict (tested).
  This also catches `DATA_DIR` seen through a bind mount at another path.
  - **Symlink policy: no symlink anywhere in the key path** (an intermediate symlink → `symlink`;
    an intermediate non-directory → `not-regular`; a `..` component → `unreadable`; `ENOENT` on
    any component → `missing`). Docker secrets (`/run/secrets/…`) are bind mounts, not symlinks,
    and pass. Not supported: a key path through `/var/run` (a symlink to `/run`) or a Kubernetes
    secret volume (its `..data` links); point the variable at the real path.
  - **Residual:** a hardlink or a copy of the key file inside the volume, a subdirectory of the
    volume mounted separately elsewhere, or a mount that puts the same storage under two unrelated
    trees are not detectable from here. The real separation is the operator's mount configuration
    (the key on a different mount from the data volume, excluded from every capture of it).
    `ProtectionState.key_location` is therefore
  `external (not verified off-host)` for a file source, `environment` for `env`, `in-volume` for
  `volume`.
- `master.key` present with `WEBTERM_KEY_IN_VOLUME` unset, or with an external source set →
  refuse. `WEBTERM_KEY_IN_VOLUME=1` on a `protected` volume without `master.key` → refuse (a key is
  never generated when a `keys.wtk` exists).
- A configured source that is missing or invalid → refuse. The default path that does not exist on
  an `empty` or `legacy-3.7` volume is "not configured" (an `ENOENT` on `open`, nothing else); a
  default file that exists is configured and must be valid.
- **Reading a key file** (`file`, `default-file`, `volume`; external files through the pinned
  walk above, `master.key` relative to the `DATA_DIR` fd): `open(O_RDONLY|O_NOFOLLOW|O_NONBLOCK|
  O_CLOEXEC)` (a symlink as the final component, or a FIFO, cannot block or redirect); `fstat` on
  that same fd: regular file, owner = effective uid or root, `mode & 0o077 == 0` (neither readable
  nor writable by group/others), size ≤ 256 bytes; then read from that fd at most 257 bytes.
- **Encoding** (file and `WEBTERM_MASTER_KEY` alike): standard base64 with padding, exactly 44
  characters that decode to exactly 32 bytes and re-encode to the same 44 characters (canonical:
  no URL alphabet, no spaces, no unused bits); one trailing `\n` is tolerated, nothing else.
- The key value is never logged and never part of an error: errors carry the source name and a
  reason code (`missing`, `symlink`, `not-regular`, `bad-owner`, `bad-mode`, `too-large`,
  `bad-encoding`, `conflict`, `no-source`, `unreadable`, `key-in-data-dir`).

**Decision table** (after lock and inventory):

| Class | No source | Valid source, MK matches / n.a. | Source configured but invalid / MK mismatch |
|---|---|---|---|
| `empty` | refuse (new installs need an external key or `WEBTERM_KEY_IN_VOLUME=1`) | bootstrap | refuse |
| `legacy-3.7` | start in **legacy** state (3.7 key, nothing written) | migrate (below) | refuse |
| `protected` | refuse (never fall back to `secret` or to another source) | open | refuse |
| `ambiguous` | refuse | refuse | refuse |

**Reading `keys.wtk`.** `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`, `fstat` on the same fd: regular file,
size ≤ 16 KiB (`MAN_MAX_LEN`); then `keyring.open_keyring_bytes(blob, MK, PROFILE_V1)` (MK id, MAC,
strict parse, profile, unwrap of every envelope). Its mode is not checked: it holds nothing usable
without the MK.

**Publication of `keys.wtk`** (`publish_manifest`, only after the MK has been verified, under the
lock):

1. The new bytes must open with the MK they are published for (`open_keyring_bytes`); with a
   predecessor, the installation id must be the same and the epoch strictly greater; without one,
   `keys.wtk` must not exist.
2. A leftover `keys.wtk.tmp` is unlinked (it is never read: `keys.wtk` is the only authority).
3. Create `keys.wtk.tmp` with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode 0600; write
   every byte (a short write loops; a zero or failed write aborts), `fsync`, close.
4. `rename(keys.wtk.tmp, keys.wtk)` (same directory fd).
5. `fsync` the directory.
6. Read `keys.wtk` back through the reader above and require the same bytes, then open it.

| Interrupted | On disk at next boot | Next boot |
|---|---|---|
| before step 3 | old `keys.wtk` (or none), maybe an old tmp | old state; tmp ignored, removed by the next publication |
| during / after step 3 | old `keys.wtk` (or none) + tmp (partial or whole) | same as above |
| after step 4, before 5 | either old + tmp or new (the rename may not be durable) | old or new, each opens with its own MK |
| after step 5 | new | new |

The process lock makes the sequence single-writer; the epoch never goes backwards, because every
publication reads its predecessor through the authenticated opener.

**Outcomes of a refusal** (`BootRefused.kind`; every raw `OSError` from a publication is wrapped
as reason `io-error` with the errno name):

| `kind` | When | On disk | Next boot (right key) |
|---|---|---|---|
| `invalid-key` | preflight: lock, inventory, key source, wrong key, manifest/marker checks, before the first write | unchanged (`.lock` may have been created) — the *Guarantee* below applies | same refusal until the cause is fixed |
| `preflight-io` | a raw `OSError` during preflight (`fstat`, listing or `stat` in the inventory, `flock` other than "taken"), normalised by `boot()` as reason `io-error` with the errno name | unchanged (`.lock` may have been created) — the *Guarantee* applies | same refusal until the I/O problem is fixed |
| `operation-incomplete` | a publication started and failed **before** `keys.wtk`'s rename (unlinking an old tmp, open, write, close, fsync of the tmp, rename; also `master.key` and `migrating.wtm`, which are sub-steps before the manifest) | a tmp may remain; `master.key` / `migrating.wtm` may have been published | recovers: class unchanged (`empty` / `legacy-3.7`, possibly the proven pre-commit state) and the operation runs again |
| `commit-unknown` | `keys.wtk`'s rename happened (this boot or an earlier one) and a later step failed: dir fsync, read-back, re-open, legacy-secret or marker removal, or the dir fsync barrier on resume | the new `keys.wtk` is visible; its durability is unknown | **never undo** the rename; the next boot re-verifies (opens `keys.wtk`, finishes the migration) |

The byte-identical guarantee covers `invalid-key` and `preflight-io` only.

**Bootstrap (`empty`).** With `volume`: reuse a valid leftover `master.key` (same reader as an
external file), otherwise generate 32 random bytes and publish them exactly like `keys.wtk`
(`master.key.tmp`, `O_EXCL|O_NOFOLLOW`, 0600, fsync, rename, fsync dir) **before** the manifest. Then
generate installation id (16 B), KWK, SNK and FK (random), publish epoch 1 with envelopes KWK, SNK
(under `K_mw`) and FK (under KWK), and re-open it from disk. A crash before the manifest's rename
leaves an `empty` volume (with leftovers) and the next boot bootstraps again, reusing `master.key`.

**Legacy migration (`legacy-3.7` + a valid source).** Order:

1. Read `secret` (`O_NOFOLLOW`, `fstat`: regular, exactly 32 bytes); it becomes `FK_legacy`.
2. With `volume`: `master.key` as in bootstrap.
3. Build epoch 1 with KWK, SNK, FK_legacy (= `secret`) and FK; write and fsync `keys.wtk.tmp`
   (publication steps 2–3).
4. **Intent marker.** Publish `migrating.wtm` atomically (`migrating.wtm.tmp`, `O_EXCL`, 0600,
   fsync, rename, fsync dir — this dir fsync also makes the `keys.wtk.tmp` entry durable). Content,
   100 bytes: `"WTM1"` ‖ installation id (16) ‖ MK id (16) ‖ SHA-256(`"wt/v1/migrate-secret\0"` ‖
   `secret`) ‖ SHA-256(manifest bytes). Digests only; the key never appears.
5. `rename(keys.wtk.tmp, keys.wtk)`, fsync dir, read back, re-open with the MK.
6. Require `fk_legacy == secret` (constant time) and the marker to name this manifest
   (installation id, MK id, manifest digest) and this `secret`.
7. **fsync the directory, then** unlink `secret`, then fsync the directory again. A failure
   **before the unlink** (the barrier fsync, the unlink itself) keeps `secret` and the boot refuses
   (`commit-unknown`). A failure of the fsync **after** the unlink also refuses (`commit-unknown`),
   but the durability of the unlink is unknown: `secret` may or may not come back after a power
   loss. Both are safe because the manifest was already synced and `migrating.wtm` is still there:
   the next boot opens `keys.wtk` and the marker drives the resume (steps 7–8 again, or only 8).
8. fsync the directory (the absence of `secret` is durable), unlink `migrating.wtm`, fsync.

The first fsync of step 7 exists for the resume path: after a crash between the rename and its
directory fsync, a restart without power loss sees the new `keys.wtk` in the page cache and could
otherwise delete the only copy of the legacy key before the manifest is durable.

| Interrupted | On disk / class at next boot | Next boot with the right MK | With a wrong / no MK |
|---|---|---|---|
| before 4 (or inside 4, before the marker's rename) | `legacy-3.7`, `secret` intact, maybe tmps | migrates again (a leftover `master.key` is reused) | refuse (wrong) / legacy (no source) |
| after 4, before 5's rename (or the rename not durable) | `secret` + `migrating.wtm` + `keys.wtk.tmp` matching the marker → `legacy-3.7`, `migrating` (pre-commit) | **authenticated resume**, before any write: `keys.wtk.tmp` is opened with the supplied MK (`open_keyring_bytes`: MK id, MAC, profile, unwrap); it must carry the marker's installation id and MK id (= id of the supplied MK), epoch 1, no retired ids, its SHA-256 must equal the marker's digest and its `FK_legacy` must equal `secret` (and the marker's secret digest). Then **exactly that blob** is published: the same fd that re-reads it (same bytes) is fsynced, renamed to `keys.wtk`, dir fsync, read back. No new keyring is generated and neither the marker nor the tmp is removed before the commit, so a crash anywhere leaves this state or step 5's | refuse (`wrong-key` / `migration-unfinished`): never back to the legacy state. A tmp that does not authenticate with the MK the marker names, or any mismatch above → `migration-proof-invalid` (e.g. a marker whose MK id was edited: tested), nothing written |
| after 5, before 7's unlink | `protected` + `migrating` + `secret_leftover` | opens, checks marker and `fk_legacy == secret`, then steps 7–8 | refuse; nothing changes |
| after 7's unlink, before 8's | `protected` + `migrating` | opens, checks the marker, step 8 | refuse |
| after 8 | `protected` | opens | refuse |
| `keys.wtk` lost after 5 (deleted, partial restore) while `migrating.wtm` remains | `ambiguous` ("migration published but keys.wtk missing") | refuse | refuse |

If `secret_leftover` and the opened `fk_legacy` differs from `secret` (or `FK_legacy` is absent,
or the marker's secret digest differs), boot refuses: two different legacy keys mean someone else
wrote one of them. A marker that names another installation, MK id or manifest → refuse
(`migration-marker-mismatch`). A `protected` volume never reads `secret` as a key. Rotation is
refused while `migrating.wtm` or `secret` remains.

**Residual (H2).** The marker defeats the loss of `keys.wtk` alone. Someone who rolls back the
whole volume — `keys.wtk`, `migrating.wtm` and the transcripts markers together — to a 3.7
snapshot gets a genuine 3.7 volume, which boots as legacy (or migrates again). That is the
rollback of §12.8 contract 1 and is only detectable with state kept outside the restorable set.

**In-volume opt-out.** `WEBTERM_KEY_IN_VOLUME=1` keeps the MK in `DATA_DIR/master.key` (0600). The
state is `reduced` ("reduced protection" in System health: the key lives next to the data it
protects); `legacy` means the 3.7 key is still in use; `protected` means an external key.

**MK rotation** (`rotate_master_key`, external sources only; the in-volume mode would need two
files to change together and is refused in 3.8.0). Open the current `keys.wtk` with the old MK;
build epoch + 1 with the same installation id, `mk_id` = id(new MK), retired ids = the old
retired ids ∪ {old MK id} (sorted, the new id removed; more than 64 → refuse), KWK and SNK
re-wrapped under the new `K_mw`, every KWK-wrapped envelope copied byte for byte; publish; re-open
with the new MK. A crash leaves the old file (opens with the old MK only) or the new one (opens with
the new MK only). Boot needs exactly the current MK.

Rotation has two points of administration, the manifest and the external key source, and the
gateway cannot know by itself which one a crash left current. Procedure (offline: gateway
stopped, the rotation command takes the process lock):

1. Generate the new MK and **persist it first** where the gateway will read it (a new file, not
   overwriting the old one). `new_key_file` is a **required** parameter of `rotate_master_key`
   (no in-memory-only rotation). After the old MK has opened the current manifest and before
   anything is published, the file is opened the pinned way (same checks as boot: no symlink in
   the path, owner, mode, encoding, not in the data tree), must equal the new MK
   (`new-key-not-persisted` otherwise), and then **that fd and its directory's fd are fsynced**
   (`new-key-not-durable` on failure; nothing published). A manifest therefore never names a key
   that exists only in the page cache.
2. Keep **both** key files until **a boot with the new key has succeeded**. A crash or a restart
   between the publish and the configuration change leaves either manifest durable; exactly one of
   the two keys opens it.
3. `keys.expected_mk_id(DATA_DIR)` parses `keys.wtk` **without the key** and
   `keys.key_file_mk_id(path)` derives the id of a key file. Both are **unauthenticated
   diagnostics** (no MAC is checked): a CLI must label them so and never use them as an
   authorization, as proof that a key matches, or as proof of durability. Only the authenticated
   open at boot decides. The operator points the configuration at the file whose id matches,
   starts the gateway, and only after that boot succeeds retires the old key file.
4. Retired MK ids: a retired id stays listed while backups made under it may still be restored
   (they carry a manifest that opens only with that MK). Remove an id — and destroy the old key —
   only after every backup made under it has expired; the 64-id bound is a policy limit, not a
   reason to drop ids early.

**Guarantee (wrong or missing key; refusals of kind `invalid-key` or `preflight-io` only).** A boot that refuses
in preflight writes nothing in `DATA_DIR` except creating `.lock` (empty, 0600) and, from the
gateway's boot, `.maint.lock` (empty, 0644; PR4 review M3) if they did not exist. Two refused boots in a row leave, for every
entry under `DATA_DIR` (recursively, symlinks not followed): the same names, types, modes, sizes,
contents and symlink targets — between the state before the first boot and after the second,
`.lock` excepted, and between the first and the second boot with `.lock` included. Timestamps
(`atime`, directory `mtime` after the creation of `.lock`) are not part of the guarantee. This
holds with a staged restore present: staging is never read before the key is verified. Refusals
of kind `operation-incomplete` or `commit-unknown` make no such promise; their recovery is in the
*Outcomes* table above.

**Wiring checklist (must be closed before `keys.boot()` is called by the real boot).** PR2 is
tested in isolation; these are not implemented and each needs its own change and test:

1. **Preflight before every mutation.** `keys.boot()` (lock, inventory, key source, key check)
   runs before `config.ensure_dirs()`'s clean-up and cap trimming, before the staged-restore
   apply and before any other write in `DATA_DIR`; those steps then run under the same lock.
   Directory bootstrap becomes explicit (what may be created before the lock: only `DATA_DIR`
   itself). The lock and directory fds stay open for the lifespan, also on error paths.
2. **3.7 staged restore.** Define what happens to a 3.7 `restore-pending/` + `.restore-flag`
   found on a `legacy-3.7` volume before migration (apply first under the 3.7 key, then migrate;
   or refuse and ask), and never publish the final migrated state before the restore set is
   reconciled.
3. **Prove FK_legacy before publishing.** Migration currently accepts any 32-byte `secret`.
   Before step 4, decrypt representative legacy data with it (a vault entry, the forward HMAC
   check, an encrypted setting) and refuse if nothing verifies; a foreign 32-byte file must not
   become `FK_legacy`.
4. **Key selection by migration state.** The vault and the forward-token HMAC use `FK_legacy`
   for data written before the migration and `FK` for new data; the choice follows the
   migration state recorded in the keyring/DB, never a guess on decryption failure.
5. **Legacy copies of the raw key.** 3.7 snapshots (`backups/*.wtsnap`) and `pre-restore-*.keep`
   files contain the raw `secret`. They are a separate protection and retention item: list them
   in System health, and define when they are re-encrypted or expired after the migration.
6. **Backup and restore move to `keys.wtk` first.** Backup reads `keys.wtk` (never `secret` or
   the MK); restore validates the restored `keys.wtk` with the configured MK before anything is
   replaced, and never deletes `.lock`. *Implemented in §12.10 (PR3), active once a `keys.wtk`
   exists; it still needs the boot to register the keyring provider, call
   `backup.set_boot_protected(True)` from the inventory taken under the process lock (so a
   missing `keys.wtk` is never read as legacy), run `apply_pending_restore` under that lock
   (it may replace `backups/.restore.lock` with it) and re-open `keys.wtk` after an apply.
   `backup.volume_kind()` is the lock-free routing PR3 uses until then.*
7. **Resume and mixed-artefact gate.** Keep the authenticated pre-commit resume tests (edited
   marker MK id + another MK, FK_legacy ≠ `secret`, broken MAC → `migration-proof-invalid`;
   crash at every resume step → same installation) and the mixed-artefact tests (pre-commit +
   a reserved name → refused) green, and add the equivalent for every new bootstrap/migration
   branch: no branch may publish a new keyring over data already protected. Restore and the
   writers import the reserved namespace from `keys.py`.
8. **Location, rotation, process exclusion.** Keep the pinned-fd location check, the rotation
   contract (required `new_key_file`, fsync of the file and its directory, both keys kept until a
   boot with the new one succeeds) and the concurrent path-mutation tests green. The lock and the
   `DATA_DIR` fd stay held through boot **and** restore, and every CLI that writes the same data
   (rotation, restore, maintenance) takes the same lock. No 3.7 process may run against the
   volume concurrently (deploy procedure: stop it before the 3.8 boot).
9. **End-to-end preflight.** One test of the real boot order: staging present, lock taken, a
   wrong key → refused before any clean-up or swap, byte-identical. Distinguish legacy volumes
   **without** any verifiable ciphertext (fresh 3.7 install: an explicit eligibility criterion
   decides whether `secret` may become `FK_legacy`) from volumes **with** encrypted data (prove
   `FK_legacy` by decrypting it, item 3, before publishing). The forward-token HMAC is handled per
   its meaning in the code; if a rotation or the migration changes the key it uses, existing
   forward tokens are invalidated explicitly (and the UI says so), never silently.

**Status (PR4, wiring).** Each item, where it is closed:

1. *Preflight before every mutation:* `bootkeys.prepare()` creates only `DATA_DIR` itself, then
   `keys.boot()` (lock, inventory, key source, key check) runs before `config.ensure_dirs()`,
   `core.cleanup_cap_temps()`, the staged-restore apply, the vault and `db.connect`. The
   `BootResult` (lock + `DATA_DIR` fd) is kept in `bootkeys._boot` for the life of the process,
   also when a later boot step fails; only process exit releases it. Before `boot()` returns, the
   same holds once anything was written (review M2): `ProcessLock.mutated` is set by the first
   publication or removal and by the hook before it applies a 3.7 restore, and from then on
   every error path keeps the lock (and `.maint.lock`) in `keys._RETAINED` until exit, a raw
   `OSError` is reported as `io-error` of kind `operation-incomplete` (never `preflight-io`), and
   an `invalid-key` refusal is re-labelled `operation-incomplete`. A refusal logs one line
   (`boot refused: <reason> (<name>) [kind=…] — <hint>`, never key material) and the lifespan
   raises, so uvicorn exits non-zero. Test: `boot_keys` "main.lifespan" (wrong key + staging +
   cap temporaries → refused, nothing cleaned up, tree unchanged).
2. *3.7 staged restore:* on a `legacy-3.7` volume with a valid source, the `before_migrate` hook
   of `keys.boot()` applies the 3.7 staging first (the 3.7 code, under the process lock, with the
   3.7 key it carries), then proves FK_legacy on the **restored** database, then migrates in the
   same boot. A staging next to `migrating.wtm` is refused (`staged-restore-during-migration`; the
   protocol never produces it). Without a source: exactly 3.7 (apply, then `data/secret`).
   Review M2: with a source, the staging is checked **before** any live mutation
   (`bootkeys.check_legacy_staging`): `.restore-flag` and `restore-pending/` with `webterm.db`
   and a 32-byte `secret`, all plain, else `staged-restore-incomplete` (3.7 would silently skip
   it; a migration does not); and the staged `secret` must prove the staged database by the
   item-3 rule, else `staged-restore-invalid`. Both are `invalid-key` (nothing written). An apply
   that then reports nothing applied is `staged-restore-not-applied` (`operation-incomplete`).
3. *FK_legacy proven:* `bootkeys.prove_legacy_key` first refuses a non-empty `webterm.db-wal`
   or `webterm.db-journal` (`legacy-db-wal-pending`, before any read: an immutable open cannot
   see the WAL, so a checkpointed valid token next to newer or mixed values in the WAL would
   prove nothing; **stop the 3.7 gateway cleanly first**, a clean stop checkpoints the WAL). It
   then opens `webterm.db` read-only and immutable (through the pinned `DATA_DIR` fd; no
   `-wal`/`-shm` is created) and takes a **complete inventory** (review H4,
   `bootkeys.legacy_inventory`): every non-empty row of every `*_encrypted` column of every
   table and every `app_settings` value (a token, or JSON holding one at any depth), streamed,
   with no row limit before classification. Each value is classified: a Fernet token (optionally
   `FKL:`) is a candidate; a placeholder or plain text is not a vault value; `FK:` anywhere →
   `legacy-db-has-protected-values`; a BLOB / number in an `*_encrypted` column, a broken `FKL:`
   value, a damaged token (`gA…` that is not a whole token) or unparseable JSON holding `gA` /
   `FK:` → `legacy-db-unclassifiable` (subject: `table.column` or `app_settings[key]`); more
   than 500 000 vault values → `legacy-db-inventory-too-large`. None of these is ever
   `no-ciphertext`. Only **decryption** has a budget (256 values: the first 4 of each source
   first, then the rest in order), and at least one of them must decrypt with `secret`.
   **Proof rule (owner decision, 2026-11-24): at least one value decrypts.** One decrypting value
   proves the key; the remaining values are not checked one by one, and a value that does not
   decrypt does not refuse the migration when another one does.
   **Eligibility rule:** a database with no encrypted value at all in the complete inventory (or
   no database and no WAL) is eligible, because nothing exists that a wrong key could make
   unreadable. A value already carrying the `FK:` prefix next to a 3.7 `secret` is refused (mixed
   set). Refusals are `invalid-key` (nothing written) unless a 3.7 restore was applied first
   (`operation-incomplete`).
4. *Key selection:* `security.encrypt_secret` writes `FK:` + Fernet(FK) on a protected / reduced
   volume and the unprefixed 3.7 form in the legacy state (so a 3.7 image still reads what a 3.8
   legacy boot wrote); `decrypt_secret` routes by prefix only (`FK:` → FK, `FKL:` or none →
   FK_legacy) and raises `InvalidToken` for a key the process does not hold. The forward-token
   HMAC keeps its derivation from FK_legacy while it exists (no invalidation at migration); a
   fresh protected install derives it from FK. **Later (not in PR4):** a verified, resumable
   re-encryption job moving every FK_legacy value to FK, after which FK_legacy is retired and the
   forward-token key moves to FK with an explicit invalidation of live forward tokens.
5. *Legacy raw-key copies:* System health `crypto.legacy_copies` counts `backups/*.wtsnap` and
   `*.wtsnap.keep` (by name, never opened; `backup.raw_key_copies`) on a protected or reduced
   volume. Retention: unchanged (`.wtsnap` expire after 7 days, `.keep` never automatically).
6. *Backup/restore:* after the key check, `bootkeys.prepare()` registers the keyring provider and
   `backup.set_boot_protected(True)` (the inventory was taken under the lock), runs
   `apply_pending_restore(keys=…)` under the process lock (the `backups/.restore.lock` flock stays
   as the in-process guard for verify/stage), and after an apply re-opens `keys.wtk`
   (`keys.open_protected`) before the vault and `db.connect`.
7. *Resume and mixed-artefact gate:* unchanged and green (`keys` 229/229); the new branches
   (`before_migrate`, the re-open after apply) never publish a keyring: the first reads only, the
   second opens.
8. *Process exclusion:* the gateway holds the lock for its life; `admin.py` takes the same lock
   only for `vacuum` (`NEEDS_LOCK`: it rewrites the whole database file) and refuses with the
   stop / run / start commands while the gateway runs. Owner decision (2026-11-24): the
   break-glass commands that change only database rows (`DB_ONLY`: passwd, disable-2fa,
   logout-all, promote, sso-only, enable) run while the gateway is up, as in 3.7, without the
   lock: none of them encrypts, decrypts, opens `keys.wtk` or publishes anything (argon2 hashes,
   deleted rows, `totp_secret_encrypted` set to NULL). A future command that writes an encrypted
   value must open the keyring read-only through `keys` or join `NEEDS_LOCK`. The read-only
   commands (list, roles, health) do not take `.lock`.
   Review M3: every admin command but `health` opens the database through
   `db.connect_maintenance()`: `mode=rw` (a missing database is refused, never created), no
   SCHEMA / migrations / role seeding / clean-up, no `journal_mode` or other persistent pragma;
   the live schema fingerprint must equal the code's (`db.expected_schema()`, built in memory
   from SCHEMA + MIGRATIONS + `POST_MIGRATION_DDL`), otherwise it refuses ("start the gateway of
   this version once") and closes every connection it opened. Recheck R-M3: the fingerprint
   (`db._schema_of`) holds, per table, the columns with declared type, NOT NULL and primary-key
   position (order-free), every index (explicit: name, uniqueness, partial flag, columns,
   normalized DDL; implicit UNIQUE / PK: origin, uniqueness, columns) and every foreign key, plus
   all triggers and views with their normalized DDL. Second recheck RC-M2: also each column's
   DEFAULT (as written), COLLATE and CHECK clauses and the table-level CHECKs and options (WITHOUT
   ROWID, STRICT), read from the CREATE TABLE text (ALTER TABLE ADD COLUMN appends there), and
   every index through `index_xinfo` (key and auxiliary columns, sort order, collation — two
   implicit UNIQUEs that differ only in collation now differ); DDL is compared by tokens: string
   literals and quoted names exactly, only spacing, comments and keyword case normalised. The
   fingerprint is taken on the connection the command then uses, inside one read transaction
   (BEGIN … COMMIT), so no other file can be swapped in between two opens; the transaction ends
   before the command runs (`passwd` prompts with the connection open; a held lock or snapshot
   would block or fail the gateway's writes), and the schema stays put for the rest of the command
   because of `.maint.lock` (shared; the boot's schema step takes it exclusively). It proves the
   constraints the admin statements rely on (a UNIQUE, a cascade) are there and that nothing extra
   reacts to writes. Limits: it does not validate the rows, does not compare what a collation
   sequence or a CHECK expression means beyond its text, ignores generated / hidden columns, and a
   process that ignores `.maint.lock` is not excluded. Checked once against every historical
   `db.py` in git (48 versions); `tests/schema_history_test.py` keeps three of them (v2.0.0,
   v3.4.0, v3.7.1, from `tests/fixtures/db-schema/`, one with a different column order) as an
   automated regression: each, upgraded through the current `db.connect()`, yields the fresh
   fingerprint. Coordination uses a
   second lock file, `DATA_DIR/.maint.lock` (opened read-only, never written, never removed;
   recheck R-M2: `0600`, owned by the service user — a root `docker exec` that creates it chowns it
   to DATA_DIR's owner before using it and refuses if that fails; a file we own with any group /
   other bit, or without the owner's read bit, is reset to `0600`; group/other access we cannot
   fix, or another non-root owner, is refused; DATA_DIR should be `0750` or stricter): the boot holds it
   **exclusively** from right after `.lock` through the preflight, a 3.7 or 3.8 restore apply,
   a migration and (from `main.lifespan`) `db.connect()`'s schema step, waiting up to 30 s for
   running admin commands (`maintenance-busy` after that); the admin commands take it
   **shared and non-blocking** and refuse (exit 3, "wait until it is up") during those phases.
   With the gateway up the lock is free, so break-glass stays online; `.lock` is never taken by
   them. There is no rotation or restore CLI yet; the host
   `scripts/restore.sh` stops the app and refuses while any container uses the volume, and never
   removes `.lock`. Recheck R-H1: `deploy.sh`, `rollback.sh`, `upgrade.sh`, `backup.sh` and
   `restore.sh` hold one host lock for their whole run (`flock` on `.deploy.lock` in the install
   directory; a child run inherits it, a concurrent one is refused). The pre-3.8 start guard checks
   the `/data` mount of the `app` service in `docker compose config --format json` (a named volume
   with its effective name; a bind directory was read on the host until RC3-M1, below): a divergent `WEBTERM_VOLUME`, an
   existing app container with another `/data` mount, any other mount kind, a second mount under
   `/data`, or an unreadable config are refused; the same plan is re-checked right before `up`
   (rollback.sh restores `.env` / `.prev-image` on a mismatch; upgrade.sh re-checks after syncing
   the host kit). Second recheck RC-H1: only a whole named volume or a plain bind is modelled, so
   `volume.subpath`, a volume definition whose `driver_opts` set `device` or `o=bind`/`rbind` (if
   the volume does not exist yet, compose would create it over a directory nobody listed), bind
   propagation other than `rprivate`, an SELinux relabel option, `consistency`, a read-only
   `/data` and any other unknown key of the mount or of the volume definition are refused (a 3.8
   image is not affected); a bind plan is refused unless the current Docker context (DOCKER_HOST
   included) is a local `unix://` socket, since the directory is listed on this host. The label,
   the plan reader and the volume listing run on the image's ID (`docker image inspect
   {{.Id}}`); the re-check right before `up` requires the same ID and that `services.app.image`
   from the same JSON plan resolves to it (upgrade.sh reads the plan with `WEBTERM_IMAGE` set to
   the target, as deploy.sh will); deploy.sh runs the re-check too. An image missing locally is
   refused, not pulled by the check. Third recheck RC2-H1: the start uses exactly the checked ID
   (`up_checked`: `WEBTERM_IMAGE=<sha256 ID>` for that call only, `up -d --pull never --no-build`;
   `.env` and `.prev-image` keep the human reference, the container's `WEBTERM_IMAGE_REF` the
   label); an `app` service with `build:` or `pull_policy` other than `missing`/`never` is refused
   for every image; rollback.sh confirms the container's image ID; upgrade.sh refuses an unpinned
   (tag) pre-3.8 target, since that target's own deploy.sh starts the reference as given. RC2-H2:
   for a pre-3.8 target the effective `WEBTERM_DATA_DIR` must be `/data` — the service
   `environment` from the JSON plan (`.env` and `env_file` already resolved by compose; an
   unresolved `env_file` or an unreadable environment is refused) and the checked image's
   `Config.Env` (missing, empty or another path = refused). Third recheck RC2-M1: the fingerprint
   also records the `ON CONFLICT` resolution of every NOT NULL / UNIQUE / PRIMARY KEY (column and
   table constraints; an absent clause counts as ABORT, the SQLite default), and table-level
   PRIMARY KEY / UNIQUE constraints with their columns. Fourth recheck RC3-H1: the plan that
   starts is rendered once (`render_checked`: `docker compose --profile '*' config --format json`
   with `WEBTERM_IMAGE=<checked ID>`, all profiles so `--remove-orphans` still knows inactive
   services) into a private `.wt-plan.*` file (0600, install directory, deleted at exit) with
   `services.app.image` set to the ID; `guard_recheck` checks that file and `up_checked` runs
   `docker compose -p <project> -f <that file> up -d --pull never --no-build`. The config is
   rendered twice, with the human reference and with the ID: any difference other than
   `services.app.image` and the `WEBTERM_IMAGE_REF`/`WEBTERM_IMAGE_TAG` environment (e.g. a bind
   source or volume name interpolated from `WEBTERM_IMAGE`), or an `app.image` that does not follow
   `WEBTERM_IMAGE`, is refused for every image. The SSO re-up in deploy.sh re-renders (the OIDC
   settings are new) and accepts only `WEBTERM_OIDC_ISSUER`, `_CLIENT_ID`, `_PROVIDER_NAME` as
   differences from the started plan, then re-checks it. deploy.sh compares the started container's
   image ID with the checked one (no automatic rollback on a mismatch). RC3-M1: for a pre-3.8 or
   unknown target only a whole named volume at `/data` is accepted (listed through the daemon); a
   bind mount is refused, so a bind-mount installation goes back to 3.7 only by restoring the
   pre-migration backup. The lock is per install directory: one kit per volume. An image without a version label is `unknown` (refused on a migrated volume)
   unless the operator sets `WEBTERM_IMAGE_ERA=3.8` for that run; no file-existence heuristic.
   Recheck R-M1: `python3 -m app.hostops stage-restore` exits 0 only when the flag is published and
   its directory fsynced (`backup.StageProgress.committed`), 3 when it refused before the first
   rename into DATA_DIR, 4 when anything failed after that; `restore.sh` restarts the app on 0 and
   3 only and prints recovery steps otherwise. The 3.7 staging path on a pre-3.8 volume uses the same
   discipline: the set extracted and fsynced in a private directory, the old flag removed durably,
   the set renamed into place, the flag written tmp → fsync → rename → directory fsync. Recheck
   R-H2: a pre-3.8 archive's `secret` must decrypt at least one value of the archive's own database
   (`legacyvault.prove_legacy_key` through `backup.prove_legacy_secret`, the same inventory and
   budget as the migration) before anything is published, in `backup.stage_restore` itself and in
   `hostops verify`: the legacy import onto a protected volume through the strict extractor
   (`backup.verify_legacy_import` = the staging's own checks, in a private directory), a 3.7
   restore onto a pre-3.8 volume after the 3.7 checks. `restore.sh` has no separate scanner any
   more. Second recheck RC-M1: one legacy pipeline. `backup.restore_route` decides by the INNER
   format (after the WTBK1 layer) and the target's policy — `wts` (protected only, never with
   `--legacy-import`), `legacy-import` (protected + the flag), `legacy-volume` (pre-3.8 volume,
   without the flag) — and is called by `hostops verify`, `hostops stage-restore` and
   `stage_restore` alike, so a WTBK1 holding a 3.7 tar gets the same verdict in verify (before the
   app is stopped) as in staging. Every 3.7 archive, on either target and in verify, the API
   verify and `_inspect` alike, goes through `_extract_legacy_strict` (verify writes only the
   database; the other members are read and hashed the same way); the strict reader refuses
   non-canonical names (`./x`, `a//b`, `..`, a leading `/`), duplicates and names that differ
   only in case. The staging proves the exact published pair again right before the first change:
   on a legacy volume the staged `webterm.db` with the `secret` read back from the set, for the
   import the staged `webterm.db` with `FK_legacy` read back from the staged keys.wtk. Recheck
   R-L1: `backup.sh` publishes a protected archive from a unique `mktemp` file, `sync`ed, `ln -T`ed
   to its exact final name (RC-L1: a directory that appeared there is refused, nothing is linked
   inside it), then the directory `sync`ed.
9. *End-to-end:* `tests/boot_keys_test.py`: legacy + no key (tree byte-identical but the two lock files, twice);
   legacy + key (migrated, proven, old values decrypt, new values `FK:`, forward tokens still
   valid); foreign `secret` refused unchanged; no ciphertext eligible; WAL pending refused; mixed
   `FK:` refused; protected + wrong / missing key refused unchanged across two boots; 3.8 staging +
   wrong key refused before any swap, right key applies and re-opens; 3.7 staging + key → restore
   then migrate; second process and admin writers refused; empty volume refused without a key,
   `reduced` with `WEBTERM_KEY_IN_VOLUME=1`. Review fixes: placeholders before a ciphertext past
   the old per-column cap, `FK:` past the old 256 cap and in nested settings JSON, a WAL with
   mixed values next to a valid checkpointed token, unclassifiable values and the inventory cap
   (H4); the supported and refused 3.7 layouts (M1, below); an incomplete or self-inconsistent
   3.7 staging refused before any mutation, the lock kept after a failed mutation (M2); admin
   DB-only refused during the exclusive phase, working after it, no schema change, a missing or
   different schema refused, the boot refusing while an admin command holds `.maint.lock` (M3).

**3.7 compatibility, precisely (review M1).** "Nothing written but `.lock`" describes the
**preflight** only: a 3.7 volume without a key source differs from a 3.7 boot by the two empty
lock files `.lock` and `.maint.lock`; after the preflight the boot makes 3.7's own writes (staged
restore apply, `ensure_dirs`, schema, clean-up). Supported 3.7 layouts (legacy without a key,
migrated with one): `secret` (32 bytes) + `webterm.db` with `transcripts/` and `backups/` as plain
directories; `backups/` as a symlink to another disk (checked through the link by
`backup.volume_kind`). `transcripts/` as a symlink to another disk is classified `legacy` by
`keys.classify` **only** on a clean 3.7 set (`secret`, no `keys.wtk`, no `migrating.wtm`, no
`master.key` or temporaries): the target is scanned through the root link with the same reserved
-name rules (`keys.find_reserved_through_link`, shared with `backup.volume_kind`) and the boot logs
a `transcripts-symlink` warning. It boots legacy, but a migration is refused
(`transcripts-symlink`): a protected volume's backup refuses a symlinked transcripts root (§12.10),
so the migrated volume could not be backed up; make it a plain directory first. Refused even
without a key (all `ambiguous`, nothing written but the lock files): a database or other data
without `secret`; `secret` not exactly 32 bytes or not a regular file; any reserved name at the
top level (`erasures.wtj`, `.restore`, the `.wt*` family other than the pre-commit marker) or under
`transcripts/` (also through a symlinked root); a symlink target that cannot be opened or listed;
a symlinked `transcripts/` next to any new-format artefact. A resolved key source (a non-empty
`WEBTERM_MASTER_KEY_FILE` / `WEBTERM_MASTER_KEY`, `WEBTERM_KEY_IN_VOLUME=1`, or a key file present
at the default mount path) means migration, whether or not `.env` was edited recently.

Deployment: `install.sh` / `setup.sh` create `secrets/master-key/master.key` (0400, uid 10001, in a
0700 directory of the same owner) only on a new install with no existing data volume; compose
mounts the directory read-only at `/run/webterm-key` and `WEBTERM_MASTER_KEY_FILE` points at the
file. A directory mount, not a `secrets:` entry, because compose refuses a missing secret file and
an upgraded install has none. `upgrade.sh` never creates a key; the opt-in is in
`docs/INSTALL.md` → *Encryption at rest*. The CI and local gate containers set
`WEBTERM_KEY_IN_VOLUME=1` explicitly (ephemeral volumes).

Verified on a real upgrade (3.7.1 image → 3.8 image, scratch volume, read-only rootfs, dropped
capabilities as in compose): no key → legacy, only `.lock` added by the key code; key file 0400 uid
10001 in a 0700 directory bind-mounted at `/run/webterm-key` → migrated; mode 0444, wrong key, no
key on the migrated volume → refused. **Image rollback residual:** a 3.7 image started on a migrated
volume with no stored host credentials does not refuse (its guard only looks at `hosts`): it creates
a new `data/secret`. 3.8 then refuses the volume as `ambiguous` (`secret` + `keys.wtk` without
`migrating.wtm`) until the operator removes that file; documented in INSTALL.md. 3.7 code cannot be
changed, so this stays an operator rule ("never start 3.7 on a migrated volume").

### 12.10 Snapshot container `WTS1` (PR3)

Normative. Closes §12.8 contract 4 and replaces the sketch of §12.6 where they differ.
Implemented in `gateway/app/snapshot.py` (pure codec: file objects in, file objects out, one
chunk in memory) and `gateway/app/backup.py` (what goes inside, where it is stored, restore);
tested in `tests/snapshot_test.py` and `tests/backup_protected_test.py`. Reachable from
production since PR4 (the boot is wired): a volume becomes *protected* only when `keys.wtk`
exists, and until then every backup path runs the 3.7 code unchanged.

**Which path.** `backup.volume_kind()` (and `is_protected()` on top of it), read without the
process lock: *protected* = `DATA_DIR/keys.wtk` is a regular file **and** `keys.classify` says
`protected` (anything else at that name, or a protected volume `classify` calls ambiguous →
refuse). *Legacy* only when `keys.wtk` is absent **and nothing says the volume was protected**:
no host-keys provider registered and no `set_boot_protected(True)`, no key artefact of the new
format (`migrating.wtm[.tmp]`, `keys.wtk.tmp`, `master.key[.tmp]`), no reserved name
(`keys.find_reserved`), no 3.8 staging (a `restore-pending.<generation>` directory,
`restore-pending/keys.wtk`, `restore-pending/restore.json`, a JSON `.restore-flag`) and no WTS1
file in `backups/` (`*.wts`, `*.wts.keep`, `*.wts.tmp`). Any such trace with `keys.wtk` missing
refuses **every** backup, verify and restore operation (a lost manifest never reopens the tar
with `secret`). The supported 3.7 layouts stay legacy (R-M3): a `backups/` or `transcripts/`
that is a symlink to another disk is checked **through the link** (names only: `*.wts*` in
`backups/`, reserved names in `transcripts/` and one level of real subdirectories below it) and,
when clean, classified legacy with a logged warning; a link whose target cannot be listed is still
a trace (refused). On a protected volume nothing changes: `transcripts/` as a symlink refuses a
backup with transcripts. A clean result is cached per process, keyed by the `stat` of `DATA_DIR`,
`keys.wtk`, the key artefacts, the flag, `restore-pending`, `backups/` and `transcripts[/arhiva]`
(with and without following links) and the boot state, and dropped by every stage and apply; a
refusal is never cached. `keys.classify` (the boot inventory) still reports a symlinked
`transcripts/` as ambiguous; the wiring PR must make the authenticated boot state the authority. `make_snapshot` (the 3.7 tar) runs only on a
volume classified legacy. *Legacy*: exactly the 3.7 code (`make_snapshot`, `.wtsnap`, WTBK1
downloads, `restore-pending/` with `secret`). *Protected*: WTS1 everywhere below. The
keyring comes from the caller (`keys=HostKeys(ring, mk)`) or from a provider the boot registers
(`backup.set_host_keys_provider`); with neither, every protected operation is refused — never
treated as legacy. On each use `keys.wtk` is re-read and must open with that MK and show the same
installation id and epoch as the keyring the process holds.

**Bytes** (little-endian unless marked BE):

| Part | Bytes |
|---|---|
| header (60 B) | `"WTS1"` · ver u8 = 1 · flags u8 (bit 0 local envelope, bit 1 portable envelope, others 0, at least one set) · reserved u16 = 0 · installation id 16 B · created u64 (ms) · keyring epoch u64 · MK id 16 B (the host's current MK when written; the portable envelope is under it) · content u8 = 1 (`tar.gz`) · reserved 3 B = 0 |
| envelopes | local first (if flagged), then portable; each 83 B: kind u8 (1 local, 2 portable) · kek_id 16 B · wlen u16 = 64 · AES-KWP(KEK, `"WTS1"` ‖ kind ‖ kek_id ‖ CK 32 B) |
| header MAC | HMAC-SHA-256(HKDF(CK, `"wt/v1/snap-hdr"`), header ‖ envelopes), 32 B |
| frames | flag u8 (0 data, 1 final) · ct_len u32 · AES-256-GCM(HKDF(CK, `"wt/v1/snap-body"`)) ciphertext ‖ 16 B tag |
| end | nothing after the final frame |

- **Keys.** CK, the content key, is 32 random bytes, new for every `Writer` (one per snapshot).
  Local KEK = `SNK` (it wraps nothing else); kek_id = key id of SNK. Portable KEK =
  `HKDF(MK, "wt/v1/portable")` (info = label ‖ 0x00, the §12.2 derivation); kek_id = its key id,
  and the header's MK id must be `key_id(MK)`. Like the keyring envelopes, the outer kind and
  kek_id are repeated inside the KWP plaintext, so a relabelled envelope fails to unwrap.
- **Frames.** nonce = 8 zero bytes ‖ counter u32 BE; AAD = header MAC ‖ counter u32 BE ‖ flag u8.
  Data frames carry exactly 1 MiB of plaintext, except the last data frame (1 B…1 MiB; never
  empty); the counter starts at 0 and increases by one per frame, the final frame included.
  The final frame is exactly one, with plaintext = data-frame count u64 ‖ total plaintext length
  u64 (ct_len = 32).
- **Reader rules.** Header fields strict (magic, version, flags, reserved, content type) → the
  envelope the caller can use (local only with SNK *and* the same installation id; portable only
  with an MK whose id is the header's) → KWP unwrap → header MAC → frames. Before a frame's body
  is read: flag ∈ {0, 1}; a data ct_len in (16, 1 MiB + 16]; a final ct_len of exactly 32; the
  counter below 2³²−1; the running plaintext within the caller's budget (default 4 GiB); a data
  frame after a short one → refused (non-canonical). A tag failure, a final with the wrong count
  or length, a missing or duplicated final, any byte after the final, truncation anywhere,
  reordered, dropped or foreign frames → refused. `read()` without a size is refused (bounded
  memory: at most one frame is buffered).
- **Writer discipline** (like `txformat.Writer`). One caller at a time: a non-blocking lock, and
  a concurrent call (another thread, or the sink re-entering the writer) **breaks** the writer
  instead of waiting. The frame counter is reserved before encryption. Every sink `write` must
  return the full length: `None`, a short count or an exception breaks the writer and the
  container is abandoned. The writer enforces the reader's plaintext budget. CK comes only from
  `secrets`; the test vector fixes it through a private module hook (`_fresh_ck`), never a
  parameter.
- **Retry after an ambiguous write.** A snapshot file is written as `<name>.tmp` (`O_EXCL`,
  `O_NOFOLLOW`, 0600) → fsync → **read back and verified** (the full restore reader, hash-only)
  → rename → fsync of the directory; any failure removes the tmp and the next attempt is a new
  `Writer`, i.e. a new CK: the counter nonces never repeat under one key. A transcoding (stored
  local snapshot → portable download) also uses a new CK.

**Content** (the `tar.gz`, streamed through the Writer; `w|gz`, so the archive is never held in
memory): `webterm.db` (`VACUUM INTO`), `keys.wtk` (the manifest bytes only — useless without the
MK), `agent-signing.key/.pub` when present, `transcripts/…` when asked, and **last**
`wts-manifest.json` = `{"format": "wts-content-1", "files": [{name, size, sha256}, …]}` for every
regular file before it (canonical JSON: sorted keys, no spaces). The tar is plain **USTAR**
(no PAX/GNU extensions). Never `secret`, `master.key` or the MK, even when a `secret` is still on
the volume (the migration's `secret_leftover` sub-state). Each file is hashed on exactly the bytes
archived (a transcript that shrinks while read is first copied, up to its stat size, into a
private temp file). Phase 1: the DB is plaintext *inside* the encrypted container (it holds the
Fernet ciphertexts as today).

- **Transcript inventory (allowlist, not exclusions).** `transcripts/` is opened with
  `O_DIRECTORY|O_NOFOLLOW` (a symlinked root, or a root that *is* `DATA_DIR` → the whole backup is
  refused) and walked through directory fds: only `transcripts/<name>.out|.cast` and
  `transcripts/arhiva/<name>.out|.cast` (`[A-Za-z0-9_-]{1,128}`, no reserved name), only regular
  files with `st_nlink == 1`, re-checked on the opened fd; never a file whose `(st_dev, st_ino)`
  is `secret`, `master.key[.tmp]`, `keys.wtk[.tmp]`, `migrating.wtm`, the signing key, the DB,
  `.lock`, `DATA_DIR` or the external key file. Symlinks, hardlinks, other names and other
  directories are skipped and logged. **Limit:** a *copy* of key bytes written into an allowed
  recording name is archived (inside the encrypted container); the inventory can stop aliases,
  not arbitrary content.
- **Fleet signing key (R-H2).** `agent-signing.key` and `.pub` are read through one
  `O_NOFOLLOW` fd each and checked on that fd: regular, ≤ 64 KiB, `st_nlink == 1`, and an inode
  that is none of `secret`, `master.key[.tmp]`, `keys.wtk[.tmp]`, `migrating.wtm`, the DB (and its
  `-wal`/`-shm`), `.lock`, `DATA_DIR` or the external key file; any of these → the whole backup is
  refused (never archived, never skipped silently). The files are a **pair**: both or neither
  (one alone → refused); `.pub` is 64 lowercase hex (+ optional newline); an unencrypted PKCS8 PEM
  must be Ed25519 and derive exactly that public key. A passphrase-encrypted PEM can only be
  checked for form (no passphrase at backup time): accepted, the pair match unproven. The same
  check runs on import (WTS1 restore, verify, transcoding, the 3.7 import) on the members held in
  memory, before anything is staged.
- **Writer budgets.** The writer enforces the reader's limits while producing (members ≤
  200 000, unpacked tar ≤ 2 GiB, content manifest ≤ 4 MiB, plaintext ≤ 4 GiB) and reports success
  only after the produced container passed the restore reader (files: before the rename; the
  in-memory portable container and a transcoded download: before they are returned).

**Restore reader** (also used by verify, by transcoding, by the post-write check and by the 3.7
import — one strict extractor, `tarfile` is not used to read): names canonical
(`[A-Za-z0-9_@+=-][A-Za-z0-9._@+=-]*` per component, no `.`/`..`/empty/absolute, at most 5
components), only the files above at the top level, under `transcripts/` only the allowlist
above (directories `transcripts` and `transcripts/arhiva`), no duplicates, the manifest last and
nothing after it, at most 200 000 members (counted on every header before it is processed), the
gzip stream with **two decompression budgets** checked after every 64 KiB step — absolute (2 GiB,
the 3.7 cap) and ratio (output ≤ max(64 MiB, 1024 × compressed input so far)) — one gzip member.
Tar profile: POSIX USTAR headers only (checksum, `ustar\0` + `00`, numeric fields octal, no
base-256, empty link name, zero header padding), type regular file or directory only, zero
padding after every member, **both end blocks zero** and nothing but zeros up to the end of the
decompressed stream (the parser reads it itself, so no byte can hide in a read-ahead buffer),
then the WTS1 final frame and EOF. PAX headers are refused in a WTS1; in a 3.7 import only one
header per member, ≤ 8 KiB, keys `path mtime atime ctime uid gid uname gname`. The content
manifest is strict JSON: UTF-8, no duplicate keys, no floats or constants, exact key sets and
types (`size` an int, `sha256` 64 lowercase hex), and byte-equal to its canonical form; every
parse error is a `SnapshotError` (400), never a 500. The extracted set must equal the manifest
(names, sizes, SHA-256); `webterm.db` and `keys.wtk` are required; the signing files are a valid
pair or absent (above); the DB passes `PRAGMA integrity_check` **and** holds the gateway's
minimal schema (`users`, `hosts`, `sessions`, `app_settings`; R-M2); the inner `keys.wtk` must open (`open_keyring_bytes`, profile v1) with the MK
the **header** names — the host's or the operator's — and carry the header's installation id,
epoch and MK id, and an SNK (writers keep outer and inner MK equal, see M4 below). The table
check proves a sound gateway database, not its full schema version nor that `FK_legacy` decrypts
it (§12.9 checklist item 3).

**Structural vs restorable** (R-M2). *Structural* = everything above except the database
(`_verify_wts(…, dest=None, restorable=False)`, hash only, nothing written). *Restorable* =
structural + the database check, on the extracted set (stage, verify) or, for a container being
produced, on `webterm.db` alone extracted into a private temp dir. Every produced container is
checked **restorable** before it is published or returned (scheduled `.wts`, safety copy,
download, re-export of a stored `.wts`); `verify` reports `restorable: true`.

**Export size** (R-M2). A download / remote upload is built in memory under a cap: its WTBK1 must
fit the restore route's upload limit (`backup.UPLOAD_MAX` = 512 MiB, which `backup_api` uses for
the uploads too). A bigger export is refused while it is produced (`SnapshotTooLarge` →
`backup.limitExceeded`), never handed out as a file no route can restore. Scheduled local `.wts`
snapshots are not capped (they are verified and restored by name; an offline import of a larger
file is a follow-up). Legacy volumes keep the 3.7 behaviour.

**Paths:**

| Path | Container | Opens with |
|---|---|---|
| scheduled local snapshot `backups/webterm-…wts` | WTS1, local envelope only | this installation's SNK |
| download (`make_encrypted`), manual and scheduled remote upload | WTBK1 (scrypt passphrase, mandatory) around WTS1 local + portable | passphrase **and** (SNK of the same installation, or the MK) |
| download of a stored `.wts` (`encrypt_stored(name, pass, mk=)`) | transcoded (streamed, no plaintext on disk) to WTS1 local + portable with a new CK; the inner `keys.wtk` is authenticated with the MK its header names and **re-wrapped under the current MK** (same installation and epoch), so one MK opens the result; a snapshot made before a rotation needs the old MK as `mk=` ("needs master key <id>"); then WTBK1 | as above |
| pre-restore safety copy `backups/pre-restore-<ts>-<restore id>-<random>.wts.keep` (R-L1: published with `link(2)`, never replaces an existing copy; with the live transcripts when the apply replaces them, R-M1) | WTS1 local + portable | the host MK (still opens after `keys.wtk` changed) |

The passphrase is mandatory for every archive that leaves the host (downloads, all remote
profiles): the product promises "two secrets" for a stolen remote archive (V3-M1), and the
remote credentials are not counted as one. Neither secret alone opens it (tested).

**Restore** (`stage_restore(blob, passphrase, keys=, mk=, legacy_import=, prefer=)`):

1. The WTBK1 layer → a WTS1 (`"WTS1"` magic) or a 3.7 `tar.gz`.
2. WTS1 on a legacy volume → refused (it can be restored only once `keys.wtk` is set up).
3. WTS1 on a protected volume → unlock: the local envelope when the header names this
   installation, otherwise (or when the local envelope is under another SNK — a recovered
   installation — or with `prefer="portable"`, chosen before any body byte is read) the portable
   one with the operator's `mk` (a snapshot from another installation, or made under a retired
   MK) or the host MK when the header names it. Under the operations lock
   (`backups/.restore.lock`, `flock` non-blocking: a second verify/stage/apply is refused with
   `backup.busy`, and `.restore-verify-*` left by a crash are removed), the whole reader above
   runs into a private 0700 directory under `backups/` (`.restore-verify-*`, same filesystem as
   the staged set). Only after everything passed: the inner keyring is **re-wrapped under the
   host MK** (KWK and SNK under the host `K_mw`, the KWK-wrapped keys unchanged; installation id of
   the snapshot; epoch = max(snapshot, host) + 1; retired ids = the snapshot's ∪ its MK id, plus
   the host's own when it is the same installation, minus the host MK id; > 64 → refused),
   replacing the snapshot's `keys.wtk`; then the set is published (below). A wrong key, a
   tampered container or any content check failing leaves no new staged set (the previous flag and set unchanged), no
   temp directory. The returned info says what the backup does **not** carry
   (`live_transcripts_kept`, `live_transcripts_quarantined`, `live_signing_key_kept`).
4. A 3.7 `tar.gz` on a legacy volume → the 3.7 code, unchanged.
5. A 3.7 `tar.gz` on a protected volume → refused unless `legacy_import=True` (the explicit
   import of §6): the archive goes through the **same strict extractor** (profile "legacy": also
   `secret`, no manifest, small PAX headers; no `tar.extract`, so no links of any kind), its
   `secret` (regular, exactly 32 B) is kept in memory only and becomes `FK_legacy` of a new
   `keys.wtk` (this installation, host MK, the other keys unchanged, epoch + 1); only
   `webterm.db`, `agent-signing.*` and the transcript allowlist are extracted (anything else →
   refused); the DB check runs on exactly the files that are then published (one extraction).
   The raw key is never written to staging.

**Staged set** (H1, R-H1). Publication of a verified directory: every file and directory
fsynced; then `restore.json` = canonical JSON `{format: "wt-restore-1", generation (random
128-bit), created, installation_id, epoch, mk_id (of the staged keyring), files: [{name, size,
sha256}], dirs}`, fsynced with its directory; then **one rename** to its own generation directory
`restore-pending.<generation>` with fsync of both parents; the flag **last**, atomically
(`.restore-flag.tmp`, fsync, rename, directory fsync) = `{format: "wt-restore-flag-1", manifest:
sha256(restore.json), state: "staged", set: <generation>}` — the flag is the pointer that switches
from the previous set to the new one; only after it is durable are the generations it does not
name (the previous set, an interrupted stage, a 3.7-named `restore-pending/`) moved aside and
deleted. A crash or an I/O error at any point leaves the previous flag with its complete set or
the new flag with its complete set, never a flag without its set (fault-injected at every step
and every fsync, including while a staged set is being replaced). **A flag in `applying` or
`committed` is never replaced**: stage (WTS1 or the 3.7 import) is refused with 409
`backup.restoreInProgress` until apply has finished the journal; a malformed flag is refused too.

**Apply** (`apply_pending_restore(keys=, force_without_safety_copy=False)`, at boot before
`db.connect`). No flag and no `restore-pending/` → nothing to do (as in 3.7). Otherwise the volume
is classified first (above): an ambiguous volume → refuse; legacy → the 3.7 code. Protected →
under the operations lock, a **journal kept in the flag**:

- no flag, staging present → an interrupted stage: ignored (logged), replaced by the next stage;
  with a flag, the generations it does not name are removed first;
- a 3.7 flag (a timestamp), a flag without its staging, a staging without `restore.json`, a
  manifest whose digest is not the flag's, a missing / changed / extra file, a non-regular entry,
  a staged `keys.wtk` that does not open with the host MK or does not match the manifest's
  identity, no keyring → **refuse** (boot stops; nothing touched), never "nothing to do";
- `staged`: the set is re-validated against its manifest; **mandatory** safety copy
  (`pre-restore-<ts>.wts.keep`, WTS1 local + portable, verified like every produced container);
  if it cannot be made the apply is refused unless the caller passes
  `force_without_safety_copy=True`; then the flag becomes `applying` (+ the safety copy's name and
  the **dataset decision** `quarantine`, taken once and resumed from the flag: once `keys.wtk` is
  replaced the live identity can no longer be compared);
- `applying`: the set is re-validated; `keys.wtk` replaced atomically if it differs
  (`keys.wtk.tmp`, `O_EXCL|O_NOFOLLOW`, fsync, rename, directory fsync, read-back); the fleet
  signing key **pair** when the backup has it (both files, or neither: the live pair stays; a
  staged half pair is refused); transcripts when the backup has them, as a durable copy
  `transcripts.restoring` then two renames through `transcripts.pre-restore` (the replaced ones
  are in the safety copy); without transcripts in the backup the **dataset rule** (R-M1) applies:
  the same installation id → the live transcripts stay (logged, `live_transcripts_kept`); another
  installation id → the live `transcripts/` is moved whole to `backups/quarantine-<restore id>/`
  (`live_transcripts_quarantined`: its session ids may collide with the restored DB's); the DB
  last (durable copy +
  rename), `-wal`/`-shm` removed, `DATA_DIR` fsynced; then the flag becomes `committed`;
- `committed`: the staging is moved aside and deleted, then the flag is removed.

Each step is idempotent (copies, not moves: the staged set stays intact until the commit), so a
re-run after a crash at any step converges (fault-injected at every step and at fsync points).
The caller must **re-open** `keys.wtk` afterwards: a restore from another installation changes
the installation id, and any restore raises the epoch (the old keyring is then refused by
`backup._host`).

**Legacy copies of the raw key (wiring item 5).** 3.7 snapshots `backups/*.wtsnap` and
`pre-restore-*.wtsnap.keep` contain `secret` in clear. They stay listed, verifiable, downloadable
(WTBK1) and restorable (through the explicit import on a protected volume), and the retention
still deletes `*.wtsnap` after 7 days; `*.keep` files are never deleted automatically. They are
now listed read-only by `backup.list_keep_copies()` (`raw_vault_key` marks the 3.7 ones) and in
`GET /api/backup/status` as `keep_copies`; System health must flag them after the migration (not
in PR3).

**API errors** (L1). `SnapshotWrongKey` with a header MK id → `backup.needsMasterKey` (vars
`{id}`); other key mismatches → `backup.wrongKeys`; any budget (`SnapshotTooLarge`) →
`backup.limitExceeded` (also an export over the upload limit, on the download route); a concurrent
verify/stage → 409 `backup.busy`; a stage while an apply journal is unfinished → 409
`backup.restoreInProgress`; the 3.7 messages keep their
codes. The detail stays the module's short English text (reason codes, no parser dump). Uploads
(`/api/backup/restore`, `/api/backup/verify`) are refused with 413 from `Content-Length` before
the body is read, and cut off at 512 MiB while streaming when the length is absent.

**Known limits (follow-up items).**

- WTBK1 is single-shot AES-GCM: downloads (`make_encrypted`, `encrypt_stored`) and uploads hold
  the whole archive (≤ 512 MiB upload, the WTS1 inside it) in memory, and the in-memory portable
  container is verified before it is wrapped. A streamed passphrase layer is a follow-up (format
  change, its own review).
- The 3.7 legacy restore path (legacy volumes) is untouched: `_gunzip_bounded` still inflates up
  to 2 GiB in memory and uses `tarfile`; it disappears with the migration.
- No global concurrency limit for downloads / scheduled backups; verify, stage and apply are
  serialised by the operations lock only.
- Plaintext temp copies remain, private (0700/0600) and removed on every path: the `VACUUM INTO`
  copy and transcript spool files (system temp dir), the verify/stage directory and
  `restore-pending.<generation>/` (DB, signing key, transcripts), the restorable check's temp
  copy of `webterm.db`, and `backups/quarantine-*` (moved transcripts, removed by hand). Their remanence on disk is outside the phase-1
  promise (it covers `secret`, `master.key` and unwrapped keyring keys, which never reach them,
  also not through an alias — H3).
- `FK_legacy` of an imported 3.7 backup is not yet proven to decrypt its DB (§12.9 item 3).

**Not in PR3 / decisions to confirm.**

- A protected restore always replaces `keys.wtk` with a re-wrapped one, even for the same
  installation, so a snapshot made before a legacy import (another `FK_legacy`) restores
  consistently. Writers now keep the header MK id equal to the inner `keys.wtk` MK id (a
  re-export re-wraps the inner keyring under the current MK), so a container needs exactly
  **one** MK: the one its header names. A local snapshot or download made before a rotation needs
  that older MK (`mk=`); the error names its id (`backup.needsMasterKey`). A retired MK must
  therefore be kept as long as backups made under it are kept.
- `keys.wtk` replacement in `apply` writes directly (not through `keys.publish_manifest`, which
  requires the same installation id); replacing a foreign installation id is a dataset
  operation and must run under the boot's process lock when wired (the operations lock in
  `backups/` is the PR3 stand-in).
- Routing: PR3 classifies the volume lock-free (`volume_kind`); the wiring PR must route from the
  boot state (`set_boot_protected`, the provider) and keep the lock through apply. There is no
  backup CLI yet; any future one must use the same classification and lock.
- `restore-pending.<generation>/` still holds the fleet signing key and the plaintext DB (as in 3.7); it holds
  no `secret`, no MK and no unwrapped keyring key (now also not through a transcript alias).
- The §12.4 restore layout (`.restore/<epoch>/`, rename journal, descriptors, erasure journal)
  and the §12.8 contract 5 snapshot coherence (barrier, pins) are not implemented: phase 1 has no
  WTX1 recordings to pin. The restore journal above (flag states) is the phase-1 form; it must be
  extended before recordings or erasures are written (the §12.4 recovery and erasure promises).
- The API does not pass `mk`, `prefer` or `legacy_import` yet (no UI to enter an operator MK);
  until then those routes surface `backup.needsMasterKey` and the operator uses a future CLI.

### 12.11 Recordings: publication, readers, backup coherence, erasure (PR5 design)

Normative design, **no code yet**. Closes, for review, the descriptor part of §12.8 contract 1 and
contracts 2, 3 and 5. Where §4, §5, §6 or §12.1–§12.5 are vaguer or differ, this section wins; in
particular (a) an index is rebuilt only by a **verified parse**, never by a length scan (§12.1
"Index"), and (b) generation files never move to `arhiva/` (§4.4 "Archive moves sealed
segments"). It applies only to a protected volume (`keys.wtk` present, §12.10 "Which path"); a
legacy volume keeps the 3.7 recording code unchanged. Writers stay disabled until this section has
passed review and the tests of §12.11.7 pass. Revised after the independent review of 2026-11-24
(findings H1–H5, M1–M6, L1 → §12.11.9); the §12.8 pointers to contracts 1, 2, 3 and 5 stay "in
review" until a second review closes §12.11.9. PR5 may land `txstore` and its fixtures before
then, with writers and migration **not** enabled.

**PR5/PR6 boundary (recheck ee2068b, R-H1).** PR5 ships the writer, the readers and the backup
path of this section with **recording encryption disabled by default**; PR6 ships the migration
(§12.11.5), the erasure journal (§12.11.4) and the continuity quarantine. Normative for a PR5
build:

- *The flag.* Recording encryption is switched on only by `WEBTERM_TX_RECORDINGS=1`. No compose
  file, `.env` example, installer or documentation sets it; only the test gates do. Absent, empty
  or any other value → off.
- *Off (the default), on any volume, legacy or protected.* Recordings are written, read, shared,
  searched, capped and backed up **exactly as in 3.7**: plaintext `.out`/`.cast`, the 3.7 recorder,
  the 3.7 readers, the v1 backup members. No `tx_descriptors`/`tx_files`/`session_keys` row is
  created for a recording. A volume on which such rows or generation files exist (left by a test
  or by a later build) is not served by the plaintext path: boot refuses with an Owner-facing
  message (`recordings encrypted by a newer build`), never reads them as absent.
- *On.* Boot evaluates, after keyring and schema and before reconcile: `migration.ready()`,
  `erasure_journal.ready()` and `quarantine.ready()` (each a PR6 component reporting that its tables,
  its journal head and its recovery pass are in place). In a PR5 build these do not exist and
  report **not ready**, so boot **refuses** the flag on a protected volume (exit with a clear
  message, System health not reached; the operator removes the flag). The only exception is a
  volume created by the test fixture helper, which writes `tx_state.test_volume = 1` at creation;
  nothing else sets it, a restore refuses an archive whose DB carries it, and a gateway that finds
  it outside a test gate (`WEBTERM_TEST_GATE` unset) refuses to boot. Enabling on a real volume
  therefore requires PR6.
- *Restore and backup in PR5.* No backup or restore report claims erasure continuity before the
  journal exists: a PR5 manifest records `erasure: not-tracked` and lists recordings as plaintext
  v1 members; restore reports "erasure history: not tracked by this version" and applies no
  journal reconciliation. An archive carrying WTX1 generations or a WTJ1 journal member is refused
  by a PR5 build outside a test volume (it cannot honour the access and erasure contract they
  imply), never restored without them.
- *Absent vs lost journal.* PR6 distinguishes a dataset that never had a journal (`erasure:
  not-tracked` in its manifest, or a pre-3.8 archive) from one that had it and lost it (manifest
  says `tracked`, member missing or unauthentic → quarantine, §12.11.4). PR5 writes only the
  first form.

#### 12.11.0 Layout and tables

- **Files:** `transcripts/<sid>.<k>.<gen>.wtx` (`k` = `out` | `cast`, `gen` = the gen_id as 32
  lowercase hex) and the optional cache `transcripts/<sid>.<k>.<gen>.idx`; both names are in the
  reserved namespace (`keys.is_reserved_name`, imported, not restated). All WTX1 files stay at the
  top level of `transcripts/`; archiving is a database state. A generation file is created with
  `openat(transcripts_fd, name, O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC, 0600)` and, once
  published, is **never renamed, truncated or rewritten**; the only removal is `retire(gen_id)`
  (deferred while pinned, §12.11.3). Readers open it with `O_RDONLY|O_NOFOLLOW` and check on the fd:
  regular file, `st_nlink == 1`, size ≥ the descriptor's `phys_len`.
- **Tables** (new, `CREATE TABLE IF NOT EXISTS` in `db.SCHEMA`; no foreign key to `sessions`: a
  recording outlives its session row, `delete_session` only archives it):

| Table | Columns | Role |
|---|---|---|
| `session_keys` | `sid` PK, `envelope` (type 6 RK envelope under KWK, §12.2), `created`, `origin` (`session` \| `migrated` \| `orphan`) | The RK. Deleting the row is destroying the key. |
| `tx_descriptors` | (`sid`, `kind`) PK, `blob` (WTD1, §12.3), `version`, `committed_at`, `archived_at`, `status` (`ok` \| `quarantined` \| `recovery` \| `damaged` \| `absent`) | The authenticated generation list, plus housekeeping columns. |
| `tx_files` | `gen_id` PK, `sid`, `kind`, `state` (`reserved` \| `created` \| `collision` \| `published` \| `retired` \| `gone`), `dev`, `ino` (set at `created`), `created` | Ledger of every generation name ever reserved. Only a `created` row (an `O_EXCL` create that **this** operation performed, inode recorded) gives a right to unlink, and only that inode. |
| `tx_migration` | (`sid`, `kind`) PK, `dir` (`transcripts` \| `arhiva`), `name`, `dev`, `ino`, `size`, `mtime_ns`, `sha256`, `state` (`pending` \| `converted` \| `unlinked` \| `missing` \| `failed` \| `orphan`), `error` | Durable inventory of plaintext recordings, taken once (§12.11.5). |
| `tx_state` | `key` PK, `value` | `erasure_head` (n, mac), `attested_heads` (per destination: n, time, object name), `keyring_epoch` (epoch, mac), `recordings_format`, `revocation_epoch` (global, §12.11.2). |

- **WTD1 flags.** The descriptor's `reserved u16` becomes `flags u16` (bit 0 = `converted`: the
  recording was migrated from plaintext; any other bit set → decode refused). Covered by the
  descriptor MAC, so a converted session is known as converted from authenticated data. No WTD1
  descriptor exists outside tests yet (writers are disabled), so `ver` stays 1; `txdesc.py` and its
  vectors change in PR5. The decoder keeps the wire cap of 4096 generations; the **operational**
  cap is 256: a larger descriptor (restore of an older build, interrupted merge) is accepted and
  merged down by the next janitor pass, never refused at restore for its size alone.
- **Keyring epoch binding (M1).** WTD1 carries no epoch. Each `keys.wtk` publication writes, in the
  same barrier, `tx_state.keyring_epoch = (epoch, HMAC(K_desc, "wt/v1/kepoch" ‖ installation id ‖
  epoch))`. Every boot compares it with `keys.wtk`: DB epoch lower than the file's (DB rolled back
  alone) or a bad MAC → every recording quarantined (§12.11.4), System health critical. A DB epoch
  higher than the file's is the restore case the §12.10 stage already handles. Nothing else is
  promised about rollback (§12.11.1 "Rollback limit").
- **Ledger compaction.** A `retired` row becomes `gone` once its unlink is confirmed (directory
  fsynced); `gone` and `collision` rows older than 90 days are deleted. After that, gen_id
  uniqueness rests on the 128-bit CSPRNG alone, as it already does after a restore (§12.11.1).

- `version` must equal the version inside `blob` (mismatch = `damaged`). The unauthenticated columns
  (`committed_at`, `archived_at`, `status`, the ledger) are hints for UI, retention and recovery:
  none of them can make a reader serve a byte the authentic descriptor does not cover, and **no
  recovery step deletes a file that an authentic descriptor lists**, whatever the ledger says
  (integrity alarm instead). Their tampering needs a write to the database, which is outside the
  phase-1 promise (§8).

#### 12.11.1 Writer lifecycle and publication (contract 1)

**Locks.** `txstore.lease(sid)`: one in-process `asyncio.Lock` per sid (§5). `txstore.barrier`:
one process-wide `asyncio.Lock` (§12.4). Lock order is always lease → barrier; inside the barrier
only the DB transaction (or the backup snapshot of §12.11.3, or the erasure journal append of
§12.11.4, the one fsync allowed there) runs; record fsync and file I/O happen **before** the
barrier is taken; no network I/O, off-host upload or unbounded `await` runs under either lock.
Cross-process exclusivity is the boot lock (§12.2); §12.11.3 says how the host-side backup meets it.

**Per-session coordinator (H1).** Each recorded sid has exactly one `txstore.Recorder`: a single
worker task with a FIFO job queue. It alone owns the writers and their fds (closed only by the
worker, after its last job), and it is the only code that runs **checkpoint, seal, roll, cap/merge
publication, finalize, writer change (start, re-adoption after teardown, agent epoch change) and
the migration of a live session**. A job holds the sid's lease from start to end, end to end:
capture → append → fsync → DB commit → `hub.committed` update. Two jobs of one sid therefore never
overlap, so a later checkpoint cannot be captured before an earlier one commits. The loop side
never touches a writer: `_process_output` only appends to the kind's *pending buffer*; a job starts
by **swapping** that buffer for an empty one (synchronous, one tick), so output arriving while the
job runs goes to the new buffer and never into the batch in flight. Callers await a job's future
through `asyncio.shield`: cancelling a caller (request, teardown) never cancels a job that has
begun; teardown enqueues `finalize` behind it. Other modules (reconcile, `delete_session`, archive,
purge, migration of closed sessions, erasure) take the same lease, so they serialise with the
coordinator; on a protected volume `sessions.agent_epoch/agent_offset` is written **only** by a
coordinator job (a source-scan test lists the writers of those columns).

**Isolated transaction.** `db.execute` commits on its own, so publication never uses the shared
helpers: `txstore` opens its own connection, used only under the barrier, and runs `BEGIN
IMMEDIATE` … `COMMIT` with no other statement interleaved and no `await` other than the DB thread
hop. Inside the transaction, before writing, it checks (CAS + monotonicity, refused → `ROLLBACK`):

- each descriptor row's `version` equals the version the job started from, and the job's writer
  token equals the hub's current one (a job of a replaced writer is dropped, its fds closed);
- **checkpoint / seal / roll:** the new generation list *extends* the committed one: same gen_ids in
  the same order, every count (`data_count`, `plain_len`, `phys_len`) ≥ the committed one, a
  committed `sealed`/`recovered` never changes, at most one new `live` at the end;
- **cap / merge:** a typed operation: the committed list starts with exactly the pinned P (gen_ids
  and counts), the tail L is preserved unchanged, `list_epoch` bump only for a cap;
- the agent position: same `agent_epoch` and `agent_offset` ≥ the committed one; an epoch change
  only in a writer-change job, which also opens a new generation.

**A checkpoint that loses** (CAS or monotonic check fails — impossible with the queue, so treated as
a bug: audited, System health warning) publishes nothing; its records stay in the file past
`phys_len` (never read) and the next job of the **same** writer re-captures a superset. It is never
retried with its old capture. **Uncertain outcome** (an exception at or after `COMMIT`): the job
does not assume a rollback; it re-reads the rows on a fresh connection: version = target and blob
hash = the job's → committed (update `hub.committed`); version = start → not committed (retry the
same capture once, then break the writer as below); anything else → the sid is re-adopted through
crash recovery (§12.11.1 table) before any further job.

**RK.** At the first writer start of a session on a protected volume (SessionHub creation, before
any output is accepted): if `session_keys` has no row, RK = `secrets.token_bytes(32)`, wrapped under
KWK, `INSERT` committed under lease → barrier before any generation is reserved. Both kinds use the
same RK (their descriptors carry the same RK hash). The unwrapped RK lives in the hub and in the
bounded txstore key cache (≤ 256, `repr` hidden), dropped on erasure. An envelope that does not
unwrap, or a descriptor whose RK hash differs → the hub does **not** start (attach refused with
`transcript.keyError`, System health alarm): a protected session is never run unrecorded because
of a key fault.

**Generation start (reservation, private).** `gen_id = os.urandom(16)`; under lease → barrier
`INSERT tx_files(gen_id, sid, kind, 'reserved')` committed (a UNIQUE violation → new id); then the
`O_EXCL` create. EEXIST → the row becomes `collision` (the existing file is **not ours**: never
unlinked by us, reported as an orphan if it is in the reserved namespace), new id. Success →
`fstat`, row → `created` with (`dev`, `ino`) committed **before** `txformat.Writer` writes the
header.
Nothing of this is in a descriptor: readers cannot see it. A generation is opened at writer start
and right after each roll, so the synchronous flush always has a writer; one that is never
published (no data before close) is retired at close, never published empty.

**Uniqueness proof (§12.8 PR1 note).** `Writer` has no reopen: each one is built on a fresh fd
from an `O_EXCL` create, under a gen_id drawn at random and reserved UNIQUE; its keys derive from
(RK, kind, gen_id); a broken writer's gen_id is never reused (its row stays until retired). So
every (K_rec, nonce) is new across all attempts, crashes included. A restore brings back an older
ledger but no older gen_id is reused except by a 128-bit RNG collision; a VM clone with RAM stays
the stated limit (§12.1).

**Hot path and checkpoint** (same triggers as today: 64 KiB unpersisted or 2 s, idle flush after
2.5 s, forced on resume/unlock, after a gap marker and at close):

1. `_process_output` (loop, synchronous): append the plaintext to the kind's pending buffer,
   `agent_offset += len`, OSC 133 scanner on `out_pos` (logical offset). No file I/O on the loop.
2. Checkpoint job (coordinator, lease held): swap the pending buffers and, **in the same tick**,
   take `(agent_epoch, agent_offset)` of their end. Off the loop (worker thread): cut each batch into
   DATA records of ≤ 64 KiB and `Writer.append` them; before each record and before SEAL the job
   reserves room against the §12.1 **hard** limits (records, bytes, SEAL size): a batch that would
   cross them is split, the generation sealed and a new one opened inside the same job, so a burst
   that jumps over the 90 % roll mark never overruns a limit. Then capture `S = {per kind: gen_id,
   data_count, plain_len, phys_len} + (agent_epoch, agent_offset)`.
3. Still off the loop: `fsync` every writer fd written since the last commit (**both** kinds;
   today only `.out`), and the `transcripts/` directory when S contains a generation not yet
   published.
4. Lease (still held) → barrier → **one isolated transaction** with the checks above: both
   descriptors re-encoded with `version + 1` and the live entry's counts from S;
   `tx_files.state = 'published'` for a newly listed generation; `committed_at = now` when the
   `.out` plain_len grew; `sessions.agent_epoch, agent_offset` from S (never the current values).
   Commit → `hub.committed = S`. Exclusive watermark = `data_count`.

**Backpressure (M4; recheck ee2068b, R-H2).** Bounds: the pending buffers are capped at 8 MiB per
sid **and** 64 MiB for the whole process (`REC_BUFFER_TOTAL`); a job's in-flight batch counts
against both until the job resolves. While a job (or a barrier held by a backup's `VACUUM INTO`)
delays the next checkpoint, output keeps going to browsers and into the pending buffer. When a cap
would be crossed, that sid enters **overflow**: the recorder discards its *pending* buffer (never
the batch in flight), stops buffering and counts the dropped bytes. It does **not** rewind
`agent_offset` (memory or DB) while a job is in flight. When the in-flight job has resolved
(committed, not committed, or the worker lost — "Supervision" below), the recorder re-reads the
committed position C (descriptor counts + `sessions.agent_epoch/agent_offset`, one read
transaction) and resumes from C: on an agent host the stream is re-attached at C's agent offset and
the bytes from there come back from the ring (to the recorder only, never again to browsers); the
bytes the ring no longer has — and on SSH, telnet and serial, every dropped byte — become **one**
`GAP_MARKER` at `.out` logical position C carrying the dropped length (the same pair as a `.cast`
gap event). The recording is `degraded` (§12.11.8 Q5) from the first dropped byte until that marker
is committed: System health alarm and an audit entry with position and size. A single record
append is bounded (≤ 64 KiB, one `os.write`) and never runs on the loop.
5. Readers trust exactly `hub.committed` / the descriptor. Because step 2 captures the offset and
   the counts together, the committed agent offset is always the end of the committed prefix: a
   restart replays from there into a new generation, so the 3.7 duplicate after a crash (bytes in
   the file past the committed offset) disappears.

**Failures.** A DB error advances nothing; the next checkpoint publishes a superset. An fsync error
or an ambiguous write breaks the writer (§12.1): the generation is abandoned without SEAL (the next
publication marks it `recovered` at its last committed counts), a new generation is opened, and
the hub rewinds `agent_offset` to the committed value and re-attaches the agent stream from it (the
existing replay path: bytes the agent ring no longer has → `GAP_MARKER`, as today); replayed bytes
up to the pre-failure offset go to the recorder only, never again to browsers. Repeated failure
(ENOSPC) → recorder `degraded`: terminal I/O continues, retry every `CAP_RETRY_SECS`, `GAP_MARKER`
at resumption, System health alarm. *(Availability choice, see §12.11.8 Q5.)* The gap marker sits at
the `.out` logical offset where recording resumed (the committed end); the same position goes to
`.cast` as a gap event. Web replay and the recorder see the same marker. An agent epoch change
while degraded (agent restarted) → nothing is replayed from the old ring, the marker is written,
the writer-change job opens a new generation. SSH, telnet and serial sources have no agent ring:
bytes lost while degraded are gone, the marker records that. A key fault is different: it
**refuses** the hub (above); only write faults degrade.

**Supervision, worker loss and restart (recheck ee2068b, R-H2).** A batch is `queued` (in the
pending buffer), `in-flight` (swapped into a job) or `durable` (its commit observed and
`hub.committed` updated). The **only** source of the resume point is the committed state: the two
descriptors and `sessions.agent_epoch/agent_offset`, written in the same transaction (hot path
step 4). Memory is a cache of it and is never trusted after a fault.

- *Supervisor.* One process-wide supervisor awaits every Recorder worker task. Each job's future
  is resolved in the worker's `finally` (its result, or `RecorderLost`), so no caller waits on a
  future without an owner. A job's fds and its lease are released only after its blocking I/O call
  has really returned: a thread still inside `write`/`fsync` keeps them, and the worker joins it
  before closing anything.
- *Worker dies or is cancelled mid-job* (an exception outside the job's own handling, or the
  shutdown cancel after the 5 s budget): the supervisor marks the Recorder `lost`, refuses new jobs
  for the sid, waits for any thread still in I/O, closes the fds, then re-adopts the sid exactly as
  boot crash recovery does for one sid (table below): descriptors, ledger and agent position
  re-read on a fresh connection in one read transaction; the live generation becomes `recovered` at
  its committed counts; a new generation is opened by a writer-change job; the stream is re-attached
  at the committed agent offset. Pending and in-flight bytes in memory are dropped, never appended
  to the new generation: the ring re-delivers them, or they become the gap marker above.
- *Retry after an uncertain commit* ("Uncertain outcome" above) may only re-publish the same capture
  whose records are already written and fsynced; a batch is never appended a second time.
- *Shutdown and gateway restart.* Jobs that did not finish within the 5 s shutdown budget are
  abandoned with the process; the next boot has no memory state and derives everything from the DB
  and the directory (crash recovery below), creates the hub with `hub.committed` = the DB values,
  and the first attach replays from the committed `agent_offset` (agent hosts with the same epoch)
  or writes a gap marker (no ring, or the agent epoch changed).
- *Guarantee.* Every agent byte up to the committed agent offset appears in `.out` **exactly
  once**, or lies inside an interval recorded by a gap marker that carries its position and length;
  nothing past the committed offset is ever assumed recorded. Tests (#19, extended): kill the worker
  after the swap, during an append, after the fsync and at `COMMIT`; fill the per-sid and the
  process cap during a commit; restart the gateway mid-burst; each asserts no duplicate and no
  unmarked hole by comparing the decrypted `.out` with the agent stream.

**Seal, roll, close.**

- `phys_len`: `live` and `recovered` = 96 + Σ(25 + len) over the committed DATA; `sealed` = that +
  73. At most one `live` per kind, always last; `sealed` and `recovered` never become live again.
- **Roll** at 90 % of a §12.1 limit (`Writer.should_roll()`), after a successful checkpoint: SEAL
  (loop) → fsync → publish `sealed` → open the next generation.
- **Close** (exit, teardown, kill): final checkpoint, seal both kinds, publish. `teardown()` stays
  synchronous and schedules `finalize()`; shutdown awaits pending finalizers ≤ 5 s. A finalize that
  never ran is the crash case below.

**Cap** (replaces `_maybe_cap`'s copy, catch-up and `os.replace`; the live writer is never touched):

1. Trigger at a checkpoint when Σ plain_len of a kind ≥ `TRANSCRIPT_MAX_BYTES` (env unchanged).
2. Roll both kinds (sealed + new live generation, published as above); output keeps flowing.
3. Off the loop, from a reader snapshot of the prefix P (every generation before the new live
   ones): build one new generation T per kind with exactly 3.7's kept content (`.out`:
   `GAP_MARKER` + the last `TRANSCRIPT_KEEP_BYTES`; `.cast`: header line ≤ `CAP_HEADER_MAX` + gap
   event + whole lines of the last KEEP bytes), reserved and created like any generation, sealed,
   fsynced (+ directory), then `verify_full` read-back.
   The compactor pins P (gen_ids, counts and its own fds) at step 3 and reads only through them.
4. A coordinator job (lease) → barrier → one isolated transaction per session: the typed cap check
   above revalidates that the committed list still starts with exactly P and that `list_epoch` is
   the one seen at step 3; a stale result (P changed, the session was erased, archived, migrated or
   its writer replaced) → T retired, nothing published. Otherwise each descriptor P ‖ L → T ‖ L
   (L = the committed generations after P, read inside the transaction), T `published`, P
   `retired`. Then `list_epoch += 1` (today's `out_gen`), then `retire(P)`.
5. Abort (teardown, I/O error, ENOSPC): T retired, nothing published, retry after
   `CAP_RETRY_SECS`.

**Merge.** When a descriptor would exceed 256 generations (many writer restarts), the same
procedure without truncation: T = the exact concatenation of P, offsets unchanged, no `list_epoch`
bump. A merged `recovered` generation becomes part of a sealed T (the mark described how it
ended, not its content).

**Crash recovery** (at every boot, after keyring, restore apply and schema, **before** reconcile
creates hubs and before recording routes serve; the same reconcile runs for one sid at writer
start). The directory is listed through its fd without following links and compared with the
ledger and the descriptors:

| Interrupted after | Found | Recovery |
|---|---|---|
| RK drawn, insert not committed | nothing | nothing |
| RK committed | `session_keys` row, no descriptor | nothing (empty recording) |
| reservation committed, create not recorded | `reserved` row, file absent | delete the row |
| reservation committed, create not recorded | `reserved` row, file present | **ambiguous ownership**: row → `collision`, file left in place as an orphan (never unlinked by recovery) |
| create recorded; header partial, or records written (fsynced or not, either kind, directory fsynced or not), publication not committed | `created` row (± file) | unlink only if `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)` matches the row's (`dev`, `ino`) and no authentic descriptor lists the gen; row → `gone`. Never committed, the DB offset predates it → replayed from the agent ring at the next attach |
| publication committed | `live` entry, maybe bytes past `phys_len` | `live` → `recovered` at the committed counts (one publication); bytes past `phys_len` are never read, sealed or served |
| SEAL written, not published | `live` entry without the SEAL | `recovered` (the SEAL is a trailing byte) |
| seal published | `sealed` | nothing |
| cap/merge T written, not published | T `created` | unlink T (identity check as above) |
| cap/merge published, P not unlinked | P `retired` | unlink P (identity check as above) |
| migration generation written, not published | `created` + plaintext | unlink the generation; plaintext stays (`tx_migration` still `pending`), retried |
| migration published, plaintext not unlinked (one or both kinds) | descriptor + `tx_migration` `converted` | §12.11.5 step 6, per kind |
| — | file with no ledger row, a `collision` row, a `created` row whose inode differs, or a header that does not authenticate under its sid's RK | **orphan**: left in place, never served or backed up, listed in System health (Owner can delete it from there, audited) |
| — | ledger `reserved`/`created`/`retired` but an authentic descriptor lists the gen | never deleted; integrity alarm |
| — | descriptor lists a file that is missing or shorter than `phys_len` | `status = damaged`; readers refuse (`transcript.damaged`); alarm |

**`recovered` means:** the generation ended without its SEAL (crash, kill, I/O error) at its last
committed prefix. It is information about how the generation ended, not a certificate of its bytes:
those are proven only by a verified read. Recovery never resumes its nonce sequence, never appends
to it and never seals an unknown tail. Readers treat it like a sealed generation for ranges; the
full check (§12.11.2) proves the prefix and reports "ended by interruption" as information. The
codec accepts a generation with zero DATA records (needed by the test vectors and by a SEAL-only
roll edge); the runtime never publishes one (an unpublished empty writer is retired at close).

**Rollback limit** (V3-H2): a MAC stops edits, not the replay of an older authentic DB together with
older files (N5); the `keys.wtk` epoch, compared with `tx_state.keyring_epoch` at boot (§12.11.0),
only catches a DB older than the key file across an epoch change. No per-commit marker outside the
restorable set is added in 3.8.

#### 12.11.2 Readers (contract 2)

One module, `gateway/app/txstore.py`; nothing else opens a generation, decodes a descriptor or
unwraps an RK (a source-scan test, like `conntypes_test`).

| Call | Does |
|---|---|
| `open(sid, kind, *, access)` → `Snapshot` | `access` is the `txstore.Access` object produced by the route's own authorization step (principal, route, the authz decision and the revocation epochs read **before** that decision), never a purpose string. Decode the descriptor (MAC, installation, sid, kind, flags, RK envelope hash), refuse tombstoned / `damaged` / `absent` / corrupt / `quarantined` always; a recording in `status = recovery` (moved there one at a time by the Owner-recovery action of §12.11.4, which lifts **only** the continuity quarantine) opens only for an `access` from the Owner-recovery route, unwrap the RK, open and check the fds of the generations, verify each header against the descriptor's `hdr_mac`, record `list_epoch`; then the linearisation check below. Plaintext (`PlainSnapshot`, same API, one fd) only for a (sid, kind) whose `tx_migration` row is `pending` and whose file still matches the row's (`dev`, `ino`, `size`, `mtime_ns`). Refused as a downgrade (`transcript.downgrade`, alarm): a plaintext file for a sid that has a descriptor, an RK, a descriptor with the `converted` flag, or a `tx_migration` row in any other state (`converted`, `unlinked`, …) — **even if its descriptor is missing** — a plaintext not in the inventory, and any plaintext once `recordings_format = wtx1`. |
| `Snapshot.length` | committed logical length (Σ plain_len) |
| `Snapshot.read(start, end, *, budget)` / `iter(start, end, *, chunk, budget)` | plaintext of [start, end) |
| `tail(sid, kind, limit, *, end=None)` | (bytes, end, epoch) of the last `limit` committed bytes, or up to `end` |
| `verify(sid, *, budget)` | full integrity report (below) |
| `exists`, `last_output_at`, `stats` | descriptor data, no file I/O |

**Range rule (V3-H3).** The bytes returned are reached only through (a) an index authentic under
K_idx for exactly the descriptor entry's (gen_id, data_count), its entries checked against
`plain_len`/`phys_len`, then a forward parse from the nearest entry ≤ start that verifies every
record (tag, seq succession, type) up to the last byte returned; or (b) a verified parse from
seq 0, within the budget, refused beyond it. The offset of a returned byte = authenticated entry
offset + Σ len of verified records. A rebuilt index is the by-product of a verified parse, written
as `.idx` (tmp `O_EXCL` → rename) for `sealed`/`recovered` generations only, one entry per 1 MiB of
plaintext; the hub keeps an in-memory index of its own live generation, built from the records it
wrote, for live tails. A range read proves the returned bytes, their offsets and the descriptor;
**not** the records outside its window (that is `verify`). Bytes past the committed prefix are
never read; inside it, a short file, bad tag, gap or a SEAL below the watermark → `transcript.corrupt`
(System health alarm, audited, never cached).

**Snapshot isolation.** The fds are opened at `open()`, so a concurrent cap, merge, archive, purge
or migration cannot change what a snapshot reads (an unlinked inode stays readable through the fd).
A reader whose offsets must match the hub (resume, OSC 133) compares `list_epoch` exactly as it
compares `out_gen` today and falls back the same way.

**Revocation and the linearisation point (H4).** Two in-memory counters, both bumped
**synchronously on the loop** (no `await` between the state change and the bump):
`revocation_epoch[sid]` (erasure, quarantine change, archive/purge, live-share or replay-link revoke
of that sid) and the global `access_epoch` (any role, binding, permission, account disable, token
or session revoke). Erasure step 1 (§12.11.4) adds the tombstone and bumps the sid's counter in the
same synchronous section, before any unlink. A snapshot is valid only if, **after** all its fds are
open, a synchronous check on the loop finds both counters equal to the values captured in `access`
before the authorization decision, the sid not tombstoned and not quarantined (unless Owner
recovery). That check is the linearisation point: the snapshot is as if authorization, descriptor
read and fd open all happened at that instant. A failed check closes every fd of the snapshot and
retries once from the authorization step; a second failure → refused (the route's own 404/403).

**Check points while serving.** The same synchronous check runs (a) before a cached response is
served and again before a computed one is put in a cache, (b) before **each** emitted chunk of a
stream (≤ 64 KiB plaintext, one DATA record or less; also for `PlainSnapshot` and for redacted
output), and (c) before a single-shot response is handed to the transport. A changed sid counter
or a tombstone → the stream is aborted (connection reset, no trailer; audited). A changed global
counter → the stream pauses and re-runs the route's own authorization for its principal (the same
dependency, share-token or replay-token lookup); denied → aborted. Every recording response larger
than 64 KiB is streamed under check (b); the only single-shot bodies are the ones built whole with
a route cap (preview, text view, `/api/replay/text`, search results), checked once at (c).

**Expiry (recheck ee2068b, R-H3).** `access` carries `not_after`: the earliest time limit the
authorization relied on — a time-bound binding's `expires_at`, the share link's or replay token's
expiry, the login session's absolute and idle expiry, and the step-up window when the route
required step-up. Each check (a)–(c) also compares the monotonic clock with `not_after`; past it →
the stream pauses and re-runs the authorization as for a global bump; denied → aborted. An expiry
needs no counter bump. Because a stalled transport never reaches the next check, every open stream
also has a timer that fires at `not_after` and on every counter bump: it runs the same check and,
on a refusal, closes the transport and sets the worker's cancel flag.

**Commit/bump fence (R-H3).** A revocation is a DB commit on the DB thread followed by work on the
loop; a check that ran between the two would pass on old counters. Closed by **bump before commit,
re-check after**: every access-reducing write (the lists in "Revocation" above) first, synchronously
on the loop, bumps the counter(s) and sets `fence_pending` for that scope (the sid, or global),
then submits its transaction; while a fence is pending every check in its scope fails into the
re-authorization path, and re-authorization **awaits the fence** (commit or rollback) before it
queries. After the commit or rollback the counters are bumped again and the fence cleared.
Re-authorization captures the counters before its query and checks them again after its fds are
open; a mismatch repeats once, then refuses. A refusal closes every fd of the snapshot; each
re-authorization builds a fresh `access`, never reusing the previous one. **Writers in another
process** (`python3 -m app.admin` `passwd`, `logout-all`, `disable-2fa`, `sso-only`, `roles` while
the gateway runs) increment a persisted `tx_state.access_gen` in the same transaction as their
change; the gateway polls it every second and bumps `access_epoch` when it moved (a poll that fails
twice in a row also bumps it). For those writers the linearisation point is the poll that observes
the change, so the stated delay is ≤ 1 s plus the two-part bound below.

**What a revocation stops** (replaces the earlier "≤ 64 KiB + 64 KiB" figure, which did not follow
from these rules; recheck R-M3). Two separate statements:

1. *Application guarantee.* From the linearisation point of a revocation or expiry (the fence for
   in-process writers, the observing poll for others), the application authorizes **no further
   unit** of that stream: at most the one unit whose check had already passed — one chunk of
   ≤ 64 KiB plaintext, or one single-shot body up to its route cap — is handed to the transport,
   and no new decrypt is started for the stream (a worker inside one record finishes it, its output
   is discarded).
2. *Transport, not recallable.* Bytes already handed to the transport — the ASGI server's buffer,
   TLS, the kernel socket send buffer, Traefik or any proxy, the browser — are outside the
   application and cannot be recalled. Their amount depends on the send buffer and proxy buffering
   and is **not bounded by this design**; no end-to-end byte figure is promised. The test (#15)
   asserts statement 1 only: no unit is authorized after the fence.

**Caches** are keyed by (sid, kind, descriptor version, generation-list digest, redaction policy
version, `revocation_epoch[sid]`, `access_epoch`) and are dropped on any bump of those counters;
an entry whose key no longer matches is never served.

| Reader today | Protected volume | Behaviour kept |
|---|---|---|
| `read_tail(sid, limit)`, fresh attach (`attach_replay`) | `tail(sid, out, limit)` | up to the last commit (= today's flushed boundary: both move at the checkpoint); `ALT_SCREEN_RE` stripping unchanged; `span` = (committed `.out` end, limit, `list_epoch`) only if both are unchanged across the read (replaces `_flushed_size`) |
| `read_tail(…, end=cutoff)`, resume/unlock (`_resync`) | `S = await hub.commit_now()` (forced checkpoint), then `tail(sid, out, limit, end=S.out_len)`; cutoff = `S.out_len` | exact logical offset; a failed commit → cutoff `None` → today's drain-queue path |
| attach/resync of a session the user may control | as the two rows above, under the websocket's own authorization (`access` built from the ws principal) | unchanged |
| `/api/sessions/{sid}/preview` | `tail(sid, out, 32 KiB)` | unchanged |
| `transcript_text` (txt view, `/api/replay/text`) | `Snapshot.read` of the last `TEXT_VIEW_TAIL` or all | same transformation, same masking |
| `search_transcripts` | `tail(sid, out, SEARCH_READ_CAP)` per session; `SEARCH_TOTAL_CAP` counted on decrypted bytes | past the budget, metadata only (as today) |
| `/api/sessions/{sid}/transcript?format=out\|cast` (`FileResponse`, authenticated download, unredacted) | streamed from `Snapshot.iter`: `Content-Length` = length, `Accept-Ranges: bytes`, one Range on **plaintext** offsets clamped to the logical length (206; start ≥ length → 416 with `Content-Range: bytes */<length>`; several ranges → 200 full), ETag = SHA-256(sid ‖ kind ‖ descriptor version ‖ generation list ‖ committed watermark), `If-Range` only on an equal ETag, `Cache-Control: no-store`. Headers are sent only after the parse up to the first returned byte has verified; corruption found later aborts the connection (no trailer, `transcript.corrupt` audited) | byte-identical to the plaintext file the same committed history produces (the generations concatenated); RBAC, step-up and token checks run before `open` |
| replay link creation (`share_api.py` `[replay]`) | `exists(sid, cast)`, not tombstoned / quarantined / `recovery`, under the creator's authorization | no link for a `recovery` recording |
| replay link lookup (`cast_path.exists()`) | `exists(sid, cast)` and not erased / quarantined / `recovery`; `access` built from the link token, **not** from the authenticated-download authorization | the same 404 for every failure |
| `/api/replay/cast` (public, `redacted_cast_file`) | `.cast` via `Snapshot.iter` into an incremental `redact_cast` (line buffer ≤ `CAP_HEADER_MAX`, longer lines refused), on the decrypted logical stream (record boundaries invisible to the redactor) | cache key as above, with the redaction policy version; checked before publish and before serve |
| `/api/replay/text` (public, conditional masking) | `Snapshot.read` of the last `TEXT_VIEW_TAIL` through the same masking as today, link-token `access` | same output; same cache rules |
| OSC 133 (`out_pos`, scanner, `span`) | logical offsets of the `.out` stream; `out_gen` → `list_epoch` (bumped only by a cap or by a migration of a live session) | unchanged |
| `transcript_stats` stat-walk | Σ `phys_len` from descriptors (+ legacy dirs until migrated) | — |

**Budgets** (constants in `txstore.py`, each with a test):

| What | Limit |
|---|---|
| request-path decrypt workers (all readers) | one global semaphore of 4; wait ≤ 5 s, then 503 `transcript.busy` |
| parse before the first returned byte | ≤ 1 MiB with an index; ≤ `TRANSCRIPT_MAX_BYTES` + `TRANSCRIPT_KEEP_BYTES` without, then `transcript.limitExceeded` |
| index | `verify_index(max_entries=65 536)` |
| search | 4 MiB per session, 128 MiB per query, 20 results (unchanged) |
| `verify` from System health | ≤ 256 MiB per pass, background, off the loop; a resumable cursor (sid, kind, gen_id, seq, offset) carries a larger generation over several passes; the cursor is discarded if the descriptor version changes |
| open snapshots / fds | ≤ 64 snapshots process-wide, ≤ 4 096 generation fds; beyond → 503 `transcript.busy`; a snapshot with no read for 60 s is closed |
| bytes processed per request | ≤ the route's own cap (download: the logical length requested; replay cast/text: `TRANSCRIPT_MAX_BYTES` + KEEP; preview/tail: 1 MiB + its limit), counted across **all** generations of the request, not per generation |
| bootstrap / resume scans | the index rule above per generation, and ≤ 2 × `TRANSCRIPT_MAX_BYTES` parsed per request in total |
| a worker after cancel | checks a cancel flag between records; stops within one record (≤ 64 KiB decrypt); its fds are closed in its own `finally` |
| caches | descriptors keyed (sid, kind, version); RK ≤ 256; redacted cast 1 entry; all keyed and dropped as in "Caches" above |

Each route of the table above has an admission check (semaphore + fd budget) before `open` and a
cleanup in the route's `finally` (snapshot closed, semaphore released) — a test per route.

**Full integrity check** (`verify`, never on a request path): descriptor; per generation: header,
every record, seq succession, count / plain_len / phys_len equal to the descriptor; `sealed`: SEAL,
the tag hash and EOF exactly at `phys_len` (a trailing byte is an error); `live` / `recovered`:
prefix only (trailing bytes reported as information); both kinds present with the same RK hash,
except a historical pair recorded with one kind only (a 3.7 session without `.cast`, inventoried as
`missing`, or a descriptor of one kind created by migration): reported as "one kind only", not as
corruption. Used by System health (rolling), by backup (on the bytes it copies), by restore (every
staged recording) and by migration (read-back).

#### 12.11.3 Backup coherence (contract 5)

**Mutations that take the barrier** (exhaustive; a test enumerates the call sites): RK creation;
generation reservation and `created` record; checkpoint publication; seal; roll; writer change
(including the agent offset/epoch: no other code writes `sessions.agent_epoch/agent_offset` on a
protected volume); cap and merge publication; migration inventory, publication and per-kind
`unlinked` record; `recordings_format`; archive (`archived_at`) by **both** paths
(`archive_closed_transcripts` and `delete_session`/`purge_host`); purge; adoption or deletion of a
session row that owns a recording; boot/housekeeping recovery writes (ledger, `status`); erasure;
quarantine and recovery-status changes; `keys.wtk` publication (MK rotation) with
`keyring_epoch`. Unlinks never take it: they go through `retire(gen_id)` (and the migration's
identity-checked unlink), which defer while the gen or the legacy inode is pinned.

**One snapshot function, every path (H2).** `txstore.backup_snapshot()` is the only way any backup
reads recordings. Who calls it:

| Path | Snapshot taken by |
|---|---|
| in-app download, scheduled, cloud / SFTP / FTPS upload, safety copy before a restore, backup "without recordings" | the gateway process, under its barrier |
| `hostops backup --live` (host script, other process) | the running gateway, through a local control socket `DATA_DIR/.ctl/backup.sock` (directory 0700, owned by the gateway uid; peer checked with `SO_PEERCRED`: uid 0 or the gateway uid); the gateway runs the same function and streams the WTS1 file back. No socket answer while the boot lock is held by a running gateway → **refused** (never a direct read of a live volume) |
| `hostops backup` with the app stopped | the host process itself, after taking the boot lock (§12.2: process exclusivity stands in for the barrier), same function |
| verify / staging of an archive | no snapshot: reads the archive only (§12.10) |

**Control socket protocol (recheck ee2068b, R-M1).** The socket serves live backup only; any
other use needs its own design.

- *Creation* (boot, under the boot lock, after crash recovery, before routes serve): `DATA_DIR/.ctl`
  is opened as a directory fd with `O_NOFOLLOW` and checked on that fd (directory, owner = gateway
  uid, mode 0700; otherwise boot alarm and no socket → live backup refused). A leftover
  `backup.sock` is unlinked through the dir fd only if `fstatat(…, AT_SYMLINK_NOFOLLOW)` shows a
  socket owned by the gateway uid; anything else → alarm, no socket. The socket is bound through
  the dir fd, mode 0600. The spool directory `.ctl/spool/` is emptied at the same point.
- *Peer check* before reading any byte: `SO_PEERCRED` uid, as seen in the gateway's namespace, must
  be 0 or the gateway uid; otherwise the connection is closed and audited (peer uid, pid). A host
  root that the container's user namespace maps to another uid is refused (fail closed; the
  documented path is `docker exec` into the container as root).
- *Framing.* Each frame = 4-byte big-endian length + payload. Requests are JSON objects ≤ 4 KiB:
  `{"v": 1, "op": …, "id": …}` plus only the op's allowlisted keys; an unknown version, op or key,
  a larger frame or invalid JSON → one `error` frame and close. No secret crosses the socket in
  either direction except the archive bytes themselves; the archive is in the form the in-app
  download of the same profile produces (its encryption per §12.10).
- *Operations* (the only ones):
  - `snapshot.start {profile, recordings: "all" | "none"}` → the gateway runs `backup_snapshot()`
    into a private spool file (`O_EXCL`, 0600, random name), fsyncs it, then runs the **full
    archive verification** (§12.10 verify) on the spool. Only after it passes: `{"ok": true,
    "snap": <id>, "size": n, "sha256": h}`. Before that nothing of the container is sent; a failed
    snapshot or verification → `{"ok": false, "code": "backup.busy" | "backup.failed"}`, spool
    unlinked. Free disk is checked first (estimated size + 10 %), else `backup.noSpace`.
  - `snapshot.read {snap, offset, length ≤ 1 MiB}` → a header frame `{"ok": true, "offset",
    "length"}` and one data frame read from the spool only.
  - `snapshot.release {snap}` → spool unlinked, `{"ok": true}`.
- *Timeouts and holds.* First request ≤ 10 s after connect, then ≤ 60 s between requests; each
  response frame must be written within 30 s (a slow peer is disconnected). `snapshot.start`
  answers within 15 min or fails `backup.busy`. The barrier and the recording pins are held only
  during snapshot steps 1–4 under their own budgets (VACUUM 120 s) and **at most 10 min in total**;
  beyond → the snapshot is aborted (`backup.busy`), barrier and pins released. Pins end when the
  spool is complete (it is a copy); a ready spool lives ≤ 15 min, and ≤ 60 s without a read.
- *Concurrency.* At most 2 connections and **one** snapshot in flight process-wide (shared with the
  in-app and scheduled backups' slot); a further connection is closed at accept, a further
  `snapshot.start` gets `backup.busy`.
- *Disconnect.* On EOF, reset or timeout at any stage: a snapshot already submitted to the worker
  is owned by that worker, which checks a cancel flag between steps and on exit unlinks the spool
  and releases the barrier, pins and fds; a request not yet submitted is dropped by the connection
  handler, which owns it until submit. Nothing is kept for a later connection.
- *Consumer side* (`hostops backup --live`): writes into a temp file in the destination directory,
  checks length, SHA-256 and the archive structure against the `snapshot.start` answer, then
  renames; a partial output is deleted and never merged with a retry (a retry is a new
  `snapshot.start`, a new file). Every op is audited (peer uid/pid, op, size), never with secret
  material. Tests: foreign uid, symlinked or stale socket, slow peer, disconnect after submit, a
  second concurrent start, hold limits.

Backup "without recordings" still snapshots the journal head and lists every recording as
`not-requested`, so a restore never mistakes it for a backup that lost them.

**Backup snapshot** (`backup_snapshot`):

1. Await the barrier. On the DB thread: `VACUUM INTO` a private temp file (time budget 120 s:
   `sqlite3` interrupt beyond it, backup fails `backup.busy`, barrier released); read the
   `keys.wtk` bytes and the volume journal bytes up to its head (member, length and SHA-256 fixed
   here); pin every gen_id listed by the descriptors **read from the VACUUM copy** (never from the
   live connection) and open their fds; for each `tx_migration` `pending` row, open and pin the
   legacy plaintext fd (identity checked against the row), so a migration cannot unlink it before
   it is copied. Release. The barrier is held for the whole `VACUUM INTO` (it is not
   "milliseconds"): it delays publications only (the §12.11.1 backpressure applies); terminal output
   keeps flowing. Duration is measured in the performance gate (§9).
2. Ownership of the pins and fds passes to the worker **at submit**: a cancellation before submit
   releases them in the coroutine; from submit on, only the worker's own `finally` releases them
   (through the thread future's done-callback), never the awaiting coroutine — a cancelled request
   does not unpin a running copy. `retire` then unlinks what it deferred.
3. Worker, **per recording pair** (all generations of `.out` and `.cast` of one sid), two passes on
   the pinned fds:
   - *Verify pass* (nothing emitted): every generation of both kinds, exactly `phys_len` bytes,
     header, every record, counts, SEAL for sealed, with the RK from the VACUUM copy. A pair that
     fails is **excluded as a unit** (§12.11.8 Q3): no member of it is written, manifest entry
     `excluded` with the reason, System health alarm naming it, the backup continues.
   - *Emit pass:* copy exactly `phys_len` bytes per generation into `transcripts/<name>.wtx` (tar
     size = `phys_len`), re-verifying while copying. A mismatch here (the media changed under a pin)
     cannot be withdrawn from a streamed WTS1, so the container is **abandoned** (temp removed) and
     rebuilt once from step 1 with a new content key and that pair excluded; a second failure fails
     the backup.
   No plaintext is written to disk by either pass (decrypted bytes live only in bounded memory for
   the verification). `.idx` files are never archived. Legacy plaintext is copied from its pinned fd
   through the current allowlist and listed as `legacy`.
4. **Corruption ≠ fault.** Only an authentication / structure failure of the recording itself
   excludes a pair. An I/O error (EIO), disk full, a DB, keyring or journal error, or a budget
   overrun fails the whole backup: temp removed, pins released, nothing published (§12.10). The
   worker keeps the §12.10 budgets.

**Content manifest** `wts-content-2` = v1 + `recordings: [{sid, kind, state, generations: [{gen,
phys_len, state}]}]` with `state` ∈ `included` \| `legacy` \| `excluded` (+ `reason`) \|
`not-requested` \| `one-kind` (the other kind never existed); `erasure_journal: {member:
"erasures.wtj", length, sha256, head: {n, mac}, attested: [{destination id, n, time}]}`. Member
allowlist: the v1 members, `transcripts/<sid>.<k>.<gen>.wtx` named by an `included` entry,
legacy files named by a `legacy` entry, `erasures.wtj`; nothing else. The manifest, the journal
member, the descriptors and RK envelopes of the DB copy, `keys.wtk` and the DB's `erasure_head`
must agree (head in DB = head in manifest = last entry of the member). The restore reader accepts
v1 and v2; a **v1** content (PR4-era backup) may contain plaintext 3.7 transcripts: they are
restored as `legacy` and migrated (§12.11.5), never treated as "no recordings".

**Restore of recordings** (extends §12.10 stage/apply):

- *Stage:* every `.wtx` member is listed in the manifest and named by a descriptor of the staged DB
  (otherwise refused); every staged descriptor is decoded with the staged keyring and RK envelope
  and every generation passes `verify` within the restore budget; member size == `phys_len`
  exactly. A descriptor whose generation is absent → refused, unless the manifest lists that
  recording as `excluded` or `not-requested` → `status = absent` ("not in this backup"); `one-kind`
  → the missing kind is `absent` without alarm. The journal member must match the manifest's
  length, SHA-256 and head.
- *Apply:* the §12.10 flag journal, unchanged. Immediately before the switch, under the boot lock,
  the erasure sources are reconciled **again** (§12.11.4 "Continuity at restore"): an erasure made
  between stage and apply is in the live volume journal, which is kept next to the staging and is
  never replaced by a shorter candidate. At the boot after it, before readers: erasure re-apply,
  `live` → `recovered`, ledger rebuilt from the restored DB against the files present. Both steps
  are idempotent after a crash. Files present that no restored descriptor lists (the R-M1 "live transcripts kept" case,
  same installation) are orphans (listed, never served); another installation's live `transcripts/`
  goes to quarantine as in R-M1.

#### 12.11.4 Erasure (contract 3)

**Four operations, kept apart:**

| Operation | Effect | Survives a restore? |
|---|---|---|
| archive (`archive_closed_transcripts`, `delete_session`, `purge_host`) | `archived_at` set; never served (as in 3.7, archived files are not readable through the app) | yes, archived — **unless** the backup was taken before the archive: then the recording comes back un-archived (readable again). The UI says so next to the backup date ("recordings archived after this backup are restored as active") |
| purge (janitor, `archived_at` + `ARCHIVE_RETENTION_DAYS`) | descriptors, RK and files deleted; **no tombstone** | the restored copy keeps the state it had in the backup (archived → purged again by the next janitor pass; active → see the row above). Only an erasure is guaranteed to survive a restore |
| erasure (explicit, §12.11.8 Q1) | tombstone + RK destroyed + files retired | re-applied (below) |
| quarantine | recordings not served pending proof | — |

**What "key destroyed" means.** The active RK envelope row is deleted and the unwrapped RK dropped
from memory caches. Copies may remain, outside this guarantee, in the SQLite WAL and free pages
until checkpoint/VACUUM, in filesystem or VM snapshots, in process memory already paged out, and in
backups taken earlier (which are authorized copies and expire with their retention, §11.4). The
journal keeps the sid, the time and the RK hash: metadata that can be correlated with other logs,
though it holds no terminal content.

**Journal** `DATA_DIR/erasures.wtj` (§12.5), all integers little-endian:
header `"WTJ1"` | ver u8 = 1 | reserved 3 B = 0 | installation id 16 B (24 B); then entries of 97 B:
`n u64 (1, 2, … no gap) | time u64 ms | sid 16 B | kinds u8 (1 = out, 2 = cast, 3 = both; other
values refused) | rk_hash 32 B | mac 32 B`, mac = HMAC-SHA-256(K_erase, `"wt/v1/wtj-entry"` ‖
installation id ‖ previous mac (32 zero bytes for n = 1) ‖ entry without mac), K_erase =
HKDF(KWK, "wt/v1/erase"). Head = (n, time, mac). Cap: 2²⁰ entries (≈ 100 MiB); at 90 % a System
health warning, at the cap erasure is refused (`transcript.erasureJournalFull`) until a later PR
defines compaction — the confirmed history is never truncated. Appended with `O_APPEND`, fsync
(+ directory at creation). **Committed head** = the DB's `erasure_head`, written in step 2 below.
**Incomplete tail:** bytes after the last whole authentic entry are allowed only beyond the
committed head (a crash during step 1): the boot copies the journal up to the last authentic entry
into a new file (tmp `O_EXCL` → fsync → rename → directory fsync) and keeps the cut bytes as
`erasures.wtj.tail-<time>` for diagnosis. A partial or non-authentic entry at or before the
committed head is never repaired: it is the quarantine case below.

**Order of `erase(sid)`** (session not live, else 409 as `delete_session`):

1. Lease → barrier: append the tombstone, fsync (the one fsync allowed under the barrier: ≤ 97 B,
   with its own time budget, 5 s, beyond → the route answers 503 and the boot decides from the
   file). In the same synchronous section, before releasing the barrier: add the sid to the
   in-memory tombstone set and bump `revocation_epoch[sid]` (§12.11.2): from here `open` refuses it,
   open snapshots and streams stop at their next check point, caches are dropped.
2. Same barrier, one isolated transaction: revoke the live share and the replay links (`shares`
   helpers), `DELETE session_keys`, delete both descriptors, ledger → `retired`, `erasure_head =
   (n, time, mac)`. Release.
3. `retire` the files (deferred while a running backup pins them: that backup's DB copy predates
   the erasure and still holds the RK — the accepted "copies in backups expire" limit, §11.4).
4. **Attestation (off the barrier, janitor):** per configured off-host destination, upload the
   journal as an **immutable** object `<installation id>.erasures.<n as 16 hex>.wtj` (never
   overwritten; a destination that cannot refuse overwrites uses a fresh name per upload and the
   reader takes the highest valid n), then read it back and authenticate it. Success for that
   destination → `attested_heads[destination] = (n, time, object name)`, committed. The erasure is
   **attested** when every configured destination holds a head ≥ its n. Failure → retry with
   backoff; System health: "erasure n not attested on <destination> since …", per destination.

The route answers `{erased: true, attested: bool}`; until attested, the UI says the erasure
survives restores on this volume only. Crash points: before 1 is durable → not erased (the route
never said so); between 1 and 2 → the boot re-applies; between 2 and 3 → ledger `retired` → unlinked
at boot; before 4 → retried. **Per-host erasure** (§12.11.8 Q1): the list of sids is fixed when the
Owner confirms it (sids of that host the Owner is authorized for, shown before confirming); each
sid is a separate `erase` with its own tombstone; live sessions are skipped and listed (409 each);
the result lists erased / skipped / failed per sid, and a partial failure is not reported as done.

**Every boot** (after keyring, restore apply and schema, before recovery of §12.11.1 and before
readers): verify the journal (installation id, chain, MACs, n without gaps). Missing journal with
`erasure_head.n > 0`, a journal whose entry n = `erasure_head.n` has a different mac (fork), a
journal shorter than the committed head (rollback), or a broken chain at or before the committed
head → **every recording is quarantined**, System health critical with the diagnosis (prefix /
fork / rollback); terminals and new recordings (new RKs) keep working. Journal ahead of the DB head
(crash after step 1) → re-apply steps 2–3 for the missing entries. Any tombstoned sid that still
has an RK (a restore) → destroyed the same way. Each step is repeatable after a crash.

**Freshness (H3).** A MAC chain proves authenticity and order, not freshness: an authentic but old
head (delayed upload, destination rolled back to an older version) is still authentic. Rules:

- Every source is compared on (installation id, n, mac of entry n, time). The **newest authentic
  head wins**: the longest chain that every other authentic source is a prefix of. An authentic
  source with a smaller n never overrides a larger one; two authentic sources that differ at the
  same n are a fork → refused.
- A destination whose newest object has n lower than the `attested_heads` recorded for it in **any**
  source (volume DB, backup manifest, another destination's knowledge) is **rolled back**: it is
  not proof, System health names it.
- Proof of freshness for a restore exists only if: the live volume journal J_v of the same
  installation is present, **or every** destination configured in the staged DB and on the current
  host answered with an authentic, non-rolled-back head. One unreachable destination, with no J_v,
  is no proof (strict choice: the erasure may have been attested only there).

**Continuity at restore** (V3-H4): candidates are the backup's journal J_b (bound by the manifest's
`erasure_journal`), the volume journal J_v (same installation, authentic) and the off-host objects
J_d (fetched from every configured destination). All must authenticate under the staged keyring's
K_erase and lie on **one** chain (each a prefix of the longest, J*); two authentic journals that
diverge → stage refused (`backup.erasureConflict`). The reconciliation runs at stage **and again
under the boot lock immediately before apply** (above), and before any quarantine is lifted.
**With proof** (rule above), every tombstone in J* is applied before access and J* becomes the
volume journal (never a shorter one), published durably together with the dataset state, repeatable
after a crash. Erasures not yet attested when the volume was lost cannot be known: that window is
the one the route and System health report while attestation is pending. **Without proof** (new
host, no destination, a destination unreachable or rolled back): the restore may proceed, but every
restored recording gets `status = quarantined`, System health says "erasures after <backup date>
cannot be proven"; a later janitor pass that obtains proof applies the tombstones of J* and lifts
the quarantine. With no independent freshness reference at all, the quarantine stays: that is the
stated limit, not a defect.

**Owner recovery mode** (route in a later PR): owner-level account, fresh factor
(`stepup.require_fresh_factor`), typed confirmation naming the backup date, audited, security
e-mail. Effect: recordings quarantined **for missing continuity proof only** move to `status =
recovery`: readable by Owners only, no live share, no replay link, no search hit for anyone else,
each read audited, UI banner "recovered without erasure proof"; the erasure guarantee is suspended
for them. A known tombstone, a corrupt or damaged recording, an absent one and a keyring-epoch
quarantine are **never** opened by recovery mode. Releasing to normal access is one recording at a
time (no "release all"), each release a separate Owner action with a fresh factor, audited, with a
security e-mail; re-quarantine is allowed. The permission is bound to the recovery route's own
authorization (`access`, §12.11.2), not to a parameter.

#### 12.11.5 Migration of plaintext recordings

A background job (janitor), one session at a time **under its lease**: closed sessions first, then
`arhiva/` files, then `lost` sessions. A live session is converted at its writer start, under the
lease, before the hub opens its first generation (attach waits, bounded by 2 × 64 MiB of AES; at
most 2 conversions at once during the boot reconcile); `list_epoch` is bumped for it.

**Inventory (H5).** At the first boot of a protected volume, before any migration or writer, one
listing of `transcripts/` and `arhiva/` through their fds (no links followed) fills `tx_migration`
in one transaction: per (sid, kind) the directory, name, `dev`, `ino`, `size`, `mtime_ns`, state
`pending`; a kind of a sid that has the other kind but not this one → `missing` (a legitimate
one-kind recording, not an error); an `arhiva/` file whose session row is gone → `orphan` (migrated
like the others with `origin = orphan`; readable only by owner-level accounts through the
authenticated download route, listed in System health). Anything outside the §12.10 allowlist, a
link, a non-regular file or `st_nlink ≠ 1` → `failed` with the reason, never migrated, listed. A
plaintext file that appears later and is not in the inventory is never served and is reported.
The inventory is the only source of "this sid may still be plaintext" (§12.11.2 `open`).

**Exclusivity.** Each step below runs under the sid's lease, which the coordinator, archive,
purge, erasure and reconcile also take, so no other modifier of that sid runs meanwhile.

Per session (`.out` and `.cast` as a pair; each kind tracked separately in `tx_migration`):

1. Open the plaintext through the `transcripts/` (or `arhiva/`) dir fd with `O_RDONLY|O_NOFOLLOW`;
   `fstat` must match the inventory row (`dev`, `ino`, `size`, `mtime_ns`), regular, `st_nlink ==
   1`; otherwise → `failed` (changed since inventory), listed. Free space ≥ 2 × size + 64 MiB, else
   postponed (`disk`). The fd is kept until step 6.
2. RK: create if absent (`origin = migrated`, or `orphan`).
3. Per kind: reserve, create, encrypt from the pinned fd while hashing the plaintext (SHA-256),
   seal, fsync, directory fsync. No truncation: the generation holds the whole file.
4. `verify_full` read-back: decrypted SHA-256 and length equal the plaintext's, and the pinned fd's
   `fstat` is still the row's (otherwise retry later). The SHA-256 goes into the row.
5. Lease → barrier, one transaction: both descriptors (`sealed`, flag `converted`), ledger
   `published`, `tx_migration` → `converted` with the SHA-256, `archived_at` = the file's mtime for
   `arhiva/` files (the retention clock is kept), `list_epoch` bump for a live session. From this
   commit, plaintext for this sid is a refused downgrade (§12.11.2), even if its descriptor were to
   vanish later.
6. Per kind, **identity-checked unlink**: `renameat2(dirfd, name, dirfd, ".wt-del-<random>",
   RENAME_NOREPLACE)`, then `fstatat(dirfd, ".wt-del-<random>", AT_SYMLINK_NOFOLLOW)` must equal
   the pinned fd's (`dev`, `ino`, `size`, `mtime_ns`) and the row's; then `unlinkat` of that private
   name, directory fsync (the effective directory: `transcripts/` or `arhiva/`), row → `unlinked`
   (committed per kind). A mismatch renames the file back (`RENAME_NOREPLACE`; if that fails it
   stays under the private name, listed), keeps it, sets `failed` and raises an alarm. **Only the
   verified inode is ever deleted; unverified plaintext is never deleted.**

**Crash and partial unlink.** At boot, per row: `converted` with the file present → repeat step 4
against the published generation, then step 6; `converted` with the file already absent (crash
after `unlinkat`, before the row update) → `unlinked` after checking that no `.wt-del-*` name
holds it (a leftover private name with the row's identity is unlinked; with another identity it is
listed); `pending` with a published descriptor cannot occur (step 5 is one transaction) and is an
integrity alarm. A layout outside this model (both a descriptor without `converted` and a
`pending` row, two files for one row) is refused and listed, never guessed.

Errors leave the plaintext in place, retry with backoff (1 h). System health shows "recordings:
migrating n / N (bytes), converted c, one-kind m, failed k, orphans o, last error". Leftover
`.cap-tmp` files are removed at boot as today, before the inventory. The global flag
`tx_state.recordings_format = wtx1` is published only when **no row is `pending` or `failed`**
(failed rows must be retried or deleted by an Owner, audited); then `arhiva/` is removed if empty,
and from then on any plaintext under `transcripts/` is refused by readers and reported. The
protection state of recordings is "protected" only then (and only with the MK outside the volume,
§2).

#### 12.11.6 Idle detection and other mtime users

| Code | Today | Protected volume |
|---|---|---|
| `idlesess._transcript_mtime` | `.out` mtime | the newest of the hub's live `last_output_at` (in memory, includes output not yet committed) and `tx_descriptors.committed_at` of (sid, out); a `pending` legacy sid keeps its file mtime while the plaintext exists; **unknown → `None`** (fail closed: no auto-close) when the recorder is `degraded`, the key is invalid, the writer is not yet adopted after a restart, a checkpoint is behind (pending buffer not empty or a job in flight), the recording is quarantined, or there is no source at all. Absent is never read as idle. The agent-side guards stay. |
| `api._last_output` | hub `last_output_at`, else `.out` mtime | hub, else `committed_at`; same "unknown" cases |
| `purge_archive` | file mtime (reset by `archive_transcript`) | `archived_at` |
| `archive_closed_transcripts` "already archived" | the files are gone | `archived_at IS NOT NULL` |
| `replay.redacted_cast_file` cache | (path, mtime_ns, size) | §12.11.2 key |
| `transcript_stats` | stat-walk | descriptors |

`committed_at` moves only when the `.out` plain_len grows, so a roll, seal, cap or migration does
not look like activity (a migration sets it to the plaintext's mtime, never to now); a restore
keeps the restored values; a cap does not move it. Times are wall-clock: a clock step backwards
makes an idle age negative → treated as "active" (no auto-close), a step forward can close a
session early only by the size of the step, the same as 3.7. No code reads a generation file's
mtime (source-scan test).

#### 12.11.7 INV-14, phase 2 (recordings), and acceptance tests

Text to add to INV-14 when the writers ship:

*On a protected volume every recording is written only as WTX1 generations under its own session
key, and nothing else under `transcripts/` holds its plaintext once it is migrated. A writer uses
exactly one generation at a time, and a generation is never written twice: fresh random gen_id,
reserved, created exclusively, never reopened. One coordinator per session serialises every
checkpoint end to end, and the DB publishes both prefixes and the upstream agent offset in one
isolated transaction that can only extend what is committed. A reader serves only the committed
prefix of an authentic descriptor, reaching each returned byte through an authentic index or a
verified parse; bytes past the watermark are never served; plaintext is refused for any session
that is converted or not in the migration inventory (per session and kind, not only after the
global flag). Authorization, descriptor and file handles are fixed together at one check, and a
revocation stops every open stream at its next chunk and every cache before it serves. A backup
reports only a coherent set: the committed prefixes named by the descriptors of its own DB
snapshot, taken by the same function on every path, with a recording pair included or excluded
as a unit. An erasure is journalled before its key is destroyed and re-applied at every boot
before any reader; removing live access is immediate, the restore of an older copy re-applies it
only with a fresh proof of the newest erasure head, and historical backups keep their copies
until they expire. A restore without that proof serves the restored recordings to nobody but an
Owner in recovery mode, and recovery mode never reopens a known erasure. Only a verified,
identity-checked plaintext file is ever deleted.*

Acceptance tests (each named in the PR; fault injection at every fsync and every transaction):

1. Crash at every row of the recovery table → the stated recovery; boot twice is idempotent.
2. Nonce: a broken writer, a crash and a restore never reuse (RK, kind, gen_id); `O_EXCL`
   collision and UNIQUE collision retry with a new id.
3. Commit atomicity: offset and both descriptors move together (DB failure injected between
   statements); a restart after a crash replays from the committed offset with no duplicate.
4. Readers: bytes past the watermark are never returned, even when they authenticate; a tampered
   interior record outside the read window is caught by `verify`, not by the range read; an index
   for another gen / data_count, a stale index, a length-scan-consistent but tampered prefix are
   refused; budgets refuse with their codes.
5. Each reader of the §12.11.2 table, concurrent with cap, merge, migration, archive, purge and
   erasure: no mixed inodes, `list_epoch` fallback, resume at the exact logical offset, OSC 133
   span, preview, search budgets, redacted replay across record boundaries.
6. Downloads byte-identical to the 3.7 plaintext for the same input (including after cap, roll and
   writer restarts); Range on plaintext offsets, 416, multi-range → 200, `If-Range`.
7. Cap output byte-identical to 3.7's `_maybe_cap` for the same input.
8. Backup: barrier call-site enumeration; descriptors from the VACUUM copy; pins survive request
   cancellation and are released only when the worker ends; copied size == `phys_len`; a corrupt
   recording is excluded and reported; disk full during the copy.
9. Restore: unlisted member, size ≠ `phys_len`, a foreign descriptor, an absent generation, a
   backup without recordings (`absent`), orphans after an apply.
10. Erasure: crash between every step; open download cut at the next record; share and replay
    links dead; journal missing / truncated / forked / foreign → quarantine or refusal; continuity
    with J_v, with J_d, without proof → quarantine; Owner recovery mode access rules and audit.
11. Migration: closed, archived, orphan, lost, live-at-writer-start; disk full; plaintext changed
    while converting; crash after publish (re-verify before unlink); downgrade refused per sid
    once converted and globally after `recordings_format = wtx1`.
12. Markers: a known plaintext marker written into a session is absent, as plaintext, from every
    in-scope artefact — every file under `DATA_DIR` except the DB (phase 1) and the inventoried
    legacy files not yet migrated (listed exceptions), backups, temp spool and restore staging —
    **and** round-trips: reading the recording through the app with the right key returns it, and
    decrypting each artefact with the right key finds it where expected. Absence from compressed
    bytes alone is not accepted as proof.
13. No generation mtime read anywhere; idle detection from hub + `committed_at`; unknown, degraded,
    invalid key, writer not adopted, checkpoint behind → no auto-close; clock stepped back and
    forward.
14. Coordinator: S2 captured after S1 but committing first is impossible; forced out-of-order
    commit is refused by the CAS / monotonic check (no smaller prefix, no older agent offset);
    cancellation of the caller before submit, during append, during fsync, after commit; teardown
    and re-adoption with a job in flight; checkpoint concurrent with cap revalidation and with
    migration of a live session; uncertain `COMMIT` outcome (committed / not committed / unknown)
    resolved from the DB; a burst crossing the 90 % mark and the hard limit in one batch;
    backpressure cap → gap at the recorded position.
15. Readers × revocation: erasure, share revoke, replay-link revoke and role change between
    authorization and fd open (snapshot refused and fds closed), during a stream (cut at the next
    chunk, max delay measured), with a cached and a just-computed redacted response (never
    served); Owner recovery cannot open a tombstoned, corrupt or absent recording; public replay
    routes do not accept the authenticated download's authorization; budgets per route and in
    aggregate (many small generations); Range 416 with `Content-Range`, corruption after headers
    → abort.
16. Backup: in-app, scheduled, cloud, safety copy, `hostops backup --live` (through the gateway,
    refused when the socket is not reachable) and with the app stopped; include / exclude as a
    pair (a corrupt `.cast` after a good `.out`: nothing of the pair emitted; a mismatch during
    emission → container rebuilt with a new CK); corruption vs EIO / ENOSPC / DB / keyring /
    journal faults (only corruption excludes); cancellation before submit, during copy, after
    emission; legacy plaintext pinned against a concurrent migration unlink; manifest v1 with
    plaintext transcripts, v2 with zero recordings, one kind only, `not-requested`.
17. Erasure freshness: erase after stage and before apply (re-applied); uploads completing out of
    order; a destination rolled back to an older object; two divergent authentic sources; one
    destination offline out of several (no proof → quarantine); incomplete journal tail beyond and
    at the committed head; journal at the cap; fsync of the journal uncertain.
18. Migration: inventory with one kind only, orphan, failed; file replaced by another inode
    between read and unlink (not deleted, renamed back); crash between the two unlinks of a pair,
    and after `unlinkat` before the row update; plaintext reappearing for a converted sid whose
    descriptor was removed (refused); global flag withheld while a row is `pending` or `failed`.
19. Performance gate on every supported platform: slow fsync (injected latency) and a large
    `VACUUM INTO` while sessions stream: loop latency, backlog, backpressure gaps, barrier hold
    time.

#### 12.11.8 Owner decisions (2026-11-24) and the original questions

Decided by the owner on 2026-11-24, each the recommended default below: **Q1** erasure = only an
explicit Owner action with a fresh factor (retention purge writes no tombstone); **Q2** an erasure is
done locally at once and shown as "not yet attested off-host" with a System health warning until the
upload succeeds; **Q3** a backup excludes a recording that fails its integrity check and raises an
alarm naming it; **Q5** a live session whose recording writes fail keeps running, marked "recording
degraded", with an alarm and an audit entry (availability over strict compliance, by choice); **Q4**
the recommended default stands (Owners only, every read audited, released one recording at a time). Also
confirmed on 2026-11-24: a restore without proof of erasure continuity (volume journal gone and any
configured destination unreachable) **quarantines** the restored recordings until proven (Owner
recovery mode excepted); a host live backup whose gateway control socket does not answer is
**refused with an alarm** (never an uncoordinated copy, never an automatic stop of the app).
Accepted as written: the erasure journal cap refuses new erasures until compaction exists; failed
migrations block the global "fully migrated" flag; a role/permission change pauses open streams
for a re-check.

| # | Question | Recommended default |
|---|---|---|
| Q1 | Which operations are erasures in 3.8.0? | Only an explicit "Erase recording" (per session and per host), Owner-level with a fresh factor; archive and retention purge stay non-journalled. |
| Q2 | Is an erasure "done" before its head is attested off-host? | Yes, done locally, reported `attested: false` with a System health warning until uploaded; with no destination configured, the UI says it survives restores on this volume only. |
| Q3 | A backup meets a corrupt recording. | Exclude that recording, list it in the manifest, alarm; do not fail the whole backup. |
| Q4 | Owner recovery mode access. | Owners only, per-read audit, released per recording by an explicit Owner action. |
| Q5 | Disk full / repeated write errors on a live session. | Keep the terminal running with the recording `degraded` (gap-marked, alarmed), as an unrecorded terminal is better than a dead one on a full disk; the stricter alternative is to lock the session's input until recording resumes. |

#### 12.11.9 Review (2026-11-24) → resolution

Independent design review of §12.11 (static, no code). Each finding and where it is now resolved.
Owner decisions (§12.11.8) unchanged; M5 tightened their wording in §12.11.4, not their substance.

| Finding | Resolution |
|---|---|
| H1 checkpoint not serialised end to end; S2 can commit before S1; autocommit helpers; uncertain commit; stale compactor; roll overrun | §12.11.1 "Per-session coordinator" (one queue per sid, lease held capture → fsync → commit, buffer swap, shielded jobs), "Isolated transaction" (own connection, CAS on version + writer token, monotonic prefix and agent offset, typed cap/merge), "A checkpoint that loses", "Uncertain outcome"; hot path step 2 (hard-limit reservation per record); Cap step 4 (revalidation); tests §12.11.7 #14 |
| H2 per-pair exclusion impossible while streaming; host live backup not under the barrier | §12.11.3 "One snapshot function, every path" (control socket for `hostops backup --live`, boot lock offline, refusal otherwise), snapshot steps 1–4 (legacy fds pinned, ownership at submit, verify pass then emit pass, rebuild with new CK, corruption ≠ fault), manifest v2 states; test #16 |
| H3 authentic but stale erasure head; stage/apply window | §12.11.4 journal format, attestation (immutable per-head objects, per-destination read-back), "Freshness" (newest authentic head wins, rollback detection, all destinations or J_v), "Continuity at restore" (reconcile again before apply and before lifting quarantine); §12.11.3 *Apply*; test #17 |
| H4 no common linearisation point for revocation and open; caches and streams after revoke | §12.11.2 `open(…, access)`, "Revocation and the linearisation point", "Check points while serving" (bound restated in "What a revocation stops", recheck R-M3), "Caches"; Owner recovery limited to the continuity quarantine (§12.11.4); test #15 |
| H5 unlink does not prove identity; partial unlink; global marker too coarse | §12.11.0 `tx_migration` and WTD1 `converted` flag; §12.11.5 inventory, identity-checked unlink (`renameat2` + `fstatat` + `unlinkat` on the dir fd), crash rules, global flag only with no `pending`/`failed`; §12.11.2 per-sid downgrade refusal; test #18 |
| M1 ledger may unlink a pre-existing file; ambiguous pending; no epoch in WTD1 | §12.11.0 `tx_files` states + inode, ledger compaction, keyring epoch binding; §12.11.1 reservation (`collision`), recovery table rows |
| M2 manifest v2 and WTJ1 under-specified | §12.11.3 manifest (states, journal member, allowlist, binding, v1 legacy); §12.11.4 journal (endianness, kinds, MAC domain, cap, committed head, incomplete tail) |
| M3 reader routes, budgets, Range, ETag, rolling verify, one-kind pairs | §12.11.2 reader table (attach/resync, link creation and lookup, public replay text/cast), budgets table (aggregate, fds, cancel, verify cursor), Range/416/headers, ETag with watermark, "one kind only" |
| M4 sync I/O on the loop, VACUUM backlog, incomplete mutation list, degraded gap rules | §12.11.1 hot path (append off the loop), "Backpressure", degraded rules; §12.11.3 exhaustive mutation list, VACUUM budget; §12.11.4 journal fsync exception; test #19 |
| M5 retention vs restore, "release all", key-destruction wording, per-host erasure | §12.11.4 retention table, "What key destroyed means", per-host erasure, Owner recovery (per recording, fresh factor) |
| M6 last committed output is not proof of idleness | §12.11.6 table and clock rules; test #13 |
| L1 normative clarifications | §12.11 intro (pointers stay "in review"), §12.11.0 (256 vs 4096), §12.11.1 `recovered` and zero-DATA generation |
| Recheck (ee2068b) R-H1 PR5/PR6 split leaves existing volumes and restore uncovered | §12.11 intro "PR5/PR6 boundary": `WEBTERM_TX_RECORDINGS` off by default and set only by test gates; off = 3.7 behaviour for recordings and their backup; on = boot refuses a protected volume until PR6's migration, erasure journal and quarantine report ready (test-fixture volumes excepted, guarded); PR5 never claims erasure continuity (`erasure: not-tracked`), refuses WTX1/WTJ1 archives outside tests |
| Recheck (ee2068b) R-H2 recorder fate after worker loss / overflow during a commit / restart | §12.11.1 "Backpressure" (per-sid + process cap, no rewind while a job is in flight, resume from the re-read commit, one gap marker with position and size, `degraded` per Q5) and "Supervision, worker loss and restart" (supervisor, futures always resolved, fds/lease released after real I/O end, re-adoption from DB only, no second append, exactly-once-or-marked guarantee); test #19 extended |
| Recheck (ee2068b) R-H3 expiry and the commit→bump window for open streams | §12.11.2 "Expiry" (`not_after` from bindings, share/replay links, login session, step-up window; checked at the same points plus a timer for stalled transports), "Commit/bump fence" (bump before commit + fence, re-check after, fresh `access`; out-of-process writers via `tx_state.access_gen` poll) |
| Recheck (ee2068b) R-M3 the "~128 KiB" bound did not follow | §12.11.2 "What a revocation stops": (1) no unit authorized after the linearisation point, at most one already-checked chunk ≤ 64 KiB or one capped single-shot body; (2) bytes already in the transport are not recallable and not bounded by this design; all bodies > 64 KiB streamed |
| Recheck (ee2068b) R-M1 live backup socket protocol | §12.11.3 "Control socket protocol": creation on a checked dir fd, peer check, versioned framing with allowlisted ops (`snapshot.start` / `read` / `release`), full verification before any byte is offered, timeouts, hold limits, concurrency cap, release on disconnect, consumer temp-then-rename |
| Recheck (ee2068b) R-H4, R-M2, R-M4, R-M5, M6 | not addressed here: R-H4 (WTJ1 freshness authority) and R-M5 (durable unlink identity) are PR6 gates; R-M2 (output frontier for other destinations, WTS v2 cardinality) and R-M4 (WTJ1 crash/epoch reconciliation) stay open before activation; M6 residual unchanged |


#### 12.11.10 Implementation notes (PR5a, txstore)

Recorded from the PR5a implementation and revised after its review (2026-11-24):

- `tx_descriptors.list_epoch` is an unauthenticated column: a hint for resume / OSC 133 offset
  consistency only. Routes must never use it as proof of authorization or integrity, and re-check
  the committed bounds when they resync.
- WTD1's former reserved u16 is `flags` (`FLAG_CONVERTED = 1`, unknown bits refused, `ver` stays 1;
  flags 0 keeps the v1 bytes). A WTD1 vector with `flags = converted` must be added to the appendix
  before any interoperability.
- `txformat.RecordCursor` is the public checked parse-from-entry API used by readers and `verify`
  (type, seq, tag, watermark on seq). Every parse reads through a reader clamped to the
  generation's committed `phys_len`, and the request budget is charged for physical bytes before
  each read, so no byte past the committed prefix is ever read.
- An RK-binding failure (`rk-mismatch`, `bad-rk-envelope`) is reported as `keyError`, and recovery
  skips all ledger clean-up for a sid whose descriptor cannot be authenticated.
- Publication unit (§12.11.1): a checkpoint whose publication fails is not lost. The bytes stay in
  the writers and the next publication carries everything the writers hold beyond the committed
  prefix (both kinds), together with the agent position of the last appended capture. If that
  publication fails again at a `resume`, the generations are abandoned (published live →
  `recovered` at its committed counts, unpublished → retired), and the offset never covers bytes
  that are not published. An uncertain COMMIT is resolved by re-reading the descriptors, the agent
  position and the ledger rows in one read transaction.
- **Admission (the contract the PR5b hub must follow; rechecks 059f21a R-H2, 5053fbd RC-H2,
  RC-M2 and 1824838 R2-H1, R2-M2).** Two positions exist per sid: the **received** position (`Recorder.received`: the end
  of everything offered in the current epoch, admitted or counted lost) and the **committed**
  position (`agent_committed`, `sessions.agent_epoch/agent_offset`, published together with the
  bytes it covers). The hub follows these rules:
  - *One call per agent chunk:* `feed(out, cast, at=(epoch, offset), agent_bytes=n)`. `at` and
    `cast` are mandatory, `n > 0` (default `len(out)`), and at least one representation is
    non-empty. The call admits the `.out` bytes and the `.cast` event together, or neither. An
    explicitly empty `cast` means the format omits that event: the offset still moves with `.out`
    and is committed with it. `.cast`-only events (the header, resizes) use
    `feed_cast_only(cast, at=received)`: they never move the offset and keep their call order
    relative to the chunks.
  - *Preconditions for `at`:* the epoch must be the recorder's (a new epoch goes through
    `change_epoch` first), and the offset must be exactly `received`. During an overflow, a chunk
    lying entirely below `received` is a re-offer: it returns `False` and is not counted again.
    Any other mismatch (a hole, a partial overlap, a duplicate outside an overflow, another epoch)
    raises `TxStoreError("position")` before anything is admitted or counted. Malformed input
    raises `badInput`. Both are hub bugs and retryable: nothing changed, and the hub resends from
    its ring at `received`.
  - *`False` is final for those bytes, and `ingress()` says why.* `overflow`: each refused
    upstream byte is counted once, keyed by its position; per-kind counts are real recorder bytes,
    never synthetic marker bytes. The hub calls `resume()`, which returns C = the committed cursor,
    re-attaches the agent from C, and replays what the ring still has. `closing` (counted in
    `rejected`) and a stopped recorder (`lost`/`replaced`/`closed`, counted in `refused`) stop
    ingress at once. After `close()` or a re-adoption, no later chunk reaches the recorder; the
    hub feeds the re-adopted recorder from its committed position.
  - *Four outcomes, never mixed.* (1) **Offer refused, retryable:** `TxStoreError` `position`,
    `busy` or `badInput` from `feed` / `feed_cast_only` / `skip_to` / `change_epoch` / `resume`.
    Nothing was admitted, counted or moved; the hub re-reads `received` and offers again. (2)
    **Interval replayable later:** `feed` returned `False` with `ingress() == "overflow"`. The
    bytes are counted in `loss` (keyed by position) but the agent ring may still have them:
    after `resume()` the hub replays from C, and `resume()` resets the count. (3) **Terminal loss:**
    the ring no longer has [C, replay_start) (a skip), the old epoch's uncovered bytes at a cut, or
    what is left unrecorded at close. Each becomes ONE marker with a `tx_gaps` row; a marker that
    cannot be published is `transcript.gapUnrecorded` and a row with `published_at` NULL. Refused
    `.cast`-only events are terminal at once (they are not in the ring). (4) **Marker accepted:**
    only a resolved `skip_to` future, a resolved `change_epoch` future or a resolved `close()`
    means the marker, its row and the cursor are committed.
  - *Attach answers:* with `replay_start` == C there is nothing to do. With `replay_start` > C
    in the same epoch (the ring lost the prefix), the hub calls `skip_to(epoch, replay_start,
    reason)`. It is a dedicated job carrying the operation's identity (a random op nonce and its
    `gap_id`) and the interval [C, replay_start). Until it commits, `received` is `replay_start`
    and any offer at or after it answers `busy` (below it: `position`), so nothing can overflow
    and drop the marker. The marker, its `tx_gaps` row and the new cursor are published in one
    transaction, and the future resolves only when the committed state holds exactly that row and
    `(epoch, replay_start)`. Otherwise it fails explicitly: `skip-refused` (the cursor moved
    before the capture, e.g. an earlier checkpoint hit a write fault: nothing counted for the
    interval), `skipNotPublished` (the write or the publication failed: the bytes admitted before
    the skip count as loss, the interval and the synthetic marker bytes do not, and the recorder
    is in overflow at the skip's start), or re-adoption (`RecorderLost`, e.g. a refused or unknown
    commit). After a failure the hub calls `resume()`, re-attaches from C and skips again; the
    next skip covers the interval. A second `skip_to`, a `resume` or a `change_epoch` while a
    skip is pending answers `busy`; `close()` is queued after it. A crash before the commit leaves
    C, and the re-attach skips again, once. A crash after it leaves `replay_start`, and the
    re-attach is a no-op. With `replay_start` < C the hub trims the overlap and feeds from C
    (`skip_to` refuses it). A source without a ring (or a sid recorded with `track_agent=False`)
    works the same way within one recorder: after an overflow, `resume()` and then `skip_to` to the
    source position the hub reached; that is a terminal loss, made visible by the marker. Such a
    sid has **no durable agent offset** (`sessions.agent_offset` is not published): a restarted or
    re-adopted recorder starts at `(None, 0)`, and the hub feeds the source's live position from
    there; nothing is replayed after a restart.
  - *Same-epoch reattach (RC-H1):* `change_epoch(e)` with `e` equal to the current epoch is a
    no-op: no cut and no offset reset. While a switch is pending (R2-M2), `change_epoch` to the
    same target returns that switch's future (it resolves at the committed `(e, 0)`, never with
    the old position), and to any other target it answers `busy`: the adaptor serializes epoch
    transitions and never treats a no-op as the completion of a pending cut. The publication transaction and the uncertain-COMMIT
    resolver accept an offset reset to 0 only when the epoch value actually changes. The hub
    trims the replayed overlap.
  - *Effects outside the recorder:* a refusal, an overflow or a skip changes only the
    recording. Browser delivery and the OSC 133 scanner work on the live stream and are not held
    back by the recorder. When a skip marker or an epoch-cut marker is published, the hub resets
    its OSC 133 prompt cache for the recording (`osc.gap()`, as 3.7 does for a transcript gap), and
    a resync of the recording reads the committed bounds again, never `received`. The hub resets
    the OSC cache and emits its own audit of a gap only once the operation's future resolved; the
    `transcript.gap` alarm comes from the commit itself.
  - *Uncertain COMMIT (obligations):* the recorder re-reads the descriptors, the cursor, the
    ledger and the `tx_gaps` rows (interval, nonce and marker positions). If the outcome is not
    exactly "committed" or "not committed", the sid is re-adopted and the operation's future fails
    with `RecorderLost`. The hub then treats the gap as unknown: it re-reads `tx_gaps` and the
    committed bounds of the re-adopted recorder before any audit entry or OSC reset, does not
    re-write the `.cast` header when the committed `.cast` is non-empty, and re-sends the current
    size as a `.cast`-only resize at the re-adopted C.
  - *Cast header and time:* the hub writes the asciicast header once, as the first `.cast`-only
    event of a sid whose committed `.cast` is empty. A re-adopted recorder with a committed
    `.cast` never writes it again. Event times are seconds since the header timestamp, from the
    hub's clock, and replayed chunks carry their replay time. A gap's `.cast` event carries the
    time of the skip or cut. Resizes refused in an overflow are not in the agent ring, so they are
    lost; after `resume()` the hub re-sends the current size as a `.cast`-only resize at C.
- Epoch change and close are cuts taken synchronously at the call. Bytes admitted before
  `change_epoch(e)` are held for the old epoch **outside the overflow path**: an overflow of `e`
  drops only `e`'s pending bytes, never the held segment (recheck R-H1). The switch commits only
  after the held bytes are published, or after ONE durable `GAP_MARKER` for exactly the old-epoch
  upstream bytes that are not covered by published bytes (an overflow before the cut, a failed
  write or publication of the segment) has been published, then alarmed (`transcript.gap`). If
  even that marker cannot be published, the loss is alarmed with its size
  (`transcript.gapUnrecorded`) and the sid is re-adopted from the DB. Bytes admitted after the
  call count from offset 0 of `e` and are published only after the switch has committed; a write
  fault on the old segment does not discard them. The switch goes through the same CAS'd
  transaction even with no descriptor. A `resume` already queued before the cut keeps the held
  segment and resumes in `e`. `close()` stops ingress at the call: later bytes are refused
  (`rejected`), and everything accepted before is drained (a failed drain is published or
  abandoned). Whatever was not recorded (an overflow still open, abandoned bytes) becomes one
  `GAP_MARKER` at the end. That owed marker and its size survive a failed close: the retry
  publishes it once, with the same total.
- A gap is written as 3.7's `GAP_MARKER` bytes plus a `.cast` gap event. Its marker bytes are
  synthetic and never count as loss. Each published marker is a `Gap` in `gaps` (`.out` and
  `.cast` positions, upstream start and size, per-kind real bytes when known, epoch, reason
  `skip:<why> | epoch-cut | close`) and a row in `tx_gaps` (sid, `gap_id`, epoch, upstream
  interval, reason, `op_nonce`, positions, `published_at`). The row is written in the same
  transaction as the marker bytes, so the marker ↔ epoch ↔ interval association survives a
  crash, for example after a cut marker is published and before the switch commits. The
  `transcript.gap` alarm (audit) names the `gap_id`. **Identity (R2-M1):** `gap_id` =
  SHA-256 over the canonical JSON `["wtgap2", sid, epoch, upstream_start, upstream_size,
  op_nonce]` (first 32 hex), where `op_nonce` is random per operation (one skip, one cut, one
  close) and stored with the row. It does not depend on the display reason or on the logical
  `.out` / `.cast` projection, so a retry of the same operation keeps its id, and two operations
  or two intervals never share one. The stored `out_pos` / `cast_pos` are **historical**: the
  logical positions at publication; a later cap or merge does not rewrite them. A second
  publication of an id that is already published is refused (`gap-dup`). A row with
  `published_at` NULL is completed only by the same operation (same epoch, interval and nonce);
  anything else is `gap-conflict`. Either refusal, in a skip, a cut, a close or a generic
  checkpoint, re-adopts the sid (never a running recorder with a dirty batch). The
  uncertain-COMMIT resolver compares the interval, the nonce and the marker positions. Retention:
  `tx_gaps` rows are kept as long as the sid's recording exists and are deleted with it by
  erasure / purge (PR6). A marker that cannot be published is alarmed as `transcript.gapUnrecorded`
  with its id, and the alarm says that re-adoption does not repair the loss. It is kept, best
  effort, as a row with `published_at` NULL.
- `resume` re-reads the descriptors and the agent position in one read transaction and adopts them
  only if they are exactly what this recorder last committed; anything moved independently (for
  example after a CAS refusal) re-adopts the sid. An uncertain COMMIT compares the descriptors
  (blob, version, and `list_epoch` for cap / merge), the agent position and the ledger rows with
  their identity (sid, kind, inode); a re-read that itself fails is "unknown" and re-adopts.
- `quarantined` does not encode its reason, so it is refused for everyone. Owner recovery opens only
  `status = recovery`, and only with an `Access` issued by the Store for the recovery route.
  Re-authorization and cached responses are bound to the same sid, principal and route. Raw and
  redacted responses never share a cache entry.
- Snapshot fds are refcounted: a close is logical, and the fds are closed by the last reader
  thread (opening the fds counts as a reader). Admission (slots, fds) is reserved before any fd is
  opened, and a snapshot is registered before its fds are opened, so `Store.close()` reaches one
  still being built; it is re-checked synchronously before it is returned. `shutdown()` returns
  the sids whose worker it had to abandon (empty = clean); a non-empty result means the Store must
  not be reused.
- Test gate (recheck R-M3): the test-volume marker binds the DB file and the transcripts dir
  (dev, ino, path). Both live in one private (0700, ours) harness dir under the system temp dir;
  a transcripts dir elsewhere, or a replaced one, is refused, and the identity actually opened
  (the directory fd, the DB re-stat after connecting) must match the marker.
  `create_test_volume` refuses unless it can prove `users` / `hosts` absent or empty. A legacy `PlainSnapshot`
  re-checks the fd's identity (regular, one link, dev, ino, size, mtime) before every read, and
  its inventory name must be exactly `<sid>.<kind>`.
- `verify` has a hard per-pass budget on physical bytes. A generation larger than one pass is
  reported `limitExceeded` (the report is not `ok`). Its resumable cursor is per generation.
- Retire uses `fstatat` + `unlinkat` on the directory fd. That holds only under the exclusivity of
  the coordinated actors (lease, pins), with no anti-TOCTOU promise against an external
  replacement. The `renameat2` scheme stays for PR6 migration.

- **PR5b wiring (`gateway/app/txhub.py`).** Active only when the flag is on **and** boot opened a
  Store (test gate + test volume); otherwise every call site keeps the 3.7 code. Boot
  (`txhub.boot`, after `db.connect`, before reconcile): a `test_volume` marker outside a test gate,
  or encrypted rows / generation files with the flag off, refuse the boot; the flag on without a
  protected keyring or on a volume the Store refuses also refuses it. The hub adapter
  (`txhub.Recording`) follows the Admission contract above with one documented simplification:
  after an overflow it calls `resume()` and then `skip_to` the hub's live position (one marker for
  everything dropped); it does **not** re-attach the agent to replay the ring to the recorder only.
  Ringless sources (SSH, telnet, serial, telnet-over-agent) use `track_agent=False` and a virtual
  offset counted by the adapter. Routes build their `Access` from their own authorization re-run
  after `txhub.snapshot()` (cookie → fresh grants → `recording.view` → step-up; replay links: the
  link row via `_replay_row`); `not_after` = the earliest of the web session's absolute and idle
  expiry, a time-bound binding, the step-up window on a 2FA host, the link's expiry. Fences
  (`revoking`) wrap: live-share revoke, replay-link deletion (every path through
  `shares.delete_replay_links`), session kill / delete, host purge, logout; `authz.bump_epoch`
  bumps the global counter synchronously **after** its caller's commit (role, binding, account
  changes are not fenced before their commit yet). `python3 -m app.admin` access changes run in
  one `db.transaction()` that also increments `tx_state.access_gen`; the gateway polls it every
  second (two failed polls also bump). Downloads have no ETag yet, so `If-Range` always serves the
  full body; a 206 is sent with `Content-Encoding: identity`. The redacted replay is computed on
  the whole decrypted `.cast` (exactly 3.7's `redact_cast`), cached per §12.11.2 "Caches", and
  emitted in 64 KiB chunks, each checked. Not yet: the per-stream `not_after` timer for a stalled
  transport (checks run per chunk only), System health surfacing of `Store.alarms` (logged only).

## Appendix: Test vectors (v1)

The same values are asserted in `tests/txformat_test.py` and `tests/keyring_test.py`; a change to
any byte here is a change of the on-disk format. All values hex.

Inputs: RK = `000102…1f`; gen_id = `101112…1f`; sid = `00112233445566778899aabbccddeeff`;
created = 1795305600000 ms; DATA 0 = `"hello\r\n"`, DATA 1 = `"$ ls\r\n"`; kind 1. MK = `404142…5f`;
KWK = `606162…7f`; FK = `808182…9f`; installation id = `a0a1…af`.

| Value | Bytes |
|---|---|
| K_hdr (kind 1) | `98614479f133a6f48d9474d9b18b32c6629e5523d5695e6e06a68fd56dec24c1` |
| K_rec (kind 1) | `cc213e3065fa21cfa24a4d84c53470c50aeea39e37e4c05040cc4cd61ca3e6cc` |
| K_idx (kind 1) | `e7e93680d905ca244d72c0644a416f312075221060263a1fed418a154d2d763d` |
| header ‖ hdr_mac | `5754583101010000101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeeff00748d00a201000000000000000000000000000000000000bba285dcda26b655a9f417b309c4cda2ff8d317dca59ed35b7278f8612f7d304` |
| DATA seq 0 | `010700000000000000783d8f7570bd6378c394721f88db2f579d9755a88dc4e7` |
| DATA seq 1 | `01060000000100000056ae7534a5ee15608a5306ee3be7eb3240d764b7d95a` |
| SEAL seq 2 | `023000000002000000ecf2a2207beb5e68abd6e36b09d2357a84609519de2ef0f48cba731ebedf29a5078aeacbe294bb286be63aeb32653aa8fff6ae47f122908b04b44595f25d057a` |
| zero-DATA generation (kind 2, whole file) | `5754583101020000101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeeff00748d00a201000000000000000000000000000000000000b431b09f12712547f8d74193369016de7b8b883dad7a3ceeba47335213466b5c0230000000000000001f49d8f9d7956aadb2c7207cce695467662a48cd8359662e0287d2205e2e1322c8e8a9dc5f178b3305a6540d98895fe535262c337f54526386817f15925faf89` |
| MK id | `52062057e5bbb03e34bb12c0d05de434` |
| K_man | `071c9f0dce956063b924440880505ea8f4df662d9a0395e4a984ec344e3f8933` |
| K_mw | `09f2a4c3196240724b7d9582a2b26e088c0db5320a2d2000eff8d46627b9c19b` |
| K_desc (from KWK) | `804e4639edacf6eb3b2d9f2316c4c8745bebc186c47e44ef3ab62a2881b9f3f5` |
| K_erase (from KWK) | `ee47abe8074d9cf1b1afcd0bb95415e16a0efd293e5a9c78b2ba9cb1e0687774` |
| envelope KWK under K_mw | `01017614b7d76f52d1a0fbd2299ee87b3ac54000d93a0b9a73b07151fcca76e53d94d458583c1e9e012ba35c38d5023aae6a2fab369e007273298558513fd30cb7cb57ef2ffe18e7931c53f120c4b223d2b4526b` |
| envelope FK under KWK | `0104f11f697470f59679fa2294223bae52cd4000a7d79b9971b751f4048a96b74ae41e2f5d2ca92750ef2b3b732c1714d705a675d7a0f10283ffd3a95a45dad3768582c67283c799ae55b9fd8d5684bcb35bb8b8` |
| envelope RK under KWK | `0106f11f697470f59679fa2294223bae52cd40009cab90a76f09514cc0cbc9713a516f12470584239e7c0702a63c4de1adfe146bfc0413330f3b724ade21506857c85af97be734dee47f2e1f1b5c8bf75baf5c53` |
| manifest (epoch 1, no retired ids, KWK + FK) MAC | `b1e621dcef08ec41607f045a18e1d345c3a5a10235d73ecbb757907b4827080b` |
| descriptor (sid above, kind 1, version 3, the sealed generation above) MAC | `d9cff1271b174d9e23ad93253030e9438c64226d3f2ceff045b8134cfcf16716` |
| index `WTI1` (kind 1, data_count 2, entries (0, 0, 96) and (1, 7, 128), whole file) | `5754493101010000101112131415161718191a1b1c1d1e1f020000000000000002000000000000000000000000000000600000000000000001000000070000000000000080000000000000004d1d98fab4e55f31a7430c27fafb843ac8aeaeb6869afbff8be106b89cbe86e9` |
| portable KEK `HKDF(MK, "wt/v1/portable")` | `8cf0b68c716729fd2f2861bf8232e1411b37dc6eec228c11cba070073072e309` |
| `WTS1` container (§12.10; SNK = `c0c1…df`, CK = `e0e1…ff`, MK and installation id above, created above, epoch 1, local + portable, plaintext `"hello"`; asserted in `tests/snapshot_test.py` `V_HELLO`) | `5754533101030000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00748d00a2010000010000000000000052062057e5bbb03e34bb12c0d05de4340100000001ed9b1d5549111099b6ed05e8bfca4f01400026fb1d7fa012d28c4c5427d09944e1fe698511c3c9c10b25e9d3e14464345fc93946edfef0bff8ec4f7b57cbeca807f6990734678749226331d245a7c94f9b9602bd94d0405378ffd3483fbc61aeb726b04000d078ded7e9a4c9494594450817cf72703278eb90a778effd81bd782c2675d36374f0d948bcea715e31fb16d4e5d5feac48077dc11ced6e0250c07656e5edfeed2c19853094b2dfe59e48df9db07f26fd87f554dcae070f090acbdb32e522dca80015000000a57126689e1a2bfed1114598dc410836ab394337a0012000000015adc832ed8bcdf93ea3b74295134b8817cba9764076dfea902388a32d8c32d8` |

The manifest and descriptor bytes in full are in `tests/keyring_test.py` (`V_MANIFEST`, `V_DESC`).
