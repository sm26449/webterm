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
   unless a per-commit monotonic marker outside the restorable set is added.
2. **Range vs full integrity (V3-H3):** a range read is served only through an authentic index bound
   to the exact descriptor, or after a verified parse of the needed prefix within a budget; a full
   integrity check (all records, SEAL, size) is a separate operation (System health, backup,
   restore); rules for `recovered` generations and for a live prefix inside a backup.
3. **Erasure continuity (V3-H4):** a journal head attested off-volume, backups bound to the head
   they contain, continuity checks, tombstones re-applied at every boot before readers; without
   proof of continuity, the recordings that could be affected stay quarantined; an Owner "recover
   anyway" is a recovery mode with the erasure guarantee suspended, recent re-auth, restricted
   access and audit.
4. **Snapshot container bytes (V3-M1):** per-envelope algorithm and purpose key, canonical AAD,
   nonce and strict counter, frame and decompression limits, single final frame, new key on retry
   after an ambiguous write; the passphrase is mandatory for downloads and for any remote profile
   that promises "two secrets".
5. **Backup snapshot coherence (V3-M2):** descriptors and keyring read from the same snapshot as the
   DB; the list of mutations that take the barrier; pins on immutable references (fds), released
   only after the worker really finished; all I/O off the loop with budgets.
6. **Boot inventory (V3-M3):** accepted artefacts for bootstrap, lock taken without changing the
   classification, leftover `keys.wtk.tmp` handled, `fstat` on the same fd, regular file, no
   symlinks, canonical encodings and size limits for manifest, envelopes and descriptors; the
   wrong-key refusal also with a restore in staging. *Written in §12.9 (PR2), together with the
   key-manifest part of contract 1; the descriptor part of contract 1 stays open.*

### 12.9 Boot and key-manifest publication (PR2)

Normative. Closes contract 6 and the key-manifest part of contract 1 (§12.8). Implemented in
`gateway/app/keys.py`, tested in `tests/keys_test.py`; **not called by the real boot yet**
(`config.load_secret`, `security.init_crypto` and `main.lifespan` are unchanged in PR2). The
wiring PR places `keys.boot()` after `config.ensure_dirs()` and before the staged-restore apply,
the vault and `db.connect`.

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

**Inventory.** The top level of `DATA_DIR` is listed without following symlinks (`lstat`
semantics). Entries are sorted into:

| Group | Entries | Rule |
|---|---|---|
| tolerated | `.lock` (regular file), `lost+found` (directory, content not inspected: it is filesystem metadata and may be unreadable), `transcripts/` that is empty or holds only an empty `arhiva/` (what `config.ensure_dirs` creates before boot) | never change the class |
| key artefacts | `secret` (3.7 key), `keys.wtk`, `keys.wtk.tmp`, `master.key`, `master.key.tmp` | each must be a regular file (a symlink, directory, FIFO… → `ambiguous`); `secret` must be exactly 32 bytes |
| staged restore | `restore-pending/` + `.restore-flag` (3.7 mechanism), `.restore/` (3.8, §12.4) | reported as `staged_restore`; never read, applied or removed by PR2 code |
| new-format markers | `erasures.wtj`, `.restore/` | data that only exists once a `keys.wtk` exists (the recording segment names join this list when they are fixed) |
| data | everything else | — |

Classes, first match wins:

1. `protected`: `keys.wtk` is present. Sub-state `in_volume` when `master.key` is present. If
   `secret` is also present, the volume is in the last step of the 3.7 migration (`secret_leftover`).
2. `ambiguous`: no `keys.wtk`, and a new-format marker is present.
3. `legacy-3.7`: no `keys.wtk`, `secret` present (anything else may be present: DB, transcripts,
   keys, a 3.7 `restore-pending/`).
4. `empty`: nothing outside the tolerated set, `keys.wtk.tmp`, `master.key.tmp` and `master.key`
   (the last three are leftovers of an interrupted bootstrap).
5. `ambiguous`: anything else (data without `secret`, a staged restore without any key, a
   non-regular key artefact). **Refuse**, naming the first offending entry.

**Key sources.** Read from the environment; a variable counts as *set* only when it is non-empty
after stripping whitespace (compose passes `${VAR:-}` as present-and-empty).

| Source | Name in `ProtectionState.source` | Configured when |
|---|---|---|
| `WEBTERM_MASTER_KEY_FILE` (a path) | `file` | set |
| `WEBTERM_MASTER_KEY` (the base64 value; warned: visible in container metadata) | `env` | set |
| `WEBTERM_KEY_IN_VOLUME=1` → `DATA_DIR/master.key` | `volume` | set to `1` (`0` = unset, any other value refused) |
| `/run/secrets/webterm_master_key` | `default-file` | the class is `protected` without `master.key` (the manifest expects an external key), **or** the file exists |

- Exactly one source may be configured. `file` + `env`, or `volume` + any external source → refuse
  ("conflicting key sources"). (Stricter than "precedence": a second configured source is an
  operator error, and guessing which one wins is how a key gets silently replaced.) When no
  explicit source is set, the default path is consulted.
- `master.key` present with `WEBTERM_KEY_IN_VOLUME` unset, or with an external source set →
  refuse. `WEBTERM_KEY_IN_VOLUME=1` on a `protected` volume without `master.key` → refuse (a key is
  never generated when a `keys.wtk` exists).
- A configured source that is missing or invalid → refuse. The default path that does not exist on
  an `empty` or `legacy-3.7` volume is "not configured" (an `ENOENT` on `open`, nothing else); a
  default file that exists is configured and must be valid.
- **Reading a key file** (`file`, `default-file`, `volume`): `open(O_RDONLY|O_NOFOLLOW|O_NONBLOCK|
  O_CLOEXEC)` (a symlink as the final component, or a FIFO, cannot block or redirect); `fstat` on
  that same fd: regular file, owner = effective uid or root, `mode & 0o077 == 0` (neither readable
  nor writable by group/others), size ≤ 256 bytes; then read from that fd at most 257 bytes.
- **Encoding** (file and `WEBTERM_MASTER_KEY` alike): standard base64 with padding, exactly 44
  characters that decode to exactly 32 bytes and re-encode to the same 44 characters (canonical:
  no URL alphabet, no spaces, no unused bits); one trailing `\n` is tolerated, nothing else.
- The key value is never logged and never part of an error: errors carry the source name and a
  reason code (`missing`, `symlink`, `not-regular`, `bad-owner`, `bad-mode`, `too-large`,
  `bad-encoding`, `conflict`, `no-source`, `unreadable`).

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

**Bootstrap (`empty`).** With `volume`: reuse a valid leftover `master.key` (same reader as an
external file), otherwise generate 32 random bytes and publish them exactly like `keys.wtk`
(`master.key.tmp`, `O_EXCL|O_NOFOLLOW`, 0600, fsync, rename, fsync dir) **before** the manifest. Then
generate installation id (16 B), KWK, SNK and FK (random), publish epoch 1 with envelopes KWK, SNK
(under `K_mw`) and FK (under KWK), and re-open it from disk. A crash before the manifest's rename
leaves an `empty` volume (with leftovers) and the next boot bootstraps again, reusing `master.key`.

**Legacy migration (`legacy-3.7` + a valid source).** Order:

1. Read `secret` (`O_NOFOLLOW`, `fstat`: regular, exactly 32 bytes); it becomes `FK_legacy`.
2. With `volume`: `master.key` as in bootstrap.
3. Publish epoch 1 with KWK, SNK, FK_legacy (= `secret`) and FK.
4. Re-open `keys.wtk` from disk with the MK and require `fk_legacy == secret` (constant time).
5. Only now unlink `secret` and fsync the directory.

| Interrupted | Class at next boot | Next boot with the right MK | With a wrong / no MK |
|---|---|---|---|
| before 3 (or during 3, before its rename) | `legacy-3.7`, `secret` intact | migrates again (a leftover `master.key` is reused) | refuse (wrong) / legacy (no source) |
| after 3, before 5 | `protected` + `secret_leftover` | opens, checks `fk_legacy == secret`, then finishes step 5 | refuse; nothing changes |
| after 5 | `protected` | opens | refuse |

If `secret_leftover` and the opened `fk_legacy` differs from `secret` (or `FK_legacy` is absent),
boot refuses: two different legacy keys mean someone else wrote one of them. A `protected` volume
never reads `secret` as a key.

**In-volume opt-out.** `WEBTERM_KEY_IN_VOLUME=1` keeps the MK in `DATA_DIR/master.key` (0600). The
state is `reduced` ("reduced protection" in System health: the key lives next to the data it
protects); `legacy` means the 3.7 key is still in use; `protected` means an external key.

**MK rotation** (`rotate_master_key`, external sources only; the in-volume mode would need two
files to change together and is refused in 3.8.0). Open the current `keys.wtk` with the old MK;
build epoch + 1 with the same installation id, `mk_id` = id(new MK), retired ids = the old
retired ids ∪ {old MK id} (sorted, the new id removed; more than 64 → refuse), KWK and SNK
re-wrapped under the new `K_mw`, every KWK-wrapped envelope copied byte for byte; publish; re-open
with the new MK. A crash leaves the old file (opens with the old MK only) or the new one (opens with
the new MK only). Boot needs exactly the current MK; the operator switches the key file after the
command reports success.

**Guarantee (wrong or missing key).** A boot that refuses writes nothing in `DATA_DIR` except
creating `.lock` (empty, 0600) if it did not exist. Two refused boots in a row leave, for every
entry under `DATA_DIR` (recursively, symlinks not followed): the same names, types, modes, sizes,
contents and symlink targets — between the state before the first boot and after the second,
`.lock` excepted, and between the first and the second boot with `.lock` included. Timestamps
(`atime`, directory `mtime` after the creation of `.lock`) are not part of the guarantee. This
holds with a staged restore present: staging is never read before the key is verified.

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

The manifest and descriptor bytes in full are in `tests/keyring_test.py` (`V_MANIFEST`, `V_DESC`).
