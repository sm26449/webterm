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
   that promises "two secrets". *Written in §12.10 (PR3).*
5. **Backup snapshot coherence (V3-M2):** descriptors and keyring read from the same snapshot as the
   DB; the list of mutations that take the barrier; pins on immutable references (fds), released
   only after the worker really finished; all I/O off the loop with budgets.
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
`gateway/app/keys.py`, tested in `tests/keys_test.py`; **not called by the real boot yet**
(`config.load_secret`, `security.init_crypto` and `main.lifespan` are unchanged in PR2). The
wiring PR places `keys.boot()` before anything that mutates `DATA_DIR` (the clean-up in
`config.ensure_dirs()`, the staged-restore apply), before the vault and before `db.connect`; see
the *Wiring checklist* at the end of this section, which must be closed before the wiring PR.

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
| tolerated | `.lock` (regular file), `lost+found` (directory, content not inspected: it is filesystem metadata and may be unreadable), `transcripts/` that is empty or holds only an empty `arhiva/` (what `config.ensure_dirs` creates before boot) | never change the class |
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
in preflight writes nothing in `DATA_DIR` except creating `.lock` (empty, 0600) if it did not
exist. Two refused boots in a row leave, for every
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

### 12.10 Snapshot container `WTS1` (PR3)

Normative. Closes §12.8 contract 4 and replaces the sketch of §12.6 where they differ.
Implemented in `gateway/app/snapshot.py` (pure codec: file objects in, file objects out, one
chunk in memory) and `gateway/app/backup.py` (what goes inside, where it is stored, restore);
tested in `tests/snapshot_test.py` and `tests/backup_protected_test.py`. Like PR2, it is **not
reachable from production** until the boot is wired: a volume becomes *protected* only when
`keys.wtk` exists, and until then every backup path runs the 3.7 code unchanged.

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
