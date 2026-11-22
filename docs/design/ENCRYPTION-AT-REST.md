# Encryption at rest (design, 3.8)

Status: **proposal v3**, revised after two independent reviews (Codex, 2026-11-22; reports kept
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
 ├─ KWK  = HKDF(MK, "wt/kwk/v1")           wraps every data key below (AES-256-GCM, unique nonce, AAD)
 ├─ SNK  = HKDF(MK, "wt/snapshot/v1")      local snapshot containers (§6)
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
- **Envelope AAD** = installation id ‖ format version ‖ purpose ‖ KWK id ‖ data-key id (‖ sid for
  RK). A wrapped key cannot be replayed into another slot.
- **Nonce discipline for wrapping:** every wrap uses a fresh random 96-bit nonce; wrap count per
  KWK is bounded (re-key the KWK, i.e. rotate MK, long before 2^32 wraps).

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
error) opens a **new segment** with a fresh random 128-bit `gen_id` and its own key
`HKDF(RK, "wt/seg/v1" ‖ kind ‖ gen_id)`. A segment is never reopened for writing. Inside a segment
the nonce is the 96-bit record counter starting at 0; a segment is sealed and a new one started
well before 2^32 records. One writer per (sid, kind) at a time, enforced by a per-session lease
(§5).

### 4.2 Byte format (little-endian)

```
header  (authenticated as AAD of every record, and by its own tag):
  magic "WTX1" | ver u8=1 | kind u8 (1=out, 2=cast) | flags u16 | gen_id 16 B | sid 16 B
  | prev_gen 16 B (zero for the first segment) | created u64 (unix ms) | header_tag 16 B
record:
  len u32 (plaintext length, 1..65536) | seq u64 | ciphertext | tag 16 B
  nonce = seq as 96-bit big-endian;  AAD = H(header) ‖ seq ‖ len
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

Acceptance tests (summary; the full list is in the review): fixed vectors; crash and resume at every
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

### 12.2 Key manifest, bootstrap and boot

- The keyring lives in **one file**, `DATA_DIR/keys.wtk`, not in the database (the SQLCipher key
  cannot live inside the database it opens). Content: installation id, epoch u64, MK ids it accepts,
  envelopes (`FK_legacy`, `FK`, `DBK`, `KWK`-checks), each envelope = AES-256 key wrap with padding
  (RFC 5649, deterministic, no caller nonce) under KWK, with a type tag; the whole file is
  authenticated by HMAC-SHA-256 under `K_man = HKDF(MK, "wt/v1/manifest")` (a key used for nothing
  else). Per-session RKs stay in the `session_keys` table, wrapped the same way; their binding to
  the session is the descriptor MAC (§12.3).
- **Publication:** write `keys.wtk.tmp` (O_EXCL, 0600, O_NOFOLLOW), fsync, rename over `keys.wtk`,
  fsync the directory. One file = one atomic switch; the epoch increases on every change.
- **Rotation:** the new file holds envelopes under the new KWK and lists both MK ids until the
  re-wrap of `session_keys` finishes; boot accepts either MK while `rotating`; when coverage is
  verified the old id is dropped (new epoch). A crash at any point leaves either the old or the new
  file, both valid, and the re-wrap resumes.
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
