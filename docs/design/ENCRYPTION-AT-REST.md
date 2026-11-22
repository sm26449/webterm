# Encryption at rest (design, 3.8)

Status: **proposal**, for review before any code. Owner decision 2026-11-22: session recordings and
everything about clients and users are encrypted at rest, on every installation, not only on a
future hosted offering.

## 1. Where we are today (3.7.1)

What is already encrypted:

- Individual secrets in the database, with Fernet (`security.encrypt_secret`): host credentials and
  agent tokens, deploy keys, connection credentials, TOTP secrets, SMTP and cloud-backup secrets,
  the agent CA private key.
- Backup downloads and cloud/SFTP uploads: scrypt + AES-GCM with a passphrase (`backup.py`).

What is **not**:

| Data | Where | Sensitivity |
|---|---|---|
| Session recordings `transcripts/<sid>.out` / `.cast`, and `transcripts/arhiva/` | data volume | **highest**: everything the terminal showed, including secrets printed or pasted |
| The SQLite file (+ WAL): emails, names, IPs, user agents, session titles and notes, command history, audit details, alerts, snippets, host notes and addresses, push subscriptions | data volume | high (personal data, infrastructure map) |
| Scheduled local snapshots `backups/*.wtsnap` (DB + vault key + recordings) | data volume | highest: a full copy, unencrypted |
| `vapid.key`, `setup-token` | data volume | medium |

And the key itself: **the Fernet key (`data/secret`) lives in the same volume as the data it
protects**, and every backup carries it. Anyone who gets the volume, a disk image, a VM snapshot or
a local snapshot gets the key with it. Today's field encryption therefore protects against a leaked
*database file alone*, and against nothing else.

## 2. Threat model

Protect against (goal):

- **T1** a copy of the data volume, a disk, a VM snapshot or a hypervisor backup;
- **T2** a leaked backup or scheduled snapshot;
- **T3** a leaked database file (support bundle, copied for debugging);
- **T4** reading old recordings after their retention, or after a user asked for deletion
  (crypto-shredding).

Explicitly **not** protected (and the docs must say so):

- **N1** an attacker running code inside the gateway, or root on the gateway host while it runs: the
  key is in memory, and a terminal gateway sees every session in clear as it relays it.
- **N2** the operator of the installation. This is self-hosted software; the operator is the
  customer.
- **N3** live traffic: that is TLS's job (and mTLS for agents).

The honest one-line summary for users: *"A stolen disk, snapshot or backup of EverShell is
unreadable without your master key, which is kept apart from the data."*

## 3. Key hierarchy

```
Master key (KEK, 256-bit)        outside the data volume
 ├─ DB key            (wrapped by KEK, in the volume)   → SQLite pages or fields
 ├─ Field key         (HKDF from DB key)                → remaining Fernet secrets (re-wrapped)
 ├─ Snapshot key      (HKDF from KEK)                   → scheduled local snapshots
 └─ Recording keys    (one random 256-bit key per session, wrapped by KEK, in `sessions`)
                                                        → <sid>.out / <sid>.cast
```

- **The master key never sits in the data volume in clear.** Sources, in order:
  1. `WEBTERM_MASTER_KEY_FILE` (default `/run/secrets/webterm_master_key`): a Docker secret, i.e. a
     file in `/opt/webterm/secrets/` mounted read-only. This is what `install.sh` and the
     production compose set up.
  2. `WEBTERM_MASTER_KEY` (environment), for platforms without file secrets. Weaker (visible in
     `docker inspect`); System health says so.
  3. Neither (plain `docker run`, old compose): the key is generated into the volume as today, and
     System health shows a **warning** "master key stored next to the data: a copy of the volume
     is readable". The installation keeps working; nothing is lost on upgrade.
- **Wrapping:** AES-256-GCM key wrap with the key id and purpose as associated data. Each wrapped key
  records which master key id wrapped it.
- **Rotation of the master key** re-wraps the small wrapped keys only (DB key, recording keys). No
  recording or page is re-encrypted. Old master key ids stay readable until the re-wrap finishes;
  progress is in System health.
- **Crypto-shredding:** deleting a session's wrapped recording key makes its recording unreadable at
  once, including any copy of the file that lingers on disk. Backups taken *before* the deletion
  still hold the wrapped key, so the recording stays readable from them until they expire: backup
  retention is the limit for erasure, and the docs say so.
- **Recovery kit:** on first setup and on every master-key change, the Owner is shown the master key
  once (and offered a download), with the instruction to keep it offline. Losing the master key
  means losing the data: that is the point, and the UI says it plainly. The key is never shown
  again by the app.

## 4. Recordings (the main part)

### 4.1 File format `WTX1`

Append-only, chunked AEAD, so that writing stays streaming and reading stays random-access:

```
header:  "WTX1" | version u8 | kind u8 (out|cast) | key id 16 B | nonce prefix 8 B | reserved
record:  length u32 | seq u64 | ciphertext (≤ 64 KiB plaintext) | tag 16 B
```

- Cipher: **AES-256-GCM** (hardware AES on every target; `cryptography` already in the image).
- Nonce = nonce prefix (random per file) ‖ seq (u32 of the counter, 96 bits total). A new file, or a
  file rewritten by the size cap, gets a new prefix: a nonce is never reused under one key.
- Associated data = sid ‖ kind ‖ seq: records cannot be moved between sessions, kinds or positions.
- One record per checkpoint flush (today: every 64 KiB or 2 s, plus idle flush), so the writer
  never rewrites bytes it already wrote. A torn last record after a crash fails authentication and
  is dropped on read (same as today's partial line, but detected).
- `.cast` keeps its line structure *inside* the plaintext; record boundaries are chosen at line ends
  so the cap and the replay readers can still work line by line.

### 4.2 Readers

All readers go through one module (`txstore.py`): `open_reader(sid, kind)` → an object with
`size_plain()`, `read_tail(n)`, `read_range(a, b)`, `iter_lines()`.

- **Random access:** a small sidecar index (`<sid>.<kind>.idx`: plaintext offset → file offset per
  record, itself authenticated) built while writing; rebuilt by a linear length-only scan if
  missing. `read_tail(2 MiB)` decrypts only the last ~32 records.
- **Live sessions:** a reader sees every complete record on disk; the bytes not yet flushed come
  from the hub's in-memory buffer as today (reconnect replay already merges the two).
- **Downloads** (`/transcript`, replay links): a streaming response that decrypts record by record;
  `.out` / `.cast` downloads stay byte-identical to today's plaintext files.
- **Search** (`/api/search`): unchanged algorithm, decrypting the last 4 MiB per session.
  AES-GCM runs at well over 1 GB/s on a server core; the 128 MiB per-query budget stays.
- **Size cap** (64 MiB → keep 16 MiB): copies whole records from the cut point into a new file with
  a new nonce prefix (decrypt + re-encrypt, off the event loop, as today's cap already is).
- **Retention:** archive moves files as today; deleting a session also deletes its wrapped key.

### 4.3 Migration of existing recordings

- New sessions are written as `WTX1` from the first boot of 3.8.
- Existing plaintext files are converted by a background job: closed sessions first, oldest first,
  one file at a time, write-new-then-rename, fsync, then delete the plaintext. Live sessions are
  converted when they close (never under a writer).
- Readers accept both formats (magic bytes), so the app is fully usable during the migration.
- Progress and errors in System health ("Recordings encrypted: 1 834 / 2 120"). A failure leaves the
  plaintext file in place and retries later; it never deletes data it could not re-read.

## 5. The database

Two options; the review should pick one.

**Option A, whole-file encryption (SQLCipher).** Every page and the WAL are encrypted with the DB
key; every query (email lookups, `LIKE` on history and audit, indexes) keeps working unchanged.

- Needs the `sqlcipher3` binding instead of the standard `sqlite3` module (our `db.py` wraps one
  connection; the change is local). **Open question:** wheels for Python 3.12 on linux/amd64 and
  linux/arm64 (the image is multi-arch), supply-chain review, and how pip-audit/Trivy see it.
- Migration: at boot, `sqlcipher_export` from the plaintext file into an encrypted one, after a
  pre-migration snapshot, then swap. One-time, seconds for our sizes.

**Option B, field-level encryption** with the field key, for a fixed list of columns:

- display-only columns (notes, titles, snippets, user agents, alert texts, host notes, IPs in
  replay opens, push subscription keys) are encrypted directly;
- lookup columns (email, SSO subject, SCIM ids) get an encrypted value plus a **blind index**
  (HMAC of the normalised value) for equality lookups;
- `LIKE` searches (command history, audit detail) become decrypt-and-filter in Python over bounded
  windows (history is capped at 10 000 rows; audit search gets a date window).

Recommendation: **A**, if the binding passes the checks above, because B touches dozens of queries,
every future column must remember to opt in, and a forgotten column leaks silently. B is the
fallback.

## 6. Backups and snapshots

- **Scheduled local snapshots** are encrypted with the snapshot key (AES-GCM, same container as
  downloads). Today they are a plaintext copy of everything, including the vault key.
- **Backups no longer contain the master key.** They contain the wrapped DB key and wrapped
  recording keys; restoring needs the master key of the installation (same host: already there;
  new host: from the recovery kit). The restore screen asks for it when it is missing and checks it
  before touching anything.
- The passphrase-encrypted download stays as an outer layer (a leaked backup then needs both).
- Restore keeps its current safety net (pre-restore snapshot, now encrypted).

## 7. What stays in clear, and why

- Ids, timestamps, states, sizes, host ids, role bindings, permission names: needed for queries,
  not personal. (With option A they are encrypted anyway.)
- Token **hashes** (API tokens, share and replay links, web sessions): already one-way.
- The Traefik files in `/edge` (IP allow/deny lists): Traefik reads them; they hold IPs only while
  an agent is connected.
- `vapid.key` and `setup-token`: move under the master key in 3.8.x (low priority).
- Data on the managed hosts (uploads staged there, `~/.webterm/inbox`): outside the gateway, the
  host's own disk encryption applies.

## 8. Invariant (proposed INV-14)

*"Recordings, the database and snapshots are unreadable without the master key, and the master key
is never stored in clear in the data volume or in a backup when a key file or key variable is
configured."* Enforced in `txstore.py`, `db.py` (open), `backup.py`, `keys.py`; tests: a written
recording and a snapshot contain no plaintext marker; a backup contains no master key; a restore
without the key refuses before changing anything.

## 9. Operations

- `install.sh` and `docker-compose.prod.yml` create `secrets/webterm_master_key` (0600, root,
  32 random bytes, base64) and mount it; `upgrade.sh` creates it for existing installations and
  moves the in-volume key out, with the recovery-kit reminder.
- System health: key source (file / env / in volume = warning), migration progress, re-wrap
  progress, "recovery kit not confirmed" reminder for Owners.
- Performance budget: < 3 % CPU at our recording rates, measured on the e2e gate; search latency
  within 10 % of today.

## 10. Phasing

1. **3.8.0:** key hierarchy and master-key placement, `WTX1` recordings + migration, encrypted
   snapshots, backups without the master key, System health, INV-14.
2. **3.8.x:** the database (option A or B per the review), `vapid.key` / `setup-token`.
3. Later: per-tenant / per-user keys are **not** planned (a terminal gateway must read recordings
   for replay and search on behalf of other authorised users).

## 11. Open questions for the review

1. Option A vs B for the database (and the `sqlcipher3` multi-arch wheel question).
2. Is a 64 KiB / 2 s record size right for replay latency vs overhead (16 + 12 bytes per record)?
3. Should the in-volume fallback (no key file) refuse to start on *new* installations, or only warn?
4. Recovery kit UX: shown once at setup; is a printable page enough, or also an email to the Owner
   (no: email is not a safe place for it)?
5. Crypto-shredding vs backups: is "until the backups that hold the wrapped key expire" acceptable
   for GDPR erasure, with the docs saying so?
