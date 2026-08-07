# Runbook: recovering when WebTerm goes down

Written after the v1.0.11 incident (13 Jul 2026): a frontend bug shipped a
white screen to production, and because the server was being administered
through WebTerm itself, there was no way back from the interface. This
document is plan B — it assumes that **the UI is completely inaccessible**.

## The golden rule

**Terminal sessions are NOT lost.** They live in `tmux` on each host
(a dedicated tmux server, socket `webterm`), not in the gateway. A downed
gateway or a broken image does not kill your shells — only web access to them.

## 1. Get onto the server without WebTerm

Direct SSH (always keep a working SSH key to the server — WebTerm is not a
replacement for it, it is a layer on top of it):

```bash
ssh <user>@<server>
```

## 2. Recover your working sessions (optional, any time)

On any host running a WebTerm agent, the sessions live in the `webterm` tmux
server:

```bash
tmux -L webterm ls                    # list sessions (name = the id shown in the UI)
tmux -L webterm attach -t <nume>      # attach directly to a session
```

Nothing that was running (processes, editors, command queues) has stopped.

## 3. Rollback to the previous version

Every deploy done with `deploy.sh` records its rollback point in
`/opt/webterm/.prev-image`. The rollback needs no network, CI, or GitHub —
the old image already exists locally:

```bash
cd /opt/webterm && sudo ./rollback.sh
```

The script switches the `WEBTERM_IMAGE` pin in `.env`, restarts the container,
and waits for the healthcheck verdict. It is reversible: a second
`./rollback.sh` brings you back (a swap).

Manual rollback (if `.prev-image` is missing):

```bash
docker images | grep webterm          # what tags exist locally
sudo sed -i 's|^WEBTERM_IMAGE=.*|WEBTERM_IMAGE=ghcr.io/sm26449/webterm:vX.Y.Z|' /opt/webterm/.env
cd /opt/webterm && sudo docker compose -f docker-compose.prod.yml up -d app
```

## 4. Quick diagnostics

```bash
docker ps                                                  # is the container running? healthy?
docker logs webterm-app-1 --since 15m                      # gateway logs
curl -sk -D- -o /dev/null https://<domeniu>/api/state      # does it respond? which version (x-webterm-version)?
```

The symptom "backend perfectly healthy, but the page dies in the browser"
(the v1.0.11 case) shows up in the logs as loops of `GET / → /api/state → GET /`
with no WebSocket upgrade at all. Since v1.0.14, in this case the page itself
displays a failsafe screen with the error and the rollback instructions (no
more white screen).

## 5. Locked out of your own account

There is **no password-reset email and no recovery CLI** — by design: a self-hosted tool with no
mail dependency, whose only administrator is you. Recovery means server access, which you have.

Work down this list; stop at the first one that applies.

**You still have a passkey.** Use it. A passkey login issues the session directly — it needs
neither the password nor a 2FA code (it *is* the stronger factor). Once in, set a new password
in Settings → Account.

**You know the password but lost the 2FA device.** Use one of the ten recovery codes printed
when you enabled 2FA; each works once. Then regenerate the set in Settings → Security.

**You know the password, lost the 2FA device *and* the recovery codes.** The password alone
cannot get you in — login returns `totp_required`. Disable 2FA from the server:

```sh
docker exec -it webterm-app-1 python3 - <<'EOF'
import sqlite3, sys; sys.path.insert(0, '/srv/webterm')
db = sqlite3.connect('/data/webterm.db')
db.execute("UPDATE users SET totp_enabled=0, totp_secret_encrypted=NULL WHERE email=?",
           ('you@example.com',))
db.execute("DELETE FROM recovery_codes")
db.commit()
EOF
```

**You lost the password too.** Same access, one more statement — the hash is produced by the
application's own argon2 parameters, so use its code rather than generating one elsewhere:

```sh
docker exec -it webterm-app-1 python3 - <<'EOF'
import sqlite3, sys; sys.path.insert(0, '/srv/webterm')
from app import security
db = sqlite3.connect('/data/webterm.db')
db.execute("UPDATE users SET password_hash=?, totp_enabled=0, totp_secret_encrypted=NULL WHERE email=?",
           (security.hash_password('a-new-strong-password'), 'you@example.com'))
db.execute("DELETE FROM recovery_codes")
db.commit()
EOF
```

No restart is needed — the next login uses the new hash immediately. Verified end to end: with
2FA enabled and both factors lost, these two statements restore access.

**If you also lost the server**, the backup is the answer, and it only helps if it was
encrypted with a passphrase you still have. See *Disaster recovery* below.

Two things worth knowing before you need them:

- **Locking yourself out is easier than losing a password.** Marking a host "require 2FA" while
  having no passkey and no TOTP used to make that host unreachable *and* un-un-markable. The
  account-password fallback exists for exactly that, but it is worth not relying on.
- **Anyone who can run `docker exec` on the gateway can do the above.** That is not a new
  weakness — that person already owns the vault key and every stored credential — but it is the
  reason the gateway host matters as much as the passwords.

## Defense layers (who catches what)

| Layer | Catches | Where |
|---|---|---|
| Smoke test in CI (headless Chromium) | UI that fails to start / JS errors at boot — the image is **not published** | `.github/workflows/docker-publish.yml`, `scripts/smoke-boot.mjs` |
| Agent signature verification | `ptyd.py` modified without re-signing | CI, on every build |
| Deploy health gate + automatic rollback | images that fail to start (crash loop, broken config) | `deploy.sh` |
| `rollback.sh` | any regression noticed after deploy — one command over SSH | `/opt/webterm/rollback.sh` |
| `failsafe.js` + ErrorBoundary | JS crash in the browser → recovery screen instead of a white one | frontend |
| tmux on the hosts | sessions survive any gateway failure | agents |
| TCP keepalive on the gateway socket | gateway vanished without FIN/RST → reconnect in ~2 min (not ~15) | agent (v21+) |
| systemd watchdog (`WatchdogSec` + `WATCHDOG=1`) | agent event loop stalled under systemd → kill+restart | agent (v21+) + unit |
| cron watchdog (G1, stale liveness) | event loop stalled on hosts without systemd | agent + `* * * * * ptyd start` |
| `send_fwd` fragmentation + bounded backlogs | large upload / fast producer → no oversized frame / OOM | gateway + agent |

## Deploy rules (so you never reach steps 1–4)

1. Deploy with an explicit version: `cd /opt/webterm && sudo ./deploy.sh v2.0.0`
   (reproducible pin + rollback point recorded automatically).
2. Do not deploy from inside a WebTerm session without a backup SSH connection
   open in another terminal, at least for frontend/gateway changes.
3. Wait for CI to go green before deploying — since v1.0.14 "green" also
   includes the UI boot smoke test.

## Known ceilings (measured, not assumed — v1.0.29)

Load test (`scripts/load-test.mjs`, real agent): **30 concurrent sessions + 15
concurrent output storms on one host** → healthy gateway: `/api/sessions`
latency p95 ≈ 57ms (baseline 16ms), memory +30 MiB, zero resyncs, sessions
usable afterward. The single SQLite connection is **not** a bottleneck in the
single-admin model (one client polls, not N).

- **Hard limits**: 32 sessions/host (`MAX_SESSIONS`, agent), 2 MiB ring/session,
  1 MiB buffer/browser (forced resync above it), 64 MiB per transcript FILE — and a
  session writes two (`.out` and `.cast`), either of which triggers the cap, so budget
  ~128 MiB per session in the worst case
  (head-truncated cap). When the session ceiling is reached, the API returns
  **409**, not 502 — a normal condition, not a gateway fault.
- **What to watch in `/api/status` → "Gateway health"**: `event_loop_lag`
  (green <50ms; red >250ms = event loop blocked by synchronous I/O), `db_ping`
  (green <20ms), process memory. If the lag keeps climbing, the gateway is
  overloaded — before it stops responding.

## Disaster recovery (tested, not assumed)

Full drill verified (v1.0.29): live backup → total deletion of DB + vault key
→ restore → `integrity_check: ok`, account + hosts + **encrypted SSH
credentials** recovered and decryptable.

1. **Backup** (crash-consistent, while the application is running):
   `sudo WEBTERM_BACKUP_PASSPHRASE=... WEBTERM_BACKUP_DIR=/var/backups/webterm ./scripts/backup.sh`
   (or the systemd timer installed by `install.sh`, daily at 03:30).
   `WEBTERM_BACKUP_PASSPHRASE` is **mandatory for unattended runs**: without it the
   script deletes the archive it just wrote and exits non-zero, because that archive
   contains the vault key in cleartext and `/var/backups` ends up in rsyncs and
   snapshots. Interactively it only warns. `install.sh` generates the passphrase and
   stores it in `/etc/default/webterm-backup` (mode 0600) — **keep a copy off the
   server; without it the archives are unrecoverable.** The directory is `chmod 700`,
   the archives `chmod 600`.

   **Check that the timer actually runs** — a failed oneshot is silent otherwise:
   ```bash
   systemctl list-timers webterm-backup.timer
   systemctl status webterm-backup.service      # Result: exit-code = no backups
   ls -l /var/backups/webterm                   # should grow daily, files end in .enc
   ```
2. **Restore**: `sudo [WEBTERM_BACKUP_PASSPHRASE=...] ./scripts/restore.sh <arhiva.tar.gz|.enc>` —
   stops the app, **extracts to staging + verifies `integrity_check` BEFORE**
   touching the current data (a corrupt archive can no longer destroy anything),
   moves the old state to `/data/.restore-prev` (safety net), then restarts.
   `.enc` archives require the passphrase.
3. **The golden rule**: the vault key (`data/secret`) is in the archive. Without
   it, agent tokens and encrypted SSH credentials are UNRECOVERABLE — boot
   explicitly refuses to start with a regenerated key over encrypted data.
   Periodically verify that you have a copy of the backup off the server.

### Backup/restore from the application (v1.0.61+, no shell on the server)

For the "I have no server access, but I have the app" case: **Settings → Backup**.

- **Download**: choose a passphrase (min. 8 characters) → you get an encrypted
  `.wtbk` (scrypt → AES-256-GCM) containing the DB + the vault key. **Keep the
  passphrase** — without it the file is useless. You can enable automatic
  daily/weekly backups (retained 7 days on the server, with a UI notification
  when ready).
- **Recovering a lost VPS**: on the new instance, complete setup, then Settings →
  Backup → *Restore from a backup* → upload the `.wtbk` + passphrase. After
  validation (passphrase + `integrity_check`), the application restarts and
  replaces the DB + key at boot (`apply_pending_restore`, before `db.connect`).
  A **pre-restore** snapshot of the current state is saved automatically to
  `data/backups/` as a safety net.
- CLI equivalent: same result as `scripts/restore.sh`, but triggered from the UI.
