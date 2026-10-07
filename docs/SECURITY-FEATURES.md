# Security features

What the gateway does to be safe on the public internet, in detail. The summary is in
the [main README](../README.md#security); what the model defends and what it does not is
in [THREAT-MODEL.md](THREAT-MODEL.md); reporting a vulnerability: [SECURITY.md](../SECURITY.md).

## Overview

Hardened for public exposure: argon2 passwords + passkeys, single-use setup token
(anti-hijack on first start), brute-force lockout on the real client IP (since 3.5.1,
X-Forwarded-For is believed only from the proxy named in `WEBTERM_TRUSTED_PROXY_HOSTS` /
`WEBTERM_TRUSTED_PROXY_CIDRS` — see [CONFIGURATION.md](CONFIGURATION.md)), constant-time login (no account enumeration), `__Host-` HttpOnly/Secure cookie,
Origin check on the WebSocket (anti-CSWSH), CSP + HSTS + anti-clickjacking,
path-traversal blocked. On **2FA** hosts, the terminal **locks on inactivity**
(output suppressed + input refused server-side) and resuming requires a **passkey
step-up** — protecting against unattended authenticated sessions
(`WEBTERM_IDLE_LOCK_SECS`, default 5 min). An optional **command guardrail**
(Settings → Infrastructure & tokens): regex rules that require **confirmation** or **block**
dangerous commands at Enter (e.g. `rm -rf`, `mkfs`) — editable, and enforced on the
server for `/run` as well, so a command sent with Run on hosts cannot walk around the browser.

**You find out when someone attaches.** A session can be watched by more than one client —
your own second tab, a phone, a share link. The viewer count told you *how many*, silently, so
you learned about a second client only if you were looking at that corner of the toolbar at that
second. Now every client already attached gets a notification (a system one, so it arrives with
the tab in the background), and the viewer list shows the IP and browser of each, next to the
button that removes them. A client attaching from an address never seen on a successful login is
flagged **new device**, its notification is raised to a warning, and an email goes out —
throttled per address, because an alert that fires constantly is an alert nobody reads.

**Credential changes from an unfamiliar device need the account's inbox.** Changing the password
or the email from a session opened on an address never seen on a successful login also requires a
six-digit code mailed to the account address — closing the case where someone who already has your
password rotates it and locks you out. A code rather than a link: links are clickable by anyone who
reaches the inbox, and mail scanners open them on their own. It escalates rather than refuses,
because being blocked from changing a leaked password while travelling is not security. Applies
only when SMTP is configured; without a mail channel it would be a permanent lockout.

**Changing your passkeys needs a second factor too.** With 2FA on, the code from your phone (or
a recovery code); without it, the emailed code from an unfamiliar device. Otherwise whoever has
the password could enrol *their own* passkey — a permanent, phishing-resistant key to your
account. Email is deliberately not accepted in place of the phone: it would make two-factor worth
exactly as much as access to the mailbox.

**And a way back in, from the server.** `docker exec -it webterm-app-1 python3 -m app.admin`
(`list`, `passwd`, `disable-2fa`, `logout-all`) recovers the account over SSH. Every gate above
is another way to lock yourself out; the product can be strict in the browser because this
exists, and shell on the server is a far higher bar than a mailbox. See RUNBOOK §5.

**Signed-in devices (Settings → Sign-in & 2FA).** The account lists every browser currently signed
in — device label, when it was last seen, which one is *this* device, and a badge on any
unfamiliar new device. Sign out one device, or **sign out everywhere else** in one click (which
also closes any open step-up windows). It's the in-UI answer to a suspected stolen cookie, short
of rotating the password — and, unlike `logout-all`, it doesn't need shell on the server.

That signal decides **how loud to be, never whether to check**. No device is ever trusted enough
to skip step-up, the idle lock, or 2FA: an IP and a user-agent both travel with a stolen session
cookie, so a "trusted device" exemption would be waved through by exactly the attacker it looks
like it stops.

**Security model:** whoever gets past login has access to the files and shell of
the agent's user (like SSH). That's why: run it with a **domain + passkeys** (not
just IP/password), install agents as a **dedicated, non-root user** where you can,
and complete setup immediately after deploy. `tests/security_test.py` covers the
protections.

**Off-host backup, from the UI (Settings → Backup).** Connect Google Drive or Dropbox with
one button (OAuth) and scheduled backups leave automatically into your account,
**encrypted with your passphrase** — the provider gets a file it cannot read; with no
passphrase configured we refuse to upload. Least privilege: `drive.file` (only files the
app itself creates) or a Dropbox *App folder* app. Separate remote retention. You can also
point backups at **your own SFTP or FTPS server** from the same screen — for SFTP the host
key is **pinned on first use** (confirm the `SHA256:` fingerprint before Save unlocks; a
later key change is refused), FTPS verifies the server certificate — with credentials stored
encrypted and the archive leaving already encrypted. See `docs/RUNBOOK.md` for the details.

If cloud OAuth is more than you want, `scripts/backup.sh` copies the encrypted archive off-host
with tools you already have — no `rclone config`: **rsync-over-SSH** (`WEBTERM_BACKUP_RSYNC=user@host:/path/`,
key auth) or **FTPS** (`WEBTERM_BACKUP_FTPS=ftp://host/path/`, `curl --ssl-reqd` — TLS enforced so
the password never crosses in clear; plain FTP is refused). `WEBTERM_BACKUP_REMOTE` (any rclone
backend: S3/B2/…) still works too. Every path refuses to upload an unencrypted archive. The same
`AUTHENTIK_BACKUP_RSYNC`/`_FTPS` options exist for the Authentik backup (`deploy/authentik/backup.sh`).

**Accounts (Settings → Account).** You can create more than one account, so each person
signs in with their own password, passkeys and 2FA, and the audit log records *who*. There
are **no roles**: every account is a full administrator over the whole fleet — multiple
accounts buy attribution, not isolation.

**Automation tokens (Settings → Infrastructure & tokens).** For cron, CI or monitoring: a bearer token
with an explicit scope (`read` for `/api/status`, `/api/hosts` and `/api/sessions`; `run` for
`POST /api/hosts/{id}/run`), mandatory expiry, hashed at rest, revocable in one click, and recorded in the audit log as
`token:<name>`. It is deliberately narrow — no accounts, no signing key, no backups, and
**hosts marked 2FA refuse tokens** because step-up needs a human with a passkey. The audit
log is **not** reachable with a token, on purpose: it holds full command text, operator emails
and IPs, so `/api/audit` stays browser-session only.

```sh
curl -H "Authorization: Bearer wt_…" https://your-domain/api/status
```

**Audit log (Settings → Audit).** Every request that changes something (POST/PATCH/DELETE
on `/api`) is recorded with actor, IP, path, status and a detail (which command, which
file, share writable or not), together with the reads that take data *out* — file
downloads, transcripts, previews. Request bodies are never stored — passwords and file
contents don't reach the log. `POST /api/history` is skipped (it has its own table), as
are rejected requests with no actor. Retention via `WEBTERM_AUDIT_DAYS` (default 120 days).
The browser session can be tightened with `WEBTERM_SESSION_TTL_DAYS` (default 30) and
`WEBTERM_SESSION_IDLE_HOURS` (default 12).

<a id="signed-agent-updates"></a>
**Signed agent updates (Ed25519).** Agents only accept `ptyd.py` signed with the
key whose public half is pinned inside them (`UPDATE_PUBKEY`, TOFU at install); CI
refuses the build if `agent/ptyd.py` changed without re-signing. There are two ways
to own that key:

- **Per-deployment key (the default — you get one automatically)** — on the first boot
  of an install with no key and no enrolled hosts, the gateway generates its own key,
  substitutes `UPDATE_PUBKEY` in the `ptyd.py` it serves, and re-signs at runtime, so
  your fleet trusts only *your* key. It lives on the gateway (`data/agent-signing.key`)
  and is written **without a passphrase**, because auto-updates must survive a restart
  nobody is watching. **Settings → Infrastructure & tokens** shows its status; the *generate* and
  *import* buttons there apply only to an install that does not have a key yet (they return
  409 once one exists — so, after the first boot, practically never). To use your own or a
  passphrase-protected key, replace it **before enrolling hosts**: stop the gateway, put
  your PEM (Ed25519, PKCS8) in `data/agent-signing.key` (mode 600) and its public key as 64
  hex characters in `data/agent-signing.pub`, and start it again (or place both before the
  first boot, so nothing is generated). After hosts are enrolled, a new key means
  reinstalling every agent, or the rollover in the design note. Full model: [docs/design/SIGNED-UPDATES.md](design/SIGNED-UPDATES.md).
- **Build-time key (fork & build your own image)** — a key that stays offline, used to
  sign at build/commit time, never on the gateway. A deployment key on the gateway takes
  precedence (the gateway re-signs with it), so this path needs a gateway with no
  `data/agent-signing.key` — set `WEBTERM_SIGNING_AUTOGEN=0` **before the first boot**, so a
  new install doesn't generate one:

  ```sh
  scripts/gen-signing-key.py /secure/path/webterm-signing-key.pem
  git add agent/ptyd.py agent/ptyd.py.sig && git commit -m "own signing key"
  ```
  On every later `ptyd.py` change: `WEBTERM_AGENT_SIGNING_KEY=<key.pem> scripts/sign-agent.py`.

Either way, **keep an offline backup of the private key** — without it, deployed
agents accept no more updates. Honest trade-off: a gateway-resident per-deployment key
means a fully-compromised gateway (with the key *unlocked*) could sign a malicious
update — but the gateway is already the single point of total compromise (see the
[threat model](THREAT-MODEL.md)), so this doesn't widen the blast radius.
