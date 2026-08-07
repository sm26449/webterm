# Threat model

This document states **what WebTerm defends, what it does NOT, and why** — so you
can deploy it with full awareness and tell a security bug apart from a design
decision. Read it before exposing it.

## Who it is designed for

WebTerm is a tool for **one administrator, or a small team where every member is
trusted with the whole fleet** — like the people who share an account on a jump host.
Since v1.0.137 each of them can have their own account (own password, passkeys,
2FA) so the audit log records *who*; but all accounts are equally powerful. It is
NOT a multi-tenant SaaS, and there is no way to give someone partial access. Many
decisions follow from this.

## Components and trust boundaries

```
[ Browser ]  --TLS-->  [ Gateway ]  --TLS-->  [ Agent (as its own user) ]  -->  [ Host: PTY, files, commands, forwards ]
   user                 FastAPI+SQLite          ptyd.py (stdlib)
```

- **Browser ↔ Gateway**: TLS + account (argon2 password / passkeys / TOTP),
  `__Host-` HttpOnly/Secure cookie, Origin verified on the WebSocket
  (anti-CSWSH), CSP, per-IP lockout.
- **Gateway ↔ Agent**: the agent authenticates with a **256-bit token** +
  **instance-pinning** (anti-clone). The gateway authenticates to the agent via
  **TLS** (public CA) or **cert pinning** (`insecure`/self-signed mode).
- **Agent ↔ Host**: the agent runs with its user's privileges and never escalates. The install
  command offered by default creates a dedicated unprivileged `webterm` user; installing as root
  gives it root.
  Filesystem operations and commands are NOT sandboxed.

## What it DEFENDS (invariants to maintain)

- **Authentication & session**: no bypass; constant-time login (no account
  enumeration); lockout on the real IP; 2FA step-up (passkey) on flagged hosts;
  idle-lock with re-authentication.
- **CSWSH / CSRF / XSS**: Origin verified on all browser WebSockets; CSP without
  `unsafe-eval`; `__Host-` cookies.
- **Injection**: parameterized SQL; `target_host` on an allowlist (anti-ANSI
  injection); filtered proxy headers (anti request-smuggling); OSC 133/52
  filtered from untrusted telnet devices; passwords redacted from the transcript.
- **Path traversal / SSRF**: validated paths (uuid sid); the forward target comes
  from the stored row, not from the URL; static SPA containment-checked.
- **Agent updates**: signed with **ed25519**, anti-rollback; the agent rejects
  any unsigned/old update. The key is **per-deployment** (yours), not an external
  one — see [design/SIGNED-UPDATES.md](design/SIGNED-UPDATES.md).
- **DNS hijack / rogue gateway**: standard TLS (public CA) rejects an invalid
  cert; **cert pinning** covers `insecure` mode; a handshake deadline cuts off a
  hostile gateway that dribbles bytes.
- **Forward isolation**: each on an isolated subdomain, HMAC token bound to the
  slug, `__Host-` cookie, anti-SSRF.
- **Post-incident reconstruction**: every state-changing API request is written to
  the audit log (actor, IP, path, status, detail) by middleware, so a new endpoint
  cannot silently escape it; request bodies are never stored. Two deliberate exceptions:
  `POST /api/history` (which has its own table, so logging it is pure noise) and rejected
  requests with no actor — scanner traffic. A 401/403 that *does* carry an actor is kept,
  because that one says something. With one account it
  buys forensics ("what was done with my stolen cookie"); with several accounts it
  also answers *who* — every account is a distinct identity, even though all of
  them are equally powerful (see limitation 2).

See [design/ARCHITECTURE.md](design/ARCHITECTURE.md) for the agent's resilience
(crash, stall, OOM, tmux wedge).

## What it does NOT defend (by design — NOT vulnerabilities)

1. **The agent runs with its user's privileges, and there is no sandbox.** Anyone who gets past
   login has that user's shell and files on **all** hosts — exactly like holding an SSH key for
   it. How much that is worth is entirely your install choice: the default command creates a
   dedicated `webterm` user, so it is that user's access; installing as the current user while
   root makes it root's. The agent itself never escalates. *Recommended mitigation:* keep the
   default dedicated user unless a host genuinely needs more.
2. **There is no object-level authorization / RBAC.** You may create several
   accounts (Settings → Account), but **every account is a full administrator**:
   any of them can do anything, on every host. Multiple accounts buy
   **attribution**, not isolation — each person has their own password, passkeys
   and 2FA, and the audit log finally records *who*. Safe ONLY while every
   account belongs to someone you trust with the whole fleet. Real isolation
   (roles, per-host permissions, sandboxing) is still absent by design.
3. **The gateway is a single point of total compromise.** It commands every agent, with whatever
   privileges each was installed with. A compromised gateway (RCE) = a compromised fleet. The update
   signature protects the **persistence** of the agent code, but `run`/`fs`
   commands are not individually signed. *Consequence:* protect the gateway like
   the crown jewels.
4. **The fleet signing key is a trade-off, not a strict upgrade.** There are two
   channels, and picking one decides *who* can put code on your hosts.

   - **Your own deployment key — this is the default, and it is generated for you.** On the
     first boot of an install that has no key and no enrolled hosts, the gateway generates an
     Ed25519 key pair by itself (`gateway/app/main.py`, `signing.should_autogenerate`). From
     then on it substitutes *your* public half into the `ptyd.py` it serves and signs every
     update with the private half. You are independent of the project's key. The cost, and it
     is the one that matters: **the gateway can sign anything**, so an RCE on it *can* implant
     persistent code on the whole fleet.
   - **No deployment key.** Agents embed the *maintainer's* public key and the gateway can
     only **relay** the blob the project signed — it cannot forge another, because it does not
     hold that private key. A compromised gateway then cannot implant persistent code on your
     hosts. The cost: you trust the project's release key, and every instance without its own
     key shares that trust anchor. You land here only if hosts were enrolled before any key
     existed — auto-generation deliberately refuses to run then, because those agents already
     hold a different public key and would rightly refuse updates signed with a new one.

   **The auto-generated key is stored without a passphrase.** A key nobody can type a password
   for at boot is a key that stops auto-updates dead, so the default trades secrecy at rest for
   a fleet that actually receives updates. It means the "keep it encrypted and locked" advice
   below does **not** describe what your install is doing unless you deliberately made it so.

   Neither is "more secure" in the abstract, and the "independence" is thinner than it
   looks: **you already run the project's container image**. If the project is compromised
   you get a malicious *gateway*, which owns the fleet through `run` and sessions — commands
   are not signed and cannot be. So a deployment key does not save you from a compromised
   project; it only decides who may replace the agent *binary*.

   Where a deployment key is genuinely needed:
   - **You build or modify the agent yourself.** Change `agent/ptyd.py` and the project's
     signature no longer matches, so the gateway refuses to push anything (fail-closed).
     Your own key is the only way to ship your own agent.
   - **Policy**: "no third-party key may authorize code on our machines", even when the
     practical delta is small.

   An **encrypted** key raises the bar: keep it locked and unlock only when you deliberately
   push an update, and a background RCE cannot sign anything because the key is not in memory.
   Auto-update pauses meanwhile, and the gateway says so in four places (red dot in Settings, a
   log line, an email/webhook alert, and the closing report of `upgrade.sh`).

   Two limits, so nobody plans around a property they do not have:

   - **A passphrase can only be chosen when the key is created.** `/api/signing/generate` and
     `/api/signing/import` both return 409 once a key exists, and there is no endpoint that
     adds a passphrase to one or deletes it. To move an auto-generated key to an encrypted one
     you replace `data/agent-signing.key` on disk yourself — and, because that changes the
     public half, every enrolled agent must then be reinstalled.
   - **Locking is a memory operation, not a durable state.** It drops the key from memory, but
     an unencrypted key is loaded again from disk on the next boot, so any restart — every
     upgrade — undoes it. Locking only means something for a key that is encrypted at rest.

   **Truly offline signing is not what the "generate key" button does.** The gateway must hold
   the private key in memory to sign. Offline means: build your own image with your public key
   substituted into `agent/ptyd.py`, sign it with `scripts/sign-agent.py` on an offline
   machine, and ship that image — the gateway then never holds a private key at all.

   Whatever you choose, **decide before enrolling agents**: agents remember the key from
   install time, so generating a key *after* enrolment makes every existing agent refuse
   updates (correctly) until you reinstall it. The gateway now records that refusal, alerts,
   and tells you the remedy — it used to swallow it.
5. **Scheduled server-side backups are unencrypted** — the server holds the vault
   key in cleartext anyway. On **download** they are encrypted with your
   passphrase. The ops backup (`scripts/backup.sh`) can be encrypted with
   `WEBTERM_BACKUP_PASSPHRASE`.
6. **Automation tokens bypass 2FA and passkeys by design.** A token is a bearer
   secret: whoever holds it acts without a second factor. That is why they are
   deliberately narrow — an explicit allowlist of read endpoints plus fleet `run`,
   mandatory expiry, hashed at rest, revocable, recorded in the audit log as
   `token:<name>` — and why **hosts marked `require_2fa` refuse them outright**:
   step-up needs a human with a passkey. A token can never create accounts, touch
   the signing key, download backups (they contain the vault key) or open shares.
   If you don't run automation, don't create one.
7. **`insecure` mode** (TLS without validation) — an **opt-in** footgun for
   IP/self-signed deployments. Cert pinning makes it usable, but in production
   use a **domain + public CA**.

## Outbound connections the gateway makes on its own

Exactly one that you did not ask for, and it is switchable off: a
`GET https://api.github.com/repos/<repo>/tags`
to answer "is there a newer version?", at most **once a day** (plus the explicit
"check now" button in Settings). It carries no information about the instance — no
identifier, no host list, no counters — and a failure is cached for an hour so a poll
loop cannot burn GitHub's unauthenticated rate limit.

Turn it off with `WEBTERM_UPDATE_CHECK=0` (env wins) or the toggle in Settings →
Preferences.

One more, triggered by you rather than scheduled: opening the port-forwarding panel makes
the gateway resolve and complete a TLS handshake against `wtcheck.<your forward domain>`,
to tell you whether the wildcard DNS and certificate are actually in place. It goes to your
own domain, carries nothing, and only happens while you are looking at that panel.

With the update check off and that panel closed, the gateway initiates no outbound
connection you did not configure. The other outbound paths exist only because you set them up: SMTP alerts,
the alert webhook, cloud backup (Google Drive / Dropbox), and the SSH/telnet hosts you
added. Unconfigured, none of them make a connection.

On a public repo the check needs no credentials. `WEBTERM_UPDATE_CHECK_TOKEN` exists
only for private repos and is deliberately optional: a GitHub token inside the gateway
is reachable by anyone who reaches the gateway.

**There is no telemetry.** WebTerm never reports usage anywhere. Who accessed *your*
instance is answered locally by the audit log, not by us.

## Safe deployment rules

1. **Domain + HTTPS + passkeys** — not just IP/password.
2. **Keep the default dedicated agent user** — do not install as root unless a host needs it.
3. **Decide the signing channel before enrolling agents** (see invariant 4): the project's
   release key by default, or your own deployment key for independence — knowing it lets a
   compromised gateway sign agent code.
4. **Protect the gateway** — it is the security SPOF. Firewall, HSTS, timely updates.
5. **Off-host + encrypted backups**; an **offline** copy of the signing key
   (without it you can no longer sign updates).
6. **Do not expose `insecure`** in production.

## Reporting an issue

If you find a way to break an invariant from "What it DEFENDS" — or to escalate
without the premises in "What it does NOT defend" (e.g. from unauthenticated) —
see [SECURITY.md](../SECURITY.md). Do not open a public issue.
