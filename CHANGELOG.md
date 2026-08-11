# Changelog

All notable changes to WebTerm. Format based on [Keep a Changelog](https://keepachangelog.com/).
The number in parentheses after *agent* is `AGENT_VERSION` from `agent/ptyd.py` — agents refuse any
update carrying a lower one, so it only ever moves forward.

Entries say **why** a change exists, not only what changed. A fix without its cause tends to come
back.

## [Unreleased]

### Fixed — from two external security audits (2026-08-10, 2026-08-11)

Both audits were run against the old private repository, so part of what they reported was
already fixed here. Everything below was verified against this tree before being changed,
and the one finding rated Critical did not survive that check.

- **No CSRF defence on HTTP.** The only control was `SameSite=Lax`, which protects nothing
  here: port-forwards are served on **subdomains of the application's own domain**, and
  subdomains are same-site. A compromised device UI on `cam1.example.com` — content the rest
  of the code already treats as hostile, stripping its terminal escapes — could issue
  credentialed POSTs to the app: agent uninstall, host deletion, session kill, and 21 other
  bodyless endpoints. A `csrf_guard` middleware now requires a same-origin `Origin` on every
  unsafe method and refuses a missing one, the position the WebSocket path already took.
  Bearer-token automation is exempt, since it is not CSRF-able.

  The audit escalated this to Critical, arguing that FastAPI parses a body with no
  `Content-Type` as JSON, which would put `/api/hosts/{id}/run` — arbitrary commands — in
  reach of a request that triggers no preflight. It flagged that as unverified. It is not
  true on the shipped versions: every CORS-simple content type, and no header at all,
  returns 422. `tests/csrf_ratelimit_test.py` asserts this against a real uvicorn, so a
  FastAPI bump that changes it fails CI instead of quietly making the claim true.

- **The global brute-force backstop was an unauthenticated kill switch.** 100 failed logins
  in 15 minutes denied *every* authentication method for *every* IP — passkeys included,
  owner included — with no reset from the UI, recoverable only by restarting the container
  over SSH: the thing WebTerm exists to replace. It now degrades instead of denying: a
  2-second tarpit, with addresses that authenticated successfully recently passing
  untouched. Per-IP limits, which are the real anti-guessing control, are unchanged. Failures
  on internal keys (`reauth:`, `passkey2fa:`) no longer feed the global counter at all, so a
  stolen cookie cannot fill it by typing wrong passwords.

- **The "much wider" hard cap on account re-auth was the same size as the soft one.** Ten
  wrong passwords from a stolen cookie locked the owner out of `/api/account` for 15 minutes
  — the only action that invalidates the attacker's session — and repeating it every quarter
  hour held the door shut indefinitely. The hard cap now has its own budget (50/hour).

- **Password hashing shared asyncio's default thread pool** with transcript `fsync`, tail
  reads, search, backup and signing KDFs. An unauthenticated burst — the rate limit is
  consulted before a failure is recorded, so a concurrent wave all passes — could stall live
  terminal persistence at ~64 MiB per verification. It has a dedicated two-thread executor.

- **`require_2fa` was missing on three host endpoints**: host deletion, the agent connection
  log, and `forget-credentials`. The last one also had no re-authentication of any kind for
  an irreversible action, and took no body, which made it an ideal CSRF target; it now takes
  a body, a step-up and the account password.

- **A 5-minute step-up minted a 12-hour port-forward ticket.** On a 2FA host the ticket is
  now capped at the step-up window, and `route_forward` re-checks that the window is still
  open on every request rather than trusting the cookie for the rest of the day.

- **Forward responses carried no framing headers**, so a device UI was iframe-able from
  anywhere. `X-Frame-Options`, `frame-ancestors 'self'` and `Referrer-Policy` are now sent —
  none of them break device UIs the way a script CSP would. Booting with `http://` while
  forwarding is configured now logs an error: without https the session cookie loses its
  `__Host-` prefix, and a forwarded page can then write a cookie into the app origin.

- **Command-guard regexes ran on the event loop.** Admin-authored patterns are validated only
  for compiling, so one with catastrophic backtracking plus a matching command blocked
  everything. They now run in a thread with a 0.25s budget each.

- **The SMTP host had no validation** while the webhook blocked cloud metadata addresses — an
  asymmetry that is hard to defend when `/api/settings/smtp/test` connects on demand. Same
  guard on both. Private ranges stay allowed on purpose: a Postfix or Mattermost on the LAN
  is a legitimate target for a self-hosted product.

- `deploy.sh` printed the setup token on every run, including upgrades where an account
  already exists and the token is inert (`/api/setup` returns 409). It now asks the running
  instance whether setup is still open.

### Changed

- **THREAT-MODEL is more precise about what signing buys.** It said a deployment key
  "decides who may replace the agent *binary*", and an audit read that as a stronger promise
  than the code makes: a compromised gateway can write `~/.webterm/ptyd.py` directly — via
  the file manager, via `run`, or by typing into a session — and the next restart executes
  it, no signature involved. Guarding the file manager alone would be theatre, since the same
  actor still holds a shell. The signature protects the *channel*, so what it buys is that an
  update pushed to the whole fleet at once cannot be forged: a blast-radius control, not
  per-host integrity.
- `command_history` is documented as client-reported and therefore forgeable; `audit_log`
  remains the record that is not.

### Fixed — certificate pinning, agent 41 (requires re-signing)

- **The agent pinned the leaf certificate**, which an audit flagged as an availability risk.
  Measuring it turned the risk into a certainty: Caddy's internal CA — used by exactly the
  IP/local install where pinning switches on — issues **12-hour** certificates. So the pin
  was not protecting that deployment, it was scheduling a fleet-wide outage before the next
  morning, with the remedy having to travel over the connection the agents had just refused
  and manual SSH to every host as the only recovery.

  Three changes. The pin is now on the **SubjectPublicKeyInfo**, so a renewal that keeps the
  key no longer breaks it. `cert_pins` is a **list**, so a rotation can be loaded before it
  is needed. And a certificate valid for less than 48 hours is **not pinned at all**, with a
  log line saying so — a pin that guarantees an outage is not a defence, and pretending
  otherwise is worse than admitting the deployment has no pin.

  Existing agents keep working: a stored full-certificate pin is still accepted, so nothing
  needs re-enrolling. The mismatch error now prints the observed fingerprint, because the
  previous message told the operator that something was wrong without telling them what to
  trust instead.

  `tests/cert_pin_test.py` generates real certificates with openssl and checks our SPKI
  against openssl's own — which is how a header-length bug in the DER walk was caught, on
  RSA keys where the length is long-form. RSA and EC both verified.

## [2.0.3] — 2026-08-09 · agent (40)

### Changed — a new mark, and the terminal gets its space back

- **New mark.** The three lines that joined the prompt to the hosts were the second-heaviest
  element and were doing the least work; they are now a trail of dots that fades toward the
  prompt, which gives the mark direction — the signal leaves the prompt and grows toward the
  machines. Everything on the right lost weight, and the chevron thinned to match: shrinking
  only one half would have tipped the whole mark. The chevron is now perforated by a grid of
  squares with the tile gradient showing through, so the prompt is made of cells while the
  hosts stay solid — a terminal is made of characters, the machines at the far end are real.
  All icons were regenerated from the one SVG; the maskable one is not that file scaled, since
  platforms crop it to a circle and it needs its own safe zone.
- **The sidebar can be hidden**, and the choice is remembered. The way back matters more than
  the hiding: the ☰ button that was mobile-only now appears on desktop exactly while the
  sidebar is collapsed. A panel that hides with no visible way to return is a trap, so the E2E
  asserts both directions.
- **"New session" moved into the host ⋯ menu**, first item, with a separator before the
  administrative entries. In the row it only appeared on hover and competed with the host name
  and the update badge; in the menu it has full text, the first position, and a rule that keeps
  an absent-minded click off "Uninstall".

Nothing changed on the server or in the agent — this release is the interface and the icons.

## [2.0.2] — 2026-08-09 · agent (40)

### Added — you find out when someone attaches to your terminal

- **Attach notifications.** The viewer count already existed, but it changed *silently*: you
  learned that a second client was on your session only if you happened to be looking at that
  corner of the toolbar at that second — and if you were working, you were not looking. Every
  client already attached now gets an `attached` event, raised to a system notification, so it
  reaches you with the tab in the background.
- **Device identity in the viewer list.** The roster carried a count and a role, which cannot
  tell your own phone apart from a stranger — so there was nothing to act on. It now carries the
  IP and a short browser label per client, next to the existing kick button.
- **Unfamiliar devices are flagged and emailed.** A client attaching from an address never seen
  on a successful login for the account is marked *new device* in the list, its notification is
  raised to a warning, and an email goes out (throttled to one per address per 15 minutes, so
  five tabs from one new place send one message). Attaches from familiar addresses stay quiet —
  an alert that fires constantly is an alert nobody reads, and then the one that mattered is
  unread too. Guests arriving through a share link always count as unfamiliar: the link was
  given deliberately, but the moment it is *used* is exactly what you want to know.

### Added — a password change from an unfamiliar device needs the account's inbox

- **Confirmation code by email.** Changing the password (or the email address) from a session
  that was opened on an address never seen on a successful login now also requires a six-digit
  code mailed to the account address. The attack this closes: someone who already *has* your
  password — reused, leaked, guessed — rotates it and locks you out of your own account. Email
  is the channel they do not have.
- **A code, not a link.** A link is clickable by anyone who reaches the inbox, and mail scanners
  open links on their own, which would consume a single-use token before you ever saw it. A code
  typed into the page you are already on proves both inbox access and that you started the change.
- **It escalates, it does not refuse.** Blocking credential changes outright from an unfamiliar
  address sounds strict until you are travelling, your password has just leaked, and that is
  precisely when you are not allowed to change it. The code lets the legitimate user through in
  thirty seconds and the attacker through never.
- The code is single-use, valid ten minutes, capped at five attempts, and re-issuing invalidates
  the previous one. It is sent to the **account's** address, not the instance alert mailbox, and
  never over the chat webhook — a confirmation code posted to a channel confirms nothing.
- **Only when SMTP is configured.** Without a mail channel, refusing the change would be a
  permanent account lockout rather than a security measure.

### Added — passkey changes need a second factor, and a recovery command

- **Enrolling or removing a passkey now needs more than the password.** It was the hole left by
  the change above: someone with your password could not rotate it any more, but could still
  enrol *their own* passkey — a permanent, phishing-resistant key to your account — or delete
  yours. With TOTP on, the code from the phone is required (a recovery code works too). Without
  TOTP, the emailed code is required from an unfamiliar device; from your usual machine the
  password stays sufficient, as before.
- **Email is not accepted in place of TOTP.** If it were, two-factor would be worth exactly as
  much as access to the mailbox and the phone would defend nothing. For a lost phone there are
  the ten recovery codes, and if those are gone too, the server.
- **`python3 -m app.admin` — recovery over SSH.** `list`, `passwd`, `disable-2fa`, `logout-all`.
  Every gate the UI gains is another way to lock yourself out; a self-hosted product can afford
  to be strict in the browser precisely because this exists. It replaces the hand-written SQL in
  RUNBOOK §5, which hashed correctly but left the open web sessions and share links alive — you
  could rotate the password and leave the intruder logged in. The new password is prompted for,
  never passed as an argument.

### Fixed — found by a four-way audit run against this release

- **Wrong TOTP codes were not counted** on the passkey gate above. Re-authenticating with the
  password calls `record_login_success`, which *clears* the failure counter — so someone who
  already had the password could send (good password + guessed code) forever, each attempt
  wiping its own trace, and brute-force a six-digit code with no lockout at all. It has its own
  counter now, which nothing else resets, and deliberately no "a correct code passes anyway
  during lockout" escape hatch: a guesser needs one lucky hit, so that hatch would delete the
  defence it belongs to.
- **The version header was served before login.** `X-Webterm-Version` went out on every
  `/api/*` response, including the public `/api/login` and `/api/state`, while the comment above
  it claimed the opposite. It now requires a session cookie.
- **Passwords had a floor and no ceiling**, so a multi-megabyte body reached argon2 on a path
  that is free to repeat. Capped at 1024 characters.
- **Traefik, docker-socket-proxy, caddy and the backup tool image floated on mutable tags**
  while the Dockerfile declared a digest-pinning policy. The backup image was the worst of them:
  it runs as root over the data volume with the vault key mounted — the most powerful container
  in the system — and accepted whatever anyone pushed to `python:3.12-alpine`. All pinned by
  digest, and Dependabot now watches the compose files too, which is why they had drifted
  unreviewed.
- **`packages: write` applied to the whole CI workflow**, so the test job ran with a token that
  could write to the registry. Scoped to the job that publishes.

### Fixed — "familiar address" meant "seen once", which defeated itself

Marking a device familiar the first time its address appeared meant an attacker who knew the
password logged in once from home and was familiar on the second attempt — the gate opened
*because* he had attacked twice. Familiar now means an address with history: at least three
logins, first seen more than 24 hours ago. The first visit from a new address already sends the
new-login alert, so that window is not silent — it is the interval in which you can react.
Existing rows are treated as established, so an upgrade does not make every known place strange.

The "new device" verdict is taken at login and frozen on the session (`web_sessions.device_new`).
It has to be: a successful login *records* the address, so a check made later would always answer
"familiar" — the gate would look like it worked while doing nothing. `tests/account_confirm_test.py`
asserts exactly that, so a future rewrite into a live lookup fails the suite.

Device identity here decides **how loud to be, never whether to check**. Nothing in this release
lets a recognised device skip step-up, the idle lock, or 2FA. That is deliberate: an IP and a
user-agent both travel with a stolen session cookie, so a "trusted device" bypass would be
waved through by precisely the attacker it appears to stop — and it would trade the idle lock's
5-minute exposure window for permanent access.

## [2.0.1] — 2026-08-08 · agent (40)

Everything here came out of nine external audits run against 2.0.0 before it was announced.
Two findings could only be found by breaking something on purpose, which is why they had
survived a year of code review.

### Fixed — things that looked like defences and were not

- **The automatic rollback never rolled back.** `deploy.sh` exports `WEBTERM_IMAGE` with the new
  tag and then `exec`s `rollback.sh`; `exec` inherits the environment, and compose prefers it
  over `.env`. So the rollback rewrote `.env`, `up -d app` re-resolved to the image it was
  fleeing, and the container stayed broken — while `.env` and `.prev-image` ended up swapped,
  pointing the manual rollback at the broken image too. RUNBOOK listed this as a defence layer.
- **`restore.sh` restored into a volume nothing used and reported success.** Docker silently
  creates a missing volume; the restore succeeded into it, exit 0, "restore OK", while the live
  app kept its own empty one. The name comes from the install directory, so it is wrong by
  default on any machine that is not `/opt/webterm` — which is exactly the rebuild procedure
  being copied between hosts. `backup.sh` had the guard; `restore.sh` did not.
- **`GET /api/search` read the contents of every transcript and left no audit trail**, while
  the same class of read through `/transcript`, `/fs/download` and `/preview` all did. After a
  stolen cookie, the log answered "nothing".
- **A missing `alive` field closed live sessions.** One loop tolerated it and read `None` as
  falsy, i.e. "it died" — `on_exit` plus `reap`, killing the real tmux session on the host.
- **Uninstalling could delete the user's entire crontab** when `crontab -l` failed for any
  transient reason, because the empty result was written back.
- **Security alerts switched themselves off**: compose passes `WEBTERM_ALERT_FROM` present and
  empty, so it never fell back to `SMTP_USER` and email alerts silently disabled themselves.
- **Deleting an account left its API tokens alive** for up to a year, because revocation keyed
  on the email, which `update_account` can change. Tokens and shares now key on the account id.

### Fixed — resource exhaustion and unbounded growth

- A compromised agent could adopt unlimited sessions (3000 rows and 6000 open files from one
  heartbeat) until the gateway's disk filled — taking the whole fleet with it. Adoption is
  capped per host and refused visibly.
- Agent-reported `hostname`, `user`, `update_blocked` and `metrics` are bounded; metrics are a
  whitelist of finite numbers, because a bare `Infinity` off the wire made the host page 500.
- Transcripts of closed sessions were never reclaimed: the retention only ever applied to
  sessions deleted by hand.
- Ports 80/443 were checked but nothing compressed the frontend: 904 KB on every cold load,
  18.6 s to first paint on 3G. Gzip in the application covers every deployment path.

### Fixed — installs and upgrades

- Installers refuse to start when the ports they would publish are taken, instead of leaving
  half a stack behind, and `setup.sh` asks compose which ports those actually are so the
  documented override recipe works.
- `.env` is parsed, not executed. Sourcing it as root meant a value with spaces broke the
  install and a value with `&&` ran commands.
- A second install can no longer hijack the first one's systemd units, whose names are fixed
  regardless of `--dir` — including the file holding the passphrase that decrypts its archives.
- The update notification pointed at `deploy.sh`, which changes the image only; half the system
  lives on the host and is synced by `upgrade.sh`.
- Getting the setup token wrong now counts down instead of locking you out without warning.

### Fixed — interface

- Romanian plurals go through `Intl.PluralRules`: "1 parametri" and "20 hosturi" are gone.
- Dates follow the chosen language and timezone; both settings existed and neither was applied.
- The file panel got the focus trap the other thirteen modals already had.
- The install command says it appends a line to `~/.bashrc`, on the screen where you copy it.
- Login and 2FA errors are translated; a host without tmux says so in words, where you work.

### Changed

- The published image is pinned by version rather than `:latest`, so a fresh install is
  reproducible and the rollback breadcrumb points at something real.
- `SECURITY.md` commits to a 7-day acknowledgement and a 30-day assessment, offers an address
  for people without a GitHub account, and states a safe harbour.

## [2.0.0] — 2026-08-07 · first public release · agent (37)

WebTerm was developed privately for about a year before this release. This is the first version
published as source, so the history below starts here rather than replaying that development.

Some documents cite `v1.0.x` versions when explaining why a piece of code looks the way it does.
Those tags belong to that private history and do not exist here; they are kept because the
reasoning is worth more than the version number. Any command you can copy and run refers to a
version that does exist.

### What it does

- **Persistent sessions.** Every session is a tmux session on the host. Close the browser, restart
  the gateway, kill the agent — the process keeps running and you reattach from anywhere,
  including a phone, from several devices at once.
- **Nothing listens on your servers.** A single-file Python agent dials *out* to the gateway over
  WebSocket, so a machine behind NAT or on a mobile connection works like one with a public IP.
- **Full history.** Each session records what came back on screen to a raw stream and an asciicast
  you can replay. Input is never recorded, so passwords typed at a prompt do not end up in the
  transcript or in a backup of it. Search runs across every session.
- **Files.** Browse, edit, upload and download over the same agent connection, with atomic saves
  and a conflict check on modification time.
- **Port forwarding.** Expose a service running on a host at its own subdomain, authenticated by
  the gateway, without opening a port on the host.
- **Telnet bastion and serial console.** Reach a switch, router or serial device on a host's
  private network as a normal session, without hopping through a shell first.
- **Fleet view.** Hosts with online status, load and disk, grouped into folders, plus running one
  command across several hosts at once.

### Security posture

- Password login plus **passkeys** (WebAuthn) or TOTP. Hosts can be marked *require 2FA*, which
  demands a second factor for connecting, reading history, browsing files, creating a port forward
  and probing one.
- **Signed agent updates.** Each deployment generates its own Ed25519 key at first boot; the
  gateway substitutes its public half into the agent it serves and signs every update with the
  private half. Agents refuse anything that does not verify, refuse older versions, and validate
  that a new release actually starts before replacing themselves.
- **Credential vault**, encrypted at rest. Backups you download, and those written by the
  installed timer, are encrypted with a passphrase you
  choose, because they contain the vault key.
- An **audit log** of every action that changes something, and of the reads that take data out —
  file downloads, transcripts, previews.
- The honest limits are documented rather than glossed: no roles, the gateway is a single point of
  total compromise, and it is built for one trusted administrator. See
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

### Interface

- Terminal rendered with WebGL, falling back to canvas and then DOM.
- Tabs, split view, and popping a session into its own window.
- Works on phones and tablets: ten real device profiles are checked in CI on every build.
- Shell integration (OSC 133) marks commands so you can jump between them, see exit codes and
  copy a command with its output.
- English and Romanian, with the language chosen from the browser and switchable in settings.
  Adding a third is copying one file and translating the values.

### Requirements

A machine with Docker, and `tmux` plus Python 3 on each host you want to reach. Nothing else.
