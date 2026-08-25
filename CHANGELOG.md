# Changelog

All notable changes to WebTerm. Format based on [Keep a Changelog](https://keepachangelog.com/).
The number in parentheses after *agent* is `AGENT_VERSION` from `agent/ptyd.py` — agents refuse any
update carrying a lower one, so it only ever moves forward.

Entries say **why** a change exists, not only what changed. A fix without its cause tends to come
back.

## [Unreleased]

### Fixed — terminal font size is now a device preference, and tabs stay in sync

- The A± font size was one value per browser, read by each tab once at mount — and the
  width-based default (phone 9 / tablet 12 / desktop 14) was written to storage on first
  visit, freezing it forever. So tabs opened before and after an adjustment disagreed,
  rotating a phone or resizing a window changed nothing, and the fix was always manual
  A−/A+ until the rendering looked right again.

  The preference is now kept per device class (phone/tablet/desktop, same breakpoints),
  A± overrides only the class you are on, and every mounted tab recalibrates when it
  becomes active, when the viewport crosses a breakpoint, and the moment A± is pressed
  in any other tab. Only a deliberate A± persists anything — the default stays live.
  A background tab that realigns announces its size passively, so it cannot steal the
  PTY size from a device actively using that session. The old single value migrates
  once, as the override of the class it was calibrated on.

### Fixed — a reboot left every new session in `sh` (agent 42)

- After a reboot the prompt collapsed to a bare `#`, with no tab completion and no history:
  the shell was dash, not bash. tmux picks `default-shell` from `$SHELL` first, then the
  passwd entry, then `/bin/sh` — and `$SHELL` is whatever the process that started the tmux
  *server* happened to have. The installer supervises the agent with cron `@reboot` plus a
  watchdog, and cron sets `SHELL=/bin/sh`. So the server came up with dash and every new
  session inherited it, while sessions created before the reboot were fine. The symptom
  appears far from the cause, which is why it survived.

  `default-shell` is now taken from the passwd entry, which is the actual source of truth for
  a user's shell, and it is in the options applied to a running server as well — so an
  existing host is fixed by updating the agent, without killing its tmux server.

### Added — uninstall from the host, confirm in the interface

- `python3 ~/.webterm/ptyd.py uninstall` removes the agent from the machine it runs on:
  daemon, supervision, the WebTerm tmux server, and `~/.webterm`. It asks first; `-y` skips.

  It does not remove the host from WebTerm. It reports that it is gone, and the host list
  shows *agent removed on the server* with a button. From a host you can always remove the
  agent — nobody stops you, it is your machine — but what stays in WebTerm's records is a
  decision made while signed in. Otherwise anyone with a shell on that host could make it
  vanish from the operator's dashboard. And often you are not deleting at all, only
  reinstalling: the notice then clears by itself when the agent reconnects.

  The endpoint is authenticated with the host token and only ever writes a marker. Both
  route-authorisation gates rejected it until it was declared with a reason — once for having
  no user dependency, then again for being a public route that writes.

### Added — the installer says the dedicated user has no sudo

- Installing as `webterm` and then hitting *"Sorry, try again"* on the first `sudo apt
  install` is confusing precisely because it is correct behaviour: the account has no
  password and no sudo, which is the reason to use it. The installer now says so at the end,
  where you are about to hit it, with the command to grant sudo and a link to the narrower
  options. Detected with `sudo -n true`, so root installs stay quiet.

  Generating a password at install time was the obvious alternative and is worse: a password
  alone grants no sudo, so the group change would be needed anyway; it makes the account
  loginable over SSH on every install, which `useradd` deliberately does not; and the
  generated secret has to travel somewhere — the terminal, the scrollback, or the gateway
  itself during one-click provisioning. The gap was missing information, not a missing
  password.

### Added — how to give the dedicated user the rights it needs

- The recommended install creates `webterm` with no password and no sudo, which is the point
  — and which makes the first `sudo apt install` fail confusingly. README now documents the
  three ways to grant it (narrow sudoers entry, full sudo with a password, full passwordless
  sudo), what each costs, and the `dialout` group needed for serial consoles.

## [2.0.5] — 2026-08-12 · agent (41)

Gateway and interface only: the agent is unchanged, so nothing in the fleet needs updating.

### Added — you can see which devices are signed in, and remove one

- Settings → Security lists every browser signed in to the account, with a readable device
  label, when it was last used, which one you are sitting in, and the same *new device* badge
  the session roster uses. Each can be signed out on its own, or all the others at once.
  Until now, suspecting a stolen cookie left two options and nothing in between: change the
  password, which kills every session including yours, or SSH to the server.

  Revoking asks for no password. It is a defensive action, and the worst someone with your
  cookie can do there is sign you out. "Sign out everywhere else" also closes the step-up
  windows — those are keyed per account and host rather than per device, so without it the
  removed device's "sudo" would have survived on yours.

### Changed — the opening diagram shows what the product actually does

- The first diagram is what most visitors read, and often all they read, and it showed a
  narrower product than this is: no direct SSH, no telnet, no port forwarding, no files, no
  serial console, no fleet run, no share links. Telnet appeared only as a tunnel through the
  agent, which suggested the agent is mandatory — the opposite of what the text below it says.
  Rebuilt as three layers: who connects, the three ways to reach a machine, and what you can
  do once there. Forwards are drawn leaving the agent and the SSH host rather than the
  gateway, because drawn from the gateway they would imply it reaches into your network by
  itself, which is backwards and is the invariant the security model rests on.


### Fixed — "forget the credentials" did not forget all of them

- Deleting the stored SSH credential removed the database row and nothing else, while
  `asyncssh` keeps `password` and `client_keys` **in clear text** inside the connection's
  options for as long as that connection lives. So the credential stayed in the gateway's
  memory, sometimes for hours, after the button that promised to remove it. Not an
  escalation — reading it needs code execution in the process, and at that point the vault
  key is there too — but a promise half kept is worse than one not made. Forgetting now also
  closes the live SSH connection, and so does switching a host to the `ephemeral` policy.
  The cost is deliberate: live SSH sessions on that host end. That is the right consequence
  of "forget the credentials", which is pressed once the SSH path is no longer needed.

### Added — the install script verifies the agent it just downloaded

- In insecure mode the first `curl -k` fetches the code that becomes the agent, and the
  certificate pin is only established afterwards; whoever intercepts that one download
  installs their own agent. The Ed25519 signature does not help there — it guards the
  *update* channel, and the agent that would check it is the one being downloaded. The
  script now compares the bytes against a sha256 the gateway computed, the same mechanism
  already used for `shell-integration.sh`.

  It does not close the hole, since the digest travels over the same connection, but it
  moves the attack from "intercept a download" to "intercept the download *and* the script
  that checks it".

  The first version of this hashed `agent/ptyd.py` on disk — and would have rejected every
  install. `/agent/ptyd.py` does not serve that file: with a fleet signing key, which the
  gateway generates by itself on first boot and is therefore the normal case, `UPDATE_PUBKEY`
  is substituted into the source. The digest now measures what actually leaves the endpoint,
  and the test generates a fleet key so the two genuinely differ — without that it passed
  against the broken implementation too.

### Added — the risk you cannot recover from is now stated in the UI

- One passkey plus at least one host marked *require 2FA* is the only combination with no way
  back through the interface: lose the device and those hosts refuse the password for as long
  as a passkey is enrolled, leaving `python3 -m app.admin` on the server. Settings → Security
  now says so while there is still time to enrol a second one.

### Added — a writable share guest leaves an attributable trace

- A guest with write access could type into a terminal and the audit log recorded "someone
  through a share". They have no account, so they cannot be named — but they can carry the
  identity they do have: the client id shown in the viewer list (the same one the kick button
  uses), the address, and the browser. Enough for "who ran this" to have an answer when a
  link went to three people.

### Added — tests for the strongest factor in the system

- An external audit listed `webauthn_api.py` as unexamined. It was examined and is correct:
  single-use challenges, RP-ID and origin validated, user verification required on both login
  and step-up, sign counts propagated. What was missing was a gate keeping it that way, so
  the properties are now asserted — including against the source, so removing
  `require_user_verification` fails the suite even on a path nothing else exercises.

## [2.0.4] — 2026-08-11 · agent (41)

A security release: two external audits, one of them escalating a finding to Critical that
did not survive being tested. The agent changes, so it carries a new signature.

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

  The guard took three rounds to get right, and each wrong version was caught by a test that
  runs the real path rather than by reading the code. The first demanded `Origin` from every
  non-Bearer request, including ones with no cookie at all — which broke scripted
  provisioning and the project's own end-to-end setup. CSRF is about a credential the browser
  attaches *by itself*, so the gate belongs on requests carrying the session cookie; a
  request that presents its credentials explicitly was never at risk. The second compared
  `Origin` only against `WEBTERM_PUBLIC_URL`, so anyone reaching the gateway by IP, or by any
  name other than the configured one, would have been refused on every write. The request's
  own `Host` is now accepted too, which weakens nothing: an attacker cannot choose `Host`,
  and in the one case where they can (DNS rebinding onto our address) our cookie is not sent,
  so the guard does not apply.

  One residual is stated rather than hidden: a not-logged-in browser can still be made to
  POST `/api/login` with an attacker's credentials. On a single-administrator product that
  means landing in someone else's account — immediately visible, with none of your data
  reachable — and blocking it would mean no script could ever authenticate.

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

  That re-check sits on the path every forwarded request takes, and the first version of it
  queried a table that does not exist (`forwards` rather than `port_forwards`), so it raised
  on each call: eight forwarding tests failed, half of them with 500. It is deliberately not
  wrapped in a `try/except` that returns "allowed" — on a security check, "could not tell, so
  let it through" is a defence in name only. `tests/forward_stepup_test.py` now exercises the
  helper against a real database with the real schema, which is what would have caught a
  wrong table name without needing a container.

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
