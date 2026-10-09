# Changelog

All notable changes to WebTerm. Format based on [Keep a Changelog](https://keepachangelog.com/).
The number in parentheses after *agent* is `AGENT_VERSION` from `agent/ptyd.py` — agents refuse any
update carrying a lower one, so it only ever moves forward.

Entries say **why** a change exists, not only what changed. A fix without its cause tends to come
back.

## [Unreleased]

### Changed
- **Unfinished uploads are remembered per account.** The resumable-upload metadata in localStorage
  (`wt_up_*`) carried no account, so on a shared browser the next person to sign in saw the
  previous account's *Incomplete* rows — names and paths — and a re-drop of the same file could
  try to resume onto a partial that belonged to someone else (refused by the server, but confusing).
  Keys are now `wt_up_u<user id>_…`, like the interrupted downloads in IndexedDB since 3.5.13: only
  the signed-in account's rows are shown, an expired session hides them until the same account
  returns, and an explicit **Sign out** forgets them (and asks the host to delete the partials).
  Keys from 3.5.16 and older have no owner and are dropped on first start.
- **The audit log says what a copy really was.** `POST /api/fs/copy` was recorded as `copy N files`
  even when the selection was folders (since 3.5.16 a folder copies a whole tree). It now reads
  `copy 2 files, 1 folder alpha:/srv → beta:/backup` — the types come from a bounded `fs_stat` on
  the source, falling back to `N items` if the host is slow — and the retry line says the same.

## [3.5.17] — 2026-10-09 · agent (58)

### Fixed
- **Forwarded apps with their own CSRF check work (Grafana charts, Grafana Live).** The proxy sent the
  target `Host: <ip>:<port>` but passed the browser's `Origin` (the forward subdomain) through, so
  Grafana answered `POST /api/ds/query` and `/api/live/ws` with 403 "origin not allowed" — the
  dashboard loaded, the panels stayed empty. WebTerm now checks the Origin itself (it must be the
  forward's own subdomain on the instance's scheme, otherwise 403 — a sibling forward on the same
  site cannot post with the shared SameSite=Lax cookie) and sends the target its own origin.
- **Terminals no longer freeze when a long session's transcript hits its cap.** Past 64 MiB a
  transcript keeps its last 16 MiB — and that copy (16 MiB of `.out` plus 16 MiB of `.cast`) ran on
  the gateway's event loop, so every ~48 MiB of output in ONE session froze EVERY terminal, every
  API call and every agent connection for as long as it took (138–152 ms measured on a 64 MiB
  transcript; longer on a busy disk). In prod, 6 of 166 transcripts had been cut and several sit
  at 60–65 MB — long Claude Code sessions, which is exactly where the freeze landed. A first
  off-loop attempt (v1.0.117) had been reverted: it closed the live file handles while the thread
  worked, and the session's close/exit/lost paths then wrote to a closed handle, dropping the
  agent connection. Now the live handles are never touched during the copy: a worker thread
  builds the truncated file next to the original from its own read descriptors (the original is
  append-only), then catches up with what was written meanwhile; the loop only copies the last
  ≤256 KiB and swaps the file in with `os.replace` in one synchronous step (<1 ms measured, worst
  event-loop stall 6 ms during a 64 MiB cap). The result is byte-identical to before, bytes
  written during the copy follow the kept tail in order, one cap at a time per session, and a
  session closed, killed or archived mid-copy just abandons the copy. A crash mid-copy leaves the
  untouched original plus a temporary file, deleted at the next start.
- **`.cast` gap event timestamp.** The gap event was stamped "now", i.e. after every event of the
  kept tail it precedes, so the recording's timestamps went backwards once per cap. It now takes
  the timestamp of the first kept event.
- **Transcript readers no longer mix two files' sizes.** `read_tail`, the text view and search
  measured the file by path and then opened it; across a cap they could combine the old size with
  the new content and return an empty tail. They now measure the descriptor they opened.

### Tests
- `transcript_cap_offloop` (new suite, 102 in all): identity with the old algorithm, output written
  during the copy through the real output path (including bursts larger than the on-loop
  residual), `.cast` validity and monotonic timestamps, `out_gen` invalidation, no second cap
  while one runs, teardown / exit / lost / archive mid-copy, `read_tail` and `attach_replay`
  hammered across the swap, a contained failure with back-off, crash-mid-copy recovery, and an
  event-loop heartbeat that must stay under 50 ms while a 64 MiB transcript is capped.

## [3.5.16] — 2026-10-08 · agent (58)

**This release updates the agent (57 → 58)** — hosts update on reconnect (deferred while a host has
open sessions; force it from the host card). The gateway keeps working with agents 50–57: the new
behaviour turns on per host, by agent version, and an older agent gets exactly the previous one.

### Added
- **Copy whole folders to another host, with their permissions.** Since 3.5.5 *Copy to host…*
  copied files only: walking a tree with the agent's existing operations would have landed a
  `deploy.sh` without its executable bit and a `0600` key readable by others. Folders are now
  copied with everything in them: the gateway walks the source with `fs_list` (bounded: 1000 files
  and 1000 folders per job, 32 levels, a directory listed truncated is an error rather than a silent
  partial copy), creates the folders on the destination parents first, copies the files through the
  same resumable-upload machinery (CRC-32 before the atomic rename), and applies the **source's
  permission bits** to files and to the folders it created — folders last and deepest first, so a
  read-only folder still receives its files. **setuid, setgid and sticky are never copied.**
  **Symbolic links inside a folder are not copied** (their target is a path on the source host;
  following them could leave the tree or loop) and **special files** are skipped — both listed with
  a note. For a folder that already exists, *Skip* and *Overwrite* merge into it (existing files
  kept or replaced), *Keep both* copies it as `name (1)`. Copying a folder into itself is refused.
  Plain file copies now keep their permissions too. The Transfers row shows the file being copied
  and, at the end, a summary (skipped, links and special files not copied, permissions not
  applied). **Retry** moved to the server (`POST /api/fs/copy/{job_id}/retry`, step-up on both
  hosts): a folder with failures is merged into the very same destination folder — also under
  *Keep both*, where it has another name — skipping what already arrived. See
  [docs/TRANSFERS.md](docs/TRANSFERS.md#copy-to-another-host).
- **Scrollback history with tmux panes.** Since agent 57 a fresh attach fills the scrollback from
  tmux's own history, but a session whose tmux window was split into panes got nothing (the agent
  declined with `multi_pane`), so exactly the sessions with the most going on fell back to a few
  screens of raw output. A **zoomed** pane is now captured like a single pane, and with several
  visible panes the gateway gets the **active pane's** history, marked *history of the active pane
  above (N panes)* since the browser shows the whole layout. The capture now targets the probed
  pane by id, so switching panes between the probe and the capture cannot mix two panes' histories.

### Changed — agent (58)
- **New `fs_chmod` operation.** Applies `mode & 0o777` (setuid/setgid/sticky are stripped by the
  agent, whatever the gateway asks) to a regular file or a directory. It never follows a symbolic
  link: it `lstat`s the path, opens it with `O_NOFOLLOW` (`O_PATH` on Linux, so no read permission
  is needed and a device is never opened), checks it is the same inode, and changes the mode
  through the descriptor. Strict input validation (path string without NUL; integer mode 0–0o7777,
  not a bool). Like every `fs_*` operation it acts as the agent's user, so the operating system
  decides what it may change. The gateway calls it only on agents ≥ 58; with an older destination
  agent a copy still works, without permissions, and the job says *permissions not kept
  (destination agent older than 58)* (`copy.noModes`).
- **`fs_stat` reports `mode`** (the `0o777` bits, as `fs_list` already did), so a single file copy
  knows its permissions without listing the parent folder. With a source agent older than 58 the
  gateway falls back to that listing.
- **`history` accepts `pane: "active"`** and reports `panes` / `zoomed`; the probe reads the active
  pane's id and zoom flag (`#{pane_id} #{window_zoomed_flag}`). Without `pane` the reply is exactly
  agent 57's, so a gateway that does not ask gets no unmarked history. Agent 57 ignores the field
  and keeps declining with `multi_pane`, which the gateway handles as before (silent fallback).

### Tests
- New hermetic suites `agent_v58` (fs_chmod on a real filesystem: masking, symlinks and their
  targets, FIFOs, the no-`O_PATH` path, an inode swapped between `lstat` and `open`; the op's
  validation; the history probe and pane targeting with a mocked tmux, and with a **real tmux on an
  isolated socket** — skipped where tmux is missing; the gateway's seam and fallbacks) and
  `fs_copy_folders` (two fake agents: a full tree with modes, the agent < 58 fallback with no
  `fs_chmod` call, merges, rename, into-itself, limits, unreadable and uncreatable folders, retry
  into the same folder, step-up on retry) — 101 suites. `fs-test.sh` copies a folder between two
  real agents and checks the modes on disk, the executable bit and the skipped symlink.

## [3.5.15] — 2026-10-08 · agent (57)

### Security
- **Live share links are rate-limited per IP.** `/api/shared/{token}` and `/ws/shared/{token}`
  were the only public token endpoints without a per-IP limit (replay links got one in 3.5.12),
  so a scanner could try tokens there for free. The replay limiter is now a reusable
  `PublicLimiter` with a **separate bucket** for live shares: a total cap per IP (120 a minute —
  a guest page makes a metadata request and a WebSocket, and a room of viewers behind one NAT is
  legitimate) and the same miss-based lock (20 unknown tokens in 10 minutes block the IP for 10
  minutes, **valid tokens included**, so the lock is not an oracle). The metadata endpoint
  answers `429 share.rateLimited` with `Retry-After`; the WebSocket closes with `4429` before
  the token is looked up, and the guest page says to wait instead of showing "invalid link".
- **Every inline step-up accepts an authenticator code.** Since 3.5.13 the password alone no
  longer passes a step-up on a 2FA host, but most routes that take an inline step-up
  (`stepup_grant` / `stepup_password` — run, git, docker and service actions, connections,
  forwards, serial, host edits, shares, replay links, deploy-key generate / revoke / verify /
  test, new sessions…) ignored a TOTP code, so a TOTP-only account could only step up through
  the separate `/stepup` call. They now all take `stepup_totp` (body or query, matching the
  route) and pass it to `_require_host_stepup` / `_require_fresh_factor`.

### Added
- **Unread-alerts indicator on the ☰ button (phones).** On a phone the alerts bell lives only in
  the drawer, so a new alert was invisible until you opened the menu. The menu button on the
  dashboard, host page and session header now shows a dot with the count, and its accessible
  name says it (*Open host list — unread alerts: 3*) — not colour alone. It reads the same
  shared 60-second counter as the bell: no second poll.
- **Alerts in the interface language.** The in-app alert panel showed the English email text to
  Romanian users. Each alert now also stores a stable message key and its parameters (new
  `alerts.msg_key` / `msg_params` columns; the parameters go through the same secret scrubber
  as the text), and the panel renders `alertmsg.<key>.title/details` in English or Romanian —
  including the nested bits (metric names, the security-change description, link validity,
  masking on/off, backup age). Emails and webhooks stay in English; alerts recorded before this
  version, and keys a UI does not know yet, keep showing their stored text.
- **The security summary counts replay links.** The *Share links* check looked only at live
  shares, though an active replay link is just as much a public way in. It now also reports
  active replay links instance-wide, labelled separately (*2 live shares · 1 replay link*),
  with how many have secret masking off; any active replay link makes the check *Attention*.

### Changed
- **Docker CPU % is relative to the host.** `docker stats` reports CPU per core, so on an
  8-core host a container using one core read "96%" and was coloured red by thresholds meant
  for the whole machine. The panel now divides by the host's core count (from the agent's
  diagnostics snapshot, returned by the stats endpoint as `host_cpus` — no extra command on
  the host) and colours the normalised value; the tooltip and screen-reader text give both
  (*12% of host · 96% of one core*). Without a known core count it shows the raw value marked
  *per core*.
- **The terminal lock says which factor it wants.** The overlay's button read "Unlock with
  passkey" for every account. It now follows `stepup_method` from `/api/state` (and the code
  of a refused unlock): *Unlock with passkey*, *Unlock with authenticator code*, *Unlock with
  SSO*, or *Set up 2FA to unlock*; the description no longer mentions a passkey.

### Fixed
- **The phone host drawer closes with Escape**, not only by tapping outside it (unless a dialog is open on top).
- **Docker Shell on hosts where only `sudo` reaches the daemon.** The list, stats and live logs
  already fell back to `sudo -n` when the agent's user is not in the `docker` group; the
  container Shell ran a bare `docker exec` and died with "permission denied". It now uses the
  same wrapper as Logs: direct, then `sudo -n` (never a password prompt), else the plain command
  so docker's real error shows, plus a hint.
- README screenshot 06 regenerated: it still showed the old Security tab instead of
  *Sign-in & 2FA*.

## [3.5.14] — 2026-10-08 · agent (57)

### Added
- **Downloads resume after a page reload** (File System Access path — Chrome/Edge). A 40 GB
  download that died with the tab (reload, crash, closed laptop) used to vanish from Transfers and
  start from zero, because nothing remembered where the bytes were going. The job — file handle,
  host, path, size, server validator and a checkpoint — is now kept in IndexedDB, keyed by user id;
  after a reload it shows as **Interrupted — Resume / Discard**. Resume asks to write the file again
  (a browser rule: it needs a click), continues from `min(checkpoint, size on disk)`, and refuses to
  glue new bytes onto old ones if the file changed on the host: the row offers **Start over** into
  the same file instead. Chromium only commits a writable stream on `close()`, so the engine
  checkpoints by closing and reopening it (`keepExistingData` + `seek`) on a **geometric** cadence
  — each reopen copies the partial file, and a fixed 256 MiB step would cost ~160 full copies on
  40 GB; now ~12, bounded by about 3× the file size in local I/O, at the price of losing up to a
  third of the progress on a reload. Pause and a final error checkpoint too. Records expire after
  7 days, are removed on completion / Cancel / Dismiss / Discard and on sign-out. Blob downloads
  (Firefox/Safari, small files) and folder `.tgz` archives are unchanged — no file handle or no
  stable validator.
- `GET /api/hosts/{id}/fs/download` sends a weak `ETag: W/"<size>-<mtime>"` and `Last-Modified`,
  from the `fs_stat` it already did (agent unchanged); `GET /api/state` returns `user_id`.

### Fixed
- **Downloading a symbolic link** sent the link's own length as `Content-Length` (`fs_stat` is an
  `lstat`), which cut the download short or broke it. A link now streams without `Range` — the full
  target, as before 3.2.0 — and is simply not resumable.
- A file download on a 2FA host whose step-up window had expired retried a 403 eight times and ended
  in *Server answered 403*; it now opens the step-up prompt and continues. Non-retryable answers
  (404, 400, 403) fail at once with the server's message instead of after eight retries.

## [3.5.13] — 2026-10-08 · agent (57)

**Upgrade note:** an account with neither a passkey nor an authenticator code (TOTP) can no longer
open hosts marked *Require 2FA* with the password alone: enrol a factor in Settings → Sign-in & 2FA.
With SSO, the identity provider must return `auth_time` (Authentik does); otherwise set
`WEBTERM_OIDC_REQUIRE_AUTH_TIME=0`.

### Security
- **A terminal on a 2FA host now locks 60 minutes after the factor that authorised it, even
  while in use.** The step-up window had an absolute cap of one hour, but the terminal WebSocket
  looked at it only when attaching; its periodic check only revalidated the web session, and the
  idle lock measures inactivity. So a terminal kept busy (or kept alive by a script typing into
  it) stayed unlocked indefinitely, and a writable share-link guest stayed usable for as long as
  the owner kept the session alive. Each terminal now records when it was authorised (the
  opening time of the step-up window it was attached with, or its last unlock) and the 15-second
  lock sweep locks it once 60 minutes have passed, unless an attached owner has opened a newer
  step-up window on that host. The lock is the existing one — processes keep running, input and
  output are held, unlocking needs a fresh factor — and it is per terminal, so it reaches every
  attached client, guests included. The overlay says why (*"Locked: re-confirm 2FA every 60 min
  on this host"*); the `locked` WebSocket message gained an optional `reason`.
- **The account password alone no longer passes a step-up on a 2FA host.** For an account with
  neither a passkey nor TOTP, the last rung of the step-up ladder accepted the password — the
  same factor already given at login, so "Require 2FA" demanded no second factor at all. It now
  answers `403 stepup.needsFactor` (*"set up a passkey or an authenticator code (TOTP) to access
  hosts that require 2FA"*) whatever password is sent, and the UI offers a button to Settings →
  Sign-in & 2FA instead of asking for a password that would be refused. Passkey, TOTP and SSO
  re-authentication are unchanged; the password still works as a `sudo`-style re-auth where no
  2FA is involved (deploying a key to a host without Require 2FA). Turning Require 2FA on is not
  blocked, but answers with a `warning` so the UI can say you will not be able to open the host
  until you enrol a factor. `/api/state` now reports `stepup_method`
  (`passkey`/`sso`/`totp`/`none`), so the step-up prompt asks for the right factor first — a
  TOTP account on a domain install no longer gets a passkey ceremony that cannot succeed — and
  unlocking a terminal now sends the TOTP code and sees a factor enrolled after the terminal
  was opened.
- **Mutations that skipped the step-up.** Renaming a session or editing its note
  (`PATCH /api/sessions/{sid}`) now needs the step-up on a 2FA host, like the other session
  routes. Clearing the whole command history (`DELETE /api/history`) — a global, irreversible
  wipe of traces across all hosts and accounts — now needs the account password (SSO: passkey
  or SSO re-authentication) and is recorded in the audit log with the number of entries.
  Writing a history entry for a 2FA host (`POST /api/history`) now needs an open step-up window
  or an unlocked terminal on that host attached by the same account, so entries from a terminal
  in use are kept while a stolen cookie cannot plant commands in a protected host's history; a
  refusal is an opaque 403.
- **WebSocket Origin check compares the scheme.** The terminal and share WebSockets compared
  only `host:port` with `WEBTERM_PUBLIC_URL`, so an `http://` page on the same name passed as our
  `https://` origin; they now compare scheme, host and port (default ports normalised). The
  port-forward WebSocket compared only the hostname and now also requires the public scheme.
- **Deploying a key to one target now also gates the source host.** The single-target deploy
  checked a fresh factor on the target only; on a source marked Require 2FA it now needs that
  host's step-up window too, consistent with the batch and rotate paths (stable code
  `sshkey.sourceNeeds2fa`, checked before the target's single-use grant is consumed).
- **SSO step-up without `auth_time` is refused by default.** WebTerm sends `max_age=0`, and
  OIDC Core then requires `auth_time` in the id_token; without it the re-authentication was an
  unverifiable `prompt=login` that was accepted with a warning. New
  `WEBTERM_OIDC_REQUIRE_AUTH_TIME` (default `1` = refuse, with a log line telling the admin to
  configure the IdP; `0` = the previous lenient behaviour). Ordinary logins are unaffected.
- **A corrupt password hash is a wrong password, not a server error.** `verify_password` let
  argon2's `InvalidHashError` / `VerificationError` escape, so a damaged hash in the database
  turned login and re-authentication into a 500. It now returns False and logs one warning.

## [3.5.12] — 2026-10-08 · agent (57)

### Added
- **Replay links for closed-session recordings.** Showing a vendor or another team what
  happened in a session meant downloading the `.cast` and mailing it — a copy of everything the
  host printed, with no expiry, no revocation and no idea who watched it. *Share replay* in the
  player of a closed session now creates a public, read-only link (`#/replay/<token>`) that
  renders only that recording's player: mandatory expiry (1 h, 24 h by default, or 7 days),
  optional label, several links per recording. **Mask likely secrets** is on by default — the
  alert scrubber's patterns, extended with AWS / GitHub / GitLab / Slack / Stripe / Google keys,
  `sk-…` keys and JWTs, applied across the whole output stream so a secret split between two
  network chunks is still caught, with same-width replacement that leaves escape sequences and
  timing intact; it is best-effort, and the dialog warns that recordings may contain sensitive
  data. Every open is audited (client IP, truncated user agent), counted in the link list
  (opens, last opened, from where) and raises an in-app alert to the link's creator, at most
  once per link per 10 minutes; creating a link is alerted too (new alert kinds *replay link
  created* / *replay link opened*). Links are listed and revoked per link or all at once in the
  dialog and under *Share links* on the dashboard, and die on password change, account
  deletion, the global *Revoke all* and session deletion — not on logout, since a recording
  with a fixed short lifetime is not a live terminal. Security model as live shares, tightened:
  token hashed and shown once, carried in the URL fragment and an `X-Replay-Token` header (never
  in a request path or the audit log), one identical 404 for unknown / expired / revoked,
  per-IP rate limit, `no-store` + `noindex`, browser session + 2FA step-up to create. New API:
  `POST /api/sessions/{sid}/replay-links`, `GET /api/replay-links`,
  `DELETE /api/replay-links/{id}`, `POST /api/replay-links/revoke-all`, and the public
  `GET /api/replay/{meta,cast,text}`.

### Fixed
- **Unknown `/api/…` paths return 404.** The single-page fallback answered them with the app's HTML
  and status 200, so a mistyped API call looked like a success.
- **Escape closed two dialogs at once.** Every focus-trapped dialog listened for Escape on the
  document, so a dialog opened on top of another (a confirmation over a list, the replay-link
  dialog over the player) closed both. Only the topmost dialog reacts now.

## [3.5.11] — 2026-10-07 · agent (57)

### Added
- **In-app alert history.** Alerts existed only as email or webhook: on an instance without
  SMTP a sign-in from a new IP, a host going offline or a failing backup left no trace in the
  UI. Every event that is emailed (or would be) is now also stored in the gateway database and
  shown behind a bell next to the sidebar search — unread count on the badge (and in the
  button's accessible name, not only as a coloured dot), newest first, severity as icon + word,
  relative time, a link to the host when there is one, full text under *Details*, *Mark all
  read*, *Clear*, *Unread only*. Account events (new sign-in, attach from a new place,
  password / email / 2FA / passkey changes, 2FA host unlock) go to that account only; fleet
  events go to every account, each with its own read state — there are no roles, so "visible
  to admins" means visible to everyone. Last 500 per account and 30 days, pruned on insert;
  the text goes through a scrubber (tokens, `password=`, URL credentials, private keys) before
  it is stored. The badge polls a count-only endpoint every 60 s and stops while the tab is
  hidden. New API: `GET /api/alerts`, `GET /api/alerts/unread`, `POST /api/alerts/read`,
  `DELETE /api/alerts` — browser session only (automation tokens get 401), each query filtered
  on the caller's account.
- **Per-event alert preferences** (Settings → Notifications → *Alert events*, searchable, with
  a `?` help). Per account and per event type: **Email** (also covers the webhook) and **In
  app**; the defaults are today's behaviour (email on, in-app on), and only deviations are
  stored, so a new event type starts on. The email is one inbox for the whole instance, so an
  account event follows that account's choice and a fleet event is sent while **at least
  one** account wants it — one account cannot silence an alert another administrator relies
  on. **Security events always stay in the in-app history** (the toggle is locked, with the
  reason shown): turning off the alert is the first thing someone who took over the account
  would do, and the history is what remains. Their email can still be turned off, with a
  warning. API: `GET` / `POST /api/alerts/prefs`; changes are audited.

### Changed
- `email_alerts._fire` and the `notify_*` helpers take the event kind, severity, host and
  account; call sites pass the host id and the account id where they have them. Deleting an
  account now also deletes its alert history and preferences. `POST /api/alerts/read` is left
  out of the audit log (it would log every time someone reads the bell); clearing is audited.

## [3.5.10] — 2026-10-07 · agent (57)

Docker: **Logs** opens a live terminal (`docker logs -f`, with colours, search and Ctrl+C), like
Services; each running container shows CPU and memory, refreshed every few seconds. No agent change.

### Added
- **CPU and memory per container in the Docker panel.** Each running container shows CPU % and
  memory used / limit (%), coloured with the shared 70 % / 90 % thresholds (`lib/thresholds`).
  New endpoint `GET /api/hosts/{id}/docker/stats`, with the same rules as the container list
  (signed-in browser session, step-up on 2FA hosts; automation tokens get 401). It runs
  `docker stats --no-stream` through the agent's `run` op, so no agent update, and returns
  numbers, not docker's strings: docker prints memory in binary units (`MiB`, `GiB`) and network
  and disk I/O in decimal ones (`kB`, `MB`), and `--` while a container starts or stops; the
  gateway parses all of them into bytes and percents, and anything it cannot read becomes
  `null` instead of a guessed number. The panel polls every 5 s only while it is open on
  Containers and the browser tab is visible. `docker stats` samples for about two seconds and
  gets slower with many containers, so it has a 6 s timeout: past that the cards say *Stats
  unavailable* and polling slows to 30 s, instead of an error every 5 s. Results are shared
  for 3 s with one run in flight per host, so two open tabs do not double the load on the host.

### Changed
- **Docker "Logs" follows the log live, like Services "Logs".** It used to open a modal with a
  snapshot of the last 500 lines, while the button with the same name in Services opened a
  terminal following `journalctl -f`: two behaviours under one label. Docker "Logs" now opens a
  terminal tab running `docker logs --tail 500 --timestamps -f <container>`, so you get colours,
  scrollback, search (Mod+Shift+F) and Ctrl+C to stop. The snapshot modal is removed rather than
  kept as a second option: the live tab starts with the same 500 lines, and for a stopped
  container `docker logs -f` prints them and exits, leaving them in the tab's history, so the
  snapshot showed nothing the tab does not. Its endpoint (`GET /api/hosts/{id}/docker/logs`) is
  gone with it. The container id is validated with the same pattern as the other Docker actions
  and shell-quoted. Where the agent's user cannot reach the Docker socket but has passwordless
  `sudo`, the tab uses `sudo -n` (as the panel's other calls do), never a password prompt. The
  Romanian label is now "Log-uri" in both panels (Services said "Jurnal").

## [3.5.9] — 2026-10-07 · agent (57)

Search in Settings (EN and RO, diacritic-insensitive, jumps to and highlights the section),
and the Security tab split into **Sign-in & 2FA** and **Infrastructure & tokens**. The
Dashboard Security card now opens the exact section. No agent change.

### Added
- **Search in Settings.** A search box at the top of the Settings dialog (or press `/` while the
  dialog has focus and no field is focused). It searches every section by its title, its help
  text and a list of synonyms in English and Romanian ("webhook slack", "yubikey", "bearer",
  "fus orar"), ignoring diacritics, so "setari" finds "setări". Results are grouped by tab;
  choosing one (click, or arrows + Enter) opens that tab, scrolls to the section and outlines it
  briefly (a static outline under reduced motion). Escape clears the search. Settings had grown
  to eight tabs and about thirty sections, and "where is the webhook?" had become a real
  question: it sits under Notifications, inside the SMTP block. The index is
  `frontend/src/lib/settingsIndex.ts`; every section carries a `data-setting-id`, and a unit test
  fails when a section has no index entry or an entry has no section.

### Changed
- **The Security tab is split in two.** It had grown to eight sections that answered two
  different questions. **Sign-in & 2FA** / **Autentificare și 2FA** is about how *you* get in:
  connected devices, passkeys, TOTP. **Infrastructure & tokens** / **Infrastructură și
  tokenuri** is about the fleet and integrations: the agent signing key, automation tokens,
  bulk enrollment, the deploy-key policy and the command guardrail. Each section's code moved
  unchanged. Links into Settings follow: the Dashboard Security card now opens the exact section
  (2FA → passkeys, guardrail, signing key, backup → automatic backup, alerts → email alerts),
  scrolled into view, and the dot on the Settings gear opens the signing key when it is missing
  *or* locked (it used to handle only "missing"). Docs and UI messages that said "Settings →
  Security" now name the new tab. Messages written by the gateway itself (and `upgrade.sh`)
  still say "Settings → Security"; they change with the next gateway release.

## [3.5.8] — 2026-10-07 · agent (57)

One name per idea for "fleet" (Run on hosts / Agent signing key / Bulk enrollment; RO
"infrastructură"), and the sidebar logo no longer truncates. No agent change.

### Changed
- **Wording: one name per idea for "fleet".** The UI used "fleet" for two different things — all
  your servers, and the action of running one command on several hosts — and the action alone had
  five names ("Fleet run", "Run a command across multiple hosts", "Run across multiple hosts",
  "Run on multiple hosts", "Fleet console"). In Romanian "flotă" read as ships. Now:
  - the action (sidebar button, dialog title, tooltips, history label, token scope, snippet
    targets, docs) is **Run on hosts** / **Rulează pe hosturi**;
  - the key that signs agent updates is the **Agent signing key** / **Cheia de semnare a
    agenților** (was "Fleet signing key" / "Cheie de semnare a flotei");
  - group-token onboarding is **Bulk enrollment** / **Înrolare în masă** (was "Fleet enrollment
    (bulk onboarding)" / "Înrolare de flotă (onboarding în masă)");
  - the whole set of servers stays **fleet** in English and becomes **infrastructură** in
    Romanian.

  Only visible text changed: i18n keys, routes, API values (history source `fleet`, token scope
  `run`) and behaviour are the same. `docs/FLEET.md` keeps its file name; its headings are now
  *Run on hosts*, *Saved commands* and *Bulk enrollment*, with the old anchors
  (`#saved-fleet-commands`, `#fleet-scale-onboarding`) kept so existing links still land.

### Fixed
- **Sidebar logo no longer truncated to "WebT…".** Next to the six header buttons the word
  didn't fit at the default 288 px width, and never on phones (44 px touch buttons). The mark
  is always shown; the word appears only when it fits (a CSS container query on the header).
  The button keeps its accessible name and stays at least 32 px (44 px on touch).

## [3.5.7] — 2026-10-07 · agent (57)

A design system: one type scale, three corner radii, shared status colours for both themes,
shared Button/IconButton/Badge/EmptyState/ErrorState/Card components, SVG icons instead of
emoji, and the light theme finished on the host page. Nothing changes functionally. No agent change.

A design system under the whole UI. **Nothing changes functionally**: every button, route,
keyboard shortcut and text does what it did; the screens look more consistent, and the light
theme (Aurora) is finished.

### Changed
- **One type scale, nothing below 11px.** The UI used 12 hand-picked sizes (`text-[9px]` …
  `text-[22px]`), 49 of them under 11px, which is unreadable on 1× screens and below Apple's 11pt
  minimum. All 348 uses now sit on a scale defined in `tailwind.config.js`: `text-2xs` (11px, the
  floor), `xs` 12, `compact` 13, `sm` 14, `base` 16, `lg`, `xl`, `display` 22, `2xl`, `3xl`. Labels
  that were 9–10.5px are now 11px. The only exception is the session thumbnail on the host page,
  an `aria-hidden` picture of a terminal screen.
- **Three corner radii.** Nine radius variants were used for the same kinds of elements (a primary
  button was `rounded`, `rounded-lg` or `rounded-xl` depending on the screen). Now controls are
  6px (`rounded-md`), cards, menus and popovers 12px (`rounded-xl`), dialogs 16px (`rounded-2xl`).
- **SVG icons instead of emoji.** About 170 emoji and Unicode glyphs were used as icons (🔌 🩺 👁
  🔔 ⚠ ✕ ✓ ☰ ⛶ ⌨ ▶ ▸ ⇅ 🕒 📁 …). They rendered differently on every OS, were missing on some
  Android builds and in headless Chromium, and sat badly next to the line icons. They are now SVG
  icons from `Icons.tsx`, in the same style: the status bar (clock, folder, latency), the session
  toolbar (menu, commands, fullscreen, close split, copied), the host page (menu, serial,
  diagnostics, AI tools, play, viewers), the sidebar (alerts, wake, warnings, the host menu), every
  close button, the diagnostics journal, fleet run, files, git, services, transcripts, toasts and
  the idle lock. Content keeps its characters: the © lines, arrows that are notation in a sentence,
  key names in keyboard legends and on the keybar, and all translated texts.
- **Shared components.** `Button` (primary / secondary / danger / ghost, three sizes, loading),
  `IconButton` (an accessible name is required), `Badge`, `EmptyState`, `ErrorState` (the
  "could not load" state; `LoadFailed` now uses it) and `Card`, in `components/ui/`. The sidebar,
  session toolbar, host page, Dashboard, Settings, files panel, transfers and about 50 dialog
  buttons use them, so the same "Save" looks the same everywhere. Primary buttons no longer
  lighten on hover (white on the lighter indigo fell to 4.47:1).
- **One set of threshold colours.** The CPU gauge and the sparkline under it showed the same 70/90%
  thresholds in two different greens and reds. `lib/thresholds.ts` is now the single source for
  the gauges, the sparklines and the toolbar load ring, with chart colours that keep 3:1 on both
  themes.
- **Semantic colour tokens.** `--ok`, `--warn`, `--danger`, `--info`, `--accent` (and chart
  `--viz-*`) are CSS variables with values for both themes, exposed to Tailwind as `text-ok`,
  `bg-danger/10` etc. The existing `.wt-good` / `.wt-warn` / `.wt-danger` classes read them, which
  replaces 13 per-zone colour overrides. On Aurora the green and info blue are a shade darker, so
  they keep AA on tinted badges.

### Fixed
- **Aurora: the host page is light.** It was rendered in the forced-dark palette of the terminal
  area, so choosing Aurora gave a white sidebar next to a black host page. It now follows the
  theme, like the Dashboard; the session previews on it stay dark. The terminal area itself (tabs,
  session toolbar, terminal, status bar, session drawers) stays dark in both themes on purpose —
  see `docs/design/DESIGN-SYSTEM.md`.
- **Aurora contrast.** Status chips and badges that used dark-theme-only colours (the agent update
  badge, the "update blocked" chip, OS-update chips, the diagnostics journal, the changelog's
  current version and inline code, link hovers) now use the semantic tokens and pass AA on both
  themes.

### Added
- **`docs/design/DESIGN-SYSTEM.md`**: the tokens, the components, when to use which, and the
  do/don't for icons and sizes.
- **A regression guard** (`frontend/src/design.guard.test.ts`, runs with the unit tests and
  `npm run lint`) fails on arbitrary `text-[Npx]` sizes, radii outside the scale, and emoji or
  icon glyphs in `.tsx` files, with an allowlist for the deliberate exceptions.

## [3.5.6] — 2026-10-07 · agent (57)

The file editor moves to monaco-editor 0.57 in a slim build: opening a file downloads about
3.4 MB instead of up to 9.8 MB. No agent change.

### Changed
- **The file editor is a slim Monaco build on monaco-editor 0.57.** 3.5.3 held monaco back on
  0.52 because 0.57 changed its package `exports` (`./*` → `./esm/vs/*.js`), so the old
  `monaco-editor/esm/vs/...` imports stopped resolving and the build failed. Instead of only
  fixing the import paths, the editor no longer imports `monaco-editor` whole: it imports the
  editor API (`monaco-editor/editor/editor.api`), only the features you use on a config file,
  and only the basic syntax highlighters for what a sysadmin edits on a host.
  - **Languages:** shell, YAML, JSON/JSONC, INI (also systemd units, `.env`, `.conf`, `.cnf`,
    `.properties`), TOML, Dockerfile, nginx, Python, JavaScript, TypeScript, SQL, XML, HTML, CSS
    (also SCSS/Less), Markdown, Go, Rust, PHP, Ruby, Lua, Perl, PowerShell, C/C++, Java and HCL
    (Terraform). Monaco has no basic highlighter for JSON, TOML or nginx, so WebTerm ships small
    ones of its own. Anything else opens as plain text.
  - **Language detection** works from the full path, not just the extension. It recognizes
    well-known names (`Dockerfile`, `Containerfile`, `Makefile`, `.bashrc`, `.zshrc`, `.env.*`,
    `Gemfile`, `Cargo.lock`…), treats everything under `/etc/nginx/` as nginx (so
    `sites-available/default` is highlighted even without an extension), and falls back to the
    shebang (`#!/usr/bin/env python3`) or an `<?xml` header. The rules live in
    `lib/editorLang.ts` and have unit tests. `Makefile` uses the shell highlighter, because Monaco
    has none for make.
  - **Features kept:** find/replace, folding, bracket matching, multi-cursor, comment toggling
    (`Ctrl+/`), go to line (`Ctrl+G`), the command palette (`F1`), the context menu, line
    operations (move/copy/delete lines, sort, trim), word navigation, smart select and the
    read-only notice. **New:** `Alt+Z` toggles word wrap, also available from the context menu
    and `F1`.
  - **The trade-off: no language-service autocompletion or validation any more.** The
    TypeScript, CSS, HTML and JSON language services and their workers are gone. That means no
    IntelliSense on `.js`/`.ts`, no JSON schema validation, and no CSS/HTML completion or error
    squiggles. The word-based suggestion popup is also gone (it only offered words that were
    already in the file). For an editor whose job is fixing a config on a server, highlighting
    is what matters, and `ts.worker` alone was 5.9 MB. Only `editor.worker` is still bundled.
  - **Sizes** (`vite build`; gzip at level 6, which is what the gateway serves):

    | | before (0.52, full) | after (0.57, slim) |
    |---|---|---|
    | FileEditor chunk | 3.34 MB (859 KB gz) | 3.15 MB (818 KB gz) |
    | FileEditor CSS + codicon font | 214 KB (65 KB gz) | 283 KB (95 KB gz) |
    | editor.worker | 232 KB (71 KB gz) | 276 KB (83 KB gz) |
    | ts / css / html / json workers | 5.9 / 1.0 / 0.67 / 0.36 MB | — |
    | **opening a `.ts` or `.js` file** | **9.8 MB (2.4 MB gz)** | **3.4–3.7 MB (≈0.92–1.0 MB gz)** |
    | opening a `.json` file | 4.2 MB (1.1 MB gz) | same as any other file |
    | opening a config (`.yaml`, `.conf`, `.sh`) | 3.8 MB (1.0 MB gz) | 3.4–3.7 MB (≈0.92–1.0 MB gz) |
    | all built assets (whole app) | 14.5 MB | 5.9 MB |

    The worst case (any JS/TS file) is 62% smaller, and the image is 8.6 MB lighter. A config
    file did **not** get much cheaper: the editor core itself (`editor.api` with no features or
    languages) is ~2.8 MB minified in 0.57. Its widget, text model, view, quick-input and
    diff-engine code is not split into optional modules. The features above add ~0.38 MB. The
    goal of "well under 3 MB raw" for the first open is therefore not met: it is ~3.4 MB, plus
    the 276 KB worker in the rare case that a feature asks for it. The slim setup never starts
    the worker during normal editing. Over the wire (gzip) it is ~0.9–1.0 MB. Getting further
    would mean stubbing Monaco internals (the diff editor, the GPU renderer) through bundler
    aliases, which would break silently on the next Monaco minor, so it was not done.
  - **CSP:** the gateway's policy has no `worker-src`, so workers fall back to
    `script-src 'self'`. The worker is a same-origin file under `/assets/` (no `blob:`, no CDN),
    so it is allowed. A new e2e check loads it under the real CSP and fails on any violation. A
    second new check opens a `.yaml` file and confirms that it is highlighted.
- **The mobile audit now opens the file editor from the phone Files sheet**, on every phone
  profile. It checks that the dialog fits the screen, that there is no horizontal scroll, and
  that a `.yaml` file renders highlighted. Until now no gate had checked the editor on a phone.
  Adding the step surfaced three problems:
  - **Monaco's screen-reader live region sat off-screen.** Monaco creates
    `.monaco-aria-container` once per page, directly in `<body>`, and keeps it for the page's
    lifetime. It is a singleton: removing it when the editor closes would silence announcements
    in the next editor. Its own CSS pushes it to `left:-999em`, so after the editor had been
    opened once, every later screen had an element outside the viewport. It is now styled like
    `.sr-only`: a clipped 1×1 px box inside the viewport, still in the accessibility tree.
  - **Closing the editor less than a second after opening it threw JS errors.** The errors
    were Monaco's intentional cancellations (`Canceled: Canceled`), which ended up as unhandled
    promise rejections. The editor now silences exactly that error and nothing else.
  - **The audit lost the Files button on the iPhone landscape profile.** This was a test bug,
    not a UI bug. The app's own tooltip layer moves a button's `title` into a data attribute
    while a *mouse* hovers it. Playwright clicks with a mouse even on an emulated iPhone, and
    leaves the pointer parked on the button. On the third opening, the toolbar Files button
    therefore had no `title`, and the audit's `button[title=…]` selector waited for nothing.
    Real touch input never triggers that tooltip. The audit now selects toolbar buttons by
    `aria-label`. It also picks the toolbar or "More" path using the same 640 px breakpoint
    as the UI, instead of a non-waiting `isVisible()`.
- monaco-editor 0.52.2 → 0.57.0 (it now depends on `dompurify` and `marked`, which are bundled
  into the editor chunk). Dependabot has no ignore rule for monaco, so future 0.57.x/0.5x
  minors arrive as normal PRs.

## [3.5.5] — 2026-10-07 · agent (57)

Phone experience, a host-offline card in the session view, and file-manager upgrades
(multi-select, folder downloads through Transfers, server-side copy to another host).
No agent change, so no fleet update.

The phone is where "your sessions, anywhere" was weakest — every external UI review said so.
Three phone fixes, plus a "host offline" card in the session view. Then the file manager grows up:
multi-select with bulk download/delete, folder downloads as real Transfers jobs, and copying files
from one host to another through the gateway. Gateway + frontend only; **no agent change**, so no
fleet update (agents stay at 57).

### Changed
- **Session panels are full-screen sheets on phones.** Files, Git, Forwards, Docker, Services,
  Toolbox, AI tools and Commands were desktop side drawers: on a 390 px phone you got a
  panel squeezed beside a terminal sliver, both unusable. Below 640 px (and on a phone in
  landscape) they now cover the screen, with a sticky **← Terminal** button and the panel title
  on top, notch/home-bar safe areas respected, the page behind locked, and list scrolling that no
  longer triggers pull-to-refresh. The **Android back button / swipe-back closes the panel**
  instead of leaving WebTerm: opening a sheet adds a history entry with the same URL, so the
  `#/s/…` routes are untouched. Done once, in the shared drawer hook, for all eight panels.
  Tablets and desktops are unchanged.
- **All tabs, one tap away.** The tab bar scrolls sideways with ~150 px tabs, so a phone showed
  two or three and gave no hint there were more. A tab-count button now sits at the end of the
  bar (always on phones, elsewhere whenever the tabs overflow) and opens a list of every open tab
  with its host, live / closed / lost state and new-output dot; tap to switch, or close a tab
  (the session keeps running). Keyboard: a proper menu with arrow keys, Home/End and Escape.
- **The touch key bar has two rows.** Its single scrolling row hid everything right of `PgDn`.
  Row 1 holds what you always need (`Ctrl`, `Alt`, `Esc`, `Tab`, arrows), row 2 the rest (paste,
  `^C` `^D`, `| / - ~`, Home/End/PgUp/PgDn, …). On short screens (phone in landscape) it collapses
  to row 1 plus a toggle, remembered per device. Key sequences and the Ctrl/Alt latch are
  unchanged; the terminal re-fits when the bar changes height. See
  [docs/SHORTCUTS.md](docs/SHORTCUTS.md#touch-key-bar-phones-and-tablets).

### Added
- **A "host offline" card inside the session.** When the agent of an open session's host
  disconnected, the only signal was "Host offline — reconnecting" in the 11 px status bar (hidden
  entirely in compact landscape), and the terminal silently stopped echoing. Wake-on-LAN and
  Diagnostics lived in the sidebar's ⋯ menu, where nobody looks mid-session. Now a non-modal card
  sits at the top of the terminal: **offline since HH:MM** and for how long, the **reason** when
  the gateway knows it (agent uninstalled, refused as relocated/cloned, restarting for an agent
  update, or the disconnect reason from the connection log; never guessed), and **Diagnostics**,
  **Wake** (same rule and endpoint as the sidebar, now one shared helper), **Open host page** and
  **Dismiss** (until the next outage). It never takes the keyboard focus. When the agent is back
  it disappears and a short "back online" confirmation fades out (aria-live). Jump targets name
  their parent's agent; direct SSH/telnet get a "Connection lost" variant with **Reconnect** for
  telnet. Pop-out windows get the same card; shared (guest) links show none. Frontend only.
  The real-agent E2E now stops and restarts the agent mid-run (169 checks) to prove the card
  appears, dismisses, clears, and that the tmux session streams again afterwards. See
  [docs/HOSTS.md](docs/HOSTS.md#when-a-host-goes-offline-mid-session).
- **Multi-select in the Files panel.** Acting on ten files meant ten hovers and ten confirmations.
  Rows now have checkboxes, with Shift+click ranges, Ctrl/Cmd+click toggles, Space / Shift+↑↓ /
  Ctrl+A / Escape on the keyboard, long-press to start selecting on phones, and a **Select all**
  that selects only what the filter shows (selecting rows you cannot see is how bulk deletes go
  wrong). A selection bar offers **Download** (one Transfers job per item; with the File System
  Access API you pick a folder once), **Delete** (one confirmation with the count, the first names
  and whether folders are deleted recursively; failures reported per item) and **Copy to host…**.
  The selection model is a pure, unit-tested lib. Double/triple-click and drop-on-folder keep
  working. See [docs/TRANSFERS.md](docs/TRANSFERS.md#multi-select-in-the-files-panel).
- **Folder downloads go through Transfers.** The `.tgz` of a folder was a bare link: no progress, no
  cancel, and a failed `tar` showed up as a nameless failed download. It is now a Transfers row:
  *preparing the archive on the host…*, then bytes received (the size is unknown up front, so no
  fake percentage), Cancel (the temp archive on the host is deleted), the server's error, and Retry
  — which restarts, because an archive built on the fly cannot be resumed (the row says so). See
  [docs/TRANSFERS.md](docs/TRANSFERS.md#folder-downloads-tgz).
- **Copy files to another host, server-side.** Moving a file between two of your hosts meant
  downloading it to the device you happen to hold and uploading it again — over a phone link, twice.
  `POST /api/fs/copy` now streams it agent → gateway → agent: the source is read with `fs_read`, the
  destination written through the resumable-upload machinery (in-order blocks, binary frames, CRC-32
  checked before the atomic rename), with a bounded queue so the gateway holds a few chunks per file,
  never the file. Skip / overwrite / keep both (`name (1).ext`), cancel (the destination temp is
  removed, finished files stay), per-file errors, a copy row in the Transfers widget, step-up on
  **both** hosts, cookie only, audited. Copying within one host is allowed. **Limits:** files only —
  folders need an agent `chmod` to keep executable bits and come with the next agent update (they
  did: agent 58, see [Unreleased]); at most
  1000 files per job; special files refused; permissions and ownership are the destination's; jobs
  live in gateway memory (a restart loses running jobs). Tested hermetically with two fake agents
  (`tests/fs_copy_test.py`, 92 suites) and end to end with a second real agent in the smoke container
  (`fs-test.sh`); the E2E (179 checks) covers bulk download, the folder job and a same-host copy
  through the dialog. See [docs/TRANSFERS.md](docs/TRANSFERS.md#copy-to-another-host).

### Fixed
- **Live-sessions badge contrast on Aurora.** The green "N live sessions" count on a sidebar host
  row measured ~4.2:1 on the selected row (below AA at 10 px). The axe gate only caught it once
  the scanned host had live sessions while selected; light themes now use a darker green (~6:1).

## [3.5.4] — 2026-10-07 · agent (57)

Five features the product owner picked from the UI reviews, built one at a time, each
with its own tests, plus two fixes. No agent change, so no fleet update.

### Added
- **Export and import hosts as CSV.** Moving a set of hosts to another gateway meant
  re-typing every one; there was no way to get the list out, or into a spreadsheet and back.
  Export from a folder header in the sidebar or from **Add host → Import CSV → Export hosts…**
  (select by host, folder or tag); import from the new **Import CSV** mode in Add host, with a
  preview that marks each row new / agent (pending) / exists / error before anything is
  created. **No secrets are ever in the file** (no passwords, keys, enrollment or agent
  tokens, host-key pins or share links), formula-looking cells are neutralised against CSV
  injection, and every imported row goes through exactly the validation of Add host — the
  two now share one function — with duplicates skipped by the server. Agent hosts come back
  pending, each with its own install command: a group link cannot attach to hosts that
  already exist. See [docs/HOSTS.md](docs/HOSTS.md#export-and-import-csv).
- **A Security card on the Dashboard** answers "is everything OK right now?" in one glance:
  your 2FA, active share links, the command guardrail, the signing key, hosts requiring 2FA,
  backups, alert channels and agent versions. It used to take four trips through Settings and
  the sessions, and nothing listed the live share links. Every row opens the place where you
  fix it. The card collapses to one line when everything is OK and opens itself when something
  needs attention. TLS expiry is deliberately not a row: the certificate is served by Traefik,
  outside the app, and the gateway cannot see it (the host-side `webterm-cert-check` timer
  does). See [docs/SECURITY-SUMMARY.md](docs/SECURITY-SUMMARY.md).
- **Share-links inventory**: every active link in the fleet, with who created it, read-only or
  writable, expiry and how many guests are connected now, plus per-row **Revoke** and
  **Revoke all**. Revoke all asks for the account password (SSO: a fresh re-authentication),
  disconnects every guest, is audited and sends a security alert. The link URL is never shown
  again: only a hash of its token is stored. Links on 2FA hosts are counted but described
  only while that host is unlocked, like the session list.
- API: `GET /api/security/summary`, `GET /api/shares`, `POST /api/shares/revoke-all`, all
  browser-only (automation tokens get 401).
- **Fleet saved commands are now snippets, stored on the gateway.** They lived only in the
  browser's localStorage, so a command saved on the laptop did not exist on the phone, and
  the terminal's snippets and the fleet's saved commands were two lists for one idea. A saved
  fleet command is now a snippet that can carry **target tags**: picking it selects the online
  hosts with any of those tags and says how many matched; you can still change the selection.
  `{{param}}` placeholders work in the fleet console too. Save offers "remember target tags"
  from the selected hosts; rename and delete edit the snippet itself. Snippet editors (Alt+S,
  Toolbox → Library) show and edit the tags. On first opening the fleet console, commands
  saved in that browser are uploaded once (deduplicated by command); the local copy is
  removed only after all of them made it, so a failed upload is retried next time. See
  [docs/FLEET.md](docs/FLEET.md#saved-fleet-commands).
- API: `/api/snippets` accepts and returns an optional `targets` (`{"tags": [...]}` or
  `null`). Old clients keep working: a PATCH without `targets` leaves them unchanged, and old
  rows list `targets: null`. Tags are normalised like host tags; more than 20 is a 400
  (`snippet.tooManyTags`), a malformed value a 400 (`snippet.badTargets`). Still
  browser-only: automation tokens get 401.
- **Test connection in Add host and Edit host** (SSH, SSH-jump, Telnet, Telnet-jump). A wrong
  port, user or password used to surface only at the first connection, after the host was
  saved. The test runs the gateway's real dial (through the via agent's tunnel for the jump
  types), stops after the login and closes everything; it saves nothing. The result is shown
  per stage (TCP, SSH greeting, host key with its SHA256 fingerprint, authentication), with the
  same messages you get when connecting, and the failing field gets the focus. After a
  successful test the button reads **Save (verified)** and the saved host is **pinned to the
  host key the test saw**, instead of trusting whatever answers the first connection. The
  server accepts only the key its own test saw for that target in the last 10 minutes, so a
  client cannot pin a key of its choosing, and an existing pin on the same target can still
  only change through the host-key alarm. The test can reach any address the gateway can, so
  it is browser-only, capped at 10 seconds and 10 tests a minute per account, refuses the cloud
  metadata address (also when a name resolves to it), and is audited without the credential.
  See [docs/HOSTS.md](docs/HOSTS.md#testing-a-connection).
- **Generate a key for this host, before saving it.** With SSH or SSH-jump and key
  authentication, Add host (and Edit host) creates an Ed25519 key pair on the gateway, keeps the
  private key encrypted in the vault and shows the public key with the exact command to run on
  the target. Test connection uses it; saving makes it the host's stored key. An unused key is
  deleted after an hour, and only the account that generated it can attach it. Before, key
  generation existed only after saving, in Edit host. SSH-jump hosts can now use key
  authentication from the form too.
- API: `POST /api/hosts/test` (`{ok, stages: [{id, ok, ms, code, vars, detail}], hostkey}`),
  `POST /api/hosts/ssh-key/pending`, and `pin_hostkey` / `pending_key_id` on host create and
  update. All browser-only (automation tokens get 401).

### Changed
- `POST /api/hosts` now refuses an empty name (`host.nameRequired`), a port outside 1–65535
  (`host.badPort`) and an SSH auth method other than password/key (`host.badAuthMethod`).
  They were accepted and produced hosts that could never connect; the CSV import made the
  gap easy to hit.
- **The paste picker (`Mod+Shift+V`) now shows one clipboard history shared by every terminal
  in the window.** It used to keep a separate list per terminal, so something copied in one
  tab was missing from the picker in the next one, which is the usual reason to open it. The
  history holds the last 10 copies, newest first (a re-copy moves the entry to the top). Each
  entry shows where it came from and how old it is ("emaildb · 4 min ago") and expires 1 hour
  after it was last copied. Each entry has a ✕, and the picker has a **Clear history** button.
  The history stays in memory only, never in browser storage, because it often holds
  passwords and tokens. It is lost on reload and cleared on idle-lock and on logout or an
  expired web session. Pop-out windows keep their own history. Paste-and-run still holds
  back the Enter when a line matches a guardrail rule.

### Fixed
- **A key generated in Edit host broke the connection to that host.** `/ssh-key/generate`
  stored the bare private key while every reader expected the JSON credential format, so
  connecting failed with a server error, and **Show public key** failed on every pasted key for
  the opposite reason. Both formats are now read, and new keys are stored like any other
  credential.
- **Pausing an upload could take effect only after the in-flight slices finished.** A pause
  pressed while the next slices were being read and checksummed missed them, so they were
  still sent. On a slow machine that delayed the pause by up to a slice's transfer time. This
  was also the root of the last e2e check that failed only in CI: the stuck pause test kept
  the shell busy, which then failed the next check (the special-characters file). Pause and
  cancel are now checked right before each slice is sent.

## [3.5.3] — 2026-10-06 · agent (57)

Fixes from four external UI reviews, each claim checked in the code first (34 of 34 confirmed),
plus the rest of the 3.5.x backlog. No agent change, so no fleet update.

### Fixed: phones and tablets
- The phone ⋯ menu now has **Docker, Services and Toolbox**; they used to be unreachable below
  640 px. **Saved commands** opens as a bottom sheet (on phones the menu item and Alt+S used to
  do nothing).
- **Who's connected** works at every width: 👁 N in the header (it stays visible on a
  landscape phone), a "Connected (N)" item in ⋯, and a bottom sheet on phones. **Kicking a
  viewer asks for confirmation.**
- **The keybar shows on every touch device**, tablets included (before, only below 768 px).
  It adds **Alt** (latched like Ctrl), **Home/End/PgUp/PgDn** with real terminal sequences, and
  modifier codes on the arrow keys. A latched Ctrl/Alt is clearly highlighted.

### Fixed: safety
- **Fleet run:**
  - starts with **no hosts selected** ("Select all (N)" is one click);
  - has a **timeout** field (1–300 s);
  - has a **Stop** button that stops dispatching further hosts;
  - no longer sends `confirmed: true` without a human confirming. If the guardrail rules failed
    to load, server-side confirm rules used to be skipped.
- **Pop-out windows get the guardrail and step-up.** Before, a popped-out terminal had no
  guardrail at all, and its password prompt was an unmasked `window.prompt`.
- **The guardrail's block strip and confirm dialog name the rule** (`/pattern/`). A declined
  confirm shows a neutral "Cancelled — not run" in Git, Docker and Services. Before, Git showed
  a red error and the others showed nothing.
- **Share links:**
  - after a reload the owner still sees that a link is live (read-only/writable, expiry) and can
    revoke it, through a new authenticated `GET /api/sessions/{sid}/share` that never returns
    the URL;
  - Revoke clears the link only when the server actually revoked it.
- **Turning off TOTP or deleting the last passkey** now says what happens to hosts that
  require 2FA.
- **Recovery codes** can be copied or downloaded as .txt.
- **A shield on the sidebar row** marks hosts that require 2FA.

### Fixed: the UI said something untrue
- The walkthrough no longer promises files and serial on SSH hosts, and no longer says "?
  works any time".
- The SSH tip no longer promises persistent sessions. SSH sessions end when the gateway
  restarts; the 3.5.1 wording was wrong.
- The README diagram no longer shows Files over SSH.
- The sidebar empty state pointed at a "+ host" button that didn't exist; it now has a real
  Add host button.
- Smaller text fixes:
  - "Password SSH" in the add-host form;
  - "● ● online" in Diagnostics;
  - untranslated online/offline on the host page;
  - Romanian labels in the English Toolbox library.

### Changed
- **Load failures say so.** Toolbox, History, Devices and Audit show "Couldn't load — Retry"
  instead of an empty list. The ten "error" fallbacks are real sentences.
- Silent failures now show a toast: rename, note save, share revoke.
- **Names and icons:**
  - the host tab "Databases" is now **Toolbox**;
  - Diagnostics is spelled the same everywhere;
  - buttons use sentence case;
  - Rename has its own icon (not Edit's pencil), and Share has its own (not Links' chain);
  - the Commands button reads ❯N instead of ⌘N.
- **Host page:** each session row has an **Open** button.
- **Update pill:** says "Update available: X".
- **"Stop session…"** is a labelled item in ⋯, and the confirm says that closing the tab keeps
  the session running.
- **Settings keeps unsaved edits** when you switch tabs.
- Text the server writes into the terminal (lost-output marker, history seam) is in English.

### Dependencies and CI
- uvicorn 0.54.0, webauthn 3.0.1, PyJWT 2.15.1, websockets 16.1.1, typescript-eslint, globals,
  Playwright 1.63.0 everywhere, and the node image digest. Lockfiles were regenerated (the
  Dependabot PRs had stale lockfiles). monaco-editor stays on 0.52: 0.57 moved its exports and
  breaks the build, so the migration is planned with the 3.6 editor work.
- **The E2E flakiness had two causes, both in the test setup:**
  - a retry couldn't start its agent, because of the agent's single-instance lock, and then
    tested a host that had no agent;
  - CI ran the browser on the runner instead of in the Playwright image that ci-local uses.
  Both are fixed. A failed run now posts its FAIL lines and the agent log as public
  annotations.

## [3.5.2] — 2026-10-06 · agent (57)

The rest of the 3.5.x backlog, including the agent items, so we didn't jump to 3.6. **Agent 57:**
every host updates its agent on reconnect. Hosts with open sessions defer the restart; force
it from the host card.

### Added
- **Full history in the terminal scrollback.** Opening an existing tmux session used to show
  only tens to hundreds of lines, or none. The browser got only the last 256 KiB of the raw
  stream, and tmux scrolls with a scroll region, which xterm never moves into its scrollback.
  The agent now reads the session's real history from tmux (`capture-pane`, with colours,
  compressed, capped at 1 MiB). The scrollback is filled up to 10000 lines on desktop and
  3000 on mobile, the same on a resume after a background tab. A dim line marks where the
  live replay starts; the few lines just below it may repeat. The commands panel works as
  before. Streams without tmux (pty, telnet, serial, closed sessions) replay 2 MiB on
  desktop instead of 256 KiB. Older agents fall back silently to the previous replay.
- **"Starts at boot" per host.** The agent reports whether it comes back after a reboot
  (systemd user unit with linger, a cron `@reboot` line, or nothing). Host overview shows
  it with an Enable/Disable button, and the sidebar warns when a host won't come back.
  Enabling never kills the running agent. When linger needs root, the UI says so.
- **Test webhook** button in Settings → Notifications.
- `WEBTERM_SIGNING_AUTOGEN=0`: skip generating a fleet signing key on first boot, so an
  offline build-time key can be used on a new install.

### Security
- **Guardrail on panel actions.** Services start/stop/restart, Docker start/stop/restart and
  Git add/reset/restore/commit now go through the same server-side check as `/run`, on the
  equivalent shell command, and the panel asks on a `confirm` rule.
- **Guardrail in the terminal.** Shift/Ctrl+Enter and Ctrl+J are checked like Enter. A
  multi-line paste with a guarded line is held back. Paste-and-run pastes without the Enter.
- **Guardrail patterns** that the browser can't compile are refused at save, because the
  terminal would silently skip them.
- **Changing the account password or email sends a security alert.** The alert module had
  promised it from day one, but nothing called it.

### Fixed
- **SMTP on port 465** (implicit TLS) works. It used to wait for a plaintext banner and time
  out.
- **`credential_policy`:** an unknown value is refused (400). It used to be stored and then
  read inconsistently.
- **Agent:** in tmux mode, every session after the first saw the first session's
  `WEBTERM_SESSION` (and `TZ`). They are now passed with `new-session -e` (tmux ≥ 3.1).
- **Agent:** the dead ops `list`, `detach` and `serial_close` were removed. `info` lists the
  `run` and `selftest` subcommands.

### CI
- Every action is on its Node 24 release, pinned by SHA (CodeQL moved off a floating `@v3`).
- Runners are pinned to `ubuntu-24.04` ahead of `ubuntu-latest` becoming Ubuntu 26
  (2026-10-19).
- The E2E step posts its FAIL/[diag] lines as public annotations, and e2e waits for the test
  agent before checks that need it.

## [3.5.1] — 2026-10-06 · agent (56)

A "what we show is what we deliver" pass: every hint, doc and claim was checked against the
code, in both directions. No agent change (AGENT_VERSION stays 56), so no fleet update.

### Security
- **The login lockout counted the proxy's IP, so all users shared one counter.** Since 3.3.0,
  `X-Forwarded-For` is believed only from `WEBTERM_TRUSTED_PROXY_CIDRS`, but no installer set
  it. Behind Traefik/Caddy every client looked like the proxy: 5 bad logins from anyone locked
  out everyone, the audit showed the proxy's IP, and new-IP alerts never fired. New
  `WEBTERM_TRUSTED_PROXY_HOSTS` names the proxy by its compose service name (resolved through
  docker DNS, cached 60 s, fail-closed). The compose files default it to `traefik` / `caddy`, so
  upgrading fixes existing installs with no `.env` change.
- **Guardrail: `block` rules now win over `confirm` rules regardless of order.** The first
  matching rule used to win, so a broad `confirm` (`^rm`) listed above a `block`
  (`rm -rf /`) let `POST /run` with `confirmed: true` through. Server and browser both fixed.

### Added
- **A `?` next to every setting that needs explaining.** Click it (it works on touch) and a
  popover says what the setting is for, gives a copyable example where useful, and links to the
  documentation **for the version you run**. It is in 19 places: tokens, guardrail, signing key,
  enrollment groups, deploy-key policy, SMTP, webhook, resource alerts, forward domain, SFTP/FTPS
  backup, OS-updates badge, tags, 2FA step-up, credential policy, install-link TTL, AI tools,
  Toolbox and forwards SSO. A test checks that every link points to an existing heading.
- **New guides:** [HOSTS](docs/HOSTS.md), [AUTOMATION-TOKENS](docs/AUTOMATION-TOKENS.md),
  [ALERTS](docs/ALERTS.md), [GUARDRAIL](docs/GUARDRAIL.md), [AI-TOOLS](docs/AI-TOOLS.md).
- **"Forget" stored credentials** in Host overview. `POST /api/hosts/{id}/forget-credentials`
  had existed since F-05 with no button. It asks for confirmation, your password, and step-up on
  2FA hosts.
- **About: a "give it a star on GitHub" card.**

### Fixed: the UI said something the code doesn't do
- Tokens: `read` never included the audit log, which is cookie-only on purpose.
- Resource alerts also go to the webhook, not only to SMTP. The SMTP hint listed 2 of about 15
  alert events.
- The guardrail is always enforced on fleet runs and tokens, not only with shell integration.
- The SSH-host tip promised a file browser and a serial console, which are agent-only. The
  sidebar no longer offers Files on SSH/telnet hosts, where it failed with "host offline".
- Host 2FA is a step-up (passkey, SSO, password or TOTP), not passkey-only.
- The reinstall dialog said "expires in 24h"; the server grants 1 hour.
- The command palette matched only English keywords, so searching "setări" found nothing. It
  now matches the translated labels, diacritic-insensitive.
- The `?` cheatsheet and SHORTCUTS.md now list the gestures nobody could find (right-click /
  long-press terminal menu, Ctrl+Shift+C, Shift+Enter in search, Mod+S, Mod+Enter, split
  divider keys, double-click).
- Toolbox history times follow the timezone chosen in Settings. Remaining hardcoded English
  strings are translated. Romanian now uses comma-below ș/ț everywhere.

### Docs
- README/SECURITY/THREAT-MODEL and the guides were corrected against the code:
  - the setup token lives in `/data/setup-token` and is no longer printed in the logs
  - the signing key is auto-generated on first boot, with steps to replace it
  - `backup.sh` refuses unattended plaintext backups
  - transfers appear in the floating widget
  - the Cloudflare token lives in `secrets/`
  - the Toolbox has four tabs and the vault is Fernet
- Env vars that existed but were undocumented: `TRUSTED_PROXY_HOSTS/CIDRS/HOPS`,
  `TRUST_CF_IP`, `ARCHIVE_DAYS`, `CLOSED_ARCHIVE_DAYS`, `TRANSCRIPT_MAX/KEEP_BYTES`,
  `UPDATE_REPO`, the `*_FILE` secret convention, and the agent-side `WEBTERM_INSTANCE_ID` and
  `WEBTERM_SESSION`.

## [3.5.0] — 2026-10-06 · agent (56)

Frontend only, no agent change (AGENT_VERSION stays 56). The 3.4.0 tag never published an image
(GitHub Actions could not assign a runner during an incident), so 3.5.0 is the first image that
includes the 3.4.0 features below.

### Added
- **AI tools: a manager for Claude Code's config files.** A new panel, opened from the terminal's
  right-click menu ("AI tools") or the host page's "AI tools" tab, lists, creates, edits and deletes
  the files coding harnesses read, at their real locations: `CLAUDE.md`, subagents
  (`.claude/agents/<name>.md`), skills (`.claude/skills/<name>/SKILL.md`) and a generic `AGENTS.md`.
  Two scopes: Global (`~/.claude`) and Project. From a terminal, the project is the session's current
  directory (OSC-7). Starter templates cover a blank agent, a code reviewer, a blank skill,
  `CLAUDE.md` and `AGENTS.md`. Names are validated the way Claude Code expects them (lowercase letters,
  digits and hyphens), and an existing file is never overwritten. Everything goes through the existing
  file API and the Monaco editor. The agent writes the files as the same OS user the harness runs as,
  so they belong to that user. WebTerm only manages these files and never runs them. Agent hosts
  only.

### Changed
- **The OS-updates badge is quieter and can be hidden.** In the host list, ordinary updates now show
  as a muted outlined count instead of a filled amber pill. Security updates keep an accent, a red
  dot next to the count, instead of a solid red block. Settings → Preferences → "OS updates badge"
  chooses between all updates, only security updates, or hidden. Each host can also hide its badge,
  from its ⋯ menu or from the updates dialog ("Hide for this host"), and Preferences can bring them all
  back. The host page always shows the count, neutral unless it includes security updates.

## [3.4.0] — 2026-10-05 · agent (56)

### Added
- **A first-run welcome walkthrough.** New sessions show a 7-step overlay (Welcome, Add a host,
  Sessions and the terminal, Paste or drop files, The toolbox, Security, You're all set) with
  Next/Back, "Skip for now" and "Don't show again". It appears once after the first login and is
  re-openable from the `?` help overlay and Settings → Preferences. Illustrations are inline SVG so
  they stay crisp in both themes and never go stale. New users were discovering features by accident;
  this hands them the map up front.
- **File actions in the terminal's right-click menu.** A nested "Files" submenu — anchored on the
  session's current directory (OSC-7, falling back to home) — adds Open files here, Upload here,
  Download, New file and New folder, reusing the existing Files panel, Monaco editor and transfer
  engine (no duplication). Plus a top-level "Clear terminal" (sends Ctrl-L, so it also works under
  tmux, unlike a local clear the server replays) and "Open path in Files" when the selection looks
  like a path. Quick file work no longer means opening the side panel first.
- **Contextual one-time tips.** Small, non-modal, dismissible hints at the right moment: on the
  add-host form tailored to the connection type (agent vs ssh/jump), near the terminal on the first
  session (paste a screenshot or drag & drop a file — it lands on the host and the path is typed),
  and pointing at the toolbar. Each shows once; Settings → Preferences can reset them. They teach in
  context, complementing the upfront walkthrough.

### Changed
- **Opening a very large file now says so plainly.** The editor already capped the preview (full
  edit up to 1 MiB, first 256 KiB read-only beyond that); it now adds a banner with the file's real
  size and a one-time toast, so accidentally opening a multi-gigabyte file is visibly safe, not
  silent.

## [3.3.1] — 2026-10-05 · agent (56)

### Changed
- **Pasting a screenshot into the terminal now explains itself.** It showed only a path in the
  prompt; now a paste/drop of image(s)/file(s) raises an immediate toast ("Uploading the screenshot
  to the inbox…") and, on completion, one that states the result ("Saved to ~/.webterm/inbox; its
  path was added to the prompt — press Enter to send it"), with a session-directory variant, a
  dedicated error toast, and a one-time first-use hint. This is how a screenshot reaches a CLI like
  Claude Code over a web terminal.

### Security
- **Browsing a forward or running a search no longer extends a step-up window.** Two passive reads
  (`forward_auth` and transcript search) still used the sliding `stepup_window_ok`, so keeping a
  forward tab open or repeatedly searching silently kept "sudo" alive on 2FA hosts up to the
  absolute cap. Both now use the read-only `stepup_window_is_open` (completes the fix from the
  2026-10-04 review).


## [3.3.0] — 2026-10-05 · agent (56)

### Changed — agent (56)
- **A malformed control frame no longer crashes the agent.** A frame that was valid JSON but not an
  object (`[]`, `42`, `"x"`) reached the control handler and raised `AttributeError` on `.get()`,
  killing the agent process (systemd restarted it). The agent now checks the frame is an object and
  logs-and-skips anything malformed, mirroring the gateway-side guard. (`agent_v56` suite.)
- **Optional agent hardening, opt-in.** Installing with `WEBTERM_AGENT_HARDENED=1` adds
  `NoNewPrivileges=true` to the agent's systemd unit. It is NOT the default on purpose: the agent
  runs arbitrary shells as its user, and `NoNewPrivileges` disables `sudo` inside sessions — so the
  OS-upgrade button and the Docker `sudo -n` fallback stop working. Documented in the RUNBOOK; the
  operator opts in knowingly. `ProtectSystem`/`SystemCallFilter`/`ProtectHome` are deliberately not
  applied (they would break arbitrary shells and home browsing).


### Changed
- **Transfers are now one floating, collapsible widget in the bottom-right corner** instead of a
  chip in the tab strip (which crowded or overlapped the tabs) plus a separate top strip. It is its
  own layer (below dialogs, above content), collapses to a compact pill and expands to a card that
  lists every transfer with name, size, progress, rate, ETA and actions (retry / pause / resume /
  cancel / copy or insert path). It auto-expands once when a transfer needs attention
  (stalled / failed / incomplete), remembers whether you minimised it, and on mobile sits above the
  key bar. Fixes the earlier chip whose pop-over could render off-screen.


### Security
*(hardening from four independent security reviews of our own gateway — our mirror pentest plus
three external second opinions; every real finding verified in code before fixing, each with a
regression test. Gateway/frontend only; the agent-side items ride the next agent release.)*
- **A closed session's scrollback could be read over the session WebSocket without step-up on a
  2FA host.** The step-up gate sat inside the live-hub branch; a closed session (no hub) streamed
  its transcript to any authenticated cookie. The 2FA requirement is now computed from the host
  regardless of session state — a closed 2FA session starts locked and replays nothing until a
  step-up window is opened.
- **SSH deploy-key batch and rotate wrote `authorized_keys` to target hosts without the target's
  step-up.** Only the source host's fresh factor was required. Each `require_2fa` target now needs
  its own open step-up window or is skipped with `sshkey.targetNeeds2fa`.
- **TOTP was never used as a step-up factor.** A user with TOTP but no passkey opened a 2FA host's
  step-up window with the account password alone, so a flagged host got no real second factor.
  Step-up now goes passkey → SSO → **TOTP (verified and consumed atomically)** → password only when
  no second factor is configured; the UI prompts for the 6-digit code (`stepup.totp`).
- **`stepup_window_ok` extended the window as a side effect of reading it.** Used in passive and
  periodic checks (the forward WebSocket's 60 s revalidation, the history "blocked" computation) it
  let an idle background tab hold step-up open to the absolute cap and let merely listing history
  slide the window on every 2FA host. A read-only `stepup_window_is_open` now backs every passive
  check; the WebSocket **unlock** requires a fresh factor, not a kept-alive window.
- **The generated setup token was printed in full to the application log**, where
  `docker compose logs` (often readable by non-admin operators) exposed it before first setup —
  whoever read it could create the admin account. The generated token is now written to a 0600
  file in the data dir and only a 6-char prefix is logged; recover it with `make token`. When the
  token is supplied via `WEBTERM_SETUP_TOKEN` (install/CI) nothing is logged. The file is deleted
  once setup completes.
- **`delete_session` and `revoke_share` lacked step-up on 2FA hosts** (unlike `kill_session`) —
  destroying transcripts or cutting a share on a protected host needed no second factor. Both now
  require it.
- **Metadata could cross the "API token = no 2FA" line.** A read-scoped token received a 2FA host's
  session list/titles, and `/api/audit` returned executed-command text for 2FA hosts without a
  step-up window. Sessions are now withheld from tokens / filtered by window, and audit detail is
  redacted for hosts the caller has not stepped up to.
- **SSO accounts could not change their e-mail** (the password re-auth always fails for them); they
  now re-authenticate with a fresh SSO window or an account passkey.
- **Revoking a single web session** now clears that user's step-up windows and bumps the forward
  epoch, like "revoke others" already did.
- **Login accepts only a small body (4 KiB) before parsing**, and Caddy caps pre-auth routes at
  256 KB, closing a pre-authentication memory-amplification path.
- **X-Forwarded-For is trusted only from an explicitly configured proxy CIDR.** The default is now
  fail-closed (a private/loopback peer is no longer assumed to be our proxy); set
  `WEBTERM_TRUSTED_PROXY_CIDRS` when running behind one. (Production was already safe — the app
  container's port is not published — but the default should be safe too.)
- **Paths inserted into the terminal are stripped of control bytes** (`\r \n \x1b …`): shell
  quoting stopped shell parsing but raw control bytes still reached the PTY line discipline.
- `totp/disable` now clears step-up windows; `restore.sh` bounds the decompressed size and member
  count of a restored archive (`WEBTERM_RESTORE_MAX_BYTES` / `_MAX_MEMBERS`).
- New hermetic suites: `sec_stepup_hardening`, `sec_login_proxy`, `sec_sso_account`,
  `sec_closed_scrollback`; the X-Forwarded-For tests were updated for the new fail-closed default
  and gained checks for it.
- Deferred to the agent release: hardening the agent's systemd unit (`NoNewPrivileges`, …) and a
  type guard on malformed control frames. Still your call: moving the agent-signing key off the
  gateway host, and making cosign verification mandatory at deploy.


## [3.2.0] — 2026-10-05 · agent (55)

### Changed — agent (55), one bundled rollout
- **Transfers phase 2 (protocol): upload chunks travel as raw binary frames, and the host checksums
  the upload incrementally.** Two costs are removed from every upload, bundled into one agent bump
  because touching `agent/ptyd.py` forces a fleet-wide update.
  - **No more base64 on the gateway→agent hop.** A file block used to be base64-encoded into a JSON
    `fs_write` control message — +33% bytes on the wire and encode/decode CPU on *both* ends (the
    optimization deliberately deferred back in 2.3.0). It now rides a dedicated binary frame
    `FRAME_FSWRITE` (`W`): `rid(8) + offset(8) + path_len(2) + path + raw block`, big-endian, the
    `rid` reusing the normal request/response correlation so the agent still replies with an
    ordinary `{id, ok, written, offset, crc32}` control frame. The same per-write offset-conflict
    guard (append only at the expected size) and `O_NOFOLLOW` guarantees as the old op.
  - **Incremental CRC-32 instead of a full re-read at commit.** The agent now accumulates the
    `.wtpart` CRC (zlib, the same polynomial as the browser and as `fs_crc32`) as it appends each
    block and returns the running value; `fs_upload/status` returns the CRC of the bytes already on
    disk, so a *resumed* upload keeps accumulating from the real offset (previously the client gave
    up integrity verification after a resume). Commit then compares the client CRC to the agent's
    running CRC **without re-reading the file** — the old `fs_crc32` full re-read of a multi-GB temp
    was a multi-minute stall that blocked the PTY loop. The resume seed is computed on the CRC
    worker, never on the event loop.
  - **Backward-compatible during rollout.** The gateway is always upgraded before the agents it
    pushes to, so a v55 gateway speaks *both* protocols: base64 `fs_write` + `fs_crc32`-at-commit to
    a v54 agent, binary frames + incremental CRC to a v55 agent (branched on `agent_version`). A v55
    agent still honors an old-style base64 `fs_write` too, so nothing breaks mid-fleet.

### Added — Transfers phase 2 (gateway + frontend only, no agent change)
- **Pipelined (windowed) uploads.** The browser now sends up to 3 chunks concurrently over HTTP to
  hide round-trip time on high-latency links. Because the agent's `fs_write` is a strict append at the
  current size, the gateway keeps a per-upload **reorder window** (`_UploadWindow`): an out-of-order
  chunk is held in a bounded buffer (≤ `WINDOW_K × max chunk` = 48 MiB/upload) and its request waits;
  the chunk that fills the gap writes everything contiguously, in order, so the agent still sees a pure
  append and its incremental CRC stays correct. Over the cap → **429** (backpressure, the client eases
  off); a duplicate of a landed chunk is idempotent. Hermetic coverage in `upload_window_test.py`.
- **Adaptive chunk size.** Uploads start at 8 MiB and adapt between 2–16 MiB from the measured
  throughput/stability of recent chunks (bigger on fast links, smaller on unstable ones). The gateway
  re-splits each chunk into 1 MiB blocks toward the agent, so the HTTP chunk size is not bounded by the
  16 MiB frame cap. Pure, unit-tested (`nextChunkSize`).
- **Pause / Resume per transfer.** A Pause button stops sending and keeps the `File` + offset in
  memory and the `.wtpart` on the host; Resume re-enters from the real offset via `fs_upload/status`.
- **Downloads through the transfer engine.** `GET /fs/download` now supports HTTP **Range** (206) over
  the existing `fs_read` (no agent change), and host→browser downloads run through the same engine as
  uploads: a `↓` job in the chip/strip with progress, speed, ETA, stall watchdog, retry and in-session
  resume. Large files stream to disk via the File System Access API when available; otherwise a Blob,
  with files over 1 GiB requiring a capable browser. **Deferred:** download resume across a page
  reload, and resumable directory archives.

### Security
- **Authorized white-box pentest of the gateway trust boundary** (login, fake-agent/token forgery,
  forward tickets, CSWSH/CSRF, SQLi, OIDC, scope escalation), run with live PoCs against a
  disposable mirror of the production image. **Every barrier held** — no auth bypass, no forgery,
  no injection. Captured as hermetic regression tests: `pentest_forward_token_test.py` (HMAC
  ticket forgery/replay/epoch), `pentest_xff_lockout_test.py` (X-Forwarded-For trust / lockout),
  `pentest_oidc_alg_test.py` (RS256-only allowlist + step-up auth_time freshness).
- **Upload `upload_id` validated at the API boundary** on all four `/fs/upload*` endpoints (one
  shared `^[0-9a-f]{16,64}$`), before it is ever logged — closes log-line forgery by an
  authenticated account via a crafted `upload_id` (file writes were already blocked by the same
  regex deeper in). One-shot upload temp names widened to 16 hex so the stale-temp GC reclaims
  them (was a slow disk leak). The file-transfer surface (inbox, paste-to-terminal path insertion,
  fs API) was reviewed end to end: path traversal and shell-metacharacter injection into the
  inserted path do not occur (paths are absolute, the quoting allowlist forces single-quoting on
  every shell metacharacter).
- Deployment note: the per-IP lockout can only be bypassed by X-Forwarded-For spoofing when the
  app container is reachable directly; in the standard deploy it sits behind the reverse proxy and
  its port is not host-published, so this does not apply. Set `WEBTERM_TRUSTED_PROXY_CIDRS` to pin
  it explicitly if you expose the container differently.


## [3.1.2] — 2026-10-04 · agent (54)

### Added
- **Transfers phase 1: drop on the terminal, paste → inbox, transfers chip in the tab strip.** The reason is
  screenshots into AI CLIs over a web terminal: Claude Code or aider run *on the host* and cannot
  read the browser's clipboard, so "paste the screenshot" had no path to them. Now a paste with
  an image/file in the clipboard uploads it to `~/.webterm/inbox/<YYYY-MM-DD_HH-mm-ss>[-n].<ext>`
  (named files keep their name, timestamp-prefixed) and types the path at the prompt — quoted
  only when it contains spaces/special characters, followed by a space, no Enter. Text pastes are
  untouched. Dropping files on a terminal uploads them to the session's current directory (OSC 7;
  the home directory when the shell has not reported one — the overlay says which) and inserts the
  path the same way; **Choose another folder…** hands over to the Files panel, where dropping on a
  **folder row** now uploads into that folder. Progress moved out of the always-on strip into a
  **transfers chip in the tab strip** (`↑ file 63% · 24 MB/s · 9m`, or `↑ N transfers · 63%`) whose popover lists
  every job with the existing actions plus **Copy path** / **Insert path**; the strip above the
  workspace now appears only for jobs that need a decision (stalled, failed, incomplete) and goes
  away once resolved. `done`/`failed` raise a browser notification when the tab is hidden.
  Settings → Preferences: *Pasted files go to* (inbox / session directory) and *Inbox retention*
  (7 days, 0 = keep), enforced client-side after each inbox upload (≤ 50 deletions per run, best
  effort). No gateway/agent change — the existing fs API suffices. [docs/TRANSFERS.md](docs/TRANSFERS.md).

## [3.1.1] — 2026-10-04 · agent (54)

### Added
- **Transfers bar + upload watchdog.** A 17 GB drag-and-drop upload to an agent host ran at
  ~24 MB/s for 1578 chunks and then simply stopped: the browser stopped sending (uplink hiccup /
  sleep) while gateway and agent were healthy. Nothing said so — the XHR had a 300 s timeout and
  five retries with 1–8 s backoff, so a hung connection sat silently for many minutes, and the
  only feedback was a row inside the Files panel (closable) plus a 6 s toast. The upload engine
  now lives outside any component (`lib/uploads.ts`, same protocol: 8 MiB chunks, step-up-aware
  status/commit, 409/403 resync, CRC-32 rules) and reports into a global **Transfers bar** under
  the top chrome, visible on every screen. A byte-level watchdog marks a chunk **Stalled** after
  20 s without progress and aborts + resends it after 60 s; each chunk gets up to 8 attempts with
  exponential backoff capped at 15 s; on exhaustion the row shows the translated reason and a
  **Retry** that re-enters the loop from the offset the host confirms (the `File` stays in
  memory). Uploads also resume by themselves on `online` / tab-visible, and a 401 pauses the job
  with "sign in again". The `wt_up_*` localStorage entries now carry JSON metadata (old plain
  upload-id values still work), so after a reload unfinished uploads appear as **Incomplete**
  rows with **Open folder** / **Discard** (deletes the `.wtpart` on the host); dropping the same
  file resumes it. State changes are announced once through a polite live region (no toast
  spam), `beforeunload` guards active transfers, and the gateway logs a rate-limited INFO line
  when a chunk *starts* so a stall mid-body leaves a trace.

## [3.1.0] — 2026-10-04 · agent (54)

**The audit release.** A full nine-section internal audit (2026-10-04) and its first three
remediation phases shipped together: data-integrity and editor fixes (P0), the bundled agent 54
(P1), supply-chain and backup hardening (P2), and the UX + accessibility sweep (P3).

### Added
- **The host page is now a dashboard hub with a left section rail.** A vertical nav (icons +
  labels) on the left — Overview · Sessions · Files · Forwards · Services · Docker · Databases —
  replaces the scattered narrow drawers; on mobile it becomes a horizontal scroll row.
  **Overview is a real dashboard**: a status hero band (big Online/Offline/On-demand with a
  host-colour glow, the address, and fact chips — agent version · backend · OS-updates · tags);
  a row of **metric tiles with ring gauges** (CPU · Memory · Disk, %% threshold-coloured, with
  trend sparklines) plus a Load tile, auto-fitting to fill the width; **live session thumbnails**
  (read-only auto-refreshing `SessionPreview`, click to open, hover for split/pop-out, with a
  "no output yet" placeholder when empty); and host connection/security/agent/apps/note as a
  balanced two-column card grid with coloured icon chips. Sessions keeps the master-detail list +
  live preview + replay; Files/Forwards/Services/Docker/Databases render the existing panels
  **full-width inline** (new `embed` mode — no drawer, no scrim), and Forwards/Services/Docker/
  Databases now lay their entries out as a **responsive card grid** (status dot or engine chip,
  labels, actions in a footer) instead of long single-column lists — uniform with the rest of the
  dashboard, one column in the narrow session drawer and multi-column inline. Agent-only sections
  show only
  when the agent is online; ssh/telnet/jump hosts get Overview + Sessions. Serial and Diagnostics
  live in a **Tools** group at the bottom of the rail. Each panel is lazy-loaded (Files pulls Monaco).
- **Jump targets are saved as children of their agent, added from its ⋯ menu.** "Add SSH / Telnet
  jump…" on an agent host opens Add-host already scoped to that agent: pick the protocol (SSH or
  Telnet), the LAN target, and save. The saved target appears **nested under the agent** in the
  sidebar (`via_host_id` tree), so you can see at a glance what hangs off which host, and one click
  opens its page. Telnet-jump reuses the proven telnet-bastion (gateway speaks telnet over the
  agent's raw-TCP forward — same `ForwardTelnetSource` as forward-telnet; interactive login, no
  stored creds), with the session owned by the telnet-jump host. Agent untouched.
- **Connect once (no save).** The jump form also offers a one-time connection: it creates an
  **ephemeral** target (hidden from the sidebar), opens the session immediately, and a reaper
  deletes it once it has no live sessions — for the quick "just get me onto that switch" case
  without leaving a saved host behind.

### Changed
- **Docker panel: auto-sudo fallback + an actionable fix when the agent lacks access.** When the
  agent's user isn't in the `docker` group, docker commands used to just fail with "cannot reach
  the daemon". The gateway now transparently retries once with `sudo -n` (passwordless sudo, like
  the OS-upgrade button) — so on hosts where the agent can sudo, Docker just works. If that also
  fails, the panel shows a clear remediation card instead of a dead error: the exact command to
  grant access (`sudo usermod -aG docker <agent-user>`, copyable) and a note to restart the agent.
- **Connection failures now say what went wrong, in an in-page error toast.** A failed connect
  used to surface as an empty "cannot connect over SSH:" (a bare `TimeoutError` has no message) or a
  missable OS notification. The gateway now maps each failure to a specific reason — *no SSH greeting
  from host:port (wrong port / not an SSH server / filtered)*, *the target rejected the credentials
  (wrong password, or it wants a key)*, *the agent could not reach host:port* — and the UI shows it
  as a red, dismissible, longer-lived toast (`role="alert"`, 12s) **in the page**, not an OS popup.
  ssh-jump dial failures are also logged at WARNING with target:port + cause (previously only
  asyncssh INFO, with no host/port — invisible). This surfaced from a real "wrong SSH port" case
  that was impossible to diagnose from the UI.
- **Clicking a host in the sidebar now exits an active split-view.** Navigating to a host page used
  to be swallowed while a split-view was active (the split kept render precedence), so the click
  appeared dead until you first clicked a session tab. `selectHost` now leaves the split like
  Home/tab navigation does — the split chip stays in the bar, so you return with one click.
- **File editor is now Monaco (the VS Code editor).** Browsing a host's files and opening one gives
  the authentic VS Code editing surface — syntax highlighting, minimap, multi-cursor, the `vs-dark`
  theme following the app theme — reading and writing through the agent exactly as before (partial-read for big files,
  atomic save with mtime conflict check, step-up retry on 2FA hosts). Monaco and its workers are
  **bundled locally** (no CDN, no phone-home) and **lazy-loaded** — they download only when you open
  a file, never in the main bundle. Replaces the CodeMirror editor (19 deps dropped). Agent untouched.

### Changed — agent (54), one bundled rollout
*(2026-10-04 internal audit; everything below rides a single fleet update)*
- **Big uploads froze the agent and then killed it.** The CRC-32 commit check of a resumable upload
  read the whole file synchronously on the event loop — the gateway waited up to 600 s, but
  `WatchdogSec=45` (and the cron liveness check at 120 s) killed the agent first. CRC now runs in a
  small bounded worker pool (2 workers, queue of 64, `busy` beyond that) so the loop keeps pinging
  the watchdog; file reads refuse anything that is not a regular file (FIFO/device) via
  fstat-after-open, closing the stat→open race on `fs_read` too.
- **A restart of the agent killed every tmux session.** The systemd unit the installer writes had no
  `KillMode=process`, so the tmux server lived in the service cgroup and any crash / watchdog kill /
  `systemctl restart` took all sessions with it — the opposite of what ARCHITECTURE.md promises.
  The installer template now sets `KillMode=process`, and the agent **self-heals existing units**
  at startup and before a self-update re-exec (only the unit whose `ExecStart` points at itself;
  user or system scope; `daemon-reload` best effort).
- **A root agent could kill the `webterm` user's tmux server** on the same host: the tmux cleanup
  (uninstall, "wedged" recovery) matched only the `-L webterm` socket. It now also requires the
  agent's own UID.
- **Hostname forwards blocked the loop on DNS.** `fwd_open` (also behind SSH-jump / telnet-jump) did
  a synchronous `getaddrinfo`; a slow resolver stalled every session on the host. Literal addresses
  connect immediately (IPv4 or IPv6); hostnames resolve in a thread with a 10 s budget (`resolve`
  error on timeout) and count toward the forward cap while pending.
- **Anti-rollback parser was fail-open.** `AGENT_VERSION = 53  # note` (or any unparsable line)
  yielded `None` and the update went through. Both sides now use one strict regex
  (`^AGENT_VERSION\s*=\s*(\d+)\s*(#.*)?$`); the agent refuses with `update_badversion`, and the
  gateway refuses to push a file it cannot version (`gateway_badversion`, blocked once + event).
- **Service accounts with `nologin` got dead panels.** `spawn_client` with a command and the `run`
  op used `$SHELL` as-is, so docker/journal/DB/`run` failed on hosts where the agent user has
  `/usr/sbin/nologin`. One resolver (`_login_shell`) now serves tmux, pty commands and `run`, falls
  back to bash/sh, and is resolved before `fork()`.
- **Serial console accepted any tty** (`/dev/pts/N`, `/dev/tty1`, `/dev/console`). Now an allowlist
  (`ttyUSB/ttyACM/ttyS/ttyAMA/ttyXRUSB`, `serial/by-id`, `serial/by-path` resolved to one of those)
  plus a character-device check on the open fd.
- **Diagnostics: one in flight per agent**, `force` at most every 30 s (busy callers get the last
  snapshot marked `stale`), instead of a thread per request. Gateway side caps the stored blob at
  256 KiB (strings cut at 4 KiB; oversized → `diagnostics_oversized` event, last good kept) and reads
  the OS-updates summary from its own column instead of parsing the whole JSON per host per poll.
- **Refusal hints from the agent are no longer trusted text**: codes map through an allowlist, free
  text is stripped of control/CSI sequences and clipped before it reaches the UI or an e-mail.
- **Docker "no access" card tells the truth**: adding the agent user to `docker` (or `NOPASSWD:ALL`)
  is root-equivalent and removes the unprivileged-agent barrier from the threat model; the card now
  leads with a sudoers rule limited to the docker binary (works at once via the `sudo -n` fallback),
  and the OS-upgrade guide offers `NOPASSWD: <package manager>` instead of `ALL`.
- Shell integration: under `HISTCONTROL=ignorespace` the hook reported the previous command as the
  current one; it now emits no command line when history did not record one (the client falls back
  to screen text).
- Dead code removed from the agent (`_persist_cert_pin`, `tmux_has_session`, `_sys_read`,
  `Session.last_respawn`, `Serial.opened_at`); legacy `cert_pin` reading kept for fleet compat.
  New `agent_v54` (119 checks) and `diagnostics_cap` (21) suites.

### Changed — UX & accessibility sweep (audit P3)
- **No more browser `confirm()` / `prompt()` / `alert()`.** 55 native dialogs (Sidebar 19,
  SessionView 10, Toolbox 7, Security 6, Fleet-run 3, …) are now in-app dialogs through one
  `useConfirm()` provider: themed, translated, focus-trapped, Escape/backdrop cancel, and —
  for destructive actions — **initial focus on Cancel** so a reflex Enter cannot delete anything.
  Native dialogs also froze every live terminal and were silently suppressed by Chromium once
  "don't show again" was ticked (the action then became impossible). Stop/restart of a service or
  container and deleting a split now ask first and name the object.
- **Every dialog and drawer is keyboard-complete.** The 7 dialogs without a focus trap (split
  wizard, host-key card, updates and command dialogs in the sidebar, Docker logs, snippet and
  connection forms, links dialog) got `role="dialog"`, `aria-modal`, labelled titles, Tab trapping,
  Escape and focus return; the 6 side drawers (Files, Forwards, Services, Docker, Toolbox, Git,
  Commands) move focus in on open, back on close, and close on Escape. The command-guard
  `alertdialog` now takes focus (Enter/Escape no longer leak into the shell). Tabs are a real
  `tablist` with roving tabindex; **`Alt+Shift+←/→` reorders the focused tab** — the keyboard
  alternative to drag that WCAG 2.5.7 requires.
- **Screen readers hear what sighted users see.** Toasts are `role="alert"`/`"status"` elements
  whose accessible name is the message (the ✕ used to replace it), announced from live regions
  mounted at start; hovering or focusing the stack pauses dismissal. Every form error is a
  `role="alert"` with `aria-invalid` + `aria-describedby` on the field and focus moved to the
  first invalid one (login, add host, editor, serial, notifications, appearance, backup).
  Login has `autocomplete` for username / current-password / one-time-code. Colour-only status
  dots (sidebar, tabs, host badge, Docker, Forwards probes) now carry text or a shape difference
  plus a screen-reader label.
- **Contrast fixed on the light theme.** 47 token pairs failed 4.5:1 because dark-only Tailwind
  colours (`text-sky/emerald/amber/rose-300|400`) were used unconditionally; they are replaced by
  the theme-aware `.wt-good/.wt-danger/.wt-warn/.wt-accent/.wt-link/.wt-info/.wt-muted` classes,
  whose values were re-measured (all ≥ 4.5:1 on both themes, field borders ≥ 3:1); the dashboard
  canvas honours the light theme instead of forcing Aurora. Button styles come from
  `settings/ui.ts` tokens (primary/secondary/danger/ghost). No text below 11 px. Hover-only row
  actions (files, host cards, commands) are visible on keyboard focus too; all icon-only buttons
  have names; small targets (10 px probe dot, sort buttons, tag chips, status-bar attach) are now
  ≥ 24 px hit areas. Romanian catalog: 100 cedilla characters (ş/ţ) replaced with the correct
  comma-below forms (ș/ț); untranslated leftovers translated.
- **Idle-lock warning (WCAG 2.2.1).** 60 s before the 2FA idle lock a `role="alert"` banner
  counts down with an "I'm still here" button; it hides on any activity.
- **Host-key change is a card, not a toast.** When a jump/SSH host presents a different key, a
  persistent `alertdialog` shows host, pinned vs received fingerprint (copyable), what it can mean,
  and two actions: *Keep blocking* (default) or *I reinstalled this host — trust the new key*
  (step-up gated, re-pins, audited, e-mailed).
- **First run explains itself.** After 45 s of "waiting for the agent" the Add-host dialog shows a
  troubleshooting checklist (outbound 443, whole token, Python minimum, time sync, the
  `journalctl` command) and the host's last agent events — the gateway now records distinct
  handshake rejections (`bad token`, `instance conflict`, `pin mismatch`). The update check shows
  "could not check" with a retry instead of a stale "up to date".
- **SSH keys: results you can see, rotation you can trust.** Multi-target deploy and rotate show a
  per-target result panel (ok / translated error, stays until dismissed, *Retry the failed
  targets*). Rotate now deploys the new key to every target **before** swapping the source key;
  an offline target no longer aborts the loop — it is marked `missing`, keeps the old line, and
  the response lists what was left with the old key.
- **Errors are translated, not Python.** 183 `HTTPException("english prose")` became coded
  `ApiError`s (`host.*`, `session.*`, `files.*`, `backup.*`, `account.*`, `auth.*`, `sshkey.*`,
  `services.*`, `docker.*`, `run.*`, `token.*`, …) with 128 new catalog entries in both languages;
  `str(e)` pass-throughs go through classifiers (`files.permissionDenied / notFound / noSpace /
  crcMismatch / conflict / timeout`, `signing.locked`, `update.refused`, …) and the raw text stays
  in the log. Errors can carry variables (`X-WebTerm-Error-Vars` + `vars` in the body) for the next
  step. Handshake rejections from agents are recorded as `agent_events`
  (`handshake_bad_token`, `handshake_instance_conflict`, rate-limited) and logged with the IP.
  Startup now **refuses to boot on a failed migration** (other than "duplicate column") instead
  of logging and running on a partial schema. New suites: `api_errors`, `hostkey_alarm`,
  `handshake_events`, `migration_failfast`.
- Debounced searches (sidebar, history, audit) ignore stale responses; nested jump targets are
  found when only the child matches (parent shown dimmed); legacy orphans render at top level;
  upload progress re-renders at most 10×/s; every `localStorage` access goes through a guarded
  helper (a `SecurityError` no longer sends the app to the failsafe page).
- **CI accessibility gate rebuilt**: `eslint-plugin-jsx-a11y` (27 rules at error, 4 at warn,
  `no-autofocus` off for modal dialogs), axe with `wcag22aa` + `best-practice`, **any**
  `target-size`/`color-contrast` violation blocks, 15 → 62 scanned surfaces (host hub tabs,
  panels, Toolbox, every Settings tab, Add-host forms, Fleet-run, `?`, palette, ConfirmModal,
  error toast, Monaco with an agent) on both themes, 12 keyboard checks (Tab order, Escape +
  focus return, ConfirmModal cycle, palette, tab reorder), mobile audit blocks on < 24 px targets
  and checks 320 px reflow.

### Changed — deployment & supply chain (audit P2)
- **`upgrade.sh` deploys by digest, not by mutable tag.** It used to pull `ghcr.io/…:vX.Y.Z` and
  then run **root-owned host scripts extracted from that image** — a re-pointed tag or a compromised
  registry meant root on the gateway host. The tag is now resolved to its digest once after the
  pull; version check, signature check, deploy-kit extraction and the deploy itself all use
  `repo@sha256:…`; `.env` records `WEBTERM_IMAGE=<repo@digest>` plus `WEBTERM_IMAGE_TAG` for the
  label; `rollback.sh` returns to the previous *digest*. **cosign** verification runs when `cosign`
  is installed and `WEBTERM_COSIGN_IDENTITY` is set (issuer defaults to GitHub) and fails closed;
  otherwise one explicit `SKIPPED (<reason>)` line — never silent. CI now publishes **provenance
  (`mode=max`) + SBOM** and signs the pushed digest keyless (`cosign-installer` pinned by SHA,
  `id-token: write` only on that job); the verify command is in RUNBOOK. `--allow-unpinned` is the
  escape hatch. New `deploy_script` suite (53 checks) actually executes deploy/rollback/remove with
  a stubbed `docker`.
- **Secrets leave the container environment.** `dockerproxy` with `CONTAINERS=1` let the exposed
  Traefik read `Config.Env` of every container — Cloudflare token, OIDC client secret, SMTP
  password, setup token. The gateway now reads `*_FILE` variants (`WEBTERM_SETUP_TOKEN_FILE`,
  `WEBTERM_OIDC_CLIENT_SECRET_FILE`, `WEBTERM_SMTP_PASSWORD_FILE`, …; the plain variable still wins
  when set), `docker-compose.prod.yml` wires them as file-based `secrets:` from `./secrets/`,
  Traefik gets `CF_DNS_API_TOKEN_FILE`, Postgres `POSTGRES_PASSWORD_FILE`. `install.sh`/`deploy.sh`
  write the files (0700 dir) and **migrate an existing `.env`** on the next run (values blanked in
  `.env` after the files exist). Secrets no longer appear on any command line (`curl -K -` via
  stdin; in-process `.env` rewrite instead of `sed` — which also fixes `&|\` corruption in
  `set_cert_env`).
- **Compose hardening** for every service, not only `app`: `cap_drop: [ALL]` + the minimal
  `cap_add`, `no-new-privileges`, memory/pids limits, json-file log rotation; `read_only` + `tmpfs`
  for dockerproxy, Traefik, Redis (Postgres/Authentik left writable — their writable paths are not
  documented); `postgres:16.15-alpine`, `redis:7.4.11-alpine` pinned to exact minors. Dev Caddy
  hardened the same way. `.dockerignore` now excludes `.env*`, `*.pem`, `*.key`, `secrets/`,
  `.venv/`, `node_modules/`, `tests/` (the image was verified to still build and to carry none of
  them). `remove.sh` removes only this project's image repo and skips images still in use.

### Changed — backups & alerts (audit P2)
- **Scheduled backups could silently never run.** The scheduler checked "is it due?" only one hour
  after boot and against the schedule alone, so a gateway restarting more often than hourly made
  zero backups and raised zero alerts. Due is now computed against the **last successful** backup
  (never ran → due now), the first tick runs 60 s after boot (catch-up), an `asyncio.Lock` prevents
  overlapping runs, and a failure persists `backup_last_error` (stage: local/cloud, destination
  name), lights the existing attention flag and e-mails (12 h throttle).
- **Archives written atomically** (`.tmp` → fsync → `os.replace`, 0600) — a crash mid-write no
  longer leaves a truncated `.wtsnap` that the UI offered for download; stale `.tmp` files are
  pruned. **Off-host uploads have timeouts** (connect / per-operation / close) and go to
  `name.part` then rename, so a half-open SFTP/FTPS server can no longer hang the backup task
  forever and a partial upload is never listed as a valid archive.
- **Settings → Backup shows the truth**: last run (ok/failed, time), the last error in red until
  the next success, next due / overdue, the off-host destination line with its last good copy, and
  a preview (name, size, file date) before a restore. **Settings → Notifications** shows e-mail and
  webhook *last sent / last failed*.

### Changed — gateway security (audit P2, LOW findings closed)
- **Guard-rule regex budget that actually works.** The 0.25 s "budget" per command-guard rule was
  a `wait_for` around a thread, which cannot be interrupted: a pathological rule (`^(a+)+$`) held
  `/run` for 12.9 s and ate a pool thread per call. Matching now runs in a dedicated minimal worker
  process killed on timeout (measured 0.31 s end to end), the rule is logged + audited as over
  budget, and **saving** a pathological rule is rejected with 400 after a short fuzz.
- `X-Webterm-Version` is emitted only for a **valid** session, not for any cookie-shaped value;
  `GET /api/hosts/{id}/connections` is behind the same step-up as forwards on 2FA hosts (the
  Toolbox and Forwards panels now open the passkey prompt instead of showing a bare 403);
  SSO step-up sends `max_age=0` and refuses a stale `auth_time` (absent `auth_time` is accepted
  with one warning — documented in SSO.md); `Trailer` is now really stripped from proxied forward
  requests (`_HOP_BY_HOP` said `trailers`; new `forward_proxy_headers` suite); e-mail addresses are
  validated with one rule at setup, create-user and PATCH /account (`account.badEmail`);
  `tail_altscreen_test` asserts on the real `core.ALT_SCREEN_RE` instead of a stale copy that lacked
  `1048`.

### Fixed
*(from the 2026-10-04 internal audit; everything below is gateway/frontend only,
agent untouched)*
- **Deleting a host left everything that referenced it behind — and the next host inherited it.**
  `hosts.id` is reused by SQLite (no AUTOINCREMENT) and `ON DELETE CASCADE` never ran (foreign keys
  are off), yet delete/uninstall/the ephemeral reaper removed only `connections` + `hosts`. A fresh
  host — the normal case for connect-once targets — appeared with the old host's **active forwards**,
  session history, agent events and update flags, and saved jump targets under a deleted agent
  vanished from the sidebar (rendered only beneath their parent) while staying in the DB, undeletable.
  One `core.purge_host()` now backs all three paths: sessions (transcripts **archived**, not
  orphaned — the reaper used to skip this), forwards (ticket epoch bumped), agent events,
  connections, RAM state; command history keeps its global rows but drops the id link. Deleting an
  agent with **persistent** jump children is refused with 409 `host.hasJumpChildren`; ephemeral
  children go with the parent. SSH deploy-key evidence is **detached, not deleted** (M-6: the key is
  still on the machine): rows move to the negated id, so they stay visible as orphans but can't attach
  to a reborn host. The sidebar also shows legacy orphans (parent missing) at top level so they can be
  deleted. New `host_delete` suite (56 checks).
- **Telnet-jump hosts always read `online: false`**, so their live sessions showed in neither the
  active nor the closed list on the host page. `online` for ssh-jump/telnet-jump now follows the
  parent agent's connection, everywhere the flag is emitted (host JSON, status counts, events, ws init).
- **Host edits could brick a host or break the jump family.** `via_host_id` pointing at the host
  itself, or a cycle (A via B via A), is refused with 400 `sshjump.viaLoop` (bounded chain walk);
  retyping an agent that still has saved jump children is refused; leaving the jump family clears
  `via_host_id`; `POST /api/hosts` rejects an unknown `connection_type` with 400 instead of silently
  coercing it to `agent`; telnet hosts created through the API default to port 23 (the `or 23` could
  never fire because 22 was always written).
- **An agent's whole connection died on a persist error or an odd control frame.** A disk-full or
  "database is locked" on one session's output tore down all sessions and forwards of that host,
  the agent reconnected in seconds, hit the same write and the fleet flapped; `on_output` failures
  now drop the frame and log once per 30 s. Control frames that are valid JSON but not an object
  (`42`, `[]`), or carry wrong types, raised `TypeError`/`KeyError` past the `ValueError`-only guard
  with the same effect — all caught now. `_shutdown()` also cancelled an in-flight `on_exit` when
  an agent with a deferred update re-exec'd right after the last session exited, leaving the session
  `live` in the DB and later "lost" with a Reconnect button for a shell that ended normally;
  exit handling now survives the connection.
- **HTTP forwards on 2FA hosts were an infinite redirect loop (feature dead, fail-closed).** The
  step-up check on the forward subdomain read the main-domain session cookie, which — `__Host-`,
  host-only — never arrives there, then redirected *relatively* to itself; the test faked the cookie.
  The window is now checked against the **user id signed into the forward ticket**, the redirect is
  absolute to the public URL, and `next` is validated (relative path only, never `//`, never
  `/__wtfwd/*`). The **WebSocket** path now enforces the same window at handshake and in the 60 s
  revalidation (close 1008) — previously an open WS to a 2FA host survived up to 55 min after the
  window closed. `fwd-test.sh` gained the end-to-end subdomain GET.
- **The Monaco editor discarded unsaved edits** on Escape, scrim click, Close or page reload — no
  dirty tracking at all — and **Ctrl+S saved twice** (window capture listener + Monaco command).
  Edits are tracked against the saved version (undo back to clean counts as clean); closing while
  dirty asks via ConfirmModal, `beforeunload` guards reloads, an unsaved dot shows in the title, Save
  is disabled when clean; Ctrl+S inside the editor is Monaco's alone. Tab inside Monaco indents
  instead of jumping to the Save button (the focus trap now respects `defaultPrevented`). The theme
  follows the app theme (`vs` on light) and switches live. The legacy file browser (Sidebar ⋯ →
  Files) saved **without the mtime check** and silently overwrote concurrent edits; it now sends
  `if_mtime` and shows the same conflict banner as the file panel.
- **Reconnects were blind, and terminal close codes were ignored.** Keystrokes typed while a session
  was "reconnecting…" (watchdog 60 s, backoff up to 20 s after laptop sleep) vanished silently; the
  terminal now shows an explicit *input paused* curtain that flashes on each dropped key and reports
  the count after reconnect (no blind replay: the gateway replays output only, and a buffered
  `rm` landing in a changed shell is worse than retyping). Gateway close codes 4401 (session
  expired) / 4403 (forbidden) / 4404 (session gone) used to feed the retry loop forever, and an
  expired login swapped the whole app for the login page without a word; they now stop retrying
  and say why, with a *Sign in again* action and a banner above the login form explaining the
  expiry. First connection is labelled *Connecting*, not *Reconnecting*.
- **`Ctrl+Shift+W` / `Ctrl+Shift+T` are reserved by Chromium** (close window / reopen browser tab)
  and could never reach the app. Close tab is now `Alt+W`, reopen `Alt+T`; `shortcut.pastePicker`
  was missing from both catalogs (raw key in the `?` cheatsheet); SHORTCUTS.md now matches
  `lib/shortcuts.ts` exactly (adds `Mod+Shift+V`, `Mod+S` in the editor, `Mod+Enter` in Git).
- **Ephemeral (connect-once) targets leaked into Dashboard, the command palette and Fleet-run**
  with counts — only the sidebar filtered them. One `isEphemeralHost()` predicate now serves all.
- **`install.sh --with-authentik` produced an empty Authentik domain.** The interactive path called
  `ask` with its arguments inverted (`"invalid variable name"`), `err` didn't exit, and the profile
  was written active with `AUTHENTIK_DOMAIN=""`. `ask` gained an optional default (Enter accepts
  `auth.<domain>`) and an empty value now aborts.
- **Scheduled backup/cert-check timers on existing installs had `Persistent=` silently off.** The
  installed units carried `Persistent=true  # comment` on one line; systemd rejects inline comments
  ("Failed to parse boolean value, ignoring") so a missed run was never caught up. The repo units
  were already fixed, but nothing ever re-synced them: `upgrade.sh` now ships the units in the
  deploy kit (Dockerfile) and re-renders them into `/etc/systemd/system` (only units it installed,
  `.bak` kept, `daemon-reload` + re-enable), with 12 new checks in the upgrade suite.
- **Docs that contradicted the code.** SECURITY.md claimed scheduled backups are unencrypted (they
  refuse to run unencrypted; the installer generates the passphrase); README said `git checkout
  v2.0.19` and that image deploys require Cloudflare DNS-01 (HTTP-01 is the default); README
  screenshots are labelled as v2.0.0/CodeMirror until regenerated; PORT-FORWARDING.md called
  SSH-jump "deferred". New **docs/SSH-KEYS.md** and **docs/SSH-JUMP.md** document the 3.0.0 headline
  features (previously undocumented). `scripts/e2e-jump.mjs` — written for 3.0.0 but run nowhere — is
  now a CI step (own container, `jump` in `ci-local.sh`); `unit-tests` gate is 67 suites.

## [3.0.0] — 2026-10-02 · agent (53)

A security- and bastion-focused major. WebTerm becomes a **complete jump host** (SSH to LAN gear
through an agent, host-key pinned by the gateway) and hardens the host→host deploy keys shipped in
2.7.x with an optional policy. Plus day-to-day glue: service-log triage, on-demand diagnostics,
Toolbox polish — all through the existing agent `run` op, so **the agent is unchanged (still 53)**
and no fleet re-sign is needed. pyjwt bumped to 2.15.0 (CVE). Static code scanning (CodeQL) added
alongside the existing Dependabot + Trivy/pip-audit.

### Added
- **SSH-jump: a first-class bastion to LAN gear, with no agent on the target.** A new host type
  `ssh-jump` reaches a device on an agent host's LAN over SSH, tunneled through that agent's
  existing raw-TCP forward — the **gateway runs the asyncssh client and owns the host-key pin**,
  so a man-in-the-middle (even a hostile agent relaying the tunnel) is rejected before auth, and
  a changed host key raises a loud alarm and refuses the session. Reuses the direct-SSH machinery
  (creds in the vault, `known_hosts` pinning, `ask`/`stored` policy); the agent is **untouched**.
  The SSH session's own crypto runs end-to-end gateway→target, so the plaintext LAN tunnel carries
  only ciphertext. Pick "SSH-jump" in Add host, choose the agent to reach through, and the target's
  LAN address. (The same host-key-change alarm now also covers plain direct-SSH hosts.)
- **Deploy-key security policy (Settings → Security, optional, off by default).** Two toggles that
  harden host→host deploy keys. **Require 2FA on source hosts:** a host holding a deploy key can
  reach its targets — the crown jewel — so when on, you can't generate a key on a host until it has
  2FA enabled. **Require restricted keys:** refuse full-shell deploy keys; each must carry a
  restriction. The deploy flow gains a restriction selector — *full shell*, *locked down*
  (`restrict`: no pty/forwarding/agent/X11), or *run only one command* (`restrict,command="…"`) —
  so a stolen key can do only its one job. `from="IP"` still composes alongside. Rotate preserves
  each edge's existing options. The forced command is validated (one printable line, no control
  characters) and escaped for the authorized_keys quoting.
- **Toolbox History shows each command's date/time**; **Library lets you add your own commands**
  (backed by the existing snippets — one list, also reachable from the command palette).
- **Services panel: "why is this box sad" triage.** A **Failed** toggle lists only failed units
  (`systemctl --state=failed`), and a per-service **Logs** button opens a session following
  `journalctl -u <unit> -f` — the same move as Docker logs, live in a real terminal. New library
  recipes for fleet `systemctl --failed` and `list-timers`. All via the `run` op; agent untouched.
- **Diagnostics: on-demand deep probes.** The Storage tab gains **disk health** (lsblk · SMART ·
  ZFS) and the Network tab gains **neighbors & firewall** (`ip neigh` · `nft`/`iptables`), loaded
  on demand and shown as labeled read-only text. Degrades cleanly without root (shows "needs root",
  never a silent empty list). Via the `run` op; agent untouched.
- **Toolbox → SSH keys: host-to-host deploy keys.** A dev host can now `ssh` into other
  fleet hosts (deploy/test on prod) without running AI agents there. The private key is
  **generated on the source host and never leaves it** (`~/.ssh/webterm_ed25519`, via the
  existing `run`/`fs_read` agent ops — the agent itself is untouched, no fleet update);
  WebTerm stores only the public key + fingerprint and the **deployment graph** (which
  targets carry it), so access is inventoried and revocable per edge. Deploying appends the
  key idempotently to the target agent user's `~/.ssh/authorized_keys` (perms 700/600,
  one line per key even across option changes); revoking matches the key **blob**, so a
  manually edited line still gets removed and foreign keys are preserved. Guardrails:
  the public key read back from the host is strictly validated (a compromised source can't
  smuggle extra `authorized_keys` lines onto targets); deploying demands a **fresh**
  2FA/password check even on hosts without `require_2fa` (granting durable SSH access must
  cost a factor — a stolen cookie alone can't plant a key) and sends an email alert; an
  **anti-pivot guard** warns before creating access chains (a host that is both source and
  target); optional `from="IP"` restriction per deployment; automation tokens can't reach
  any of it. Verify reconciles reality (`deployed` / `edited on target` / `missing`), and
  deleting a key refuses while active deployments exist. **Multi-target deploy** (one
  fresh-factor check authorizes the key to N hosts, per-target results), **Test connection**
  (ssh from the source to a target with the deploy key — BatchMode, accept-new TOFU — reports
  reachability without touching the target), an idempotent **~/.ssh/config alias** on the
  source so `ssh <name>` works without `-i`, and a guided **Rotate** (fresh keypair →
  redeploy to every target → drop the old key, no window without access).
- **Connections: InfluxDB 1.x and 2.x.** 1.x uses the ask/stored password model (the client's
  `password:` prompt). 2.x authenticates with an API token: a launcher emits its own hidden
  prompt and passes the token to `influx v1 shell` only through the process environment —
  never the command line or the transcript — so the token can be stored in the vault like any
  password, or left to the host's own `influx config`.

## [2.7.0] — 2026-09-28 · agent (53)

Two headline features: the **Toolbox** (databases, command library, history) and **named split
views**. **This release updates the agent (52→53)** for stored-credential injection; older agents
keep working (they just ignore the new field and fall back to `ask`).

**Toolbox** — a per-host side panel for the day-to-day work that isn't "open a shell and remember
the flags." Three tabs, reached from a host's page or from inside a session.

**Split views** — turn 2–4 open sessions into a **named**, saved layout (2 = a resizable split with
a draggable divider, 3–4 = a 2×2 grid). Each split view rides in the tab bar as its own chip beside
the session tabs; click to switch between layouts and single sessions like tabs (leaving a split
keeps its chip, so you return anytime). Panes are bordered — the focused one gets an accent border —
and **broadcast** types into every pane at once. Create one from the **"+ Split view"** button,
**right-click → Add to split view**, or **Alt+D**. Definitions are saved **server-side** (they
follow you across devices); the same session may appear in a tab and in split views, but only the
view you're on is live, so a session never fights itself for size. Details:
[docs/design/SPLIT-VIEWS.md](docs/design/SPLIT-VIEWS.md).

### Added

- **Connections** — saved database launchers. One click opens a session that runs the right client
  on the host (`psql`/`mysql`/`mongosh`/`clickhouse-client`/`redis-cli`) with host, port, user and db
  pre-filled — no memorizing connection strings. Two credential policies:
  - **Ask** (default): the client prompts for the password; WebTerm stores nothing.
  - **Stored**: the password is encrypted in the vault (same Fernet vault as SSH creds) and the agent
    types it once into the client's password prompt on the PTY. It never appears in argv, the process
    list, the environment, a file, or the transcript. Redis has no password prompt, so it stays on
    *ask*. On a 2FA host, both launching a connection **and** creating/editing/deleting one cost a
    step-up factor — a connection is a credentialed hole into the host, so a stolen cookie can't
    re-target a stored connection to harvest its password.
- **Library** — built-in command recipes (git, docker, systemd, system, db) with `{placeholder}`s.
  Click to copy; paste into any terminal. Works from the host page too, without an open session.
- **History** — the host's own command history (from OSC 133 shell integration), searchable, click to
  copy. 2FA-gated like the rest of the history API.
- **Apps presets** for the database & observability web consoles (Adminer, pgAdmin, phpMyAdmin,
  Mongo Express, Kibana, ClickHouse) so a forward to one gets the right label, colour and glyph.

### Fixed

- Deleting or uninstalling a host now removes its saved connections too — the `ON DELETE CASCADE`
  is inert without `PRAGMA foreign_keys`, and host ids get reused, so an orphaned row could otherwise
  surface a stored credential on a different host.
- The agent type-guards the injected credential field, so a malformed control frame can't crash the
  reader loop.

Verified: full Playwright UI suite (e2e-session 79/79, axe 0 serious, FS API 35, features 8), gateway
suites (connection CRUD step-up + host-delete cleanup + validation, agent injection + type-guard),
i18n en/ro parity.

## [2.6.4] — 2026-09-27 · agent (52)

Dependency maintenance. **No agent change** (still 52). The dependabot group updates were applied
onto current main and each verified, rather than merging the diverged auto-PRs.

### Changed

- **Frontend deps** bumped: CodeMirror 6.x, `@fontsource/jetbrains-mono`, `qrcode-generator`,
  autoprefixer, postcss, typescript-eslint, eslint tooling. The `@xterm/addon-*` minor bumps were
  **held back** — they target xterm 6.x and break the terminal on our xterm 5.5 (caught by e2e); they
  wait for a deliberate xterm 6 upgrade.
- **Gateway deps** bumped: FastAPI 0.139→0.141.1, uvicorn 0.50→0.52.4, cryptography 50.0.0→50.0.1;
  `requirements.lock` regenerated with hashes (pip-audit clean, lock in sync).
- **CI actions** (checkout, docker build-push) and the bundled **Authentik** image pin (2026.8.3)
  bumped.

Verified: full Playwright UI suite (e2e-session 79/79, axe 0 serious, FS API 35, features 8) and the
gateway test suites pass on the new versions.

## [2.6.3] — 2026-09-27 · agent (52)

Polish on the OS-updates feature. **No agent change** (still 52) — gateway + UI only.

### Changed

- **The updates badge is readable now.** It was a translucent 15%-opacity fill with pale text and
  almost no contrast; it's now a solid amber pill (dark text) — red with white text when there are
  security updates — matching the broadcast button's weight.
- **"Upgrade in a terminal" on a host without sudo now shows what to do next.** Instead of a dead-end
  "needs root" line, it lists the options and leaves the choice to you: run it yourself as root, or
  grant the agent user passwordless sudo (with the exact `sudoers.d` command to copy) so the button
  works next time. It runs nothing on its own and drops you into a shell.

## [2.6.2] — 2026-09-27 · agent (52)

Follow-ups to the machine-management features, from continued testing. **This release updates the
agent (51 → 52)** — hosts update on reconnect (deferred while a host has open sessions).

### Fixed

- **The updates badge clears after you upgrade.** The agent's update count was cached for 6h, so the
  sidebar badge lingered even once the host was up to date. An on-demand diagnostics refresh now
  forces a fresh check (bypassing the cache), and finishing an "upgrade in a terminal" session
  triggers that refresh automatically — the badge clears on its own.
- **"Upgrade in a terminal" no longer leaves a lingering root shell.** After the upgrade (or the
  guidance message on a host without sudo) the session ends instead of `exec`-ing a fresh login
  shell — which, on a root agent, was an extra persistent root prompt. The scrollback stays
  readable; open a normal session if you want a shell.
- **dnf hosts can report "up to date".** The dnf update check now distinguishes 0 pending from a
  failed check via the command's exit code (100 = updates, 0 = current), instead of showing nothing.
- A non-numeric `WEBTERM_UPDATES_CHECK_SECS` no longer crashes the agent at startup (falls back to
  the 6h default), and a Wake-on-LAN request with a numeric (not string) MAC/broadcast is reported
  as a clean `wake_error` rather than an internal error.

### Added

- **Pending-updates badge on Arch, openSUSE and Alpine too** — the agent now also counts updates via
  `checkupdates` (pacman), `zypper` and `apk`, not just apt/dnf.

## [2.6.1] — 2026-09-27 · agent (51)

Fixes from a five-reviewer audit of the 2.6.0 machine-management features. **No agent change**
(still 51) — gateway + UI only, no host update.

### Fixed

- **"Upgrade in a terminal" no longer hangs on hosts without sudo.** It is now privilege-aware:
  as root it upgrades directly; with passwordless sudo it uses `sudo sh -c`; otherwise it prints
  the exact command (correctly quoted as one `sudo sh -c '…'`, so the whole `apt-get update &&
  upgrade` runs as root) and drops you into a shell — no unanswerable password prompt. Fixes the
  default dedicated `webterm` user (which has no sudo). README documents which OS/managers the
  agent's features support.
- **A poisoned host can't take down the fleet list.** `_host_updates` and the Wake-on-LAN
  interface parser now type-check the diagnostics JSON before reading it — a compromised or buggy
  agent storing a non-object top-level value (`[1,2]`, `42`, `"x"`) used to raise on every host in
  the listing and 500 the shared `/api/hosts` view.
- **Services / ports panels tell you when the tool is missing.** `systemctl list-units` no longer
  hides its stderr, so a host without systemd returns a clear "systemctl not available" instead of
  a silent empty list; the ports tab does the same for a missing `ss`.
- Updates badge announces the security-update count to screen readers (not just sighted users), and
  the Diagnostics modal resets its Ports tab per host.

### Tests

- `_host_updates` / `_host_ipv4_ifaces` now covered for malformed diagnostics JSON (the 500 path),
  valid parse, and the `count`-as-bool rejection.

## [2.6.0] — 2026-09-26 · agent (51)

Machine management from the same pane: OS updates, systemd services, listening ports — plus the
split view gets a proper home. **This release updates the agent (50 → 51)** — hosts update on
reconnect (deferred while a host has open sessions).

### Added

- **Pending OS updates, surfaced.** The agent counts pending updates (apt / dnf, checked every 6h,
  read-only) and reports them in diagnostics. A host with updates shows a **badge in the sidebar**
  (red when any are security) — you see it without opening the host. Click it to review the count,
  then **Upgrade in a terminal**: WebTerm opens a session running the upgrade command for the
  detected manager. It never installs for you — it's glue to the terminal, not a package-manager UI.
  Off with `WEBTERM_UPDATES_CHECK_SECS=0`.
- **systemd services panel** (toolbar, agent hosts): list units with live state, filter, and
  **start / stop / restart** — through the agent's `run` op, step-up-gated on 2FA hosts. Runs as the
  agent's user, so system units need the right privileges (surfaced, not silently swallowed).
- **Listening ports in Diagnostics.** A new **Ports** tab runs `ss -tulnp` on demand: protocol,
  port, address and the owning process (process names need root).
- **Path-friendly selection at the shell prompt.** tmux `word-separators` now mirror the browser
  terminal's, so with mouse mode on a double-click on `/etc/nginx/nginx.conf` at the prompt selects
  the whole path — matching how it already behaved inside vim / Claude Code.

### Fixed / hardened (agent v51)

- **Wake-on-LAN uses a reliable interface signal.** The agent reports a `physical` flag per NIC
  (has `/sys/class/net/<n>/device`); the gateway filters wake candidates on that instead of guessing
  from the interface name (the name-prefix rule stays as the v50 fallback).
- `fs_stat` derives dir/link from the same `lstat` (no re-stat, no symlink-follow) — a symlink to a
  directory now reports `link=true, dir=false`, consistent with `fs_list`.
- `send_magic_packet` validates the broadcast address (an IPv4 literal — a hostname would block the
  reader thread on DNS) and the port range; a bad port is a clean `wake_error`, not `internal`.

## [2.5.2] — 2026-09-26 · agent (50)

Quality-of-life around alerts, the file manager and multi-terminal, plus the fixes from a
five-reviewer audit of everything shipped in the last week. **No agent change** (still 50).

### Added

- **Mute offline alerts per host.** A bell on the offline host's sidebar row: mute a machine you
  stopped on purpose and it emails nothing while it is down; unmuting re-arms the alert (a host
  still down alerts once again — you asked to know). The sent-once dedup now **persists in the DB**,
  so a gateway restart no longer re-sends an email for every host that was already down — that was
  where the "one more offline email after every deploy" came from. On a 2FA host, muting requires
  **step-up**: silencing monitoring is exactly what a stolen cookie would want to buy.
- **Copy name / path in the file manager.** Double-click a file name copies the name,
  triple-click copies the full path — through the standard copy toast, with the non-HTTPS fallback.
- **Split view instead of the grid strip.** The entry moved where it belongs: a button **in the tab
  bar** (the permanent bar above the workspace is gone — it cost a line of screen even unused).
  Two sessions now make a real **resizable split** (drag the divider; arrow keys; double-click
  resets; persisted), 3–4 keep the 2×2 grid. Broadcast and exit sit next to the button while active.
- **Unicode 11 widths** (Settings → Terminal, off by default): emoji and wide CJK take the right
  number of cells so TUI boxes stay aligned. Lazy-loaded only when enabled. (Font ligatures were
  investigated and dropped: the xterm addon needs Node/Electron APIs — it cannot run in a browser.)

### Fixed

- **Wake-on-LAN on hosts with Docker.** Virtual interfaces (`docker0`, `br-*`, `veth*`, VPNs) no
  longer qualify as wake target or relay peer: the bridge sorts before `eth0` in diagnostics, so
  the old code could pick the bridge MAC and "find" a peer on another physical LAN via 172.17/16 —
  a silent false success. /31–/32 interfaces (no real broadcast) are excluded, peers still on
  agent v49 are skipped during a rollout, and the "neighbour too old" error now says so.
- **The install password is validated** to a shell-safe alphabet (letters/digits/`._-`, max 64) at
  all three intake points — it gets interpolated into the copied one-liner, where a quote or
  `$(…)` would break or alter the very command you paste on the host.
- **Unknown `app_type` is a 400 now**, not a silent coercion that made a promote "succeed" while
  the tile never appeared.
- **Alert sweep is storm-proof.** The offline alert used to be sent before the dedup flag was
  persisted, with the DB write unguarded — a full disk (reads work, writes fail) would have meant
  one email per host per sweep. A RAM backstop plus per-host error isolation closes it.
- **New-file dialog hardened**: the name must be a bare filename (`/` and `..` rejected), and the
  duplicate check re-lists the directory just before creating — a file made in the terminal after
  the last listing can no longer be silently truncated. Dialogs are mutually exclusive and
  keyboard navigation pauses under the delete confirmation.
- Small Track A polish: switching hosts quickly can't show the previous host's app buttons; the
  ⌘K selection no longer shifts when apps load; un-starring then re-starring a forward keeps its
  app type (Proxmox stays orange).

### Docs / tests

- README caught up on: install-link TTL + password (2.4.1), file create/copy, the offline host row.
- New tests: WoL virtual-interface and /32 paths, mute step-up asymmetry, hermetic agent
  `fs_stat` + `fs_write` offset-conflict; the alerts test moved to the persisted-dedup model.

## [2.5.1] — 2026-09-24 · agent (50)

A small file-manager convenience and a cosmetic fix. **No agent change** (still 50) — hosts need no update.

### Added

- **Create a file, not just a folder.** The file manager's new **+📄** opens a small dialog: name the
  file, then either create it **Empty** or **From clipboard** — the latter reads your clipboard and
  writes it straight into the new file, so pasting a config or key is one step instead of upload-a-file.
  Either way the editor opens on it (atomic save, mtime-conflict detection). Clipboard reading needs
  HTTPS and a click; if the browser refuses, the dialog stays open with **Empty** as a fallback.

### Fixed

- **`upgrade.sh` no longer warns after a clean prune.** A trailing test left a non-zero exit that
  tripped the warning path, printing a spurious "prune skipped" even when old images were removed fine.

## [2.5.0] — 2026-09-24 · agent (50)

Reach the tools behind the bastion without leaving it, and wake the machines that are off.
**This release updates the agent (49 → 50)** — hosts update on reconnect (deferred while a host has
open sessions).

### Added

- **App bookmarks for Proxmox / Portainer / Grafana / anything web.** A wizard ("Add app") turns a
  service on a host into a named tile — internally just a `https` port-forward on its own subdomain,
  behind your passkeys, so there's nothing new to secure. Apps show on an **Apps** strip on the
  dashboard, as buttons on the host page, and open by name from ⌘K; any existing forward can be
  promoted (☆). A bookmark is a forward + a little metadata (`app_type`); `/api/apps` aggregates
  them across the fleet without exposing the internal `host:port`. An honest SSO hint (no helper):
  point the app's OIDC at the same Authentik WebTerm uses and it's one login — WebTerm holds no app
  credentials and provisions nothing.
- **Wake-on-LAN.** A **Wake** button on an offline agent host: a neighbouring online agent on the
  same LAN sends the magic packet, so a powered-off machine comes back without a trip to it. The
  MAC comes from the host's last diagnostics; the neighbour is matched by the peers' own LAN IPs
  (not the NAT'd source IP). New agent op; needs `iproute2` on the host and an online peer on the
  same LAN.

### Fixed (agent hardening, v50)

- **Resumable upload: the agent verifies `st_size == offset` before an O_APPEND write** — a mismatch
  (stale gateway cache, partial-chunk retry) is refused as a conflict so the client resyncs, closing
  the blind-append duplication path at its source (the gateway side was fixed in 2.3.x).
- **`fs_stat` — an O(1) size probe.** Resume/GC used a directory listing capped at `FS_MAX_LIST`, so
  a resume silently restarted from 0 in a folder with more than ~2000 entries; it now stats the temp
  directly (falling back to the listing on pre-v50 agents while the fleet updates).

## [2.4.1] — 2026-09-24 · agent (49)

Enrollment hardening and disk hygiene. Gateway/tooling only; agent unchanged.

### Added

- **A configurable validity window and an optional password on install links.** When you add a
  host (or a group enrollment token), you now choose how long the link is valid (15 min / 1 h /
  24 h / 7 d; default 1 h, was a fixed 24 h) and may set a temporary **install password**. The
  password is required at install time and travels as an HTTP header (`X-Enroll-Pass`), never in
  the URL — so a link captured in a proxy/access log can't be used on its own. It's checked before
  the single-use token is claimed (a wrong guess doesn't burn the link) and rate-limited per host/
  group so the URL can't be used as a brute-force oracle. Deliver it out-of-band for real
  defence-in-depth.
- **Unused install links are visible.** A host whose install link is still valid and unclaimed
  shows an "install link active (unused)" badge in the sidebar (flagging whether it's
  password-protected), so a forgotten or leaked link gets noticed; it clears when the agent first
  connects or the link expires.

### Changed

- **`upgrade.sh` now prunes old images**, keeping the last 7 versions (override with
  `WEBTERM_KEEP_IMAGES`) for manual rollback, plus always the running image and the rollback
  target. Every upgrade used to leave the old ~300 MB image on disk forever.

### Notes

- **Rolling the gateway back while agents are ahead is safe by design.** A rolled-back gateway
  never downgrades an agent (it only pushes when the host's version is *older*, and the agent
  refuses downgrades regardless), and agent wire changes are additive, so an older gateway talking
  to a newer agent stays compatible — you simply lose newer features until you roll forward.

## [2.4.0] — 2026-09-24 · agent (49)

A feature release built entirely on the existing agent — **no fleet update** (agent stays at 49).
Docker/tar run through the agent's existing `run` op; container shells reuse the session `cmd` the
agent already supported. Every item was reviewed by adversarial audits and proven end-to-end before
shipping.

### Added

- **Docker panel** (toolbar button, agent hosts). Tabs for **containers / images / volumes /
  networks**, listed by running the host's `docker` CLI through the agent (no new agent op, no extra
  daemon exposure). **Start / stop / restart** a container, view its **logs**, and open a **shell
  inside a running container** in its own terminal tab — `docker exec` with bash and an `sh` fallback
  so it works on minimal images (alpine/busybox) too. The container shell lives in tmux, so it
  survives a reconnect like any session. Reads and actions take the same 2FA step-up as any host
  action; logs (a classic secret store) are gated too.
- **Multi-terminal grid + input broadcast.** Pick 2–4 open sessions into a **2×2 grid**, all live at
  once; toggle **broadcast** to type into every pane simultaneously, with an amber band on each pane
  so there's no doubt where the keys land. A picker chooses exactly which terminals go in the grid.
- **Download a folder (or file) as a `.tgz` archive** from the file panel — tarred on the host and
  streamed down, with the host-side temp cleaned up even if the download is aborted.
- **Resizable sidebar** — drag the edge (or arrow keys on the handle, double-click to reset) to
  trade list detail for terminal width; persisted per browser.
- **Offline hosts** sink to the bottom of their sidebar group with **how long they've been down** and
  an editable **note** ("why is it down"), shown on the Dashboard too; a collapsed group's count
  turns into `alive/total`.

### Changed

- Account-secret prompts (SMTP/backup/signing/passkey/user-delete re-auth) now use a **masked modal**
  instead of `window.prompt`, which showed the password in cleartext.

## [2.3.3] — 2026-09-23 · agent (49)

Sidebar ergonomics for powered-off hosts, plus the fixes from a UI/accessibility audit of the
recent surfaces. Gateway untouched beyond version; agent unchanged.

### Added

- **Offline hosts sink to the bottom of their sidebar group**, with how long they have been down
  (last heartbeat; hover for the exact date) and a **note** — "why is it down" survives the two
  weeks it takes to forget. The ✎ button edits it in place; the note also shows on the Dashboard's
  offline cards. A collapsed group's count turns into `alive/total` so hidden down hosts stay
  visible.

### Fixed

- **Account passwords are no longer typed into `window.prompt()` in cleartext.** Every re-auth
  flow (SMTP settings, user delete, backup and signing-key downloads, TOTP enrolment, passkey
  add/remove) now uses a proper masked modal with focus-trap and Escape; short-lived TOTP/email
  codes deliberately stay visible while typing.
- **Hosts can be selected from the sidebar by keyboard** — the host name is a real button now
  (rows were click-only divs; the ⌘K palette was the only keyboard path).
- The ✎ note/rename buttons were invisible on touch devices (hover-only reveal); the settings-gear
  status dot carried a hard-coded, language-mixed aria-label (dropped — the parent button's
  translated title carries the state); threshold-save errors rendered two sections away from the
  button that caused them.

## [2.3.2] — 2026-09-23 · agent (49)

A seven-day retrospective inspection: three adversarial reviews (upload protocol, the 2.3.1
security fixes themselves, frontend) plus a cross-cutting sweep. Every critical finding was
re-verified against code or a live PoC before fixing. Gateway/interface only; agent unchanged.

### Security

- **The OSC filter closes two ESC+C1 desync bypasses.** A C1 control is an "anywhere" transition
  in the VT parser, so `ESC` followed by `0xC2 0x9D` still starts an OSC — but the filter's
  pass-through branch emitted the bytes raw, and an OSC 52 (clipboard exfiltration) sailed through
  verbatim; same after a benign OSC terminated by a dangling ESC. Both confirmed with PoCs at
  every fragmentation boundary; one new state covers both, with five regression tests.
- **Any SMTP settings change now requires the account password.** Only the webhook re-authed;
  `smtp_host` did not — yet email confirmation codes (the fallback second factor) transit that
  server and the gateway AUTHs to it with the stored credential. A stolen cookie could repoint it
  and receive both. The notifications form also gains the previously-missing password prompt.
- **Uniform second-factor policy on account credential ops.** Rotating the account password,
  moving the recovery email, and deleting a co-admin now go through the same `second_gate` as
  passkeys/tokens/recovery codes (TOTP when enabled; the email-code-on-new-device escalation is
  unified instead of duplicated). The account tab also gains the 2FA prompt for user creation,
  gated in 2.3.1 but never wired into this form.

### Fixed

- **Resumable uploads: the silent-corruption and false-CRC-failure paths are closed.** A chunk
  dying after writing part of its blocks left the offset cache stale; the client's retry then
  passed the fast-path and the agent's blind `O_APPEND` glued the whole chunk after the partial —
  duplicated bytes mid-file, committed without error when CRC was off. And the client folded CRC
  at read time, so any re-sent slice counted twice: commit failed a *false* integrity check and
  deleted the good temp. The cache now invalidates on any chunk exception, and CRC accumulates
  only after a slice has confirmably landed. Also: commit/abort run under the per-upload lock,
  the tracking dicts evict instead of freezing at their cap, GC matches the full id range the
  API accepts, the chunk XHR gets a real timeout (a hung TCP connection froze the upload forever),
  and a mid-upload step-up expiry re-prompts instead of dying as an opaque 403.
- **Uploads survive closing the file panel — visible and cancellable.** The transfer always kept
  running, but invisibly: reopening showed an empty list and re-dropping the same file started a
  second writer on the same upload id. Upload state now lives in a module-level store; reopening
  shows the moving progress bar, cancel works, finished rows clean up.
- **A drop that misses the file panel no longer navigates the page away** (the browser opened the
  local file over the SPA, killing every open session view).
- **The toolbar load ring has a real accessible name** and its tooltip — the only place with the
  exact numbers — is reachable by keyboard, not just hover.

### Docs

- README documents resumable uploads with CRC-32 integrity (the 2.3.0 headline was missing) and
  the toolbar load ring.

## [2.3.1] — 2026-09-22 · agent (49)

Security hardening from an external adversarial audit. Gateway/interface only; agent unchanged at 49.

### Security

- **2FA can no longer be weakened with only the password.** Regenerating recovery codes and minting
  an automation token now require the second factor, not just the password — new recovery codes are
  themselves a valid second factor, and a `run`-scoped token is a persistent shell credential. (This
  also fixed a latent gap where disabling 2FA already required the factor but the UI never prompted
  for it.)
- **A writable share guest can no longer hold a session open past the owner's 2FA idle-lock.** Only
  an authenticated owner's input now counts as operator activity; a guest's keystrokes refresh only
  their own timer, so on a `require_2fa` host the session still locks when the owner steps away.
- **Distributed IPv6 login guessing no longer bypasses the global backstop** (the real-IP vs
  internal-key check was fooled by the `:` in IPv6 addresses).
- **The untrusted-device OSC filter now also catches the 8-bit C1 form** of OSC 52/133 (`0xC2 0x9D` /
  `0xC2 0x9C`), and the serial device path is normalized before the `/dev/` check.
- **Resumable uploads**: a per-upload lock serializes concurrent chunks (a same-offset race could
  duplicate bytes), the in-memory maps are bounded, and the abandoned-temp cleanup is strict.

## [2.3.0] — 2026-09-22 · agent (49)

Carries an agent update (48 → 49, fleet-wide auto-update): a new `fs_crc32` op for upload integrity.

### Added — big-file uploads that survive a dropped connection

- Drag & drop used to be one HTTP request per file: a drop at 90% of a large upload restarted from
  zero, so you reached for scp/rsync. Now the browser **slices the file** (`File.slice`, no RAM) and
  sends each part with an offset under a stable `upload_id`; the gateway appends to a persistent
  `.wtpart` temp and commits with the same **atomic rename**. On any failure — wifi blip, laptop
  sleep, even a **gateway restart** — the client asks how much landed and **resumes from that byte**,
  with per-chunk retry/backoff; a desynced or duplicate chunk gets a 409 and re-syncs instead of
  corrupting. The `upload_id` is kept so re-selecting the same file after a reload resumes it; cancel
  aborts and deletes the temp; abandoned temps are cleaned up after 24h.
- **Integrity check**: the browser computes a **CRC-32** while it reads, and on commit the agent
  CRC-32s the file **before** the atomic rename — a corrupted upload (disk error, truncation) never
  reaches the target. **A real progress bar** replaces the bare percentage (byte-level, colored by
  state). This replaces scp/rsync for reliably pushing a big file or folder; rsync stays better for
  *incremental* sync (only changed blocks) and directory mirroring.

## [2.2.1] — 2026-09-19 · agent (48)

Gateway and interface only; agent unchanged at 48.

### Added — host load at a glance in the toolbar

- The session toolbar now carries a small **dual-arc ring** between the session name and the search
  button: outer arc **CPU**, inner arc **memory**, colored by pressure (green under 70%, amber under
  90%, red above). It reads the metrics already in the 5-second poll — no new requests, no agent
  change — moves only on update (and respects reduced-motion), and shows only for online agent hosts.
  Hover it for exact CPU / memory / load, with a pointer to Diagnostics for swap and the rest.

## [2.2.0] — 2026-09-12 · agent (48)

First release that carries an **agent update** (47 → 48): installed agents update themselves to
it automatically, so the new diagnostics snapshot lights up fleet-wide after the gateway upgrade.

### Added — host diagnostics you can read from the UI

- The **Diagnostics panel** went from "connection state + event log" to a full, tabbed host view:
  **Overview** (system: OS/kernel/uptime/arch; CPU model/cores/load; memory + swap with usage
  bars), **Storage** (every filesystem, not just the fullest, with usage), **Network** (each
  interface with its IPv4/IPv6, MAC, MTU and traffic, plus the **routing table**), and **Logs**
  (the 7-day connection log and the agent log tail, now full-width).
- The agent collects this snapshot from `/proc`, `/sys` and `ip` — pure stdlib, best-effort per
  field, on a worker thread so it never blocks the event loop. It's **pushed on (re)connect and
  hourly**, and on-demand via a **Refresh** button. The gateway **persists the last snapshot**, so
  a host's IPs, routes and disks stay visible **even when it's offline** — labelled "as of …".

### Added — confirm before signing out

- **Sign out** now asks for confirmation (a small dialog). On a terminal app an accidental logout
  means re-authenticating; the prompt notes that tmux sessions keep running and reattach next login.

## [2.1.2] — 2026-09-12 · agent (47)

Gateway and interface only; agent unchanged at 47. No user-facing behaviour change — an internal
refactor of the Settings modal plus a CI robustness fix, released so the cleaner codebase ships.

### Changed — Settings modal broken up

- `SettingsModal.tsx` had grown into a ~2489-line god-component holding ~80 pieces of state across
  every tab. It's now a **94-line shell** (header + category rail + tab dispatch) with each section
  extracted into its own `frontend/src/components/settings/*Tab.tsx` — **AuditTab, PreferencesTab,
  AccountTab, AppearanceTab, NotificationsTab, BackupTab, SecurityTab**. Each tab owns its state and
  loads on mount, so a section's data is fetched when you open it, not eagerly on every modal open.
  Shared class strings and the `downloadBlob` helper live in `settings/ui.ts`. Pure refactor:
  verified per tab with tsc + eslint + i18n parity, and end-to-end (backup round-trip, features,
  accessibility, mobile) with no behaviour change.

### Fixed

- The **E2E-sessions** CI step is now retry-safe (idempotent setup-or-login), so a timing flake in
  that one test can no longer block a release the way it did for 2.1.1.

## [2.1.1] — 2026-09-11 · agent (47)

Gateway and interface only; agent unchanged at 47. A UX / accessibility pass over the 2.1.0
features, from a follow-up frontend audit.

### Changed — fleet onboarding is where you add hosts

- Creating a **group enrollment token** moved from Settings → Security (three levels deep, never
  linked to "+ host") into the Add-host flow: a **"One host / Many machines"** switch, with the
  reusable install one-liner shown in place. The token **list + revoke** stay in Settings → Security
  as the credential-management surface (with a pointer and an empty state). Onboarding a fleet is now
  found where you'd look for it.

### Fixed

- **Hardcoded strings in the sidebar** were showing in English (or, in one case, Romanian) instead
  of going through the translation layer — including one where the translation key already existed,
  unused. Now routed through `t()`; a real bug where **tag filtering was case-sensitive**
  (`Prod` didn't match a search for `prod`) is fixed too.
- **Fleet-run on 2FA-protected hosts** no longer fires a passkey prompt per host in parallel (or an
  SSO redirect that abandoned the whole run). The required hosts are unlocked **serially before**
  the parallel dispatch; a host whose step-up is cancelled is marked skipped.
- **SSH key generation** is no longer a dead end when adding a new host — a hint explains to save
  the host first, then generate the key (generation needs the host to exist).

### Accessibility

- One-time secret reveals (group token, personal automation token) now **announce** to screen
  readers (`role=status`/`aria-live`), and the personal token gained the **copy button** it was
  missing. The terminal region carries a permanent screen-reader hint (how to enable Accessibility
  mode, `Ctrl+M` to leave) so a blind user isn't dropped into silence. Fleet host-selection chips
  got `aria-pressed`; the group-token rows got text alternatives for the folder arrow and 2FA badge.

### Friendly

- Add-host **tag input suggests tags already in use** (stops `web` / `webserver` fragmentation).
  Saved fleet commands use an inline name field (not a browser prompt), **confirm before
  overwriting**, and say they're saved in this browser. The group-token list shows an empty state.

## [2.1.0] — 2026-09-11 · agent (47)

Gateway and interface only: the agent is unchanged at 47, nothing in the fleet needs updating.
Features from a product review — each extends a mechanism that already existed rather than adding a
new subsystem, and each keeps the "single replica, no always-on background state" design.

### Added — fleet-scale onboarding (group enrollment tokens)

- WebTerm called itself a *fleet* manager but hosts were enrolled one at a time. A **group
  enrollment token** gives you one reusable install one-liner to run on many machines: each run
  auto-creates a host with its **own** agent token, so every machine stays individually revocable —
  the per-host trust model is not eroded; the group token only *authorizes* creation. Security-first
  and opt-in: creating one re-auths **and** passes the second factor (it's a provisioning-class
  credential); expiry is mandatory; a max-uses cap is enforced **atomically** (TOCTOU-safe — two
  concurrent installs can't both slip past `max_uses=1`); it's revocable; every auto-enrollment is
  **audited and alerted**. New hosts inherit the group's folder + require-2FA and get a placeholder
  name that the agent's hostname replaces on first connect. Manage under Settings → Security.

### Added — security-event alerts (login/credential events → webhook + email)

- The alert path (`_fire` → email **and** webhook) already fired on new-device logins, credential
  changes, agent relocation, host-offline and more. Three rare-but-critical events were missing and
  now alert too: a **new account** created (a new equal admin), a **new automation token**, and a
  **2FA-protected host unlocked** via step-up. Per-command fleet-run was deliberately *not* added —
  it would be noise and is already in the audit log.

### Added — host tags + tag filtering

- Folders are a single hierarchy; **tags** scale a fleet ("all prod", "all debian"). Set tags when
  adding/editing a host; the sidebar search matches them and each host shows clickable tag chips
  that filter the list by that tag.

### Added — SSH key helpers for direct-SSH hosts

- For a direct-SSH host you can now **generate an Ed25519 key pair** from the UI (the private key is
  stored encrypted in the vault, the public key is shown once to drop into `authorized_keys`) and
  **show the public key** again later (re-derived from the stored key). No more `ssh-keygen` +
  copying files by hand.

### Added — saved fleet commands

- Fleet-run can **save a command under a name** and reload it in one click. Stored per-browser
  (localStorage), deliberately not in the gateway: an in-gateway scheduler would break the
  no-always-on-state design, so this stays a manual, re-runnable convenience over the existing
  guardrail-checked `/run` path.

### Added — installable PWA

- The manifest and icons existed; a small, deploy-safe **service worker** now makes WebTerm
  installable (add to home screen / desktop). It is network-first for navigations and hash-named
  assets (a deploy never serves a stale page) and **bypasses every live path** (`/api`, WebSockets,
  `/agent`, forwards, `/install`) so terminals always hit the network.

### Tests

- New Playwright e2e for the group-token and tag UIs, wired into CI; hermetic backend suites for
  group enrollment, the new security-event alerts, SSH key-gen, and host-tag normalization.

## [2.0.20] — 2026-09-11 · agent (47)

Gateway and interface only: the agent is unchanged at 47, nothing in the fleet needs updating.
Findings from a full audit pass (security, responsive/design, dead code).

### Security — two defense-in-depth gaps closed

- **Creating a second account and disabling TOTP now pass the same second factor as enrolling a
  passkey.** Both were gated by the account password alone; the rest of the credential-changing
  surface (password/email change, passkey enrol/remove) already requires — on a device the session
  has never been seen on, with SMTP configured — a code mailed to the account, or a TOTP/recovery
  code when 2FA is on. So an attacker with a stolen cookie + the known password, from a new device,
  could mint a second admin that survives the victim's "rotate the password" recovery, or strip
  TOTP with the password only. `create_user` and `totp_disable` now go through that same gate
  (`second_gate`).
- **Login timing no longer leaks whether an email exists via an oversized password.** The
  constant-time equaliser (a dummy verify) ran only when the account was missing; a password over
  the length cap short-circuited before the hash for an *existing* account (fast) while a
  non-existent one still hashed (slow). The dummy verify now runs whenever the real one is skipped.

### Added — off-host backup copy over rsync or FTPS (no rclone needed)

- The backup scripts can now push the (already-encrypted) archive off the host over **native
  rsync-over-SSH** (`WEBTERM_BACKUP_RSYNC=user@host:/path/`, key auth, `+_RSYNC_KEEP_DAYS`) or
  **FTPS** (`WEBTERM_BACKUP_FTPS=ftp://host/path/` with `curl --ssl-reqd`, which refuses a server
  that won't do TLS so the FTP password never crosses the wire in clear). Both sit alongside the
  existing rclone remote (S3/B2/Drive/…) — pick any or all. A backup that only lives on the machine
  you are backing up doesn't survive losing that machine; these give an off-host copy with tools
  everyone already has, no `rclone config`. Same guards as before: the copy is **refused unless the
  archive is encrypted**. Applies to both the WebTerm backup (`scripts/backup.sh`) and the Authentik
  backup (`deploy/authentik/backup.sh`).

### Added — configure an SFTP/FTPS backup destination from the UI (no env, no OAuth)

- **Settings → Backup** now offers **SFTP** and **FTPS** next to Google Drive and Dropbox: point the
  (already-encrypted) backup at your own server straight from the browser, no env var and no OAuth
  app to register. The gateway runs in a hardened container with no `rsync`/`ssh`/`curl` binary, so
  this is done in-process — `asyncssh` for SFTP (same SSH transport and security as rsync-over-SSH)
  and `ftplib.FTP_TLS` for FTPS. **Security first:** the SSH host key is **pinned on first use** — a
  probe shows you the `SHA256:` fingerprint to confirm and saving is blocked until you do, so a key
  that later changes is refused (anti-MITM); FTPS always verifies the server certificate (system CAs
  or an optional pinned CA/cert PEM for self-signed) and encrypts both channels. Credentials (SSH
  key / password) are encrypted at rest in the vault and never returned to the UI; both endpoints
  re-auth on the account password and are audited, and removing a destination wipes its credentials.

### Changed — touch targets on modal close buttons

- The ✕ close buttons in the About, Changelog and Keyboard-shortcuts dialogs now meet the 44px
  touch-target minimum on touch devices (they carry `wt-touch`, like the rest of the mobile
  controls). Desktop is unchanged (the rule is `@media (pointer: coarse)`).

### Removed — dead code

- Unused functions (`cloudbackup.forget_all`, `cliphistory.clear`), a dead CSS rule (`.wt-caret` +
  its `@keyframes`), ten unused i18n keys (from both catalogs), and a few unused imports/locals in
  tests. No behaviour change. (The agent is deliberately left byte-identical — a dead-code cleanup
  isn't worth a fleet-wide agent update, so it stays at 47.)

### Hardened — follow-up from a full audit (security / reliability / coverage)

- **The audit log can no longer be poisoned or rotated through `/api/login`.** The attempted email
  was marked as the audit *actor* before the lockout check, so an unauthenticated client could
  (a) inject arbitrary attribution and (b) flood the log — every request, including the `429`
  lockout responses, wrote a row — until genuine incident entries rotated out of the retained
  window. The email is now recorded only *after* passing the lockout gate (so a `429` carries no
  actor), and actor-less `429`s are dropped as scan noise like `401/403/404/405`. A real failed
  login still records the attempted email. Regression test added.
- **Container memory and PID limits** (`mem_limit: 1g`, `pids_limit: 512`) on the gateway in both
  compose files. Without them a leak or runaway output grew RSS unbounded and the kernel OOM-killer
  fired against the *host* — which also runs the reverse proxy (and optionally Authentik), so one
  leak could take the whole front door down. CPU is left uncapped on purpose (the gateway
  multiplexes every terminal; a hard cap would add interactive latency).
- **A failing off-host backup now alerts** instead of failing silently. The scheduled upload only
  recorded a field for the UI; an expired OAuth token or wrong passphrase meant you believed you
  had off-host copies you didn't. After two consecutive failures it emails/webhooks (throttled
  12h), and `/api/backup/cloud` now reports the age of the last successful off-host copy.
- **Log rotation on the default (Caddy) compose stack** — the prod stack already capped
  `json-file` logs (10m×5); the default path didn't, so a long-lived install could fill the disk
  with container logs and corrupt the SQLite WAL. Same cap now on both.
- **`restore.sh` pins its tool image by digest**, like `backup.sh`. Restore runs that image as
  root over the data volume, wiping and rewriting the DB and the vault key — the most destructive
  operation — so a floating tag was exactly the wrong place to trust whatever someone pushed.
- **Three hardcoded UI strings** (`aria-label`/`title` on the toast dismiss, the Add-host port
  field, the Agent section) now go through `t()` — they were English for Romanian users and screen
  readers. The i18n catalog test now also fails on literal `aria-label=`/`title=` so this class of
  miss regresses loudly.
- **Serial console gained tests.** The agent's `_configure_serial` (termios: baud / data bits /
  parity / stop bits / raw) and the raw byte bridge were shipping with zero automated coverage;
  `tests/serial_test.py` exercises them against a PTY.

## [2.0.19] — 2026-09-10 · agent (47)

Gateway and interface only: the agent is unchanged at 47, nothing in the fleet needs updating.

### Added — optional SSO / OpenID Connect (e.g. Authentik)

- WebTerm can now delegate login to an OIDC identity provider. A **"Sign in with &lt;provider&gt;"**
  button appears on the login page **only when SSO is configured** (issuer + client id + secret in
  `.env`); with no config, nothing changes — local email + password, passkeys and TOTP work exactly
  as before. See [docs/SSO.md](docs/SSO.md).

- The flow is authorization-code + **PKCE (S256)**, with single-use `state` **bound to the
  initiating browser** by a `__Host-` cookie (anti login-CSRF / session-fixation), `nonce`, and
  full `id_token` validation (RS256 allowlist — no `alg:none`/confusion, `iss` checked against the
  configured issuer, `aud`/`exp`/`iat`/`nonce`, JWKS via the provider) using PyJWT. The redirect URI
  is always derived from `WEBTERM_PUBLIC_URL`, never taken from a request (anti open-redirect).

- **Break-glass stays.** The local admin keeps its password (and passkey) and can always log in —
  the password form remains on the login page even when SSO is on, so a down IdP never locks you
  out. On first SSO login a user is provisioned; if its email matches an existing local account,
  the SSO identity is **linked** to that account (audited) — but only when the IdP asserts a
  **verified email**, so an unverified address can't be used to claim an existing account (e.g. the
  admin's); otherwise a new SSO user is created with a locked local password.

- **Access control lives in the IdP.** Each WebTerm instance is one OIDC *application*; bind it to
  a group (the reference stack ships `wt-access`) so only that group can reach the instance. An
  optional `WEBTERM_OIDC_ALLOWED_GROUPS` makes WebTerm re-check the group claim on top of the IdP.
  There is still no in-app RBAC — everyone who gets in is a full admin of that instance; separate
  trust levels by running separate instances (see [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)).

- **2FA hosts under SSO** step up by re-authenticating at the IdP (`prompt=login`); the local
  break-glass admin still steps up with WebTerm's own passkey/password.

- Every login (local and SSO) and each host-session attach is written to the audit log
  (actor = email, IP, time), so per instance you can see who logged in and which hosts they
  reached; the IdP's own event log is the cross-instance "who reached which instance" view.

- **Bundle Authentik with one flag.** `install.sh --with-authentik` (or `deploy.sh --with-authentik`)
  runs Authentik in the same stack behind the same Traefik — via a compose **profile**, so
  standalone stays the default and nothing Authentik-related exists until you ask for it. It
  **generates the Authentik secrets unique to that install** (never shared defaults), waits for
  Authentik, and auto-creates the OIDC application, writing the `WEBTERM_OIDC_*` lines back. Also
  shipped: a separate `deploy/authentik/docker-compose.prod.yml` for the "one central Authentik, N
  WebTerms" topology, and `provision.py`/`provision.sh` that work against **any** existing Authentik.
  Authentik is pinned to a current stable line (`2026.8.x`); the provisioner and blueprint tolerate
  its cross-version model changes (flow slugs, `grant_types`, redirect-URI shape).

### Changed — login page: passkeys and SSO on one row

- The passkey and SSO buttons now sit **side by side on a single row**, each with an icon
  (a key, a shield). When only one method is available it takes the full width and shows its full
  label. The password form is unchanged and still on top.

### Fixed — a stale browser tab no longer breaks after a deploy

- WebTerm keeps your sessions alive across deploys (they live in tmux), so people leave tabs open.
  A deploy changes the hashed names of lazy-loaded chunks, so an old tab that then opened, say, the
  file editor hit *"Failed to fetch dynamically imported module"*. The app now catches Vite's
  `preloadError` and reloads once (throttled) to pick up the fresh assets.

## [2.0.18] — 2026-09-08 · agent (47)

Gateway and interface only: the agent is unchanged at 47, nothing in the fleet needs updating.

### Added — copy feedback and a per-terminal clipboard history with a paste picker

- Every copy now shows a brief "Copied" toast — a single subtle pill, bottom-centre, that
  fades on its own and never stacks. It fires on all copy paths, including a tmux mouse
  selection (OSC 52), which previously gave no feedback at all.

- Each terminal keeps its own clipboard history: everything you copied *in that terminal*,
  newest first, deduplicated, capped. Open the paste picker with Cmd/Ctrl+Shift+V (or the
  toolbar button / right-click) to browse it — ↑↓ to move, Enter to paste, click to paste.
  Entry #1 is your last copy and is preselected, so Cmd+Shift+V then Enter re-pastes the
  last thing. Plain Cmd/Ctrl+V is untouched — it still pastes the real system clipboard, so
  pasting something copied from another app keeps working.

- Pasting from the picker uses bracketed paste (multi-line stays inert — no accidental
  execution). "Paste & run" (the ⏎ button, or Shift+Enter) pastes *and* presses Enter — an
  explicit, clearly-labelled action, opt-in only, because auto-running pasted content is
  exactly what bracketed paste exists to prevent.

- The history is in-memory only, never written to disk or localStorage: the clipboard
  routinely holds passwords and tokens, so a persisted history would be a recoverable
  secret store. It clears on reload — the right trade-off for an infrastructure tool.
  Verified end-to-end in a real browser.

## [2.0.17] — 2026-09-07 · agent (47)

Gateway and interface only: the agent is unchanged at 47, nothing in the fleet needs updating.

### Fixed — switching tabs could revert the clipboard to an old selection

- Copy something, switch to another session tab, and paste — and you'd sometimes get an
  earlier value instead of what you just copied. On tab switch the gateway replays the
  session transcript, and a terminal that had emitted an OSC 52 clipboard write (a tmux
  mouse selection, `set-clipboard on`) has that sequence in its history. The replay
  re-ran it, and because switching tabs is itself fresh input, the 10-second anti-hijack
  window was open exactly then — so the stale selection overwrote the clipboard. The OSC 52
  handler now ignores sequences that arrive during history replay (the same guard the OSC
  133 command tracker already uses), so only a live selection writes the clipboard. The
  anti-hijack window for live output is unchanged. Both directions verified end-to-end in a
  real browser (without the guard the clipboard reverts; with it, it keeps the new value).

## [2.0.16] — 2026-09-03 · agent (47)

### Fixed — a very old tmux rejected the agent's config (`bad key: None`), agent 47

- On an older host the tmux config printed `tmux.conf:2: bad key: None` and other errors:
  `set -g prefix None`, `mouse on`, `set-clipboard`, and `focus-events` were all introduced
  in tmux 2.1 (2015), and an older tmux rejects them. tmux carries on past the errors so the
  session still worked, but with noise and with Ctrl-B still grabbed as the prefix. The agent
  now detects the tmux version (`tmux -V`) and emits those options only on 2.1+, keeping the
  universally-valid ones (`default-shell`, `history-limit`, …) everywhere — so the essential
  behaviour, including the correct login shell, still applies on old tmux, with no errors.
  Guarded by a test that checks version parsing and the config on both old and modern tmux.

## [2.0.15] — 2026-09-03 · agent (46)

The agent moved to 46 — reinstall or let it auto-update; older hosts crash-looping on the f_fsid error need a reinstall.

### Fixed — the agent crashed on connect on older Python (no `f_fsid`), agent 46

- On an older server the agent died the moment it connected, with
  `AttributeError: 'os.statvfs_result' object has no attribute 'f_fsid'`, and never
  started at all. The disk-metrics sampler deduplicated the two filesystems it reports
  (`/` and `~/.webterm`) by `st.f_fsid` — a field older Python builds don't expose on the
  statvfs result (and one that is 0 on many Linux filesystems anyway, so it wouldn't have
  deduplicated correctly). It now keys on `os.stat().st_dev`, which every Python and
  platform provides and which uniquely identifies a filesystem. Reproduced by sampling
  through a statvfs result stripped of `f_fsid`, and guarded by a test. Reinstall the agent
  on any host where it was crash-looping on this.

## [2.0.14] — 2026-09-02 · agent (45)

Gateway and interface only: the agent is unchanged at 45, nothing in the fleet needs updating.

### Added — drag tabs to reorder them, and the order stays put

- Tabs can now be dragged left/right into the order you want, and it persists across
  reloads. Dragging also switches the strip to manual ordering, so the activity sort
  (which reshuffles tabs by last use) stops moving them out from under you — the thing
  that made a tab hard to find once you'd learned its position. The activity toggle is
  still there when you want it; a drag just means "I'll place these myself." Verified
  end-to-end in a real browser. (Reordering is drag-based, so it's a desktop gesture;
  touch devices keep the manual/activity toggle.)

### Changed — a pinned host's IP change no longer emails, on dual-WAN

- A two-WAN server's agent flaps between the two public IPs, and the gateway used to send
  a "reconnected from a new IP" email each time (throttled to one an hour, but still noise
  for a machine that never moved). On a pinned host the anti-clone fence already proved it
  is the same machine, so an IP change there is just a network path — dual-WAN or DHCP, not
  a relocation. The email is now suppressed for pinned hosts; the change is still recorded
  in the agent event log for audit. Unpinned hosts still get the alert. Consistent with the
  conflict-alert suppression from 2.0.13.

## [2.0.13] — 2026-09-02 · agent (45)

Gateway only: the agent is unchanged at 45, nothing in the fleet needs updating.

### Fixed — a dual-WAN host's reconnect froze its open terminals

- On a server with two WANs, the agent re-connects over the second WAN before the first
  connection is detected as dead, so the gateway *supersedes* the old connection with the
  new one. The old connection's teardown then runs a tick later — after the registry
  already points at the new connection — so its `was_current` check is false and it skips
  detaching the hubs. They stay marked attached, the new connection's re-attach is a no-op,
  and the live sessions are never handed to the new transport: the agent shows connected
  but every open terminal is frozen, while new sessions work. `register_agent` now detaches
  the host's hubs on any supersede, so the reconnecting agent re-attaches them cleanly.
  Restarting the gateway (this upgrade) also recovers already-frozen sessions — no need to
  close anything.

- And the "repeated agent replacements — two machines share this token" alert no longer
  fires for a pinned host: the anti-clone fence already refuses a different machine, so a
  supersede on a pinned host is the same machine reconnecting (dual-WAN or a fast reconnect),
  not a shared token. The alert stays for unpinned hosts, where two machines really can
  alternate. Dual-WAN redundancy is now a supported, quiet setup.

## [2.0.12] — 2026-08-29 · agent (45)

Gateway and interface only: the agent is unchanged at 45, nothing in the fleet needs updating.

### Fixed — the Links menu now catches URLs that apps wrap themselves (Claude Code login)

- The Links menu rejoined a URL only when the *terminal* soft-wrapped it (xterm's isWrapped
  flag). But a TUI like Claude Code's login does its own wrapping — it emits the URL as
  separate, box-indented lines that xterm never marks as wrapped — so the menu showed only
  the first fragment (`…mcp_serv`) instead of the whole link. It now also joins a row to the
  next when the row is full to the edge (an app-side wrap), stripping the continuation's
  leading indentation so a boxed URL reassembles cleanly. Guarded so a short line ending in
  a URL isn't glued to the next line. Both the terminal-wrap and the app-wrap cases are
  verified end-to-end in a real browser and covered by unit tests.

## [2.0.11] — 2026-08-28 · agent (45)

Gateway and interface only: the agent is unchanged at 45, so nothing in the fleet needs
updating. A read-it-in-app changelog, a Links menu for URLs the terminal wraps, and the
rename-breaks-the-terminal fix.

### Fixed — renaming a host broke the terminal you already had open

- Renaming a host (or any edit) bounced the agent offline for a few seconds, and the
  terminal you already had open came back with a truncated last line, no cursor, and no
  way to type — while new sessions worked. Two faults compounded. First, the edit form
  always sends `connection_type` even for a pure rename, and the server treated any
  connection field *present* as a connection *change* — so every rename re-pointed the
  host, needlessly disconnecting the agent (and demanding step-up on 2FA hosts). The
  server now compares against the current values and only re-points when something
  actually changes, so a rename no longer touches the connection at all. Second, when a
  real connection change does drop the agent, the edit path pops the source before
  disconnecting it, so the agent's teardown skipped detaching the hubs — they stayed
  marked attached, the reconnect's re-attach was a no-op, and the new agent connection
  was never told to attach those sessions, so keystrokes went nowhere. The edit path now
  detaches the host's hubs explicitly. Both reproduced end-to-end in a real browser (the
  symptom needs the tmux backend, where sessions survive the bounce) and guarded by tests.

### Added — a Links menu that catches URLs the terminal breaks across lines

- Long URLs — an OAuth login link, for instance — wrap across terminal rows, and the
  inline click-to-open only works on a single unbroken line and only when the app isn't
  capturing the mouse (Claude Code's login has mouse tracking on, so clicks go to it, not
  the link). The result was copy-paste, made worse on mobile where a wrapped link is hard
  to tap. A new Links button (in the toolbar on desktop, the ⋯ menu and right-click on
  smaller screens) scans the terminal buffer, rejoins URLs across wrapped rows, and lists
  them — one tap to open in a new tab (noopener) or copy. It lives outside the terminal, so
  it works regardless of mouse mode or wrapping. Only http/https are ever offered, never
  javascript: or other schemes; the extractor is unit-tested and the wrapped-URL case is
  covered end-to-end in a real browser.

### Added — read the changelog inside WebTerm

- About → "What's new" now opens this changelog rendered in the app, so you can see what
  changed without leaving for GitHub. The gateway serves it from the copy baked into the
  image (so it works on an air-gapped deployment too), authenticated like any product view,
  and the current running version's section is highlighted. The Markdown is rendered as
  text nodes, not HTML — no injection surface even though the file is trusted. The changelog
  is parsed by a small purpose-built reader (no Markdown dependency), unit-tested.

## [2.0.10] — 2026-08-28 · agent (45)

A deep review of the resync/uninstall changes shipped in 2.0.9 — the reviewer's sharpest
findings were in that release's own fixes, which is exactly what the review was for — plus an
adversarial security audit of everything since 2.0.5. The agent moved to 45 for the token-leak
and hardening fixes; hosts on 44 keep working until they update.

### Security — a locked client could pull scrollback through the pong-timeout path (agent unaffected)

- The 2FA idle-lock and the ownerless share-viewer lock both withhold scrollback, and the
  sender's resync path checks for it — but `_flow_control` calls `_resync` directly on
  pong-timeout recovery, bypassing that check. A locked share guest could time its own pong
  (hold it past the 20s timeout, answer before the 40s hard cutoff) to land in that path and
  receive up to 256KiB of transcript the lock exists to withhold. `_resync` now refuses on a
  locked client itself — the only correct place, since it has more than one caller.

### Security — `ptyd.py uninstall` leaked the host token to a MITM (agent 45)

- Every agent connection pins the gateway certificate (TOFU) before sending the bearer
  token, so even in insecure mode the token is MITM-protected — except the uninstall
  notification, which used an unverified TLS context with no pin check at all. An on-path
  attacker during an uninstall could capture the host's persistent credential (still valid,
  since uninstall keeps the host on the gateway) and impersonate the agent. The notify now
  pins the certificate on the same socket it sends the token over, and refuses to send if
  insecure mode has no pin configured.

### Security — hardening from the audit

- A backgrounded popout doing a `storage`-driven font sync claimed the shared PTY size from
  the focused device; it now sends a passive resize unless the window actually has focus.
  Session ids are restricted to hex at the agent's `create` op (they become tmux session
  names, and tmux target syntax should never appear there), and the passwd shell is escaped
  when written into the tmux conf. The audit also confirmed clean: the `redraw` op has no
  command injection, and `modeRestoreSeq` emits only hardcoded whitelisted DECSET sequences.

### Security — the offline alert can no longer be silenced by the agent's own report

- Posting `/agent/uninstalled` then killing the agent produced a state indistinguishable
  from a real uninstall, so the "host offline" email was suppressed — an attacker with a
  host shell could buy silence during a teardown. The alert now ALWAYS fires when a host
  goes silent; only its wording adapts. A reported uninstall gets a calmer message (the
  usual `tmux ls` / `ptyd.log` steps are useless — those files are gone — so it points at
  the right action instead) that also says, plainly, that if you didn't run the uninstall
  the agent was stopped by someone with shell access and the machine needs investigating.
  No suppression, no schema change, and a legitimate uninstall still avoids the scary
  wrong-steps incident. The credibility heuristic now gates only the cosmetic UI badge.

### Fixed — resync intent is client state, and every path that deserves "full" gets it

- The lossy/full split stored the intent as queue sentinels — droppable data: a
  slow-client overflow could swallow an unlock's pending "full" and downgrade it, and
  pause's drain could lose it entirely (output missed while locked never arrived until
  unrelated output pushed it). Intent now lives on the client as a level (none < lossy <
  full) that drains cannot touch, combined by max, with a single wake sentinel. The
  pong-timeout recovery was also wrongly demoted to lossy — that client already proved
  its size, so a 20s wifi blip during heavy TUI output re-broke the prompter frame; it
  is full again. And `.cast` is flushed (best-effort) at resume again, so the recording
  no longer lags what the operator just watched.

### Fixed — transcript rewrites are detected by generation, not by size

- The 64MiB cap's head-truncate was detected by "file got shorter", but a cast-triggered
  cap with a small `.out` rewrites it LONGER (gap marker + full content), and a file can
  regrow past the old cutoff (ABA) — both slipped through and could duplicate or drop
  the last pre-cutoff bytes mid-stream. The hub now bumps a generation counter on every
  rewrite; a resync whose captured generation changed falls back to the historical
  dedup. The test that was supposed to catch this was itself vacuous (its fixture never
  reached the stale branch) — rewritten so that deleting the detection fails it.

### Fixed — uninstall markers are judged by what heartbeats did afterwards

- 2.0.9's 300s heartbeat self-clear had it backwards: an attacker who plants the marker
  and then kills the agent keeps it forever (offline alerts silenced for a compromised
  host), while an agent-43 orphan that heartbeats through its own genuine uninstall gets
  its REAL marker erased — recreating the false alert. The marker is now immutable and
  interpreted at read time: credible only if heartbeats stopped right after it was set.
  A planted marker neither silences the offline alert nor shows the "agent removed"
  badge that invites deleting a live host. This also removes the extra per-heartbeat
  UPDATE from the hot path.

### Changed — vendor code ships in its own cacheable chunks

- The main bundle carried React and xterm alongside the app (833KB, over vite's warning
  threshold on every build). `manualChunks` now splits them: the app chunk drops to
  385KB (gzip 237→114KB), and a returning browser re-downloads only WebTerm's own code
  after an upgrade — the vendors, unchanged for months at a time, stay cached.

### Added — the frontend has unit tests

- vitest (config kept out of the image build, no jsdom — the two globals are stubbed by
  hand), wired into `ci-local.sh` and the publish workflow. The first 12 tests pin the
  exact bugs found this cycle: the frozen width-default, A± under blocked localStorage,
  the legacy-key migration, and the DECSET restore sequences. `modeRestoreSeq` moved to
  `lib/termmodes.ts` to be testable.

## [2.0.9] — 2026-08-28 · agent (44)

An adversarial review of everything shipped since 2.0.5, plus one field report. The agent
moved to 44 for the uninstall and login-shell fixes; hosts on 43 keep working, they just
carry those two defects until they update.

### Fixed — switching back to a tab kept the screen but lost the terminal's modes

- Field report after 2.0.8: the prompter frame was healed, but the wheel stopped
  scrolling until a font A±. The resume replay starts with `term.reset()`, which wipes
  the DECSET modes tmux believes are still active — mouse tracking above all (with
  `mouse on`, the wheel *is* tmux copy-mode), but also bracketed paste, focus events and
  application cursor keys. tmux only retransmits modes on attach and on resize (verified
  by capturing the client PTY: `refresh-client` repaints content, not modes) — which is
  precisely why A±, a resize, repaired it. The client now snapshots `term.modes` before
  the reset and re-asserts them before the tail; newer toggles inside the tail still win.

### Fixed — the repaint now also covers page reloads, and only deliberate resyncs

- A fresh attach (F5, or a second same-size device) replayed diffs with no repaint —
  the same missing-frame symptom 2.0.8 fixed for tab switches — because an unchanged
  size never triggers a tmux redraw. The gateway now requests the repaint after fresh
  attaches too. In the other direction, the flush-and-repaint treatment was running on
  *every* resync, including slow-client backlog drops and pong-timeout recovery, where
  the client may be freshly attached at another size (the replay/resize collision
  `read_tail` documents) and where a chronically slow client would loop full-screen
  repaints; those paths are back to the historical lossy behaviour, on a separate marker.

### Fixed — two races that could duplicate output on resume

- The resync cutoff is now taken from the `.out` handle alone (a failure flushing the
  `.cast` file discarded a perfectly valid cutoff), and after the threaded read the
  gateway detects whether the transcript was head-truncated (the 64MiB cap) or the flush
  failed outright — in both cases it falls back to the historical drop-the-queue dedup
  instead of replaying bytes that are also sitting in the queue.

### Fixed — `ptyd.py uninstall` left the daemon running on cron-supervised installs (agent 44)

- `systemctl --user disable --now` is a no-op on the installer's cron fallback, so the
  daemon survived its own uninstall with token and connection in memory: the host stayed
  online, the "agent removed" badge (gated on the host being offline) never appeared, and
  the next reconnect silently erased the uninstall marker — a "live" host with no
  supervision, no tmux and no `~/.webterm`, that even `ptyd.py stop` could no longer find
  (the pid file was deleted). Uninstall now stops the running daemon first, gracefully,
  while the lock file still exists.

### Fixed — a service account's `nologin` no longer becomes tmux's default-shell (agent 44)

- The agent-42 fix took `default-shell` from passwd, the source of truth — but a service
  account's passwd says `/usr/sbin/nologin`, which exists, is executable, and kills every
  new session with "This account is currently not available". Unusable passwd shells now
  fall back to a valid `$SHELL` (how those installs worked before 42), then `/bin/bash`.

### Fixed — decommissioning a host no longer emails a false "host offline" incident

- The offline sweep now skips hosts marked `uninstalled_at`: the silence after a
  deliberate uninstall is not an incident, and the alert it sent suggested diagnostics
  the uninstall had just deleted. Reinstalling clears the marker and re-arms the alert.

### Hardened — `/agent/uninstalled` against planted markers and event spam

- Anyone with shell on a host can read the agent token and POST the endpoint without
  uninstalling anything, leaving a latent "agent removed" badge that surfaces during the
  next offline window and invites deleting a live host. A marker older than 5 minutes on
  a host that is still heartbeating is now cleared automatically (a real uninstall stops
  the daemon within seconds), and repeated POSTs write nothing — no fresh timestamp, no
  new `agent_events`/audit rows.

### Fixed — font preference now reaches popouts, and survives blocked storage

- The `wt-font` event never crosses windows, so a popout kept a stale size and pressing
  A± there rewrote the shared preference backwards from stale state; popouts now follow
  the cross-window `storage` event. And where `localStorage.setItem` throws (Safari
  private mode), A± was a complete no-op and the legacy-key migration could crash the
  session view during render — persistence is now best-effort, the font always moves.

## [2.0.8] — 2026-08-27 · agent (43)

The agent moved to 43, so fleets should update it: the repaint below is an agent-side
operation, and a host still on 42 keeps the old behaviour until its agent updates.

### Fixed — returning to a tab asks tmux to repaint the whole screen (agent 43)

- The 2.0.7 fix closed the data loss on resume, and the symptom survived it: TUI frames
  (the two border lines of Claude Code's prompter) still came back broken. The reason is
  one level deeper — tmux transmits diffs, only the cells that changed. A transcript
  replay reconstructs what was *transmitted*, not what is *on screen*: during a long
  thinking spinner only the spinner's region is retransmitted, so the static border may
  not appear in any replay window at all. After the resume's reset-and-replay, those
  lines are simply absent, and nothing ever redraws them — until a font A± forces a
  resize and tmux repaints everything. That manual repair is now automated: after the
  resume resync the gateway asks the agent for a `tmux refresh-client` — a full-screen
  retransmit with no size change, flowing through the normal pipeline (transcript +
  queues), so it lands after the tail and heals every connected client. Debounced, and
  a fleet still on agent 42 answers with an error that is deliberately ignored — the
  behaviour simply stays as it was until the agent updates.

## [2.0.7] — 2026-08-26 · agent (42)

Gateway only: the agent is unchanged, nothing in the fleet needs updating.

### Fixed — returning to a background tab no longer loses the last seconds of output

- Background tabs pause their stream; on return, the gateway replays the transcript tail —
  but only the bytes already flushed to disk, and the transcript lags by up to 2s/64KiB
  (the checkpoint window). The loss was known and measured (0.6–1.8s per attach). For a
  shell the screen converges on the next output, so nobody noticed; a TUI never redraws
  its static frame, so the border of Claude Code's prompter came back with missing lines
  and stayed that way until a forced redraw (font A±, or a page reload).

  On resume/unlock the gateway now flushes the transcript before reading the tail. The
  historical reason for not doing so — replaying the unflushed window collides with the
  resize redraw when a different-sized device attaches — does not apply here: a resuming
  client already has the session's size, and fresh attaches keep the old behaviour. The
  drain→flush→tell sequence is atomic on the event loop and the tail read is bounded to
  the flush offset, so a checkpoint racing the read can neither drop nor duplicate a
  chunk: everything below the cutoff comes from the tail, everything above from the queue.

## [2.0.6] — 2026-08-25 · agent (42)

The agent moved to 42, so fleets should update it: the reboot/`sh` fix below only reaches an
installed host through the agent update (no re-install and no tmux server restart needed).

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
