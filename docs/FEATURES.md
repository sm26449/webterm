# Features in depth

The [main README](../README.md#features) has the one-line overview; this is the long
version, with the reasoning behind the design. Per-area guides are linked inline.

## Why

Put a terminal in a browser and the session ends up living in the thing in the
middle. Restart it, deploy over it, lose the network for a minute, and the work
goes with it. That is not a bug in any particular implementation — it is what
happens when the session belongs to the server you happen to be looking through.

WebTerm puts it somewhere else. The session is a `tmux` session **on your own
machine**, on its own socket. The gateway is a window onto it, and windows can be
closed, upgraded and rebuilt without touching what is behind them. Kill the agent
and the session keeps running. Restart the gateway and it is re-adopted by name.
Close the laptop and open a phone.

**Two ways to reach a machine, and the difference is the whole product.**

*With the agent* — a single Python file, stdlib only, that dials **out** over
WebSocket. Nothing listens on your server, so NAT and firewalls are not obstacles
and there is no port to expose. It authenticates with a token bound to that one
machine, and the gateway stores no login for it: there is nothing to steal because
there is nothing to store. Sessions live in tmux and outlive everything above them.

*Direct SSH or telnet* — for a switch, a box you do not own, a machine where you
cannot install anything. Nothing to deploy on the target. The trade is real and
worth knowing: that session lives in the gateway's memory, so a gateway restart
ends it, and any credential you choose to save is kept in the encrypted vault
rather than not kept at all. You can also tell a host to never store one and ask
you each time.

So the agent is not overhead you pay to use this. It is the part that makes a
session something you come back to instead of something you start again.

Around that: everything is bounded (2 MiB of scrollback per session, 32 sessions
per host, stop-and-wait flow control every 256 KiB, rotated logs, capped
transcripts), the agent restarts itself after a kill or a reboot, and idle cost is
close to nothing. It is built to sit on the public internet — what that means, and
what it does not cover, is in [Security](SECURITY-FEATURES.md) and
[docs/THREAT-MODEL.md](THREAT-MODEL.md).

## By area

### Sessions

- Sessions as conversations: title, note, full history of everything the host
  printed, search (what you type is never recorded — see Security)
- Multiple devices at once on the same session (desktop + phone, live)
- **Instant tabs**: recent sessions stay mounted (terminal + buffer), and
  switching is just a visibility change. The stream flows **only** on visible
  panes; background tabs are paused at the gateway and re-sync on return if they
  missed anything
- Named **split views** (2–4 sessions, saved server-side — see Fleet), popout into
  its own window, layout restored on reload
- **History replay**: closed sessions can be replayed in the UI (play/pause,
  seek, 1×/2×/4×), not just downloaded (`.cast`)
- **History as text**: a **Text** tab next to the player renders the transcript with
  control sequences stripped — searchable, and downloadable as `.txt`. Replay is faithful
  but useless when a full-screen app ran inside (it repaints the same screen instead of
  scrolling); text is how that history becomes readable

### Session sharing

- **Share link** for a session: **read-only** or **writable** (the guest can
  type), with **expiry** and **instant revocation**. The guest window mirrors the
  owner's PTY grid (size + its own zoom); on revoke, the broadcast stops and the
  terminal is wiped with a dedicated "403" page
- **Roster** of viewers (how many / who) and **kick** from the session; optional
  watermark over the share

### Commands as objects (OSC 133)

[Details](SHELL-INTEGRATION.md).

- With shell integration enabled, every command has identity — exit code,
  duration, its own output. A side panel lists all commands, `Alt+↑/↓` jumps
  between them, green/red gutter decorations
- **Per-command actions**: "Run again" (drops it at the prompt — you run it with
  Enter, nothing re-runs blindly), copy the command / the output / as markdown
  (command + output + exit code, ready to paste into a ticket)
- We re-render nothing → **TUIs stay intact** (vim, htop, Claude Code)

### Keyboard-first

Press `?` for the cheatsheet.

- Command palette (⌘K): sessions, hosts, actions, snippets
- Shortcuts for scrollback search, close/reopen/navigate tabs, split, popout,
  font, snippets — [full map](SHORTCUTS.md)
- **Parametrized snippets** (`{{param}}`): a form at run time, with a preview of
  the final command before execution. Snippets live on the gateway (every device) and
  double as the saved commands of **Run on hosts**, optionally with **target tags** that
  preselect the matching hosts — see [docs/FLEET.md](FLEET.md#saved-commands)

### Fleet

- Per-host metrics (CPU, RAM, disk, load) with a **trend sparkline**, plus a subtle
  **dual-arc load ring** in the session toolbar (CPU + memory of the active host at
  a glance, exact numbers in its tooltip)
- **Threshold alerts** (CPU/RAM/disk) over email and/or webhook, with hysteresis and throttling
- **In-session file manager** (toolbar button): a side panel that **follows the
  terminal's `cd`** (OSC 7), dense listing with sort/filter/keyboard navigation,
  mkdir/rename/delete, **create a file in place** (empty, or filled straight **from
  your clipboard** — paste a config without making a local file first), double-click
  a file name to copy it, triple-click to copy its full path,
  drag&drop upload (including **folders**) with a real progress
  bar + cancel — **resumable**: a dropped connection (or a closed laptop) keeps the
  bytes already uploaded, re-dropping the same file continues where it left off, and
  a **CRC-32 integrity check** guards the commit; every upload also shows up in the
  **Transfers widget** (see below); **download a folder (or file) as a
  `.tgz` archive** (tarred on the host, streamed down as a Transfers job with Cancel);
  **multi-select** (checkboxes, Shift/Ctrl+click, long-press on phones) with bulk
  download / delete and **copy to another host** — agent → gateway → agent, the data never
  passes through your browser ([details](TRANSFERS.md#copy-to-another-host)); a **Monaco** (VS Code) editor with
  syntax highlighting for what you edit on a server (shell, YAML, JSON, INI/systemd/.env, TOML,
  Dockerfile, nginx, Python, JS/TS, SQL, XML/HTML, CSS, Markdown, Go, Rust, PHP, Ruby, Lua, Perl,
  PowerShell, C/C++, Java, HCL), find/replace, folding, multi-cursor, `Alt+Z` word wrap, large
  files opened view-only (partial-read), atomic save with conflict detection. It is a slim build:
  highlighting only, no language-service autocompletion
- **Transfers** — [details](TRANSFERS.md): progress lives in **one floating widget in the
  bottom-right corner** — a compact pill (`file 63%`, `N transfers · 63%`) that expands into a
  card with every job and its actions, and opens by itself when a job needs a decision (stalled,
  failed, incomplete). **Drop files on the terminal** to upload them into the session's current
  directory (OSC 7) and get the path typed at the prompt; **paste a screenshot or a file** into
  the terminal and it lands in the host's inbox (`~/.webterm/inbox/<timestamp>.png`) with its
  path typed for you — AI CLIs (Claude Code, aider, …) cannot read your browser clipboard, so
  WebTerm materialises the file on the host and hands them the path. Inbox retention is a
  setting (7 days by default). Born from a real incident (a 17 GB drop that
  silently stopped at chunk 1579 while gateway and agent were healthy): a byte-level
  **watchdog** marks the row **Stalled** after 20 s without progress, aborts and re-sends the
  chunk after 60 s, retries each chunk up to 8 times with capped backoff, and resumes by itself
  when the browser comes back online or the tab becomes visible again. When retries run out the
  row turns red with the reason and a **Retry** button (the file stays in memory, so it
  continues from the offset the host confirms — including after a passkey step-up or a new
  sign-in). After a page reload, unfinished uploads are listed as **Incomplete**: drag the same
  file into the same folder to resume, **Open folder** jumps there, **Discard** deletes the
  temporary part on the host. Closing the tab while something is uploading asks for
  confirmation.
- **Git panel** (toolbar button): for the repo in the session's current directory
  (follows `cd` via OSC 7) — status, **colored diff**, stage/unstage and
  **commit**, without opening GitHub. Focused scope: merge/rebase/push/branch stay
  in the CLI
- **Docker panel** (toolbar button, agent hosts): tabs for **containers / images /
  volumes / networks**, **start/stop/restart** a container, view **logs**, and open a
  **shell inside a container** in its own terminal tab (`docker exec`, bash with an
  sh fallback for minimal images). Runs the host's `docker` CLI through the agent — no
  extra daemon exposure; the same 2FA step-up as any host action
- **Database connections** (Toolbox → *Connections*, toolbar + host page, agent hosts):
  saved launchers for **PostgreSQL / MySQL·MariaDB / MongoDB / ClickHouse / Redis**. One
  click opens a session with the right client (`psql` / `mysql` / `mongosh` /
  `clickhouse-client` / `redis-cli`) already pointed at host, port, user and database — no
  connection strings to remember. Two credential policies: **Ask** (the client prompts;
  WebTerm stores nothing) or **Stored** — the password is kept in the same encrypted vault
  as SSH credentials and the agent types it **once** into the client's password prompt on
  the PTY; it never appears in argv, `ps`, the environment, a file, or the transcript. On a
  2FA host, both **launching** and **creating/editing** a connection cost a step-up factor —
  a saved connection is a credentialed hole into the host. [details](DATABASE-TOOLBOX.md)
- **Command library & history** (Toolbox → *Library* / *History*): a built-in **library** of
  command recipes (git, docker, systemd, system, db) with `{placeholder}`s — click to copy,
  paste into any terminal, and it works from the host page with no session open; plus the
  host's own **command history** (from OSC 133), searchable, click to copy
- **systemd services** (toolbar button, agent hosts): list units with live state, filter,
  and **start / stop / restart** — through the agent, step-up-gated on 2FA hosts. Runs as
  the agent's user, so system units need the right privileges (surfaced, not silently swallowed)
- **Port forwarding** (toolbar button): expose web services from the host through
  the browser, protected by your own auth — Docker containers, monitoring, admin
  panels bound to localhost. Reverse-proxy **HTTP + HTTPS + WebSocket** (no
  `ssh -L`, works from an iPad too); on **agent** hosts through the WSS tunnel, on
  **SSH** hosts through a direct-tcpip channel. Each forward on an isolated
  subdomain (`<slug>.<domain>`, domain configurable in Settings), `__Host-`
  cookie, slug-bound HMAC token, anti-SSRF. The connection opens only on real
  traffic. [details](PORT-FORWARDING.md)
- **Telnet bastion** (`telnet` scheme on a forward): the CLI of a device on the
  host's LAN (switch/router) inside a **terminal tab**, tunneled through the agent
  — the host becomes a jump host. Custom IAC shim; password redacted from the
  transcript, OSC 133/52 filtered from the untrusted device; **↻ 1-click
  reconnect** if the agent drops. [details](design/TELNET-BASTION.md)
- **Serial console** (RS232/RS485/USB): a serial device attached to the host,
  inside a **terminal tab** through the agent — with port **discovery** (rich
  metadata: VID:PID, USB serial, driver, physical path, UART type) and **physical
  identification** (unplug/replug the adapter). [details](SERIAL-CONSOLE.md)
- **Run on hosts**: one command → N hosts → a grid of
  live results (state, exit code, output per host), with a deliberate confirmation
  first. **Save a command** under a name and re-run it later: saved commands are server-side
  snippets (since 3.5.4), the same on every device and the same list as the terminal's snippets,
  optionally with **target tags** that preselect the matching hosts.
  "Copy report" as markdown. [details](FLEET.md)
- **Split views — named, saved, several of them**: a "+ Split view" button (or **right-click a
  terminal → Add to split view**) turns 2–4 open sessions into a layout you **name** (2 = a
  resizable split with a draggable divider + grip, 3–4 = a **2×2 grid**, all live at once). Each
  pane is bordered — the focused one gets an accent border so it's clear where your keys go — and
  each split view rides in the tab bar as its own **chip** next to the session tabs: click to
  switch between layouts and single sessions like tabs (clicking a tab leaves the split, its chip
  stays so you return anytime). A session can appear in a tab **and** in split views at once; only
  the view you're on is live (so a session never fights itself for size). Definitions are **saved
  server-side** (they follow you across devices) and the active one is restored on reload. Toggle
  **broadcast** to type into every pane simultaneously (an amber band marks each pane) —
  interactive fleet ops, not just one-shot commands. [details](design/SPLIT-VIEWS.md)
- **Bulk enrollment**: a reusable **group enrollment token** — one install
  one-liner run on many machines, each auto-registering as its own host with its own
  agent token (individually revocable). Opt-in, expiring, revocable, use-capped, and
  every auto-enrollment is audited + alerted. [how-to](FLEET.md#bulk-enrollment)
- **App bookmarks** (Proxmox / Portainer / Grafana / anything web): a wizard turns
  "add my Proxmox" into a named tile — internally a `https` port-forward on its own
  subdomain, behind your auth. They show on an **Apps** strip on the dashboard, as
  buttons on the host, and open by name from ⌘K; any forward can be promoted to one.
  **Ready-made presets** for the common database & observability consoles — Adminer,
  pgAdmin, phpMyAdmin, Mongo Express, Kibana, ClickHouse — so a bookmark gets the right
  label, colour and glyph. Point the app's OIDC at the same Authentik and it's single sign-on
- **Wake-on-LAN**: a **Wake** button on an offline agent host — a neighbouring agent on
  the same LAN sends the magic packet (MAC read from the host's last diagnostics)
- **Host tags**: free-form tags on hosts ("prod", "debian") on top of folders; the
  sidebar search matches them and tag chips filter the list in one click
- **SSH key helpers** (direct-SSH hosts): generate an Ed25519 key pair from the UI
  (private key kept in the vault, public key shown to drop into `authorized_keys`), or
  re-show the public key later — no `ssh-keygen` by hand
- **Global command history**: search across every command run — on all hosts and
  sessions, from the command palette. Also a light audit log
- **Pending OS updates, at a glance**: the agent counts pending packages (apt / dnf / zypper /
  pacman / apk, checked every few hours, read-only) and a host with updates shows a **badge in
  the sidebar** — red when any are security — so you see it **without opening the host**. Click
  it to review the count, then **Upgrade in a terminal**: WebTerm opens a session running the
  right upgrade command for the detected manager. It never installs on its own — it's glue to
  the terminal, not a package-manager UI (`WEBTERM_UPDATES_CHECK_SECS=0` turns it off)
- **Host diagnostics** (host menu, available even offline): a tabbed panel with a full
  **host snapshot** — OS/kernel/uptime, CPU model/cores/load, memory + swap, **every
  filesystem**, and **each network interface** (IPv4/IPv6, MAC, MTU) with the **routing
  table**; a **Ports** tab runs `ss -tulnp` on demand (protocol, port, address and the owning
  process). The agent pushes the snapshot on connect and hourly, and you can **Refresh** on
  demand; the last snapshot is **persisted**, so a host's IPs, routes and disks stay visible
  **when it's down** (labelled "as of …"). Plus live link health (**agent↔gateway RTT**,
  uptime/reconnects), an **event timeline** (connect/disconnect + reason) and the **agent
  log** — debugging without SSH
- Time zone synced across sessions; the server clock in the status bar

### Data & backup

[Details](RUNBOOK.md).

- **Backup/restore from Settings**, no server access needed: download a
  crash-consistent DB snapshot (`VACUUM INTO`) + the vault key, **encrypted with a
  password you choose** (scrypt → AES-256-GCM). Automatic daily/weekly backup
  (kept 7 days, in-UI notification). Validated restore (password + `integrity_check`)
  with a pre-restore snapshot as a safety net

### Appearance & accessibility

- UI themes: Aurora (light), Midnight (dark), Auto (follows the system); **installable PWA**
  (add to home screen on mobile, install on desktop) with a network-first service worker that
  bypasses every live path, so terminals always reach the network and a deploy never serves stale
- **Custom terminal themes**: scheme editor with live preview, **iTerm2/VS Code
  import**, per-host scheme ("production is reddish")
- **Watermark** optional (Settings → Appearance): a tiled overlay (email/host/time)
  over the workspace **and** over shared sessions (applied server-side) — deters
  leaks / gives traceability
- **Resizable sidebar**: drag its edge (or arrow keys on the handle; double-click to
  reset) to trade list detail for terminal width — persisted per browser
- **Offline hosts sink** to the bottom of their sidebar group, showing **how long
  they've been down** plus an editable **note** ("stopped it myself, waiting for
  parts") and a per-host **mute for offline alerts** — right where you look for them
- Guaranteed minimum contrast (WCAG AA) in the terminal, screen-reader mode
  (opt-in), `Ctrl+M` to Tab out of the terminal
- Desktop-grade copy/paste: Ctrl/Cmd+C on a selection copies (no selection = ^C),
  copy-on-select, right-click context menu, focus events (vim `autoread`)
- **The interface speaks English and Romanian**, picked from the browser and
  switchable in Settings. A third language is one file: copy `frontend/src/lang/en.ts`,
  translate the values, register it — the catalogue is checked in CI, so a missing key
  fails the build rather than showing a raw key to a user

### Operating it

- **One-click provisioning**: give WebTerm an existing SSH connection to a host and it
  installs the agent over it — no copying an install command by hand
  (host → *Provision*; the same enrolment token, just delivered for you)
- **Alerts by email *and* webhook** — Slack, Discord, Teams, or any endpoint that
  accepts JSON (`WEBTERM_ALERT_WEBHOOK`, or Settings → Notifications). The webhook is
  independent of SMTP: if chat is where you actually look, you never need a mail server.
  Covers resource thresholds **and** security events: login from a new device, a new
  account or automation token, a credential change, an agent going offline, a
  2FA-protected host unlocked, an auto-enrollment, a failing off-host backup
- **Update notice**: the gateway checks whether a newer release exists and says so in
  the UI — it never updates itself (`WEBTERM_UPDATE_CHECK=0` turns the check off,
  `WEBTERM_UPDATE_COMMAND` sets the command it shows you)
- **Certificate expiry watch**: the installer sets up a `webterm-cert-check` timer that
  warns before the certificate runs out, so a renewal that quietly stopped working is
  noticed while there is still time (`WEBTERM_CERT_MIN_DAYS`, default 15)
- **Clean uninstall**: `./remove.sh` (or `make remove`) takes the gateway back off the
  machine and asks before anything irreversible — it tells you exactly which volumes
  hold your data and refuses to guess on your behalf

## Persistence

**Persistence is tmux.** Without `tmux` on the host the agent falls back to a plain PTY
and says so (Host details → Backend: `pty`), but the fallback is silent in the sense that
matters: sessions still open and still work — they just do not survive an agent restart.
The table below describes the tmux backend.

| Event | Effect |
|---|---|
| Close the tab / browser | nothing — the gateway stays attached and keeps recording |
| Gateway restarts | the agent reconnects, exact reattach from the offset |
| Agent dies (`kill -9`) | tmux keeps the sessions; the new agent re-adopts them |
| Server reboots | sessions are marked "lost"; the conversation & history remain |

History: `<sid>.out` (raw stream, replayed on reconnect) + `<sid>.cast`
(asciicast v2 with timestamps, downloadable). Both hold **output only**: input is
never written to a transcript, so a password typed at an echo-off prompt cannot
leak into a recording or a backup of one. Closed sessions
stay in the sidebar until you delete them.
