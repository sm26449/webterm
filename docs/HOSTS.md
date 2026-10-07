# Hosts — connection types and per-host settings

Everything WebTerm does happens on a **host**: a machine (or a device behind one) you open
terminals on. This page explains the settings a host carries — how it is reached, how it is
labelled, what extra proof it demands before anyone touches it, what happens to its
credentials, and the maintenance helpers (Wake-on-LAN, the OS-updates badge, diagnostics).
Read it when you are adding a host and wondering which type to pick, or when you come back to
a setting months later and no longer remember what it does.

You add a host with **Add host** (sidebar or command palette); you change it later with
**Edit host**, on the host page or in the host's **⋯** menu. Some settings deliberately live outside
the edit form (2FA, forgetting credentials, the install link) because changing them needs a
fresh factor.

## Connection types

The type decides who opens the connection and, with it, which tools you get.

| Type | Who connects | What you get |
|---|---|---|
| **Agent** | A small agent on the host phones **home** to the gateway over WSS; the host needs no open port | Terminals plus every host tool: Files, Port forwards, Services, Docker, Databases (Toolbox), AI tools, Serial console, Diagnostics, Wake-on-LAN, OS-updates badge, fleet runs |
| **SSH** | The gateway dials the host's SSH server | Terminals, and port forwards over the SSH connection ([PORT-FORWARDING.md](PORT-FORWARDING.md#ssh-hosts)). You can install the agent later from the host's **⋯** menu (**Install the agent (SSH)**) |
| **Telnet** | The gateway dials the device directly | Terminals only. Plaintext: use it only on a trusted network or for legacy gear |
| **SSH-jump** | The gateway runs the SSH client **through an agent host's tunnel** to a device on that agent's LAN | Terminals; the host key is pinned. No agent on the target |
| **Telnet-jump** | The same, for telnet through an agent's tunnel | Terminals; interactive login, no stored credentials |

What the code enforces:

- The type is one of `agent`, `ssh`, `ssh-jump`, `telnet`, `telnet-jump`; anything else is
  refused (*"unknown connection type"*). SSH, telnet and both jump types need a hostname; SSH
  and SSH-jump also need a username. The default port is 22 for SSH and 23 for telnet.
- **Jump targets are created from the agent's ⋯ menu** (**Add SSH / Telnet jump…**), not from
  the generic type selector, and appear nested under that agent in the sidebar. The `via` host
  must be an agent; a jump host cannot route through itself, and chains that loop back are
  refused. An agent that still has saved jump targets under it cannot be retyped or removed
  until you re-route or delete them. The jump form also offers **Connect once**: it opens a
  session on a throw-away target that is hidden from the sidebar and deleted when the session
  ends.
- A jump host counts as *online* when its parent agent is connected.
- **Agent-only tools.** On the host page, the Files, Forwards, Services, Docker, Databases and
  AI tabs and the Serial console appear only for an agent host that is online; Diagnostics
  appears for every agent host. On the server side the file, service, Docker, diagnostics and
  wake routes all go through the agent connection and answer *"host offline"* (or a specific
  *agent hosts only* error) otherwise. Port forwarding is the exception: it also works on SSH
  hosts.
- **SSH host keys** are pinned on first connect. If the key later changes, the host carries a
  *host key changed* alarm and every connection is refused without dialling until you review
  the new fingerprint and accept it. Changing the hostname or port of a host resets the pin
  (the response says so), because the old pin belongs to the old machine.
- You can change the type of an existing host at any time (**Edit host**). The edit form says
  why you would: if the agent stops responding, switch the host to SSH to get in and fix it;
  history and sessions stay on the same host. Changing a connection field (type, hostname,
  port, user, credential…) drops the live connection so the new parameters take effect, and on
  a host with **Require 2FA** it needs a step-up first.

## Testing a connection

**Test connection** sits next to **Save** in Add host and Edit host, for SSH, SSH-jump, Telnet
and Telnet-jump. It runs the same dial the gateway uses when you open a terminal, stops right
after the login, and closes everything. It saves nothing, opens no session and starts no
shell. The result is shown per stage, so you see *where* it broke:

| Stage | What it checks | Typical failure |
|---|---|---|
| **TCP** | The gateway (or, for a jump type, the agent) can open the port | Refused (wrong port, service down), unreachable / timed out (firewall, wrong address), name not found |
| **SSH** / **Telnet** | Something answers: the SSH greeting, or for telnet any banner or login prompt within 3 seconds | Not an SSH server on that port; no greeting at all. A silent telnet device is only a *warning*: some wait for the first Enter |
| **host key** | The server's host key; its SHA256 fingerprint is shown | On an existing host whose pinned key differs: the test stops here and the password is **not** sent |
| **authentication** | The user and password or key are accepted | The same message you would get when connecting |

What you need to know:

- The whole test is capped at 10 seconds. You can cancel it.
- After a successful test the save button reads **Save (verified)**. Saving then **pins the host
  key the test saw**, so the host is protected from its first connection instead of trusting
  whatever answers first. The server only accepts the exact key its own test saw for that
  target in the last 10 minutes; a client cannot supply its own. On an existing host that
  already has a different pinned key, a test-then-save cannot replace it: a changed key goes
  through the host-key alarm, where you compare fingerprints and accept explicitly.
- Changing any connection field after a test (hostname, port, user, password, key, via host)
  clears the result; test again before saving as verified.
- In Edit host, leaving the password empty tests with the stored credential. On a host with
  **Require 2FA** that needs a step-up first, exactly like connecting.
- With the **Ask every time** policy there is nothing to log in with, so the test stops after
  the host key and says authentication was not tested.
- For SSH-jump and Telnet-jump the test goes through the via agent's tunnel, so that agent has
  to be online.
- **Limits.** The test can reach any address the gateway can, so it is browser-only (automation
  tokens are refused), limited to 10 tests per minute per account, and it refuses the cloud
  metadata service (`169.254.169.254`, `metadata.google.internal`, `fd00:ec2::254`), also when
  a name resolves to it. Every test is in the audit log as *connection test to host:port →
  result*; the credential is never logged or stored.

**Generate a key for this host.** With SSH or SSH-jump and *SSH key* authentication, the form
can create an Ed25519 key pair for you, also before the host exists. The private key is
created on the gateway and kept encrypted in its vault; the form shows only the public key and
the command to run on the target:

```sh
mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '<public key>' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
```

Run it there, press **Test connection** (it uses the new key), then save: the key becomes the
host's stored credential. An unused generated key is deleted after one hour, and only the
account that generated it can attach it to a host. Only Ed25519 is offered.

## Tags

Free-form labels for finding hosts: `prod`, `debian`, `web`, `customer-x`.

1. In **Add host** / **Edit host**, type them in **Tags**, separated by commas or spaces. The
   field suggests tags you already use on other hosts.
2. They appear as chips on the host's row in the sidebar (and the first five on the host
   page).
3. **Click a tag chip** in the sidebar to filter the list by it; the sidebar search also
   matches tags (substring match, like names and hostnames).

Normalisation, done on the server: lowercased, duplicates removed, each tag cut to 32
characters, at most 20 tags per host. Tags are labels only: they grant nothing and restrict
nothing.

## Export and import (CSV)

Move a set of hosts to another WebTerm gateway, or keep the list in a spreadsheet and load it
back. **No secret ever goes into the file.**

**Export.** Hover a folder header in the sidebar and press its download icon (the folder's
hosts come pre-selected), or open **Add host → Import CSV → Export hosts…**. Tick hosts one by
one, or select them in bulk with **All**, a **Folder** chip or a **#tag** chip, then press
**Export CSV**. The browser downloads `webterm-hosts-YYYYMMDD.csv` (UTF-8 with a BOM, so Excel
shows diacritics correctly; RFC 4180 quoting).

Columns, always in this order:

```
name,connection_type,hostname,port,username,via_host,folder,tags,note,require_2fa,credential_policy,auth_method,agent_note
```

- `via_host` is the **name** of the agent an ssh-jump/telnet-jump target goes through (ids do
  not survive a move to another gateway).
- `tags` are space-separated; `require_2fa` is `0`/`1`.
- Agent hosts leave `port`, `username`, `credential_policy` and `auth_method` empty and carry
  `agent_note` = "reinstall the agent on the new gateway".
- Never exported: passwords, private keys, passphrases, enrollment links, agent tokens,
  instance ids, pinned host keys (`known_hosts`) and share links. A host-key pin is a fact
  about *this* gateway's first contact; the new gateway pins on its own first connection (or
  on a **Test connection**).
- "Connect once" targets are not exported, exactly as they are not in the sidebar.
- Hosts that **require 2FA** are exported without a step-up: the file holds the same metadata
  `GET /api/hosts` already shows to the signed-in browser. Step-up guards access *to* a host
  (shell, files, stored credentials), not its name and address.
- Cells starting with `=`, `+`, `-` or `@` get a leading `'`, so a spreadsheet shows them as
  text instead of running them as a formula (CSV injection). The import removes that `'`
  again.

**Import.** **Add host → Import CSV**: drop the file, pick it, or paste the text. The browser
parses it and shows a preview, one row per host, with a status:

| Status | Meaning |
|---|---|
| New | will be created |
| Agent | will be created **pending**; it needs its agent installed |
| Exists already | same name, or same hostname + port + username; skipped |
| Error | the reason: missing name/type/hostname/username, unknown `connection_type`, invalid port, `via_host` not found / not an agent / ambiguous |

Rows that can be created are ticked; untick any you do not want. Applied to all ticked rows:
an optional **folder** (otherwise each row keeps its own), **extra tags**, and the
**credential policy** of SSH/Telnet rows — *Ask every time* by default, or *Stored*, in
which case you add the password or key later by editing the host. **Test connection** and
**Generate a key** stay per host (edit the host after the import); they are not applied in
bulk.

The gateway re-checks everything: every row goes through exactly the validation of
`POST /api/hosts`, duplicates are detected again on the server, at most 500 rows per import.
Agent rows are created first, so an ssh-jump row can name an agent defined further down the
same file. One audit entry records "imported N hosts (M skipped)".

Each imported agent host gets **its own install command**, valid for 24 hours, shown after
the import (a fresh one is under the host's **⋯ → Reinstall**). A group enrollment link
cannot be offered here: running a group link *creates a new host* on every machine, it cannot
attach to hosts that already exist, so it would duplicate every imported agent.

API (browser session only; automation tokens are refused):
`GET /api/hosts/export.csv?ids=1,2,3` and `POST /api/hosts/import` with
`{"rows": [{…columns as text…}], "options": {"folder": "", "tags": "", "credential_policy": "ask"}}`,
which answers with one result per row: `{index, ok, id?, code?, vars?}`.

## Require 2FA (step-up)

Mark a host as one that a stolen browser session must not be enough to reach. On such a host,
**every sensitive action** asks for a fresh second factor first: opening or attaching to a
session, `run`, every file operation, Docker/services/ports, diagnostics and the agent log,
port-forward handshakes, Wake-on-LAN, a new install link, provisioning, forgetting
credentials, and changing the host's connection fields.

**Where to set it.** When adding a host: **Require 2FA (step-up) on every connection**. On an
existing host: the host's **⋯** menu → **Require 2FA to connect** (shown as **✓ 2FA to
connect** when on). Turning it **on** needs nothing extra and immediately invalidates every
existing port-forward ticket. Turning it **off** needs a step-up, so a stolen cookie cannot
simply switch it off. Muting offline alerts on a 2FA host also needs a step-up.

**Which factor is asked for**, in this order, depending on what your account has:

1. **Passkey** — if you have registered one (and the instance runs on a domain, which
   WebAuthn needs). With a passkey on the account, the password is not accepted instead.
2. **SSO re-authentication** — for an SSO account when OIDC is enabled: a fresh login at the
   identity provider.
3. **TOTP code** (or a recovery code) — if TOTP is enabled and there is no passkey. Codes are
   single-use (a replayed code is refused) and the attempts are rate-limited per account.
4. **Account password** — only when the account has neither a passkey nor TOTP.

**The step-up window.** A successful factor opens a window for **that host** (per account),
like `sudo`: further actions pass without asking again. The window closes after **5 minutes
without a sensitive action** on that host and, however active you are, **1 hour** after the
factor was presented. Logging out or changing your password closes all windows. A passkey
grant itself must be used within 120 s.

**Terminals lock when idle.** A terminal on a 2FA host locks after
`WEBTERM_IDLE_LOCK_SECS` seconds (default 300; `0` turns it off) without input, hides its
scrollback, and asks for a factor again to unlock.

**Automation tokens are refused outright** on these hosts (*"the host requires 2FA — not
reachable with an automation token"*): a token cannot present a passkey, so a 2FA host stays
reachable only by a person in a browser.

A fresh unlock of a 2FA host sends a *host unlocked* email/webhook alert (throttled per host)
if alerts are configured.

## Credential policies

For SSH and telnet hosts: what WebTerm does with the password or private key.

| Policy | In the UI | Behaviour |
|---|---|---|
| `stored` | **Save (encrypted)** | The password, or private key plus optional passphrase, is encrypted in the gateway's vault and used on every connect. Needed for port forwards on an SSH host without an open session |
| `ask` | **Ask every time** | Nothing is saved; the credential is requested on every connection |
| `ephemeral` | *(API only; shown as "Ephemeral (bootstrap only)")* | Stored only until **Install the agent (SSH)** succeeds: once the new agent has connected, the host becomes an agent host and the credential is deleted |

Telnet-jump hosts have no credential fields (you log in interactively); agent hosts never hold
an SSH credential. The **Credentials** row of the host page's Security card shows the current
state: *Stored, encrypted*, *Asked on every connection*, *Ephemeral (bootstrap only)* or
*None*.

**Forget stored credentials.** Once the agent has taken over, or whenever you no longer want
WebTerm to hold the secret: host page → **Security** card → **Credentials** → **Forget**
(shown when credentials are stored and the policy is not *ask*).

1. Confirm the dialog. It tells you what you lose: on an agent host, only the ability to
   re-provision over SSH without typing the credential again; on an SSH host without an agent,
   your stored way in.
2. Re-enter your **account password** (and pass the step-up on a 2FA host).
3. The encrypted credential is deleted and any open SSH connection that used it is closed, so
   it does not linger in the gateway's memory. Live SSH sessions on that host end.

This **cannot be undone**. Switching an agent host back to SSH later asks you for a password or
key again.

## Install links and their TTL

An agent host is enrolled with a one-line install command that contains a single-use enroll
token. **Install link valid for** (shown when adding an agent host) sets how long it works:
**15 minutes**, **1 hour** (default), **24 hours** or **7 days** in the form. The API accepts
any value and clamps it to **5 minutes – 30 days**.

- The link is **single-use**: the token is claimed and invalidated atomically the moment the
  install script is fetched; a second fetch, or one after expiry, gets *"invalid or expired
  enroll token"*.
- **Install password (optional)** — letters, digits, `.` `_` `-`, up to 64 characters. It is
  sent as an `X-Enroll-Pass` header, not in the URL, so a URL that leaks into a log is not
  enough. Deliver it on a different channel from the link. A wrong password does not consume
  the token, but attempts are rate-limited per host.
- While a valid, unused link exists, the sidebar row shows *install link active (unused)* (or
  *(password-protected)*), so a forgotten or leaked link is visible. It clears when the agent
  first connects or the link expires.
- **New link for an existing host:** the host's **⋯** menu → **Reinstall agent**. This
  replaces any previous link, needs a step-up on a 2FA host, and is issued with the default
  TTL of 1 hour and no password.
- **Install the agent (SSH)** on an SSH host creates its own 1-hour link, runs the installer
  over the SSH connection and waits up to about 40 s for the agent to connect.

Enrolling many machines with one reusable token is a separate feature (enrollment groups):
see [FLEET.md](FLEET.md#fleet-scale-onboarding).

## When a host goes offline mid-session

If the agent of an open session's host disconnects, a card appears at the top of the terminal
(it does not cover the prompt at the bottom and does not take the keyboard focus):

- **"\<host\> is offline"**, with **Offline since HH:MM · duration** (date and time once it is
  more than ~20 hours old). The time is the agent's disconnect from the host's connection log
  when the page can read it, otherwise the last heartbeat, otherwise the moment the page noticed.
- **Reason**, only when the gateway knows it: the agent was uninstalled, it was refused as
  relocated/cloned (`instance_refused`), it is restarting to apply an agent update, or the
  disconnect reason from the log (clean close, no heartbeat for 90 s, WebSocket error, replaced
  by a reconnect). Nothing is guessed. On a 2FA host the log needs a step-up, which the card never
  asks for on its own: without an open step-up window it just shows no reason.
- **Diagnostics** (the same window as the host menu; offline it shows the connection log and the
  last snapshot), **Wake** (exactly when the sidebar offers ⏻, see below), **Open host page**,
  and **Dismiss**, which hides the card in this session until the next outage.

When the agent reconnects the card goes away by itself and a short *"\<host\> is back online"*
confirmation fades out (also announced to screen readers). tmux sessions survive the outage and
are re-adopted, so the terminal simply picks up again.

Other connection types:

- **SSH-jump / telnet-jump targets** depend on their parent's agent: when it is down the card
  names the parent (*"Jump host \<parent\> is offline"*), and its actions apply to the parent.
- **Direct SSH / telnet** have no agent and no heartbeat. When the gateway loses a session's
  connection the card says *"Connection to \<host\> lost"*; telnet sessions get **Reconnect**
  (the same action as the session bar). A dropped direct SSH connection ends the remote shell, which the
  gateway cannot tell apart from `exit`, so it shows as a closed session; open a new one.
- **Shared links (guest view)** show no card: they carry no host information and no admin actions.
- **Pop-out windows** show the same card; **Open host page** opens the main app in a new tab.

## Wake-on-LAN

Turn a powered-off agent host back on from the browser. Wake-on-LAN is a layer-2 broadcast,
so the gateway cannot send it itself: it asks **another agent that is online on the same
LAN** to send the magic packet.

How to use it: an offline agent host shows a **⏻** button on its sidebar row (next to the
offline-alerts bell), and an open session on it shows a **Wake** button on its offline card.
Click either; the toast says *Wake packet sent to … via \<neighbour\>*.

What has to be true:

- **Agent hosts only.** SSH/telnet hosts don't get the button and the API refuses them.
- **The target's MAC and subnet come from its last diagnostics snapshot.** The host must have
  reported diagnostics at least once while online; otherwise *"no MAC/IPv4 known"*. Loopback,
  virtual interfaces (Docker bridges, veth, VPN/WireGuard/Tailscale, …) and /31–/32 addresses
  are skipped; the interface whose IP matches the address the gateway last saw is preferred.
- **A neighbour:** another agent host, online, running agent v50 or newer, with an interface
  in the same IPv4 subnet (taken from its own diagnostics). None → *"no online agent on the
  same LAN"*. The packet goes to that subnet's broadcast address.
- **The machine itself must accept it:** Wake-on-LAN enabled in the BIOS/UEFI and on the NIC
  (for example `ethtool -s eth0 wol g` on Linux), wired Ethernet, and power to the NIC while
  off. WebTerm can only confirm that the neighbour **sent** the packet, not that the machine
  woke up: watch the host come back online.

On a 2FA host, waking it needs a step-up. Each wake is recorded in the audit log with the MAC
and the neighbour used.

## OS updates badge

A count of pending OS package updates on the host's sidebar row (and a chip on the host page),
so you notice hosts that need patching.

**Where the number comes from.** The agent checks with the package manager in read-only or
simulation mode. It never installs anything:

| Manager | Check | Security count |
|---|---|---|
| apt | `apt-get -s upgrade` (simulation, no lock, no root) | yes — packages from a `-security` repository |
| dnf | `dnf -q --cacheonly check-update` | no |
| zypper | `zypper -x list-updates` | no |
| pacman | `checkupdates` (pacman-contrib) | no |
| apk | `apk version -l '<'` | no |

The result is cached on the host for `WEBTERM_UPDATES_CHECK_SECS` seconds (agent environment,
default **21600 = 6 h**; `0` turns the check off and the badge with it) and travels in the
diagnostics snapshot. **Refresh** in Diagnostics forces a new check (at most once every 30 s),
so the badge clears right after you upgrade.

**Using it.** Click the badge: the dialog shows the count, the manager and how many are
security updates. **Upgrade in a terminal** opens a session that runs the upgrade for apt
(`apt-get update && apt-get upgrade`) or dnf (`dnf upgrade`): directly if the agent runs as
root, with `sudo` if passwordless sudo is available, otherwise it prints the exact command
and the options instead of hanging at a password prompt. Other managers: run the upgrade
yourself in a terminal.

**How loud it is** is a preference of **your browser**, not of the host:

- **Settings → Preferences → OS updates badge:** **All updates (security highlighted)**
  (default), **Only security updates**, or **Hidden**. Security counts exist only for apt, so
  *Only security updates* hides the badge on other distributions.
- **Per host:** **Hide for this host** in the updates dialog, or the host's **⋯** menu →
  **Hide OS updates badge** (and **Show OS updates badge** to undo). **Show on all hosts
  again** in Preferences clears every per-host hide.
- Hiding affects only the sidebar list. The chip on the host page is always shown.

## Starting at boot

**Why it matters.** The agent is what makes an agent host reachable. If nothing starts it
again after a reboot (a kernel update, a power cut, a RAM upgrade), the host stays **offline**
in WebTerm until someone logs in over SSH and runs `python3 ~/.webterm/ptyd.py start`. That
is exactly the situation WebTerm exists to avoid.

**Where you see it.** The host page's **Agent** card has a **Starts at boot** row: **Yes
(systemd)**, **Yes (cron)**, **Only after a login (no linger)**, **No**, or **Unknown**. A host
that will not come back by itself also gets a small amber **⚠** on its sidebar row. Agents from
v57 report this in their diagnostics snapshot (on connect, then hourly). Older agents show
**Unknown** until they update.

**The modes**, the same ones the installer sets up:

| Mode | What it is | Starts at boot when |
|---|---|---|
| systemd | a user service, `~/.config/systemd/user/webterm-agent.service` (`Restart=always`, `KillMode=process`, a 45 s watchdog) | the unit is enabled **and** linger is on for the agent's user |
| systemd (system) | a system unit in `/etc/systemd/system`, for agents run as root by hand | the unit is enabled |
| cron | `@reboot … ptyd.py start # webterm`, plus a `* * * * *` watchdog line that restarts a dead or hung agent | the `@reboot` line is present |

**Linger.** A systemd *user* service runs inside the user's service manager, and by default
that manager starts only when the user logs in. `loginctl enable-linger <user>` starts it at
boot instead. Enabling linger usually needs root once, which the agent (running as that user)
does not have. **Enable** tries anyway, without prompting. If it is refused, you get the exact
command to run as root, and the row shows **Only after a login (no linger)**. The dedicated-user
install command (`useradd … && loginctl enable-linger webterm`) already does this.

**Changing it from the UI.** On an online agent host (v57+), use the button on the row:

- **Enable** sets up what the installer would. It uses systemd if a user service manager is
  reachable, and otherwise falls back to the two cron lines. When systemd is used, old WebTerm
  cron lines are removed, so you never run two mechanisms. An existing unit file is enabled as
  it is, never rewritten, so an opt-in hardened unit (`WEBTERM_AGENT_HARDENED=1`) keeps its
  settings.
- **Disable** asks for confirmation, then runs `systemctl --user disable` (deliberately
  **without** `--now`) and removes only the WebTerm lines from the crontab. If the crontab
  cannot be read, it is left untouched rather than rewritten.

Neither action restarts or stops the agent that is running now. The change takes effect at the
next boot. On a 2FA host both actions need a step-up, and each one is recorded in the audit log.

## Diagnostics

A health and inventory view of an agent host, without SSH: the **Diagnostics** button on the
host page's tools, or the host's **⋯** menu → **Diagnostic**. Available for every agent host;
when the host is offline you see the **last snapshot** it reported (useful to recall what IPs,
routes or disks a dead machine had).

The agent pushes a full snapshot when it connects and then every hour; **Refresh** asks for a
fresh one now (online only). Tabs:

- **Overview** — last heartbeat, agent version, the IP the gateway sees, connection uptime and
  reconnect count; system (OS, kernel, architecture, hostname, uptime), CPU (model, cores, load
  averages), memory and swap.
- **Storage** — mounted filesystems with usage, plus an on-demand probe: `lsblk`, SMART health
  (`smartctl`, usually needs root) and `zpool status`.
- **Network** — interfaces (state, MAC, IPv4/IPv6, MTU, traffic counters, physical vs.
  virtual) and routes, plus an on-demand probe: ARP/ND neighbours and the firewall ruleset
  (`nft` or `iptables-save`, usually needs root).
- **Ports** — listening sockets (`ss -tulnp`; process names usually need root).
- **Logs** — the agent's connection log for the last **7 days** (connects, disconnects and why,
  updates), and on request the tail of the agent's own log (`ptyd.log`).

The same snapshot feeds Wake-on-LAN (MAC and subnet) and the OS-updates badge. Snapshots are
capped at 256 KiB; an oversized one is refused, logged as an event, and the last good one is
kept. Diagnostics read host details (IPs, routes, mounts), so on a 2FA host they need a
step-up like any other read.

> The [single-account invariant](../README.md#security) applies: anyone past login
> administers every host. Require 2FA is how you put a second factor in front of the hosts
> that matter.
