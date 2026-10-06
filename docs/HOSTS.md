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

## Wake-on-LAN

Turn a powered-off agent host back on from the browser. Wake-on-LAN is a layer-2 broadcast,
so the gateway cannot send it itself: it asks **another agent that is online on the same
LAN** to send the magic packet.

How to use it: an offline agent host shows a **⏻** button on its sidebar row (next to the
offline-alerts bell). Click it; the toast says *Wake packet sent to … via \<neighbour\>*.

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
