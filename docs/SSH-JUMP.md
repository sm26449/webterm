# SSH-jump and Telnet-jump — LAN gear through an agent

Reach a switch, router, appliance or server that sits on an **agent host's LAN** — SSH or
telnet — in a normal terminal tab, with **no agent on the target**. The agent only opens a raw
TCP tunnel; the protocol client runs in the gateway. Shipped in 3.0.0 (SSH-jump), with saved
Telnet-jump targets, nesting and "Connect once" added on top. The agent is unchanged.

Sibling of the telnet bastion in port forwarding ([PORT-FORWARDING.md](PORT-FORWARDING.md),
threat model in [design/TELNET-BASTION.md](design/TELNET-BASTION.md)) — Telnet-jump is literally
the same `ForwardTelnetSource`, only owned by a saved host instead of a forward.

## Usage flow

1. In the sidebar, open the **⋯** menu of an **agent** host → **Add SSH / Telnet jump…** (the item
   is there whether the agent is online or not; it is the only place jump targets are created —
   the generic Add-host selector does not offer them).
2. The form opens scoped to that agent: **Reach via** is fixed, pick the protocol with the
   **SSH-jump / Telnet-jump** toggle (port defaults to 22 / 23), enter the target's LAN address
   and a name. SSH-jump also takes the user and a password — stored in the vault or
   *Ask every time*. Telnet-jump takes no credentials at all (plaintext, interactive login).
3. **Save target** — the host is saved and appears **nested under the agent** in the sidebar
   (indented; collapses with the agent's folder). One click opens its page: Overview + Sessions
   (the agent-only sections — Files, Forwards, Services… — belong to the agent, not to the target).
4. **Connect once** — the same form, no saved host: an **ephemeral** target is created, hidden
   from the sidebar, dashboard, palette and fleet run, and a session opens immediately. A reaper
   (every 60 s) deletes it once it is at least two minutes old and has no `live`/`creating`
   session. An ephemeral target cannot be promoted to a saved one; save it instead if you need it again.
5. **New session** on the target → the session runs through the agent's tunnel. The agent must be
   **online**; otherwise *"The host is offline — its agent is not connected."* / the connect toast
   below.

### Editing a jump host

**Edit host** on the target's page (or ⋯ → Edit) shows the protocol toggle instead of the
generic Agent/SSH selector; name, address, port, user/password (SSH-jump), note, tags and the
**via** agent can change. A jump host cannot be turned into an agent/SSH/telnet host from the
UI, and a via that would route a host through itself (or in a loop) is refused.

Deleting an agent that still has **saved** jump targets is refused until those targets are
removed; ephemeral targets are purged with their agent.

## How it works

- **The tunnel.** The gateway asks the agent for a raw TCP connection to `target:port`
  (`fwd_open`, the same op port forwarding uses — IPv4). The agent neither speaks SSH nor telnet.
- **SSH-jump: the gateway is the SSH client.** asyncssh runs in the gateway over the tunnel,
  so the SSH session's own crypto is end-to-end **gateway → target**: the plaintext LAN leg
  carries only ciphertext, and the **host-key check belongs to the gateway**, not to the agent.
  A hostile agent relaying the tunnel cannot impersonate the target. Credentials are the
  direct-SSH machinery (vault, `ask`/`stored`); the UI offers password auth for jump targets.
- **Telnet-jump: the gateway speaks telnet.** The IAC shim and the untrusted-device guards of
  the telnet bastion apply: the device's **OSC 133 / 52 / 7** sequences are stripped (no forged
  command markers, no clipboard poisoning), and the password prompt is redacted — typed input
  is never written to the transcript anyway. If the agent drops, the session becomes `lost`
  (not `exited`) and **↻ Reconnect** opens a new telnet to the same target in the same tab —
  telnet is stateful on the socket, so you land at a fresh login.

## Host-key pinning and the host-key-change alarm

- **First connect (TOFU):** no key is pinned yet, so the target's host key is accepted and
  stored on the host record (`known_hosts`).
- **Every later connect:** the pinned key is checked **before authentication**. A different key
  means the tunnel is torn down and the session is **refused** with *"the host key fingerprint
  changed — possible MITM; connection refused"*, shown as the in-page error toast; an
  email/webhook alert (*"SSH host key changed — connection refused"*, with the advice to verify
  out-of-band before clearing the pin) goes out if alerts are configured, throttled to one per
  host per 15 minutes. The same alarm covers **plain direct-SSH hosts**.
- **Accepting a legitimately re-provisioned target:** there is no "accept new key" button. The
  pin is reset when you **edit the host's address or port** (Edit host → change hostname or
  port; changing only the via agent keeps the pin). Do that only after verifying the new
  fingerprint out-of-band.

## Connect errors

Failures are mapped to a reason and shown as a red, dismissible, 12-second toast **in the
page** (`role="alert"`), never only as an OS notification:

- *No SSH greeting from the target — wrong port, not an SSH server, or filtered.*
- *The target rejected the credentials — wrong password, or it wants an SSH key.*
- *The agent could not reach the target — refused, no route, or wrong address.* (Also what you
  get when the via agent itself is offline.)

ssh-jump dial failures are logged at WARNING with `target:port`, the via host and the cause.

## Security notes and limits

- **2FA is per host record.** A jump target under a 2FA-protected agent is **not** automatically
  2FA-protected: set *Require 2FA* on the target itself if the device deserves it (the session
  step-up checks the target's flag, not the agent's).
- The target address is anything the **agent** can reach, including its own loopback and
  private ranges — the agent is the trust anchor here, as in port forwarding.
- Via must be an **agent**; there is no jump through an SSH host and no multi-hop. No SSH agent
  forwarding.
- Telnet-jump sessions share the gateway-wide telnet cap (32). Telnet is plaintext on the LAN
  leg — the usual argument for preferring SSH-jump where the device supports it.
- A gateway restart marks jump sessions `lost` (`gateway-restart`); the target's state is not
  resurrected.

## Maintenance notes

- Gateway: `core.dial_ssh_jump` / `SshJumpSource` (SSH), `core.create_telnet_jump_session` and
  `reconnect_telnet_session` (telnet), `sweep_ephemeral_hosts` (reaper); host columns
  `via_host_id`, `ephemeral`, `known_hosts`. Tests: `tests/ssh_jump_test.py`
  (tunnel, PTY session, host-key mismatch → alarm + refusal, TOFU), `tests/telnet_jump_test.py`
  (agent resolution, session creation, agent offline), `scripts/e2e-jump.mjs` (UI: menu, form,
  nesting, host hub, error toast — runs in CI without a real agent).
- Frontend: `AddHostModal` (preset-jump form), `Sidebar` (`via_host_id` tree, ⋯ menu),
  `HostOverview` (Connection card shows protocol + authentication).
