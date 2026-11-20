# Business rules that are easy to get wrong

WebTerm's code is full of checks that look redundant until you know which incident put them
there. This page lists the rules that contributors (people and coding agents) have actually got
wrong, why each rule exists, where the code enforces it and which test fails if it breaks.

Read it before changing anything about hosts, credentials, step-up, shares, roles, the command
guardrail, the agent or forwards. Each rule has an ID. The code enforcing it carries a comment with
that ID (`grep -rn 'INV-03' gateway frontend/src`), and `tests/invariants_test.py` checks that the
IDs in this page and in the code stay in step.

The rules are ordered from "a mistake leaks a secret or grants access" to "a mistake confuses users".

| ID | Rule in one line |
|---|---|
| [INV-01](#inv-01) | A stored secret belongs to a **target**, not to a host row |
| [INV-02](#inv-02) | Connection types live in one table; no type means `agent` |
| [INV-03](#inv-03) | A password never goes to a host key nobody confirmed |
| [INV-04](#inv-04) | Step-up is per user *and* host, short, and capped |
| [INV-05](#inv-05) | Shared access never outlives or exceeds the person who shared |
| [INV-06](#inv-06) | Roles limit what WebTerm lets you reach, not what a shell can do |
| [INV-07](#inv-07) | There is always an Owner who can sign in without SSO |
| [INV-08](#inv-08) | The command guardrail may only add readings, never drop them |
| [INV-09](#inv-09) | The agent is a separately versioned, signed product |
| [INV-10](#inv-10) | The gateway never gains new powers on a host |
| [INV-11](#inv-11) | Every forwarded request is authenticated |
| [INV-12](#inv-12) | An agent host that has connected with its client certificate never goes back to the token alone |

---

<a id="inv-01"></a>
## INV-01: a stored secret belongs to a target, not to a host row

**Rule.** A saved password (or key passphrase) was given for one destination: protocol, host
name (case-insensitive), port (with the protocol's default) and, for jump types, the `via` host.
If an edit moves the row to another destination, the secret must be typed again. It is never
carried over. Switching to `ask` or to an agent host clears it.

**The misconception.** "Editing a host's address keeps its credentials, like a bookmark." In
3.6.33 that let anyone with `hosts.edit` point a saved root password at a server they control and
read it. The first fix still missed two paths: an `agent` row moved to `ssh`, and a move through
`ask` and back. Both were critical findings in the 3.6.34 review.

**Applies equally to** Toolbox database connections, backup SFTP/FTPS destinations (and an OAuth
hop wipes the direct credentials) and the "Test connection" button, which uses a stored password
only on the same target.

**Enforced in**: `hosts_api.py` `[hosts]`: `_conn_target`, `_retargets`, `_has_stored_password`,
`update_host`; `[hosts-test]` `test_host_connection`; `api.py` `[toolbox-db]` `update_connection`;
`cloudbackup.py` `save_config_direct`, `_wipe_direct`.
**Tests**: `host_edit`, `host_test_connection`, `cloud_direct`, `hostkey_alarm`.

<a id="inv-02"></a>
## INV-02: connection types live in one table; no type means `agent`

**Rule.** `agent`, `ssh`, `ssh-jump`, `telnet`, `telnet-jump` and their groupings (SSH family,
telnet family, jump, network) are defined only in `gateway/app/conntypes.py` (frontend mirror:
`lib/conntypes.ts`). A row with no type is an agent host. When an agent host's address is
compared as a credential target, it counts as SSH: its password came from SSH provisioning.

**The misconception.** Hand-written tuples such as `("ssh", "ssh-jump")`, repeated about 70
times. The INV-01 bypasses came from a branch that forgot one type.

**Enforced in**: `conntypes.py`. **Tests**: `conntypes` (rejects type lists anywhere else,
including SQL, and checks that backend and frontend lists match).

<a id="inv-03"></a>
## INV-03: a password never goes to a host key nobody confirmed

**Rule.**
- With **password** authentication and no pinned key, the first connection stops before
  authenticating (`HostKeyUnverified`, a `first: true` alarm). A person confirms the fingerprint.
  Accepting is bound to that exact fingerprint: a key that changed in between is refused
  (`ssh.hostKeyStale`).
- With **key** authentication, trust-on-first-use is acceptable: a key signature reveals no
  reusable secret.
- Switching a host from key to password drops a pin that was learnt by TOFU.
- Certificate host keys are pinned as their plain key.
- The backup SFTP probe pins only keys that it actually saw.

**The misconception.** "TOFU is fine for SSH." It is not when the next thing sent is a password:
whoever answers first receives it.

**Enforced in**: `core.py` `[ssh]`: `_needs_first_contact`, `_hostkey_first_contact`,
`peek_host_key`; `hosts_api.py` `[ssh]` `host_hostkey_accept`; `cloudbackup.py` `_PROBED`.
**Tests**: `hostkey_alarm`, `host_test_connection`, `cloud_direct`, `ssh_jump`.

<a id="inv-04"></a>
## INV-04: step-up is per user and host, short, and capped

**Rule.**
- On a `require_2fa` host, opening a terminal and every risky action (`run`, files, update,
  provision) needs a second factor for **that user on that host**.
- A grant is single-use and lasts 120 s (`STEPUP_TTL`).
- The window closes after 5 minutes of inactivity (`STEPUP_WINDOW`) and **never lasts more than
  60 minutes** (`STEPUP_WINDOW_MAX`). At 60 minutes, open terminals lock (`core.sweep_stepup_caps`).
- A terminal opened inside the window is **not** re-checked against the 5-minute idle window.
  This is by design (documented in HOSTS.md and THREAT-MODEL.md), not a bug.
- A password alone is never a second factor.
- An SSO step-up needs a fresh `auth_time` from the identity provider.
- Granting durable access (deploy keys and similar) needs a fresh factor even on hosts without
  `require_2fa` (`stepup.require_fresh_factor`).

**The misconceptions.**
- "A terminal must be re-verified every 5 minutes." An external report claimed this. The cap is
  60 minutes on purpose.
- "A password re-entry counts as step-up." It was refused in 3.5.13.

**Enforced in**: `security.py` (grant and window mechanics); `stepup.py` `require_host_stepup`,
`require_fresh_factor`, `consume_factor`; `core.py` `sweep_stepup_caps`; `oidc.py` `_check_stepup_auth_time`.
**Tests**: `stepup`, `sec_stepup_factor`, `forward_stepup`.

<a id="inv-05"></a>
## INV-05: shared access never outlives or exceeds the person who shared

**Rule.**
- A **live share link** is a view of someone's terminal. A guest cannot do step-up, so on a
  `require_2fa` host the link works only while a verified operator is attached. When the operator
  leaves, guests lock (`SessionHub.has_operator` / `sync_guests`).
- A link to a session that has ended is refused, and cleared.
- Live links die when their creator logs out, changes password or loses `share.live` on that host.
- **Replay links** show a finished recording. They survive logout, but die on a password change,
  account deletion or loss of `share.replay`. Every public open re-checks the issuer's current
  `share.replay` on the recording's host (disabled account, expired role, narrowed scope), so a
  link stops working at once, without waiting for the scheduled cleanup.
- A root maintenance terminal on the gateway host (certificate renewal, System health fixes) is
  never shared: not live, and not as a replay of its recording.

**The misconception.** "A share is a capability: whoever holds the link can use it." In 3.6.33 a
link on a 2FA host stayed usable after the operator left. Two attach-order races were found in the
same review.

**Enforced in**: `core.py` `[hub]`: `has_operator`, `sync_guests`; `share_api.py` `[share]` + `_replay_issuer_ok`, the
`shared_ws` / `browser_ws` websockets (`api.py` `[ws]`); `sessctl.py`; `shares.py`.
**Tests**: `share_presence`, `replay_links`, `share_ratelimit`.

<a id="inv-06"></a>
## INV-06: roles limit what WebTerm lets you reach, not what a shell can do

**Rule.**
- A role decides **which hosts** you can reach and **which WebTerm actions** you can take there.
  Inside a host shell, the host's own users and `sudo` decide. Do not build features that pretend
  otherwise.
- Every route declares exactly one permission (`authz.perm(...)`), or an entry with a reason in
  `authz.PUBLIC` / `authz.SELF`. An undeclared route answers 500 (`authz.undeclared`): it fails
  closed instead of being open.
- A host you may not see answers exactly like a host that does not exist (404, `authz.not_found`):
  no oracle.
- List routes filter. They never deny.
- Forward tickets are re-checked against the issuer's **current** grants on every request.
- Automation tokens never reach a `require_2fa` host and never exceed their creator.

**Enforced in**: `authz.py` (`perm`, `declared`, `not_found`); `forward_api.py` `_forward_authz_ok`.
**Tests**: `route_auth` (also checks Appendix A of `ROLES-AND-SSH.md`), `rbac_filter`,
`rbac_escalation`, `rbac_crown`.

<a id="inv-07"></a>
## INV-07: there is always an Owner who can sign in without SSO

**Rule.**
- No action may remove the last Owner, or the last Owner who has a local password (break-glass).
  This covers revoking, expiring, SCIM deletion, SSO sync and account deletion.
- Accounts that still have a local password **never** receive roles from SSO groups.
- SCIM never answers 409 when creating a user: Authentik cannot recover from it.

**The misconception.** "SSO group membership is the source of truth for every account." In 3.6.2
the review found that an Admin could plant a local account and then have SSO adopt it into Owner.

**Enforced in**: `owners.py` (the whole rule: `owner_count`, `last_break_glass`,
`is_permanent_owner`, `owner_ids`, and the audited refusals), called from `authz.py`,
`accounts.py`, `scim.py`, `ssomap.py`, `api.py`, `admin.py` and `syshealth.py`;
`ssomap.py` `has_local_password` (no SSO roles for local-password accounts).
**Tests**: `rbac_escalation`, `sso_rolemap`, `scim_protocol`, `multi_account`.

<a id="inv-08"></a>
## INV-08: the command guardrail may only add readings, never drop them

**Rule.**
- The guardrail reads what is about to run, from the typed line, the screen and shell
  integration, and asks for confirmation or blocks.
- Every heuristic may only **add** a reading. Shortening, trimming or ignoring part of the input
  to "reduce false positives" is a bypass. When unsure, the result is "unknown", which is
  treated strictly.
- The first matching rule wins, so `block` rules go first.
- The bracketed-paste mode announced by tmux is not trusted: `termmodes.pasteModeUntrusted`
  allows only `pty` and telnet.
- **Paste is consent.** A pasted or dropped screenshot types its path, exactly like pasted text.
  No extra click.

**The misconception.** "Ignore this byte or this case to stop a false alarm." 3.6.13 needed about
12 review rounds. 3.6.17 shipped a red build because a trimmed key lost sync after a trailing
space.

**Enforced in**: `frontend/src/lib/broadcastGuard.ts`, `lib/commands.ts`, `lib/termmodes.ts`;
`gateway/app/osc133.py` (the hub's scanner).
**Tests**: `broadcastGuard.test.ts`, `commands.test.ts`, `echo.test.ts`, `termmodes.test.ts`.

<a id="inv-09"></a>
## INV-09: the agent is a separately versioned, signed product

**Rule.**
- `AGENT_VERSION` (in `agent/ptyd.py`) is not the WebTerm version.
- Any edit of `ptyd.py` needs a version bump. Stefan then re-signs it with his offline key, and
  every host in the fleet updates. Once a version has been pushed to `main`, the next edit needs
  another bump.
- Bundle agent changes; never ship a refactor alone.
- The agent is Python 3.6+, stdlib only. Older hosts get a portable runtime.
- The agent acts as **its own OS user**. `su` or `sudo` typed in a terminal does not change who
  Files or the Git panel act as. That is why the Git panel isolates repository config: an
  agent running as root reading another user's repository must not execute its config.

**The misconception.** "The agent does what the logged-in shell user could do." The Git config
code-execution findings in 3.6.26–3.6.27 came from that assumption.

**Enforced in**: `core.py` `maybe_upgrade_agent` (signed updates, never downgrade); the CI
main-push gate. **Tests**: `git_panel`, `pyruntime`.

<a id="inv-10"></a>
## INV-10: the gateway never gains new powers on a host

**Rule.**
- When WebTerm cannot fix something from the UI (certificates, disk, Authentik, host timers), it
  **detects, notifies, explains and recommends**.
- It shows the exact command, or opens it typed but not run in a terminal on the gateway host,
  for an Owner after step-up.
- New features must not add privileges, sudo rules or root helpers to the gateway or the agent.
  Root from the browser (Files elevation) was deliberately postponed for this reason.

**Enforced in**: `syshealth.py`; certificate renewal through a typed command.
**Tests**: `syshealth`, `cert_renew_script`.

<a id="inv-11"></a>
## INV-11: every forwarded request is authenticated

**Rule.**
- Port forwards (`<slug>.<forward domain>`) are reachable only with a signed-in session that has
  `forward.use` and `host.view` on the host. This is checked on every request and websocket.
- The `Origin` header is compared in full, port included.
- There are no anonymous or "demo" links. This was decided on 2026-10-23: a bearer link to an
  internal service cannot be made as safe as not having one. Public demos belong outside WebTerm.

**Enforced in**: `forward_api.py` `[forward]`: `_forward_authz_ok`, `_fwd_origin_for_target`.
**Tests**: `forward_stepup`, `forward_proxy_headers`.

## INV-12: a host that has used mTLS never goes back to the token alone

**Rule.**
- After an agent's first successful connection with its client certificate (mTLS), its host is
  marked `mtls_required`. From then on, a connection for that host with the token alone is refused.
  A stolen token is then useless without the certificate's private key.
- Only re-enrolling the host clears the mark, as it clears the instance pin.
- The requirement is lifted only when mTLS is off on purpose or cannot exist here
  (`edgemtls.enforce_ratchet()`: `WEBTERM_AGENT_MTLS=off`, a CDN in front, no valid agents name). That
  is the rollback, and it must work even when the CA cannot be loaded. When mTLS is broken (CA error,
  file not writable), the requirement stays and System health raises a critical alarm.
- A client certificate counts only when the request came through Traefik's mTLS router, which proves
  it with the installation's secret header. A certificate is public information; the header alone
  proves nothing.

**Enforced in**: `api.py` `[ws]` `agent_ws`; `edgemtls.py` `router_secret_ok`; `agentca.py` `verify_client_cert`.
**Tests**: `agentmtls`, `agentca`.

