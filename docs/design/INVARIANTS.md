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
| [INV-13](#inv-13) | Idle sessions are only announced, never closed automatically (3.7.1) |
| [INV-14](#inv-14) | A protected volume never opens without its own key, and never falls back to the old one (3.8) |

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
- Only re-enrolling the host clears the mark, and only when the new install claims the link
  (`api.install_script`), not when the link is generated.
- The requirement is lifted only when mTLS is off on purpose or cannot exist here
  (`edgemtls.enforce_ratchet()`: `WEBTERM_AGENT_MTLS=off`, a CDN in front, no valid agents name, an
  edge directory that is switched off (`WEBTERM_AGENT_LISTS_DIR=off`) or does not exist). That
  is the rollback, and it must work even when the CA cannot be loaded. When mTLS is broken (CA error,
  file not writable, an edge directory that exists but cannot be checked: permission denied, a file
  instead of a directory, a path through a file), the requirement stays and System health raises a
  critical alarm. Only "does not exist" counts as missing; any other error is a failure, and so is a
  broken symlink. A missing directory counts as "cannot exist here" only while no host requires
  mTLS: once one does, a directory that has vanished (a mount that failed after a restart) is a
  failure too. The rollback is then the explicit switch (`WEBTERM_AGENT_MTLS=off` or
  `WEBTERM_AGENT_LISTS_DIR=off`).
- A client certificate counts only when the request came through Traefik's mTLS router, which proves
  it with the installation's secret header. A certificate is public information; the header alone
  proves nothing.

**Enforced in**: `api.py` `[ws]` `agent_ws`; `edgemtls.py` `router_secret_ok`, `intent_off_reason`; `agentca.py` `verify_client_cert`.
**Tests**: `agentmtls`, `agentca`.

<a id="inv-13"></a>
## INV-13: idle sessions are only announced, never closed automatically (3.7.1)

**Rule.**
- A session is idle only when, for the whole period, nobody typed in it, it printed nothing and no
  browser (owner, other account or share-link guest) was attached. Output counts as use: a build or a
  `tail -f` is never idle.
- After the configured number of days (default 7, 1–90) the session's owner is notified (with no
  owner, the accounts with `session.manage` on the host, in one alert; a root terminal on the gateway
  host with no owner notifies nobody). One notice per idle period: any use cancels it at once, and a
  new idle period brings a new notice. A session marked **Keep open** is never notified.
- **Nothing is closed automatically in 3.7.1.** `idlesess.AUTOCLOSE_AVAILABLE` is `False`: the
  settings route answers `autoclose_available: false` and refuses `autoclose: true` with 400
  `settings.autocloseUnavailable`; a stored `autoclose: true` (from a 3.7.1 release candidate's
  database) is read as off; the sweep never sends a kill; a notice never carries a closing date or
  promises a close. The gateway has no code that sends the agent's conditional kill.
- When anything is unknown it does nothing: no hub watching the session's output, the host offline,
  an unreadable transcript, no one to notify, an error. A notice whose alert row could not be written
  does not mark the session as notified; it is retried after an hour.
- Why: closing a session safely needs a guarantee on the **agent** side that nothing happened between
  the gateway's last check and the kill (an atomic, conditional close inside tmux). That work is not
  ready. Its design and code are kept on branch `feat/agent62-autoclose` for 3.8; turning automatic
  closing on before it ships would close sessions that were in use.

**Enforced in**: `idlesess.py` `AUTOCLOSE_AVAILABLE`, `sanitize`, `sweep`, `_notify`, `notice_json`, `last_activity`; `core.py` `[hub]` `_idle_activity`; `api.py` `save_idle_sessions`; `alert_history.py` `record_required`.
**Tests**: `session_idle`.

<a id="inv-14"></a>
## INV-14: a protected volume never opens without its own key, and never falls back to the old one (3.8)

**Rule** (phase 1 of [ENCRYPTION-AT-REST.md](ENCRYPTION-AT-REST.md) §8; recordings are not
encrypted yet, so this covers the keys, backups, snapshots and the boot).
- Once a data volume has a key manifest (`keys.wtk`), every boot needs exactly the master key it
  was protected with. A missing, wrong or divergent key, an invalid envelope or a tampered manifest
  stops the boot **before** any clean-up, staged-restore apply, schema change or writer, and the
  data directory is left as it was (only the empty lock files `.lock` and `.maint.lock` may be
  created). Nothing ever falls back to
  `data/secret`, to the in-volume key or to another source.
- A 3.7 volume with **no** key source configured boots exactly as before (legacy state): the
  only difference from 3.7 is in the preflight, which adds the two empty lock files; after it,
  the boot makes 3.7's own writes (staged-restore apply, schema, clean-up). Upgrading the image
  changes nothing else until the operator provides a key. Supported 3.7 layouts: `secret` + the
  database, with `transcripts/` and `backups/` as plain directories or as symlinks to another
  disk (a `transcripts/` symlink boots legacy with a warning, but is not migrated: make it a plain
  directory first). Refused, even without a key: a database without `secret`, a `secret` that is
  not 32 bytes, any name of the new format (`*.wt*`, `.restore`, `master.key`…) or a symlink
  target that cannot be listed. A resolved key source (an env variable, or a key file at the
  default mount path) means migration, whether or not the operator edited `.env` recently.
- A configured key migrates a 3.7 volume once; the old 32-byte key becomes `FK_legacy` only after
  it has been proven on the database. The proof is **at least one stored encrypted value decrypts
  with it** (Stefan's decision, 2026-11-24: one value is enough; the others are not checked one by
  one). The inventory behind it is complete: every row of every `*_encrypted` column and every
  `app_settings` value (JSON at any depth) is classified, without a row limit; only decryption has
  a budget. A database with encrypted values none of which decrypts is refused (a foreign key file
  never becomes `FK_legacy`); a database with no encrypted value at all is eligible. Refused as
  well: a non-empty WAL or hot journal (the probe cannot see it: stop the 3.7 gateway cleanly
  first), any `FK:` value next to a 3.7 `secret` (a mixed set), a value that looks encrypted but
  is not a token, an inventory over the hard cap. A staged 3.7 restore must be complete and its
  own `secret` must prove its own database before anything is touched; it is then applied under
  the old key and migrated in the same boot. The same proof, on the archive's own database, gates
  every restore of a pre-3.8 archive before anything is published: the explicit legacy import
  onto a protected volume, and a 3.7 restore onto a pre-3.8 volume. Both go through one pipeline:
  the route is decided by the archive's **inner** format (a `.wtbk` holding a 3.7 tar is a 3.7
  archive) and the target's policy, the same way in `verify` and in staging (so the verdict comes
  before the app is stopped); one strict reader refuses duplicate, non-canonical (`./`, `//`,
  `..`, absolute) and case-only-colliding names; and the staging proves the exact pair it
  publishes (the staged database with the staged key) again right before publishing.
- Once a boot has started to change the volume (a 3.7 restore applied, a key file published), it
  keeps the data-directory lock until the process exits, on every error path, and reports the
  failure as `operation-incomplete`, never as a preflight refusal.
- A new, empty volume needs an external key, or `WEBTERM_KEY_IN_VOLUME=1` (reduced protection,
  shown as such). One process at a time on the keys: the gateway and `app.admin vacuum` hold the
  same lock on the data directory (`.lock`). The break-glass admin commands that change only
  database rows (`passwd`, `disable-2fa`, `logout-all`, `promote`, `sso-only`, `enable`) run while
  the gateway holds that lock, as in 3.7: they never open, write or publish key material (Stefan's
  decision, 2026-11-24). They use a maintenance connection that never creates the database, runs
  no schema step and changes no journal mode (a schema whose fingerprint — columns with types,
  NOT NULL, primary keys, DEFAULT, COLLATE and CHECK clauses, table CHECKs and options, every index
  with its key and auxiliary columns, sort order and collation, foreign keys, triggers, views —
  differs from the code's is refused, and no connection stays open; the fingerprint is taken on
  the connection the command then uses, inside one read transaction), and take `.maint.lock` shared (both
  lock files are `0600`, owned by the service user, so no other local user can hold them); the boot holds it exclusively through the preflight, a restore, a
  migration and the schema step, so an admin command is refused (not queued) during those. A new
  admin command that writes an encrypted value must open the keyring read-only or take the lock.
- Every backup and snapshot of a protected volume is a `WTS1` container that needs the key held
  apart from the data; it never contains the master key or the old key in clear. Older 3.7 backups
  that do hold the old key are listed in System health until they are deleted.
- Stored secrets name their key: values written on a protected volume carry the `FK:` prefix and
  decrypt only with `FK`; unprefixed values decrypt only with `FK_legacy`. A value that names a key
  the process does not hold is an error, never a retry with another key.
- A pre-3.8 image is never started on a migrated volume: the host scripts check the `/data` mount
  compose will actually start (its effective volume name or bind directory), refuse a divergent
  `WEBTERM_VOLUME`, a remapped mount, an unknown mount or an unreadable config, and any mount they
  do not model (`volume.subpath`, a volume whose `driver_opts` change its device, non-default
  bind propagation / SELinux options, `consistency`, a read-only `/data`); a bind mount is
  checked only with a local Docker daemon (unix socket). Everything runs on the checked image's ID,
  and right before starting the same plan is checked again and compose's `services.app.image`
  must resolve to that same ID (a pull that re-points the tag in between = refusal). One lifecycle
  operation runs at a time (`.deploy.lock`, per install directory: one kit per volume). An
  image without a version label is of an unknown version unless the operator declares it 3.8.
- A host-side restore reports one of three outcomes: committed (the flag published and flushed),
  refused before any change, or uncertain; only the first two restart the app.
- Limits (stated, not hidden): until SQLCipher ships, the database file and its WAL are outside
  this rule; a rollback of the whole volume to a 3.7 copy is a genuine 3.7 volume; the forward-token
  HMAC keeps its key derived from `FK_legacy` until the re-encryption job exists.

**Enforced in**: `keys.py` `boot`, `classify`, `resolve_master_key`, `migrate_legacy`, `open_protected`, `acquire_lock`, `acquire_maint_lock`; `bootkeys.py` `prepare`, `check_legacy_staging`; `legacyvault.py` `prove_legacy_key`, `legacy_inventory`; `backup.py` `prove_legacy_secret`, `verify_legacy_import`, `verify_legacy_volume`, `restore_route`, `_extract_legacy_strict`, `StageProgress`; `hostops.py` `cmd_stage`, `_route`; `db.py` `connect_maintenance`, `_schema_of`, `_table_ddl`; `main.py` `lifespan`; `security.py` `init_crypto_keyring`, `decrypt_secret`; `backup.py` `set_boot_protected`, `volume_kind`, `raw_key_copies`; `admin.py` `NEEDS_LOCK`, `DB_ONLY`; `syshealth.py` `c_crypto_protection`, `c_crypto_legacy_copies`.
**Tests**: `boot_keys`, `keys`, `backup_protected`, `snapshot`, `host_backup_script`, `deploy_script`, `upgrade_script`, `schema_history`.
