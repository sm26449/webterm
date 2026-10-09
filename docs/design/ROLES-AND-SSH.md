# Roles (3.6.x) and native SSH access (3.7.x)

**Status:** Part A milestone **3.6.0 (roles core) implemented** — see §7 for the implementation
notes and the deviations from this text. 3.6.1/3.6.2 and Part B are still proposals.
**Written:** 2026-10-09, against `main` at `fa9f026` (WebTerm 3.5.16, agent 58).
**Audience:** the maintainer deciding scope, and whoever then builds it.

Every file and line reference below was checked against that commit. Line numbers will drift, but
the function names won't.

---

## 0. Summary

**Part A: roles (3.6.x)**

1. **Change the product stance openly.** `ARCHITECTURE.md` ("Why there is no RBAC"),
   `FUTURE-DIRECTIONS.md` and `THREAT-MODEL.md` §2 all say that roles would be "theatre". That
   is true for limits *inside* a host where the user already has a shell. It is not true for
   limits on *which hosts* a user can reach, or on whether they get a shell at all. 3.6 should
   restrict exactly those two things, and say plainly that every other permission is a
   convenience or guardrail once a user has a shell on the host. In the catalogue, each
   permission that amounts to a shell carries a **⚑ shell-equivalent** flag.
2. **Model: roles plus scoped bindings.** A *role* is a named set of permissions (the "what").
   A *binding* attaches one role to one user over one *scope*: all hosts, a folder, a tag, or a
   single host (the "where"). On a given host, a user's effective permissions are the union of
   every binding whose scope matches that host. There are no deny rules in 3.6, because a union
   is easier to reason about and explain. The `require_2fa` step-up stays as the one implicit
   "deny unless".
3. **Built-in roles:** Owner, Admin, Operator, Viewer. Custom roles come in 3.6.1.
4. **Migration:** every existing account becomes **Owner over all hosts**. A single-user install
   behaves exactly as before. You cannot delete or demote the last Owner. `python3 -m app.admin`
   gains a `promote` command as the break-glass path.
5. **Enforcement:** one new module, `gateway/app/authz.py`.
   - Each route declares its permission with `Depends(authz.perm("files.read", host="host_id"))`.
   - A router-level guard refuses at runtime any route that declares no permission. This is the
     fail-closed default.
   - `tests/route_auth_test.py` is extended so that every route must declare a permission, or be
     listed as `PUBLIC` or `SELF` with a stated reason.
6. **Check order:** authenticate, then authorize (404 if the host is not visible to you, 403 if
   it is visible but the permission is missing), then step-up. Step-up never grants a permission.
7. **Lists, searches, history, audit, alerts and status are filtered** by "hosts visible to this
   principal". This reuses the silent-filter pattern that `/api/search` and `/api/history`
   already apply to 2FA hosts.
8. **Automation tokens get a role and a scope.** Their effective permissions are capped by what
   their creator can do *now*. Tokens still cannot reach `require_2fa` hosts.
9. **WebSockets re-check permissions** in the existing 60-second revalidation loop. A role
   change also bumps an `authz_epoch`, which kicks the affected sockets and forward tickets
   immediately.
10. **SSO:** a table maps OIDC groups to roles and scopes. Bindings that came from SSO are
    re-synced at every login. Bindings added by hand are left alone.

**Part B: native SSH (3.7.x)**

11. **SSH server inside the gateway, built on asyncssh.** asyncssh is already a pinned dependency
    (2.24.0, used as the SSH client and for SFTP backups), so this adds **no new package**. Bump
    to **≥ 2.24.1** first: that release fixes server-side issues, including an auth race that
    could set the wrong authenticated username, and SFTP chroot escapes.
    - The server is opt-in through `WEBTERM_SSH_PORT` (default off; suggested value 2222).
    - It needs its own ed25519 host key. The fingerprint is shown in Settings.
12. **Target syntax:** `ssh -p 2222 web01@gw`. The public key identifies the account, so the SSH
    username is free to name the target. Suffixes add options: `web01+ro`, `web01+s=<sid>`.
    Connecting with no target, or an ambiguous one, opens an interactive picker.
13. **Authentication:**
    - Public keys stored per account. Adding a key goes through the same second gate as adding a
      passkey.
    - No password authentication.
    - `require_2fa` hosts are unlocked **in-band**. After key auth the terminal shows the same
      "locked" state as the browser. You unlock it with a TOTP code typed into the terminal, or
      by approving a short-code link in the browser with a passkey or SSO. Either way this opens
      the same per-(user, host) step-up window as the browser does.
14. **Sessions:**
    - An SSH shell is a normal WebTerm session: tmux-backed, recorded, listed in the UI and
      attachable from the browser.
    - Idle-lock and the 60-minute step-up cap apply unchanged. The SSH connection simply joins
      the session hub as another client.
15. **Phasing and agent bumps:**
    - **3.7.0 needs no agent bump:** interactive PTY to agent hosts, picker, keys, in-band 2FA,
      audit.
    - **3.7.1:** SFTP (which also covers modern `scp`) mapped onto the existing `fs_*` agent ops,
      plus `-L` forwarding onto `fwd_open`.
    - **3.7.2 needs agent 59:** a binary-safe `exec` op with real pipes. That is what makes
      `ssh host cmd`, `rsync`, `git` over SSH and legacy `scp -O` work.
    - **Later, optional:** a ProxyJump mode (`ssh -J`), SSH CA certificates, and SSH/jump hosts as
      targets.

The open decisions are collected in §5. Each has options and a recommendation. Appendix A is the
route-by-route permission matrix.

---

## 1. Context: what changes in the promise

Today:

- `docs/SECURITY-FEATURES.md:95` says: "every account is a full administrator over the whole
  fleet".
- `THREAT-MODEL.md` §2 says: "Multiple accounts buy **attribution**, not isolation".
- `tests/multi_account_test.py` asserts "no difference in rights between accounts".
- `FUTURE-DIRECTIONS.md` argues that a `role` column "would not be" honest, because a read-only
  user with a shell can read private keys.

That argument is correct, and the design keeps it. The boundary 3.6 adds is something the gateway
can actually enforce:

| Boundary | Enforced by | Real? |
|---|---|---|
| **Which hosts** you can see or touch at all | the gateway: it never relays a frame or op for an out-of-scope host | **Yes.** The agent only obeys the gateway. |
| **Whether you get a shell** on a host (session.open, run, files.write, …) | the gateway | **Yes.** Without these, there is no code-execution path. |
| Finer limits **once you have a shell** (e.g. "may open a terminal but not delete files") | the gateway's UI and API | **No.** It is a guardrail. A shell can `rm`. The role editor must say so: shell-equivalent permissions carry the ⚑ flag. |
| Instance administration (users, settings, backups, signing key) | the gateway | **Yes.** |

There is one sharp edge: **a host that runs the gateway itself.** A user with a shell on the
Docker host that runs WebTerm can read `webterm-data` and become Owner. §A.11 proposes marking
such hosts ("crown-jewel") and warning when someone binds a non-Owner role over them.

Docs to update in 3.6.0: `ARCHITECTURE.md` "Why there is no RBAC", `FUTURE-DIRECTIONS.md`
"Multi-user through isolation", `THREAT-MODEL.md` §2, `SECURITY-FEATURES.md`, and
`tests/multi_account_test.py`. That test's premise flips; it becomes "Owners are equal".

---

## Part A: Roles (3.6.x)

### A.1 Goals and non-goals

**Goals**

- Several people share one instance, each with a host scope (folder, tag or host) and a level
  (watch, operate, administer).
- Single-user and "everyone is admin" installs see zero behaviour change.
- New routes are denied by default, enforced both at runtime and in CI.
- The audit log can answer "who did what, on which host, with which role".

**Non-goals for 3.6**

- Mapping to Unix users on the target. The agent runs as one user; that is Teleport's `logins`
  concept, and we deliberately do not have it.
- Deny rules.
- Multi-tenancy, i.e. separate settings or SMTP per team.
- Access requests (described in §A.10, marked as later).

### A.2 Concepts

| Term | Meaning |
|---|---|
| **Principal** | Who is acting: a `user` (cookie), a `token` (Bearer `wt_…`), an `ssh` connection (3.7, which resolves to a user), or a `guest` (share or replay token, never a role holder). |
| **Permission** | A string id from the catalogue (§A.4). Either **global** (instance-level) or **host-scoped**. |
| **Role** | A named set of permissions. Built-in roles are immutable; custom roles can be edited. |
| **Scope** | `all` \| `folder:<name>` \| `tag:<name>` \| `host:<id>`. |
| **Binding** | (user, role, scope [, expires]). A user may have several. |
| **Effective permissions on host H** | The union of `role.perms` over bindings whose scope matches H. |
| **Global permissions** | Taken **only from bindings with scope `all`**. A global permission in a role bound to `folder:prod` is ignored, and the UI shows a warning. Otherwise "Admin on folder lab" would mean "admin of the whole instance". |

Comparison with the products we looked at:

- **Warpgate** binds users to roles, and targets allow roles.
- **Teleport** puts label selectors inside the role (`node_labels`).
- **Boundary** uses grant strings within scopes.

We take Warpgate's simplicity (role ↔ target set) and Boundary's separation of what from where:
the scope lives on the *binding*, not inside the role. Then "Operator" stays one role, reused as
"Operator on prod" and "Operator on lab", instead of being copied into N role variants.

### A.3 Data model

All changes follow the existing style: new tables in `SCHEMA` as `CREATE TABLE IF NOT EXISTS`, and
new columns as `ALTER TABLE … ADD COLUMN` appended to `MIGRATIONS` (`gateway/app/db.py`). A
"duplicate column" error is ignored; any other error stops boot (G-16).

```sql
-- roles: built-in rows are seeded (and re-asserted) at every boot; builtin=1 rows are read-only
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,                 -- 'owner'|'admin'|'operator'|'viewer' for builtins; NULL for custom
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    perms TEXT NOT NULL DEFAULT '[]',-- JSON array of permission ids (validated against the catalogue)
    builtin INTEGER NOT NULL DEFAULT 0,
    created REAL NOT NULL,
    updated REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS role_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    scope_kind TEXT NOT NULL,        -- all | folder | tag | host
    scope_value TEXT NOT NULL DEFAULT '',   -- '' for all; folder name; tag (lowercase); host id as text
    source TEXT NOT NULL DEFAULT 'manual',  -- manual | oidc | migration
    expires REAL,                    -- NULL = permanent; reserved for time-bound grants (§A.10)
    created REAL NOT NULL,
    created_by_id INTEGER,
    UNIQUE(user_id, role_id, scope_kind, scope_value)
);
CREATE INDEX IF NOT EXISTS idx_rb_user ON role_bindings(user_id);

-- OIDC group → (role, scope); editable in the UI, optionally bootstrapped from env
CREATE TABLE IF NOT EXISTS oidc_group_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grp TEXT NOT NULL,               -- exact group name from the `groups` claim ('*' = any authenticated)
    role_id INTEGER NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_value TEXT NOT NULL DEFAULT '',
    UNIQUE(grp, role_id, scope_kind, scope_value)
);
```

```python
# appended to MIGRATIONS (attribution + token roles + crown-jewel flag)
"ALTER TABLE api_tokens ADD COLUMN role_id INTEGER",           # NULL = legacy token → mapped from `scopes`
"ALTER TABLE api_tokens ADD COLUMN scope_kind TEXT DEFAULT 'all'",
"ALTER TABLE api_tokens ADD COLUMN scope_value TEXT DEFAULT ''",
"ALTER TABLE sessions ADD COLUMN created_by_id INTEGER",       # who opened it (NULL = pre-3.6)
"ALTER TABLE sessions ADD COLUMN origin TEXT DEFAULT 'web'",   # web | ssh | token (3.7 uses ssh)
"ALTER TABLE command_history ADD COLUMN user_id INTEGER",
"ALTER TABLE audit_log ADD COLUMN actor_id INTEGER",
"ALTER TABLE audit_log ADD COLUMN host_id INTEGER",            # filled by authz when the route is host-scoped
"ALTER TABLE audit_log ADD COLUMN via TEXT DEFAULT ''",        # cookie | token:<id> | ssh:<key fp>
"ALTER TABLE snippets ADD COLUMN created_by_id INTEGER",
"ALTER TABLE hosts ADD COLUMN crown_jewel INTEGER DEFAULT 0",  # §A.11
"CREATE INDEX IF NOT EXISTS idx_audit_host ON audit_log(host_id, ts)",
```

**Seeding (idempotent, in `db.connect()` after the migrations):**

1. Upsert the four built-in roles by `key`, rewriting their `perms` from the code catalogue. That
   way a new permission added in a later release reaches the built-ins automatically.
2. Run this only if `app_settings['rbac_seeded']` is absent: for every row in `users`, insert
   `(user, owner, all, source='migration')`. Then set `rbac_seeded=1`.
3. For every user with **no** bindings (for example one created by `admin.py` or by a restore from
   an older backup), log a warning. Do not grant anything: a user with no binding sees an empty
   fleet.

**Why the scope is a column and not JSON:** "who has access to folder prod?" becomes one indexed
query, which both the UI and the alerts fan-out need.

**Matching rules:**

- `folder` is a flat string column today (`hosts.folder`), so matching is exact. If folders later
  gain hierarchy, `folder:prod/*` can become a prefix match.
- `tags` is a comma-separated lowercase column. Matching tokenises it, using the same parser as
  `_tag_list`.
- `host:<id>` is an exact match.
- Ephemeral jump hosts (`hosts.ephemeral=1`) inherit the scope of their `via_host_id` parent.
  Otherwise "connect once" would create an out-of-scope host that nobody can see.

### A.4 Permission catalogue

⚑ = **shell-equivalent**: holding it on a host gives the agent user's full power there, directly
or in one step. The role editor shows the flag. Any role with at least one ⚑ permission on a host
should be treated as "has a shell there".

#### Host-scoped permissions (granted per host through bindings)

| Permission | Covers | ⚑ |
|---|---|---|
| `host.view` | See the host in lists, sidebar, dashboard and status counts; its name, online state, versions, update badge and supervision summary. **Every other host permission implies this one.** | |
| `host.diagnostics` | Events journal, agent log, diag probes (storage/net), listening ports, diagnostics refresh, host-key status. | |
| `session.watch` | Read-only attach to live sessions on the host (`client.writable=False`), roster. | |
| `recording.view` | Transcripts, previews, the host's transcript-search hits, command history, replay of closed sessions. | |
| `session.open` | Create a session, attach writable, reconnect, resize, kill own sessions; Docker "shell in container"; OS-upgrade-in-terminal. | ⚑ |
| `session.manage` | Rename, kill or delete **any** session on the host; kick guests. | |
| `files.read` | Browse, cwd, preview, download, archive. | |
| `files.write` | Upload (incl. resume), mkdir, rename, chmod; destination of a host-to-host copy. | ⚑ (can write `~/.bashrc`, `authorized_keys`) |
| `files.delete` | Delete files or folders. | |
| `run` | Run on hosts (single and fleet), `git` actions. | ⚑ |
| `docker.view` / `docker.act` | List and stats / start, stop, restart, remove. | (`act` is ⚑-adjacent: a container with host mounts) |
| `services.view` / `services.act` | List / start, stop, restart, enable. | |
| `forward.use` | Open forwarded apps (HTTP/WS proxy), probe, apps strip. | |
| `forward.manage` | Create, edit, delete forwards; telnet-forward sessions. **A network pivot**: it reaches anything the host can reach. | |
| `serial.use` | Discover and open serial consoles. | ⚑ (console = login prompt) |
| `toolbox.use` | List and launch saved DB connections (opens a session running the DB client). | ⚑ (it is a session) |
| `toolbox.manage` | Create, edit, delete DB connections, including stored credentials. | |
| `deploykey.manage` | Generate, deploy, revoke, rotate, verify and test deploy keys, write ssh-config. **Requires the permission on both the source and the target host.** | ⚑ (it grants durable SSH access) |
| `share.live` | Create or revoke a read-only live share for a session on the host. | |
| `share.live_write` | Make a live share **writable**, i.e. give an anonymous guest a keyboard. | ⚑ (by proxy) |
| `share.replay` | Create or revoke replay links for closed sessions on the host. | |
| `host.wake` | Wake-on-LAN. | |
| `host.edit` | Rename, note, credentials, SSH-host key generation, host-key accept, credential policy. Changing **folder or tags** also needs `hosts.create` at scope `all` (see §A.11). | |
| `host.admin` | `require_2fa` toggle, enroll renew, provision, agent update, autostart toggle, uninstall, delete, forget credentials. | ⚑ (provision/update) |
| `ssh.login` (3.7) | Use the SSH entry point for this host. Separate from `session.open`, so SSH can be enabled per role. | ⚑ |
| `ssh.forward` (3.7.1) | `-L` direct-tcpip to declared forwards on this host. | |
| `ssh.jump` (3.7.x) | ProxyJump to this host's own sshd (end-to-end; WebTerm cannot record it). | |

Derived capabilities, which deliberately have **no bit of their own**:

- **Host-to-host copy** needs `files.read` on the source and `files.write` on the destination.
  The user could already do the same thing by downloading and re-uploading, so a separate bit
  would be theatre.
- **OS updates** (apply) work through `session.open`. The upgrade runs in a terminal.
- **Transfers** (the floating widget and the inbox) work through `files.write` on the target host.

#### Global permissions (honoured only from a binding with scope `all`)

| Permission | Covers |
|---|---|
| `hosts.create` | Add host, import CSV, test connection, pending SSH key, enroll groups (create, list, revoke). Also needed to move a host between folders or tags. |
| `hosts.export` | CSV export. Filtered to visible hosts in any case. |
| `settings.manage` | Command guard, watermark, SMTP/webhook (+ tests), alert thresholds, forward domain, deploy-key policy, update-check toggle and refresh. |
| `users.manage` | Create and delete accounts; add and remove role bindings (subject to the no-escalation rule, §A.6.6). |
| `roles.manage` | Create, edit and delete custom roles (3.6.1). |
| `tokens.create` | Create and revoke **own** automation tokens, limited to own permissions. |
| `tokens.manage` | See and revoke **everyone's** tokens. |
| `shares.manage` | List and revoke all live shares and replay links (`/api/shares*`, `/api/replay-links/revoke-all`). |
| `snippets.manage` | Edit or delete snippets created by others. Snippets are a shared library; anyone can read them and create their own. |
| `history.clear` | `DELETE /api/history`, a global, irreversible wipe. |
| `audit.view` | The whole audit log (still filtered by host visibility). Without it, users see only their own entries. |
| `security.view` | The instance security summary, plus instance-level security alerts (new account, token created, signing key, …). |
| `backups.manage` | Backup download, restore, schedule, cloud. **Owner only**: a backup contains the vault key, so it is the whole instance. |
| `signing.manage` | Agent signing key: generate, import, unlock, lock, backup. **Owner only.** |

**Self-service** (any authenticated user, no permission needed): own account, password, TOTP,
passkeys, web sessions, alert preferences, split views, own alerts, version and changelog, the
shell-integration command, own SSH keys (3.7), and `/api/me/permissions`.

### A.5 Built-in roles

| | Owner | Admin | Operator | Viewer |
|---|---|---|---|---|
| Intended for | the instance owner(s) | team lead / co-admin | engineers doing the work | auditors, on-call watchers, managers |
| Host: view, diagnostics | ✓ | ✓ | ✓ | ✓ |
| Host: session.watch, recording.view | ✓ | ✓ | ✓ | ✓ |
| Host: session.open, session.manage ⚑ | ✓ | ✓ | ✓ (manage: own only, see Q5) | — |
| Host: files.read / write / delete | ✓ | ✓ | ✓ | — (see Q4) |
| Host: run ⚑ | ✓ | ✓ | ✓ | — |
| Host: docker / services view | ✓ | ✓ | ✓ | ✓ |
| Host: docker / services act | ✓ | ✓ | ✓ | — |
| Host: forward.use | ✓ | ✓ | ✓ | ✓ |
| Host: forward.manage | ✓ | ✓ | — | — |
| Host: serial.use, toolbox.use ⚑ | ✓ | ✓ | ✓ | — |
| Host: toolbox.manage, deploykey.manage | ✓ | ✓ | — | — |
| Host: share.live, share.replay | ✓ | ✓ | ✓ | — |
| Host: share.live_write | ✓ | ✓ | — | — |
| Host: host.wake | ✓ | ✓ | ✓ | — |
| Host: host.edit, host.admin | ✓ | ✓ | — | — |
| Host: ssh.login (3.7) | ✓ | ✓ | ✓ | — |
| Global: hosts.create, hosts.export | ✓ | ✓ | — | — |
| Global: settings.manage | ✓ | ✓ | — | — |
| Global: users.manage | ✓ | ✓ (cannot touch Owners) | — | — |
| Global: roles.manage | ✓ | ✓ (no-escalation) | — | — |
| Global: tokens.create | ✓ | ✓ | ✓ | — |
| Global: tokens.manage, shares.manage, snippets.manage | ✓ | ✓ | — | — |
| Global: audit.view, security.view | ✓ | ✓ | — | — |
| Global: history.clear | ✓ | — | — | — |
| Global: backups.manage, signing.manage | ✓ | — | — | — |

Notes:

- Owner is the only role that can create or remove Owner bindings.
- Admin is "everything except taking over the instance". Backup download or restore and the
  signing key are exactly the takeover paths: the vault key and fleet code-signing.
- Operator and Viewer only make sense with a scope. The Users & roles UI pre-selects
  `folder`/`tag` for them, not `all`.
- Example custom roles shipped as presets in 3.6.1 (not built-ins): **Auditor** (`audit.view`,
  `recording.view`, `host.view`; no live sessions) and **Files-only** (`files.read`, `files.write`).
  The Files-only preset is labelled as shell-equivalent through `files.write`.

### A.6 Enforcement design

#### A.6.1 One module, one dependency

`gateway/app/authz.py` (new):

```python
@dataclass(frozen=True)
class Principal:
    kind: str                 # user | token | ssh
    user_id: int | None       # token → creator id (created_by_id); ssh → the key's account
    email: str
    token_id: int | None = None
    user_row: Any = None      # the sqlite Row require_user returned (step-up helpers need it)

PERMS: dict[str, PermSpec]    # the catalogue: id → (global|host, shell_equiv, i18n key)

async def effective(principal) -> Grants:      # cached per (user_id, authz_epoch)
    ...                                        # Grants.global_perms: set; Grants.host(hid) -> set

def perm(name: str, *, host: str | None = None, any_host: bool = False):
    """FastAPI dependency factory. `host` names how to find the host id for this route:
       'host_id' (path param) | 'sid' (sessions.host_id) | 'fid' (port_forwards.host_id)
       | 'conn_id' | 'link_id' (replay_links → sessions.host_id) | 'body:src_host_id,dst_host_id'.
       `any_host=True` = list/filter routes: passes if the permission exists on ≥1 host and puts
       Grants on request.state for the handler to filter with."""
```

How it composes with what exists today:

- `perm()` **calls `security.require_user` or the token principal itself**, so a route has
  exactly one auth dependency. `require_scope("read"|"run")` becomes a thin alias:
  `perm("host.view", any_host=True, tokens=True)` and `perm("run", host="host_id", tokens=True)`.
  Routes that do not pass `tokens=True` reject Bearer tokens, which keeps today's allowlist
  semantics.
- The handler keeps its existing `_require_host_stepup(...)` / `_require_fresh_factor(...)` call
  **after** the dependency. Order: authn → authz → step-up → action. Step-up therefore never
  runs for a principal who lacks the permission. That also prevents an oracle: today, a 403
  `stepup.*` tells you the host exists and is 2FA.
- **404 vs 403.**
  - A host that is not visible (no `host.view` there) → `404 host.missing`. This is the same
    response as a non-existent id, so there is no existence oracle.
  - A host that is visible but lacks the permission → `403 authz.denied`, with
    `vars={"perm": "files.write"}`, so the UI can say what is missing.
- **Caching.** `effective()` reads `role_bindings` + `roles` + the host's folder and tags. It is
  cached in-process, keyed by `(user_id, authz_epoch)`.
  - `authz_epoch` is a module integer, bumped on any write to roles, bindings or OIDC mappings,
    and on any change to a host's folder or tags.
  - The gateway is a single uvicorn process (Dockerfile `CMD`; `--workers` is deliberately not
    used), so an in-memory epoch is correct.
  - `python3 -m app.admin` runs in another process. It writes `app_settings['authz_epoch']`, and
    the 60-second janitor picks that up.

#### A.6.2 Fail-closed for new routes

These are two separate nets, because a test only guards CI while a runtime guard also covers a
hot-patched build.

1. **Runtime.** `router = APIRouter(dependencies=[Depends(authz.declared)])` on all three
   routers. `declared` reads `request.scope["route"].endpoint` and checks that it is either
   marked by `perm()`, or in `authz.PUBLIC` / `authz.SELF` (tables that move out of the test and
   into code). If it is neither, it returns `500 authz.undeclared` and logs an error. Fail closed:
   a route someone forgot is unusable, not open.
2. **CI.** `tests/route_auth_test.py` already enumerates every route of every router mounted in
   `main.py` and fails on unguarded ones. It gets a new check: "every non-PUBLIC route has
   exactly one `perm(...)` dependency, or is in `SELF`". `SELF` entries carry a reason, like
   `PUBLIC` entries do today. A second new check: "every `host=` locator names a real path or
   body parameter of that route", which catches `host="hostid"` typos.

#### A.6.3 Lists and cross-host information

These routes return data about more than one host. Each one filters with
`grants.hosts_with(perm)`. They filter silently, never with a 403, following the precedent in
`search()` and `search_history()`.

| Route | Leak today (for a scoped user) | Filtering rule |
|---|---|---|
| `GET /api/hosts` | every host, incl. hostname, user, port, folder, tags | `host.view` |
| `GET /api/status` | fleet totals, session counts by state | counts over visible hosts only; `storage`/`gateway` health only with `security.view` |
| `GET /api/sessions` | every session on every host | `session.watch` ∪ `recording.view` hosts |
| `GET /api/search` | transcript content across 500 sessions | `recording.view` hosts (∩ the existing 2FA window filter) |
| `GET /api/history` | commands + cwd from all hosts | `recording.view` hosts; `host_id IS NULL` rows only with `audit.view` |
| `GET /api/audit` | every action, command text, operator emails and IPs | `audit.view`: rows whose `host_id` is visible or NULL; without it: `actor_id = me` |
| `GET /api/alerts*` | per-user table already | the fan-out changes (§A.6.8), not the read |
| `GET /api/security/summary` | instance checks | with `security.view`: everything; else only own-account checks |
| `GET /api/apps` | every app-forward on the fleet | `forward.use` hosts |
| `GET /api/shares`, `GET /api/replay-links` | all shares / own links | own; all with `shares.manage` |
| `GET /api/tokens` | all tokens | own; all with `tokens.manage` |
| `GET /api/users` | all accounts | `users.manage`; others get `[self]` |
| `GET /api/enroll-groups` | all groups | `hosts.create` |
| `GET /api/snippets` | all | all (it is a shared library); a snippet's `targets.tags` stays a hint, not access |
| `GET /api/split-views` | already per user | a pane whose session is no longer visible renders as "no access" |
| `GET /api/hosts/export.csv` | all hosts | `host.view` ∩ `hosts.export` |
| `GET /api/fs/copy/{job}` | any job by id | the job's creator (jobs carry `user_id`), or Owner |
| `/api/hosts/{id}/connections` | | per host, `toolbox.use` |
| WS roster (`broadcast_roster`) | who is attached (emails, IPs) | unchanged: you already have the session |

#### A.6.4 WebSockets and the forward proxy

| Endpoint | Today | 3.6 |
|---|---|---|
| `/ws/sessions/{sid}` (`browser_ws`, api.py:9149) | `require_user_ws`; any account can attach to any session | Resolve the host from the session. `session.open` → writable owner client. Else `session.watch` → `client.writable=False` (the frontend already supports read-only guests). Else `recording.view` and the session is closed → replay only. Else close with 4404. The 60-second `_revalidate` (api.py:9307) also re-runs `effective()`. A downgrade from open to watch flips `writable` live; a loss of access closes with 4403. |
| `/ws/shared/{token}` (`shared_ws`) | the token is the credential | Unchanged for guests. **But** a share is revoked when its creator loses `share.live` on that host (bindings change → `_revoke_all_shares(owner_id=…)` filtered by host). A writable share is downgraded when the creator loses `share.live_write`. |
| `/agent/ws` | host token | Not a user principal; RBAC does not apply. Agent-originated events (alerts, diagnostics, reconcile) fan out by role (§A.6.8). |
| Forward proxy (`route_forward` + `ForwardWSMiddleware`, `/__wtfwd/auth`) | HMAC ticket `(slug, exp, uid)`, 12h TTL; 2FA hosts also check the window | `/__wtfwd/auth` issues a ticket only with `forward.use` on the forward's host. Because the ticket outlives role changes, `route_forward` and `handle_forward_ws` re-check `forward.use` for the ticket's `uid` (cached by epoch, so it is a dict lookup). A binding change also calls the existing `security.bump_forward_epoch(user_id)`. |

#### A.6.5 Automation tokens

- New tokens get `role_id` + scope. The UI offers built-in roles and "custom subset", and the
  scope can be narrower than the creator's.
- **Effective permissions = token role ∩ creator's current effective permissions.** If the
  creator is demoted, the token shrinks. If the creator is deleted, the token dies. `delete_user`
  already deletes `api_tokens` by `created_by_id`/`created_by` (api.py:~845); keep that, and also
  treat a token whose creator has no bindings as having no permissions.
- Legacy tokens (`role_id IS NULL`): `read` → `{host.view}` at scope `all`; `run` → `{host.view,
  run}`. Both are then capped by the creator. The tokens of an instance that upgrades keep working
  unchanged, because every creator becomes Owner.
- Kept as-is:
  - tokens never satisfy step-up, so they cannot reach `require_2fa` hosts;
  - tokens are accepted only on routes whose `perm()` says `tokens=True`. That stays a short
    explicit allowlist: status, hosts, sessions, run, plus later what Q12 decides.
- `security.require_scope` currently returns `{"id": None, …}`. With `authz.Principal`, the token
  finally has an `actor_id` (its creator) and `via=token:<id>` in the audit log.

#### A.6.6 Managing users and roles: no escalation

These rules are enforced server-side in the binding and role endpoints:

1. You can bind role R at scope S only if **R.perms ⊆ your effective perms at every host in S**
   (global perms: ⊆ your global perms) **and S ⊆ your scope**. An Admin over `folder:lab` cannot
   make anyone Operator over `all`.
2. Only Owners can create, remove or edit Owner bindings.
3. You can **never** add a binding to yourself.
4. The last Owner cannot be removed, demoted or deleted. This extends today's "cannot delete the
   last account".
5. A custom role that holds a permission you lack cannot be edited by you.
6. Binding changes are credential-class changes. They need `_verify_reauth_password` plus
   `webauthn_api.second_gate`, as `create_user` does today. They are audited and fire
   `notify_security_change` to holders of `security.view`.

#### A.6.7 Step-up interplay

Nothing changes in `_require_host_stepup`, `_require_fresh_factor` or the window semantics
(5-minute sliding window, 60-minute absolute cap). The one rule is that `perm()` runs first.

`POST /api/hosts/{id}/stepup` needs `host.view`. Otherwise the step-up ceremony itself would leak
which hosts exist and are 2FA.

#### A.6.8 Background work and alerts fan-out

- `alert_history._target_users(scope, …)` (alert_history.py:~150) currently returns **all**
  users for fleet- and instance-scoped kinds. The comment in `db.py` says so: "nu există roluri".
  It changes to:
  - account kinds → the user, as today;
  - host kinds (offline, hostkey changed, unlocked, guardrail, auto-enroll on a host, …) →
    users with `host.view` on `host_id`;
  - instance/security kinds → users with `security.view`.
  - Email and webhook follow the same recipient set. The webhook is instance-wide, so it only
    fires for events that have at least one `security.view` recipient, or that are host events
    (configurable later).
- `fscopy` jobs record `user_id`. `retry` re-checks the permission on both hosts. A job already
  running keeps running when the permission is revoked; cancel-on-revoke is an open question
  (Q10).
- The janitor and reaper are not principals; they are unaffected.
- `email_alerts.notify_session_attach` goes to the attaching user, as today.
- New alert kind `rbac_changed`: tells the affected user "your access changed" and tells
  `security.view` holders what changed.

#### A.6.9 Audit attribution

- `audit.record(...)` gains `actor_id`, `host_id` and `via`. The middleware takes them from
  `request.state.principal` and `request.state.audit_host`, both set by `perm()`.
- Denials (403/404 from authz) are already recorded when an actor is present. That is the
  intended signal: a cookie that keeps probing hosts it cannot see.
- WS attach rows (api.py:~9268) also get `actor_id` and `host_id`.
- `sessions.created_by_id` answers "who opened this shell" directly. Today that needs a join on
  the audit path.

### A.7 SSO / OIDC

- **Mapping:** the `oidc_group_roles` table, edited in Settings → Users & roles → SSO mapping.
  Optional bootstrap: `WEBTERM_OIDC_ROLE_MAP="ops=operator@folder:prod;admins=admin@all"`, read
  only when the table is empty, so the UI stays the source of truth afterwards. `oidc.py`
  already extracts `groups` (`_claims_groups`).
- **At every SSO login** (`oidc_api.callback`, login branch): compute the desired set from
  `groups`, then **replace all bindings with `source='oidc'`** for that user in one transaction.
  `manual` bindings are untouched. If the result changed, bump `authz_epoch`.
- **JIT provisioning:**
  - A new SSO user is created as today.
  - If their groups map to **no** role, they get no bindings: logged in, empty fleet, with an
    "ask your admin" state.
  - An alternative is to refuse the login (Q7). We already have `OIDC_ALLOWED_GROUPS` for hard
    gating, so the recommendation is to allow login with no access. That is easier to debug,
    and the callback logs the groups it saw.
- **Groups removed in the IdP** take effect at the next login. Until then, the web session lives
  at most `WEB_SESSION_TTL` / idle. Options to tighten this are in Q8: a shorter session TTL for
  SSO users, or re-checking at step-up. **Recommendation:** re-sync at every SSO step-up as well.
  Step-up already round-trips to the IdP and returns a fresh `id_token` with `groups`, so the
  sensitive moments get fresh group data at no extra cost.
- **Adoption of an existing local account by `sub`** (an existing path) keeps its manual
  bindings. The migration made all existing users Owner, so adopting the admin by email keeps
  Owner. That is correct, and it is documented.
- Warpgate offers `roles_claim`/`role_mappings` and a `'*'` wildcard. We take the wildcard
  (`grp='*'` = any authenticated SSO user, for example "Viewer over tag:public"). We do not take
  a dedicated `warpgate_roles`-style claim: groups are what Authentik and others emit by default.

### A.8 Migration and zero-change guarantee

- Every existing user → Owner @ all (`source='migration'`). Existing tokens keep working (§A.6.5).
- `setup` (the first account) → Owner @ all.
- `create_user` (Settings) → the creator chooses role + scope in the same dialog. The default is
  **Viewer with no scope** ("no access yet"), never Owner by default.
- `admin.py`:
  - `list` shows bindings;
  - new `promote <email>` (→ Owner @ all) and `roles <email>` subcommands for break-glass.
  - Both write `authz_epoch` into `app_settings`.
- Backups contain the new tables automatically (it is the same SQLite). Restoring a 3.5 backup on
  3.6 runs the seeding again, because `rbac_seeded` is absent in it.
- Rolling back from 3.6 to 3.5 is safe: the extra tables and columns are ignored by old code.
  The only behaviour lost on rollback is RBAC itself. **Say this in the 3.6.0 changelog**: a
  rollback silently makes every account admin again.

### A.9 UI

- **Settings → Users & roles** replaces the account list in `AccountTab.tsx`. Split it out as
  `settings/UsersTab.tsx`, following the `SettingsModal` split pattern. It holds:
  - users with their bindings shown as chips ("Operator · folder prod");
  - add or remove bindings (scope picker: All / Folder / Tag / Host, with autocomplete from the
    host list);
  - pending invites (later).
- **Role editor** (3.6.1, custom roles):
  - permissions grouped as in §A.4, with ⚑ badges;
  - a live "this role can give a shell" banner whenever any ⚑ permission is ticked;
  - a diff against a built-in role.
- **"Explain access":** `GET /api/authz/explain?user=&host=` returns
  `[(binding, role, perms)]` plus the effective set. It is shown in the user drawer ("Why can
  Ana open files on web01?"). It is also the debugging tool for SSO mapping.
- **Frontend gating:** `GET /api/me/permissions` returns `{global: [...], hosts: {id: [...]}}`.
  It is polled with the host list and invalidated by an `authz_epoch` field already present in
  that response.
- **Hide vs disable:**
  - **Hide** a feature that the user has on **no** host (for example the Settings → Backup tab
    without `backups.manage`, or the Run console without `run` anywhere).
  - **Disable with a tooltip** a control that the user has on some hosts but not this one (for
    example "Upload — you can read files on this host but not write them (role: Viewer)").
  - Never hide the reason: an unexplained missing button produces a support question.
  - The server enforces regardless. The UI gating is cosmetic.
- **No-access states:**
  - empty fleet → "You don't have access to any host yet. Ask an Owner or Admin." Include the
    names of users with `users.manage`, so the person knows who to ask;
  - a 404 on a deep link to a host → a "not found or no access" page, deliberately ambiguous.
- **Read-only terminal:** a `session.watch` attach shows a "watching (read-only)" pill. The
  keyboard is inert, matching today's read-only guest.
- The **walkthrough and help** (3.4/3.5) need a Roles page in `docs/` and in in-app help.

### A.10 Later (proposed, not in 3.6.0)

- **Time-bound bindings.** `role_bindings.expires` exists from day one. The janitor deletes
  expired rows and bumps the epoch. The UI offers "for 4h / 1d / 7d". This is cheap and useful,
  so it is targeted at 3.6.2.
- **Access requests (just-in-time).** In the style of Teleport and Warpgate 0.29:
  - a user requests (role, scope, duration, reason);
  - approvers (holders of `users.manage` over that scope, never the requester) approve in the UI
    or through the alert email link;
  - approval creates an expiring binding.
  - Teleport keeps the full web flow in Enterprise; we would ship a small version. Target 3.8 or
    later, if there is demand.
- **Per-session approval** (Warpgate "require administrator approval for each connection") as a
  per-host flag. It shares mechanics with the SSH web approval (§B.5), so it is cheap after 3.7.
- **Per-role recording policy.** Recording is always on today, which is good. Possible policies:
  "watchers of this role cannot open replay links", "sessions opened by role X are kept N days
  longer", "role X requires a live observer" (Teleport moderated sessions are Enterprise-only and
  heavy). Recommendation: not before someone asks.
- **Deny rules.** Only if a real case appears that a narrower scope cannot express.

### A.11 Security considerations

1. **Folder and tag edits change access.** Moving a host into `folder:lab` grants every
   lab-Operator a shell on it. So `host.edit` alone cannot change folder or tags; that needs
   `hosts.create` @ all. Enroll groups land hosts in a folder (`enroll_groups.folder`), so they
   need `hosts.create` too.
2. **Crown-jewel hosts.** A host that runs the gateway (or holds its backups) equals Owner.
   - Add a `hosts.crown_jewel` flag (manual, plus a hint when the agent's diagnostics show the
     `webterm-data` volume or the container).
   - Binding a non-Owner role with any ⚑ permission over a scope that contains it shows a
     blocking confirmation and is audited.
3. **Deploy keys spread trust.** A key from A deployed to B lets anyone with a shell on A reach
   B. So `deploykey.manage` needs the permission on **both** hosts. The deploy-key graph view
   must flag edges whose source scope is wider than the target scope ("anyone who is Operator on
   lab can reach prod-db").
4. **Jump hosts.**
   - Creating or using an `ssh-jump`/`telnet-jump` host needs `forward.manage` on the `via` agent
     host, because it opens TCP from that host.
   - Using an existing jump host needs `session.open` on the jump host itself.
   - Ephemeral jump hosts inherit the via host's scope (§A.3).
5. **Forwards are a network pivot.** `forward.manage` is not in Operator. `forward.use` is gated
   per request (§A.6.4).
6. **Writable shares hand a keyboard to an anonymous guest.** That is why `share.live_write` is a
   separate permission. When a binding changes, the creator's shares are re-evaluated.
7. **Tokens cannot exceed their creator**, and they die with the creator's account (already
   true in `delete_user`; it must stay true).
8. **Stale privileges.** The cache is keyed by epoch. WebSockets re-check every 60 seconds plus
   on an epoch bump. Forward tickets re-check per request. Step-up windows are per (user, host)
   and grant nothing by themselves.
9. **Oracles.** Out-of-scope hosts give 404, and the check runs before step-up. Search, history
   and audit filter silently. The `explain` endpoint is limited to `users.manage` (for others)
   and to self.
10. **Guardrail (command guard) and watermark** are instance settings (`settings.manage`). Making
    the guardrail per-role ("Operators get the strict rule set") is a natural follow-up, not in
    3.6.0.
11. **Snippets are shared.** A malicious snippet could trick an Owner into running something.
    Show the creator on each snippet (`snippets.created_by_id`). Only `snippets.manage` can edit
    other people's snippets.
12. **SQL filtering.** Visible-host filtering must happen in SQL, or in Python before any content
    is read (`search_transcripts` reads files). Never filter after the expensive read: that is
    both a timing leak and a DoS amplifier.

### A.12 Test strategy (3.6)

- **`route_auth_test.py` extended** (§A.6.2): every route has exactly one `perm()` or is
  `PUBLIC`/`SELF`; host locators are valid.
- **New `rbac_matrix_test.py`, generated from Appendix A as data.** For each (route, method),
  call it as:
  - Owner,
  - Viewer @ host,
  - Operator @ other-folder,
  - a no-binding user,
  - a token,
  
  and assert the expected 2xx / 403 / 404. The matrix in this doc and the test data come from the
  same table: `authz.ROUTE_PERMS` is exported, and the doc appendix is regenerated from it by a
  script. This keeps the doc honest.
- **`rbac_filter_test.py`:** lists, search, history, audit, apps, status counts and the alert
  fan-out, with two folders and two users.
- **`rbac_escalation_test.py`:** each no-escalation rule (§A.6.6), the last-Owner protections,
  token ∩ creator, a token surviving the creator's deletion (it must not).
- **`rbac_ws_test.py`:** read-only attach drops input bytes; a role downgrade flips `writable`
  within one revalidation tick; revocation closes the socket; a share is revoked when its
  creator loses `share.live`; forward ticket re-check.
- **`rbac_oidc_test.py`:** group mapping, re-sync at login and at step-up, manual bindings kept,
  wildcard, no-group user.
- **`rbac_migration_test.py`:** a 3.5.16 DB fixture → every user Owner, tokens unchanged, idempotent
  across reboots, restore of an old backup.
- **Playwright** (`scripts/ci-local.sh … e2e`): Viewer UI (no upload button, read-only pill,
  empty-fleet state), Users & roles tab.
- **Mind the docs-counts gate:** adding e2e-session `check()`s requires bumping README and
  CONTRIBUTING in the same commit.
- **Dedicated post-implementation security review before 3.6.0 ships.** It runs on a disposable
  mirror, as in the 2026-10-04 pentest. Its specific goals:
  1. a Viewer reaching a shell by any path (WS flags, docker exec `cmd`, toolbox, serial, git,
     upgrade-in-terminal, share-writable, deploy key);
  2. a scoped user learning about out-of-scope hosts (ids, names, counts, timing);
  3. escalation through bindings, tokens, SSO, or folder/tag edits;
  4. stale access after revocation (WS, forward ticket, step-up window, fscopy job).

---

## Part B: Native SSH through WebTerm (3.7.x)

### B.1 Goals and non-goals

**Goals**

- `ssh -p 2222 web01@term.example.com` gives a WebTerm session on an agent host. It uses the
  user's own terminal, keys and muscle memory, with the same roles, 2FA, recording and audit as
  the browser.
- Later: `sftp`/`scp`, `-L` forwards, `ssh host cmd`, `rsync`.

**Non-goals**

- Replacing the hosts' own sshd.
- Mapping to Unix login users: the agent runs as one user.
- Agent forwarding, X11, remote (`-R`) and dynamic (`-D`) forwarding.
- Password authentication.

### B.2 Library: asyncssh (recommended) vs paramiko

| | **asyncssh** | paramiko |
|---|---|---|
| Already a dependency? | **Yes.** `asyncssh==2.24.0` in `requirements.lock`; used by `core.dial_ssh`, `dial_ssh_jump`, `_PinnedHostKeyClient`, `backup_dest` SFTP | No (new package + transitive deps + pip-audit surface) |
| Concurrency model | asyncio. It runs in the same event loop as the hubs, so an SSH channel can be a hub client directly | A thread per connection, with blocking callbacks. Needs a thread↔loop bridge for every byte |
| Server API | `SSHServer.begin_auth`, `validate_public_key`, `kbdint_auth_supported`/`get_kbdint_challenge`/`validate_kbdint_response`, `session_requested`, `connection_requested` (direct-tcpip), `server_requested` (refuse), `sftp_factory`, `allow_scp`, `login_timeout` | `ServerInterface.check_auth_publickey`, `check_auth_interactive`, `check_channel_*` |
| Licence | EPL-2.0 OR GPL-2.0-or-later (already accepted, since we ship it today) | LGPL-2.1 |
| Security history | CVE-2023-46445/46446 (fixed 2.14.1), Terrapin CVE-2023-48795 (strict kex, 2.14.2), SCP traversal (2.23.1). **2.24.1 (Oct 2026)** fixes a server-auth race that "could result in the wrong username being set as the authenticated user", SFTP chroot escapes, options leaking across auth attempts, and packet-length DoS | Auth bypass CVE-2018-1000805, Terrapin fixed in 3.4.0 |
| PROXY protocol | Not native (nothing found in the docs or changelog). We parse the header ourselves (below) | Not native either |

**Recommendation: asyncssh, pinned ≥ 2.24.1.**

- Do the bump in its own commit before 3.7.0, with hashes in `requirements.lock`, following the
  pip-audit release-gate recipe.
- Exposing the asyncssh *server* to the internet puts new code paths in play. Our current use is
  client-only, to targets we chose. So the security-scan cron and pip-audit gate become more
  important. Subscribe to asyncssh releases.

**Server hardening:**

- `kex_algs`, `encryption_algs`, `mac_algs` restricted to modern sets (curve25519, chacha20-poly1305,
  aes-gcm, etm MACs).
- Strict kex on.
- `login_timeout=30`.
- `allow_scp=False` until 3.7.2.
- `agent_forwarding` and `x11_forwarding` refused.
- `server_requested` → False.
- `connection_requested` refused until 3.7.1.
- `max_auth_attempts` low (asyncssh: count failures in our `validate_*` and disconnect).
- Keepalive (`keepalive_interval=30`, `keepalive_count_max=3`), so dead NAT'd clients are reaped.

### B.3 Listener, host key, deployment

- **In-process.** `asyncssh.create_server(...)` is started in `main.lifespan` next to the janitor
  and reaper, and stopped on shutdown.
  - It must be the same process: hubs, step-up windows and `core.sources` are in-memory.
  - Config: `WEBTERM_SSH_PORT` (default `0` = off), `WEBTERM_SSH_PUBLIC_HOST` (what to print in
    the UI, default the `PUBLIC_URL` host), `WEBTERM_SSH_PROXY_PROTOCOL` (default off).
- **Host key.**
  - Generate `data/ssh_host_ed25519_key` (0600) at first start with the server enabled.
    Optionally also generate an RSA-3072 key for old clients (Q15). Store it encrypted with the
    vault like other secrets, or as a 0600 file next to `data/secret` (Q16).
  - It is included in backups. Without that, a restore would change the fingerprint and train
    users to ignore warnings.
  - Shown in **Settings → SSH access**: fingerprint (SHA256), a copyable `known_hosts` line
    (`[term.example.com]:2222 ssh-ed25519 AAAA…`), and the SSHFP DNS record.
  - Also returned by `GET /api/ssh/info` (authenticated).
  - Rotation: Owner-only "rotate host key", which serves old and new keys for a grace period
    through OpenSSH `hostkeys-00@openssh.com` (asyncssh can send multiple host keys; verify this
    during implementation), then drops the old one.
- **Docker / compose.**
  - *Caddy stack* (`docker-compose.yml`): add `ports: ["2222:2222"]` on `app` only when enabled.
    The installer asks. Caddy's L4 support needs a plugin (caddy-l4), which we do not ship, so
    use a direct publish.
  - *Traefik stack* (`docker-compose.prod.yml`): add a TCP entrypoint `ssh` on `:2222` and a
    router `HostSNI(\`*\`)` → service `app:2222` with `proxyProtocol: {version: 2}`. Set
    `WEBTERM_SSH_PROXY_PROTOCOL=1`.
  - Caveat: with Docker's userland-proxy (IPv6, or `userland-proxy: true`), a direct publish may
    show the bridge IP as the client. Document `"userland-proxy": false` / iptables DNAT, or use
    the Traefik path.
- **PROXY protocol and the real client IP.**
  - Accept the raw socket with `asyncio.start_server` ourselves.
  - If the peer is in `TRUSTED_PROXY_CIDRS`/`_peer_is_trusted` (the same function as XFF), read
    and strip a PROXY v1/v2 header (≤ 232 bytes, 3-second timeout). If the peer is not trusted,
    a PROXY header is a protocol error and the connection is closed.
  - Then hand the socket to asyncssh. To verify during the spike: the exact asyncssh entry point
    for running a server on an existing socket (`asyncssh.run_server(sock, …)` or
    `connect_reverse`-style). Fallback: a tiny in-process relay. Plan a 1-day spike.
  - The resulting IP feeds rate limits, audit, `seen_logins` and alerts.
- **Rate limiting and brute force.**
  - Reuse `security.login_allowed` / `record_login_failure` with keys `ssh-ip:<ip>` and
    `ssh-acct:<id>`.
  - Add a cap on concurrent unauthenticated connections (global 64, per IP 8), plus the global
    tarpit (`apply_global_tarpit`).
  - A public-key offer that matches no account is a failure: one failure per offered key, so a
    client with 20 keys in its agent is not locked out by key-probing. Count per connection and
    per IP, not per key.
  - **Fix the "probe for registered keys" oracle:** asyncssh answers `PK_OK` only when we say a
    key is acceptable. Answer the same way for unknown keys until the signature check (asyncssh's
    `validate_public_key` is called with signature verification; confirm it does not leak during
    the spike).

### B.4 Target selection

**Syntax.** The SSH username carries the target, because the **public key** identifies the
WebTerm account (keys are unique across accounts).

| You type | Meaning |
|---|---|
| `ssh -p 2222 web01@gw` | new session on host `web01` (case-insensitive name; must be unique among visible hosts) |
| `ssh -p 2222 '#12@gw'` | host id 12 (for duplicate names) |
| `ssh -p 2222 web01+s=ab12cd@gw` | attach to an existing session (sid prefix, ≥ 6 chars, must be on web01) |
| `ssh -p 2222 web01+last@gw` | reattach to my most recent live session on web01 |
| `ssh -p 2222 web01+ro@gw` | watch read-only (with `+s=`); needs only `session.watch` |
| `ssh -p 2222 gw` (username = local login, matches no host) or `ssh -p 2222 pick@gw` | **interactive picker**: an arrow-key menu of visible hosts (online first, folder headers) and my live sessions, then a 2FA unlock if needed |

**Why not Warpgate's `user:target@host`?**

- WebTerm accounts are emails, and `stefan@x.com:web01@gw` is awful to type.
- With key auth the account part is redundant.
- We **accept** the `:` and `#` forms anyway for Warpgate muscle memory (`anything:web01` or
  `anything#web01` → `web01`). The prefix is ignored after checking that it equals the key
  owner's email local part, or is empty. Q13.

**`~/.ssh/config` snippet** shown in Settings → SSH access:

The UI generates one explicit block per favourite host. It does not rely on `%`-tokens, which
are not portable across clients:

```
Host web01.wt
  HostName term.example.com
  Port 2222
  User web01
```

**Which hosts are targets?**

- **3.7.0: agent hosts** (`connection_type='agent'`), the only kind with tmux persistence and
  the full op set.
- **3.7.x:** direct-SSH and `ssh-jump` hosts. These already work as `SessionSource`s
  (`SshSource`, `SshJumpSource`), so the PTY path is generic through `core.create_session` →
  `source_for(host_id)`. What is missing is the per-type 2FA and credential-policy prompts
  (`credential_policy='ask'` needs an in-band password prompt).
- **Telnet and serial:** possible through the same hub mechanics; low priority.

### B.5 Authentication

**Keys**

- New table:

  ```sql
  CREATE TABLE IF NOT EXISTS user_ssh_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      public_key TEXT NOT NULL,        -- single validated line (reuse the deploy-key validator)
      fingerprint TEXT NOT NULL UNIQUE,-- SHA256:…; UNIQUE = one key ↔ one account
      key_type TEXT NOT NULL,
      created REAL NOT NULL,
      last_used REAL,
      last_ip TEXT DEFAULT '',
      expires REAL                     -- optional
  );
  ```

- Allowed types:
  - `ssh-ed25519`, `ecdsa-sha2-nistp256/384`, `rsa-sha2-*` with ≥ 3072 bits;
  - `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com` (FIDO security keys).
- Adding or removing a key is a credential change:
  - `_verify_reauth_password` + `second_gate`, as for passkeys;
  - SSO users use an SSO step-up;
  - alert `ssh_key_added`;
  - audit entry.
- Deleting an account deletes its keys and **kills its live SSH connections**. A registry
  `ssh_conns[user_id]` is closed by `delete_user`, `logout-all` (admin CLI: it runs in another
  process, so it writes an epoch the main loop sees within 60 seconds), password change and
  key deletion.
- **Not in 3.7.0: an SSH CA** (accepting user certificates signed by an org CA, with principals =
  account email). It is a clean later add-on (`TrustedUserCAKeys`-style), and it fits
  FUTURE-DIRECTIONS' "SSH certificate authority" note. 3.7.x, if requested.

**Second factor on `require_2fa` hosts: in-band unlock (recommended)**

Key auth only proves "this account". On a 2FA host the session then starts **locked**, exactly as
`browser_ws` starts a hub locked when there is no step-up window (api.py:~9220). The terminal
shows:

```
web01 requires 2FA.
  • Type your 6-digit authenticator code, or
  • approve in the browser: https://term.example.com/approve/K7Q-4MD   (code K7Q-4MD, 120 s)
Waiting…
```

- **TOTP.** The digits typed go to the existing ladder (`_stepup_consume_factor`). That reuses
  the TOTP anti-replay (`verify_second_factor`) and the dedicated lockout key
  `stepup-totp:<uid>`.
- **Web approval** (Warpgate-style).
  - The link opens the SPA, which shows: "Approve SSH login to **web01** from **IP**, key
    **SHA256:…**, code **K7Q-4MD**?"
  - Approve runs the existing **passkey step-up** (`/api/webauthn/stepup/*`) or the SSO step-up.
    Success opens the normal step-up window for (user, host) and resolves the pending approval.
    The SSH side wakes up and unlocks.
  - The browser must be logged in as the **same** account as the key.
  - Approvals live in memory (`_ssh_approvals[code] = (user_id, host_id, conn_id, expiry)`) and
    are single-use, with a 120-second TTL.
  - The code is shown on both sides, so the user can confirm it is their own login. That is
    Warpgate's "security key" check against phishing by a parallel attacker.
- **Why in-band, and not keyboard-interactive at auth time?**
  1. It works identically for the *mid-session* idle-lock and the 60-minute cap. Those already
     lock the hub, so the SSH client needs exactly the same unlock UI anyway.
  2. It needs no 2FA logic in the SSH auth state machine. That is where asyncssh's past bugs were
     (options leaking across auth attempts, the username race).
  3. It works with every client. Some clients (or `BatchMode`) handle keyboard-interactive badly.
  4. The SSH connection is not "authenticated to the host" until unlock. No bytes flow to or
     from the agent while locked, because the hub suppresses output (as for browsers).
  - **Downside:** non-interactive channels (exec, SFTP) cannot show a prompt. Rule: on a 2FA
    host, exec and SFTP need an **already-open** step-up window (opened in the browser, or by an
    interactive SSH unlock within the window), or a keyboard-interactive TOTP at auth time. That
    keyboard-interactive TOTP is offered **only** when the requested username targets a 2FA host
    and the account has TOTP. Q14.
- **sk-* keys (FIDO).** The key needs a physical touch per signature, which is real user
  presence. Should an `sk-` key with the `verify-required` option (PIN or biometric) satisfy
  step-up on its own? It is cryptographically comparable to a passkey. **Recommendation: yes, as
  an opt-in per account** ("this security key counts as 2FA"). This is how Teleport treats
  `hardware_key_touch`. Q11.
- **Step-up window reuse.** The window is per (user, host) and shared between browser and SSH. A
  browser unlock lets SSH in without a prompt for 5 minutes, and vice versa. The 60-minute
  absolute cap still applies. The unlock alert (`notify_host_unlocked`) gains a "via SSH from IP"
  field. Q9.
- **SSO accounts** (no local password, often no TOTP) use web approval through SSO step-up.
- **Automation over SSH:** no in 3.7.0. Proposal for later: a key can be bound to an automation
  *token* principal (role-limited, never 2FA hosts, expiring), for CI `rsync`/`scp`. That reuses
  §A.6.5 entirely.
- **Rate limits:** §B.3. Failed web approvals and TOTP attempts count against the existing
  `stepup-totp:<uid>` key.

### B.6 Sessions

**Architecture.**

- An SSH session channel becomes an **`SshHubClient`** attached to a `core.SessionHub`, side by
  side with `BrowserClient`s. Today `SessionHub.clients: Set[BrowserClient]`, and the hub calls
  `push()`, `lock()`, `unlock()`, `send_text()` / `broadcast_json()`.
- The refactor: extract a small `HubClient` protocol (`push(bytes)`, `lock()`, `unlock()`,
  `on_control(dict)`, `is_owner`, `user_id`, `writable`, `id/label/remote_addr`).
  - `BrowserClient` already satisfies it.
  - `SshHubClient` maps control messages to terminal actions:
    - `locked` → print the lock banner;
    - `resize` → ignore (the SSH client owns its size);
    - roster → ignore, or a one-line notice "ana@ attached (web)";
    - `exit` → exit-status + close.
- Flow control: an asyncssh channel has its own window. Use `SSHWriter.drain()` in a sender task,
  the analogue of `BrowserClient.sender()`, with the same bounded queue and lossy-resync policy.

**Behaviours**

| Aspect | Design |
|---|---|
| Create | `core.create_session(host_id, title="ssh · <email> · <ip>", rows, cols)`, using the PTY size from `pty-req`. Record `sessions.origin='ssh'` and `created_by_id`. |
| Recording | Unchanged: the hub writes `.out`/`.cast`. Input is **not** recorded (existing rule, protects passwords). |
| Visible in UI | Yes: listed with an "SSH" badge, attachable from the browser (with roster) and vice versa. |
| tmux persistence | **Disconnect ≠ kill.** The session stays live like a closed browser tab; reattach with `web01+last`. On login the banner says: "Persistent WebTerm session ab12cd. `exit` ends it; disconnecting keeps it." Q6. |
| Window change | `window-change` → `hub.resize(rows, cols)`. Same last-writer-wins as several browsers today. |
| Env | Accept only `LANG`, `LC_*`, `TZ`. TZ maps to the existing `tz` arg of `create`. `TERM` from `pty-req` is passed through (agent `create` takes `term`). Everything else is refused. |
| Agent forwarding / X11 | Refused (the channel request returns false). A gateway holding users' agent sockets would be a key-theft machine. |
| Exit codes | `hub.on_exit(status, sig)` → `chan.exit(status)` / `exit_with_signal`. |
| Read-only (`+ro`) | `SshHubClient.writable=False`. Input is dropped and a "read-only" banner is shown. |
| Idle-lock and 60-minute cap | Free: `sweep_idle_locks` / `sweep_stepup_caps` act on the hub. `SshHubClient.is_owner=True` and `user_id` are set, so its keystrokes count as operator activity and its user's windows can re-authorize the cap, exactly as for browser owners. |
| Session limits | The agent's `MAX_SESSIONS=32` applies. Add a gateway cap on SSH sessions per user (default 8). |
| Kick / revoke | `session.manage` holders can kick SSH clients from the roster in the UI. Role downgrades are applied on the 60-second revalidation, as for WebSockets. |

**`ssh host 'cmd'` (exec)**

- **3.7.0: refused** with a clear message ("exec arrives in 3.7.2; use an interactive session").
- Option (not recommended): map `ssh -t host cmd` onto `create_session(cmd=…)`. That works today
  (it is how Docker "shell in container" runs) and gives a recorded PTY session, but the output
  is PTY-cooked (CRLF, merged stderr, no binary safety). It would look like exec while breaking
  pipes. Allowing it only when the client requested a PTY (`-t`) is defensible; Q17.
- **3.7.2 (agent 59): a new `exec` op.**
  - It spawns the command with **pipes** (stdin, stdout, stderr), streams over the existing
    multiplexed frames (like `fwd_*` streams), and returns the exit code.
  - It is not wrapped in tmux; non-interactive work does not need to persist.
  - Recorded as an `exec` audit entry (command text + exit code + byte counts). The stream is not
    recorded by default (binary payloads, `tar` streams); per-role recording policy is later.
  - Gated by `run` (⚑), since it is the same power.

**SFTP / scp (3.7.1, no agent bump)**

- OpenSSH ≥ 9.0 `scp` uses SFTP by default, so an SFTP subsystem covers `sftp`, `scp` and most
  GUI clients (WinSCP, FileZilla, VS Code remote explorer's SFTP).
- Implement `asyncssh.SFTPServer` methods over the existing agent ops through `AgentConnection`:

| SFTP | Agent op (v58) | Notes |
|---|---|---|
| `stat/lstat` | `fs_stat` (lstat semantics, `mode`) | |
| `opendir/readdir` | `fs_list` | capped at `FS_MAX_LIST=2000`, with `truncated` → return what we have and log it; documented limit |
| `open(read)` + `read(off,len)` | `fs_read` (256 KiB chunks, any offset) | random reads OK |
| `open(write)` + `write(off)` | `fs_write` / binary `FRAME_FSWRITE` (`fs_write_bin`) | **sequential only**: agent v50+ refuses non-append offsets (`offset_conflict`) → `SFTP_FAILURE` "random writes unsupported". Upload into a temp name + `fs_rename` on close, like the HTTP upload |
| `mkdir` | `fs_mkdir` | |
| `rename` / `posix-rename` | `fs_rename` (overwrite flag) | |
| `remove` / `rmdir` | `fs_delete` | |
| `setstat` (mode) | `fs_chmod` (v58) | times/owner → `OP_UNSUPPORTED` (so `scp -p` preserves mode but not times) |
| `readlink` / `symlink` / `statvfs` / `realpath` | — / — / — / compute in gateway (`fs_list` `path` is absolute) | `realpath` locally; others unsupported |

- Permissions: `files.read` for reads, `files.write` / `files.delete` for writes, checked per
  operation. 2FA uses the existing window, which must already be open (§B.5).
- Each file open/close is audited like `/fs/download` and `/fs/upload`.
- **Verdict: feasible with no bump.** Missing pieces (utimes, symlinks, random writes) can ride
  along with the agent-59 bump if wanted, because changing `ptyd.py` forces a fleet-wide update
  anyway.

**Port forwarding (`-L`, 3.7.1)**

- `connection_requested(dest_host, dest_port, …)` → `AgentConnection.open_forward(host, port)`,
  the same `fwd_open` the HTTP forwards and SSH-jump use. No bump.
- **Allowed destinations:** only the (target_host, target_port) pairs **declared** on that host as
  `port_forwards` or Toolbox `connections`, with `ssh.forward` on the host. This keeps the
  existing anti-SSRF principle (targets are admin-declared, never taken from user input).
- An opt-in permission `ssh.forward_any` for arbitrary destinations is possible later.
- The forward host is chosen through the SSH username (`web01`); the session channel is optional
  (`ssh -N -L 5432:127.0.0.1:5432 web01@gw`).
- Audit one row per channel (destination, bytes, duration).
- `-R` and `-D` are refused.

**rsync**

- rsync runs `rsync --server …` through **exec** with a binary-clean pipe, and needs `rsync` on
  the target. So it is **3.7.2 / agent 59**.
- Gate: `run` (it is exec), or a narrower `files.write` + allowlisted command prefix
  `rsync --server` (Q18).
- Alternative without any bump: ProxyJump mode (below), where rsync talks to the host's own sshd
  end-to-end.

**ProxyJump mode (3.7.x, optional)**

- `ssh -J web01@gw:2222 user@web01.internal` → the client asks the gateway for a direct-tcpip
  channel to `web01.internal:22` → `fwd_open` from the web01 agent to its own `127.0.0.1:22`.
- The user then authenticates **to the host's sshd** with their own Unix credentials.
- WebTerm only sees ciphertext. There is **no recording**, only connection audit. That is why it
  is a separate `ssh.jump` permission, off in every built-in except Owner/Admin.
- Value: full native SSH (rsync, git, sshfs, IDE remotes) with zero agent work. Cost: it bypasses
  WebTerm's recording, which some installs will want forbidden. That is what the permission is
  for.

### B.7 Roles over SSH

- Authentication → `Principal(kind='ssh', user_id=key.user_id)`, then the same `authz.effective()`.
- The **picker lists only hosts with `ssh.login`** (and `session.watch` for `+ro`).
- Not visible → the same message as "no such host" (no oracle).
- Global gate: none needed. Without any `ssh.login` binding, the picker is empty and the user is
  told so.
- Each channel type has its own permission (§A.4): session → `ssh.login` + `session.open`; `+ro`
  → `session.watch`; sftp → `files.*`; `-L` → `ssh.forward`; exec → `run`; jump → `ssh.jump`.

### B.8 Audit, alerts, kill switches

- `audit_log` rows with `method='SSH'` and paths like `ssh://web01/session/<sid>`,
  `ssh://web01/sftp/get /etc/hosts`, `ssh://web01/forward/127.0.0.1:5432`, plus
  `via='ssh:<key fp>'`, the real IP (after PROXY), and status (200 / 403 / 401).
- Failed auth with a known key → recorded with that actor. Unknown key → anonymous, and
  therefore subject to the existing "do not log anonymous 401/403" anti-flood rule. Counted in
  metrics instead.
- Alerts:
  - `ssh_key_added` / `ssh_key_removed` (security);
  - SSH login from a new IP (reuse `seen_logins` / `note_new_login` with the SSH IP);
  - `notify_host_unlocked` with `via=ssh`.
- **Kill switches:**
  - Settings → SSH access → "disable SSH entry" (live; closes the listener and all connections);
  - per-user "SSH allowed" (implicit through `ssh.login` bindings);
  - per-key revoke (closes the connections using that key).

### B.9 Agent version impact

| Milestone | Agent | Why |
|---|---|---|
| 3.7.0 interactive PTY, picker, 2FA, audit | **none (58)** | `create`/`attach`/`resize`/`kill` already exist; `term`/`tz` already passed |
| 3.7.1 SFTP + `-L` | **none (58)** | `fs_*` incl. `fs_chmod` (v58), `fwd_open` |
| 3.7.2 exec / rsync / legacy scp | **59** | binary-safe `exec` op with separate stdout/stderr and exit code |
| optional with 59 | 59 | `fs_utime`, `fs_symlink`/`fs_readlink`, positional `fs_write` (SFTP completeness) |

Following the fleet-cost rule (agent refactors force a fleet update, so bundle them), agent 59
should collect every queued agent change, such as the agent-supervision follow-ups.

---

## 4. Phasing

Effort is relative: S ≈ days, M ≈ 1–2 weeks, L ≈ 3–4 weeks, XL ≈ more, for one person at the
current pace.

| Milestone | Scope | Risk | Effort | Acceptance criteria / tests |
|---|---|---|---|---|
| **3.6.0: roles core** | schema + seeding; `authz.py`; `perm()` on all 198 routes + 3 WS + forward; runtime fail-closed guard; built-in roles; list filtering (§A.6.3); token ∩ creator; alert fan-out; audit `actor_id/host_id/via`; minimal Users & roles tab (bind built-in roles with scope); `/api/me/permissions` + UI gating of the main surfaces; admin CLI `promote`; docs (ARCHITECTURE, THREAT-MODEL, SECURITY-FEATURES, new ROLES.md) | **High.** It touches every route, and one mis-mapped route is a hole | **L–XL** | the tests in §A.12 green; a 3.5.16 DB upgrades with zero UI difference for a single user (Playwright snapshot of the main screens unchanged); dedicated security review passed; route matrix test generated from `ROUTE_PERMS` |
| **3.6.1: custom roles + SSO** | role editor with ⚑ badges and presets (Auditor, Files-only); `oidc_group_roles` + UI + env bootstrap; re-sync at login and step-up; explain-access drawer | Medium (SSO edge cases) | M | `rbac_oidc_test`; editor prevents escalation; explain endpoint matches the matrix |
| **3.6.2: polish** | time-bound bindings (expires + janitor); crown-jewel flag + warnings; deploy-key graph scope warnings; per-role guardrail rule sets (optional) | Low | S–M | expiry test; warning shown and audited |
| **(3.6.x later)** | access requests / JIT; per-host "approve each connection" | Medium | M | not scheduled |
| **3.7.0: SSH entry (interactive)** | asyncssh ≥ 2.24.1 bump; listener + PROXY v2 + rate limits; host key + Settings → SSH access; `user_ssh_keys` + UI (second gate); target syntax + picker; `SshHubClient` (HubClient refactor); in-band 2FA unlock (TOTP + web approval); idle-lock and 60-minute cap; audit + alerts; compose and Traefik docs | **High.** It is a new internet-facing protocol surface | **L** | an `ssh_entry_test` using asyncssh's client against the in-process server: key auth, unknown-key behaviour, picker, 2FA lock → TOTP unlock → output flows, web-approval round trip, idle-lock mid-session, cap at 60 minutes (time-mocked), read-only attach drops input, revocation closes the connection, PROXY header from a trusted vs untrusted peer, brute-force lockout; e2e: a browser sees the SSH session live; pentest on a mirror (pre-auth fuzz, auth-state confusion, resource exhaustion) |
| **3.7.1: SFTP + `-L`** | SFTP server over `fs_*`; `-L` to declared forwards | Medium (path handling and 2FA for non-interactive use) | M | `sftp`/`scp` (OpenSSH 9+) put/get/ls/mkdir/rm/chmod against a test agent; random-write refusal; traversal tests (the agent resolves paths; check `..` and symlink handling is the agent's existing semantics, not a chroot); 2FA host needs an open window; `-L` to an undeclared target refused |
| **3.7.2: exec (agent 59)** | `exec` op; `ssh host cmd`, rsync, `scp -O`; bundled agent changes | Medium (fleet update) | M | binary round trip (`cat bigfile \| ssh h 'cat > f'`, sha256 equal); exit codes and signals; rsync incremental; agent-version gating with a friendly "update the agent" message on < 59 |
| **3.7.x: optional** | ProxyJump mode; SSH/jump hosts as targets; SSH CA (user certs); keys for automation principals | Medium | M each | |

**Release order recommendation:** ship 3.6.0 and let it settle before 3.7.0. The SSH surface
relies on `authz` for everything; building it on unfinished RBAC doubles the review work.

---

## 5. Open questions for the maintainer

> **Decided 2026-10-09:** the maintainer accepted the recommendation (**R**) on every question
> below, questions 1–21. Implementation follows them; any change goes through this document first.


Each has options and a recommendation (**R**).

1. **Is the product stance change acceptable?** Today's docs say "no RBAC, by design".
   (a) ship RBAC framed as host-scoping + shell/no-shell, with ⚑ honesty; (b) keep "isolation, not
   roles" and do only per-instance teams. **R: (a)**, with the doc rewrites listed in §1.
2. **Where does scope live?** (a) on the binding (role = what, binding = where); (b) inside the
   role (Teleport labels); (c) both. **R: (a).**
3. **Deny rules in 3.6?** (a) no, union only; (b) yes. **R: (a).** Revisit with a concrete case.
4. **Viewer and files.** Should Viewer read files? (a) no, file content is the most sensitive
   read; (b) yes, read-only. **R: (a).** Offer it through a custom role.
5. **Session ownership inside a host scope.** Can an Operator attach to *another* user's live
   session on a host they can access? (a) yes, team model, roster shows it; (b) only own sessions,
   others need `session.manage`; (c) yes but read-only. **R: (b)** for write and (c) for watch:
   Operators can watch others' sessions but type only into their own, unless they hold
   `session.manage`. Needs `sessions.created_by_id`; pre-3.6 sessions (NULL) count as "everyone's".
6. **SSH disconnect semantics.** (a) the session persists (WebTerm model, reattach with `+last`);
   (b) the session is killed on disconnect, as with plain ssh; (c) per-user preference. **R: (a)**
   with a clear banner. Add (c) later if users complain.
7. **SSO user with no mapped group.** (a) log in with no access; (b) refuse login. **R: (a)**, with
   `OIDC_ALLOWED_GROUPS` for hard gating.
8. **Revocation latency for SSO group removal.** (a) next login; (b) also at every SSO step-up;
   (c) shorter session TTL for SSO users. **R: (a)+(b).**
9. **Step-up window shared between browser and SSH?** (a) shared per (user, host); (b) separate per
   channel. **R: (a)**, with the unlock alert naming the channel.
10. **Revoked user's running jobs** (fscopy, exec, forwards). (a) cancel on revoke; (b) let them
    finish. **R: (a)** for forwards and exec (they are live access); (b) for copy jobs, audited.
11. **FIDO `sk-*` keys with `verify-required` as a second factor?** (a) yes, opt-in per key; (b)
    never; SSH always needs a separate unlock on 2FA hosts. **R: (a)**, opt-in, labelled.
12. **Tokens: which routes beyond status/hosts/sessions/run?** Candidates: files read/write (backup
    scripts), docker/services act. **R:** in 3.6, keep today's allowlist and only add role
    capping. Widen per request, one route at a time.
13. **SSH username syntax.** (a) `target@gw` only; (b) also accept Warpgate `user:target` and
    `user#target`. **R: (b)**, prefix ignored after a sanity check.
14. **Non-interactive SSH on 2FA hosts.** (a) needs an already-open window; (b) also offer
    keyboard-interactive TOTP at auth time; (c) never allowed. **R: (a)+(b).**
15. **RSA host key for old clients?** **R:** ed25519 only, plus an opt-in env for RSA-3072.
16. **Host key storage.** (a) a 0600 file in `data/`; (b) encrypted with the vault key. **R: (b).**
    Consistent with other secrets, and it rides in backups.
17. **`ssh -t host cmd` before agent 59?** (a) refuse all exec until 3.7.2; (b) allow only with `-t`,
    as a PTY session. **R: (b).** It is cheap, honest (the user asked for a TTY), and recorded.
18. **rsync gate.** (a) needs `run`; (b) `files.write` + `rsync --server` prefix allowlist. **R: (a)**
    first. (b) is a parser-shaped hole waiting to happen.
19. **ProxyJump mode at all?** It bypasses recording. (a) yes, behind `ssh.jump` (Owner/Admin only by
    default); (b) no. **R: (a)**, but after 3.7.2, and only if asked for.
20. **Admin manages roles?** (a) Admin has `roles.manage` with no-escalation; (b) Owner only. **R:
    (a).**
21. **Who can create accounts?** Should `users.manage` @ folder scope exist (team leads onboarding
    their own people)? **R:** not in 3.6; `users.manage` is global only.

---

## 6. What else might be missing (optional, not scope creep)

These are candidates for after 3.7, listed so they are not forgotten. None is proposed for 3.6 or
3.7.

- **Audit export / SIEM.** Syslog (RFC 5424) or JSON-lines webhook streaming of `audit_log` rows.
  With RBAC, the audit log becomes an evidence log rather than a self-check. Cheap: a sink beside
  `audit.record`.
- **Prometheus exporter** (already on the post-3.0 backlog): `/metrics` behind a token scope, with
  hosts online, sessions, agent versions, SSH connections and auth failures.
- **API documentation.** FastAPI generates OpenAPI; publishing it, filtered to token-accessible
  routes and annotated with the permission each needs (from `ROUTE_PERMS`), would document RBAC
  for free.
- **Recording storage off-box** (S3-compatible), as Warpgate does, for retention beyond the local
  volume.
- **HA / multi-instance.** The gateway is deliberately single-process. Hubs, step-up windows,
  approvals and the authz cache are in memory. Any HA story (active/passive with shared storage)
  must start from that fact; nothing here makes it harder, and the SSH server makes it no worse.
- **SCIM** user provisioning from the IdP, so deprovisioning works without waiting for a login.
  Only relevant for larger installs.
- **Session moderation / four-eyes** (Teleport-style required observers) for crown-jewel hosts.

---

## 7. Implementation notes (3.6.0)

Milestone 3.6.0 is implemented in `gateway/app/authz.py` (catalogue, built-in roles, grants,
`perm()`, the runtime guard, `PUBLIC`/`SELF`, seeding) plus the route and handler changes in
`api.py`, `webauthn_api.py`, `oidc_api.py`, `alert_history.py`, `audit.py`, `main.py`,
`admin.py` and `core.py` (read-only clients only). Where the code differs from the text above,
the code is right and the reason is here.

**Enforcement**

- `perm()` returns exactly what `security.require_user` / `require_scope` returned, so handlers
  did not change shape. `require_scope` is no longer used on routes; the token allowlist is
  `perm(…, tokens="read"|"run")` on the same four routes.
- **List routes never deny** (`list=True`). The text said a list passes "if the permission exists
  on ≥1 host"; an account with no access would then get 403s instead of the empty fleet that the
  "no access yet" UI needs. An empty list leaks nothing.
- **Fast path:** when the permission holds on every host (a scope-`all` binding), `perm()` does
  not look the host up, so an Owner's response for a missing host is byte-identical to 3.5. A
  scoped principal gets the uniform 404 for both "missing" and "not visible".
- 404 bodies per locator are the handlers' own: `host.missing`, `session.missing`,
  `forward.missing`, `replay.missing`.
- Body locators follow the code's field names: `/api/fs/copy` is `src_host` / `dst_host`.
- `/__wtfwd/auth` and the WebSocket handlers authorize inside the handler (a dependency cannot
  close a socket with our codes); `browser_ws` is declared with `authz.ws_perm`, `/__wtfwd/auth`
  stays in `PUBLIC` and checks `forward.use` itself.
- Binding removal is `POST /api/users/{uid}/bindings/{bid}/delete` with a reauth body (like
  account deletion), not a DELETE with a body. `GET /api/roles` ships read-only in 3.6.0 (the UI
  needs the catalogue); editing roles stays 3.6.1.

**Stricter than the text (fail-closed choices)**

- Session control: rename, kill, delete **and reconnect** need `session.open` plus own session
  (or pre-3.6 `NULL`) or `session.manage`.
- `POST /api/hosts/test` with `host_id` uses that host's stored credential, so it also needs
  `host.edit` on it (besides `hosts.create`, and `forward.manage` on a jump `via`).
- `POST /api/history` without a host needs `session.open` on at least one host.
- Snippets with no recorded creator (pre-3.6) are editable only with `snippets.manage`; creating
  a duplicate snippet no longer re-targets someone else's.
- Deploy-key rotation refuses up front if any active target is outside the caller's
  `deploykey.manage` scope (it would otherwise leave that edge half-rotated). `GET deploy-key`
  keeps out-of-scope edges in the list but blanks their names and ids.
- `GET /api/hosts/{id}/forwards` blanks `target_host`/`target_port` without `forward.manage`.
- Replay-link listing stays own-only even with `shares.manage` (the matrix's "— / shares.manage"
  would have widened it); `POST /api/shares/revoke-all` is global only with `shares.manage`,
  otherwise it revokes your own links.
- A read-only WebSocket client cannot resize or kick, and only writable clients keep a 2FA
  terminal awake (`touch`, idle-lock) or re-authorize the 60-minute step-up cap — a watcher must
  not hold a terminal open for someone who walked away. A live downgrade (open → watch) is applied
  at once; an upgrade needs a reconnect.
- `/api/state` filters host-key alarms to visible hosts and shows the backup / signing dots only
  to holders of `backups.manage` / `signing.manage`; `/api/totp/status` counts only visible 2FA
  hosts; the security summary without `security.view` returns only the account check.

**Tokens**

- Legacy scopes map to the permissions today's read routes need, or an upgrade would silently
  empty existing monitoring tokens: `read` → `host.view`, `session.watch`, `recording.view`
  (+ `security.view` for the status details); `run` → `host.view`, `run`. The legacy scope check
  stays in front, and the result is then capped by the optional role/scope and by the creator.
- Global permissions come only from scope-`all` bindings, so an Operator bound to a folder has no
  `tokens.create`; an Operator over all hosts does.

**Accounts, SSO, alerts**

- A new account, including a **new SSO user**, gets no binding ("no access yet"). The group →
  role mapping is 3.6.1, so until then an Owner/Admin grants access by hand. The
  `oidc_group_roles` table already exists, unused. Accounts that existed at upgrade (SSO ones
  included) were seeded as Owner.
- Creating an account and changing bindings accept the SSO account-scope re-auth (passkey grant
  or the SSO window), as `/api/account` does. Before, an SSO admin could not create accounts.
- No new `rbac_changed` alert kind: a binding change notifies `admin_change` (→ `security.view`
  holders, new message keys `role_granted` / `role_removed`) and `account_change` (→ the affected
  account, `access_changed`), so no new preference row appears.
- `/api/me/permissions` does **not** list the Owners' and Admins' emails (§A.9 suggested it): an
  account without access — e.g. a freshly provisioned SSO user — would learn exactly who holds the
  most power. It returns `has_admins` and the UI says "ask an administrator" (security-first
  default, pending the maintainer's confirmation; isolated in its own commit).
- Webhook/e-mail delivery is unchanged: an event still leaves if at least one recipient wants it,
  and an event with no recipient at all still leaves (the instance mailbox is the admins').

**Data**

- Seeding runs in `db.connect()` after the PRAGMAs (writes cannot precede `PRAGMA synchronous`).
  `hosts.crown_jewel` exists but is unused (3.6.2).
- The admin CLI gained `roles <email>` and `promote <email>`; it writes
  `app_settings['authz_epoch']`, which the gateway polls from its 60-second reaper loop. Cached
  grants also expire after 30 seconds on their own.

**Security review fixes (before release):** a read-only client cannot unlock a 2FA-locked hub, and
a factor unlocks only the presenting account's clients; a watcher attaching without a window
locks only itself; every target field of a jump host needs `forward.manage` on the effective via;
account ids are never reused (persisted `user_id_floor`, explicit ids at insert) and a deleted
account's rows keep a negated id; live shares and replay links need your own session or
`session.manage`; Wake-on-LAN peers need `host.wake`; grants are re-checked under the lock;
SELF routes must authenticate (runtime + CI); probe errors are generic. See
`tests/rbac_secreview_test.py`.

**Tests:** `route_auth_test` (declaration, locators, token allowlist, code ↔ this appendix,
runtime guard), `rbac_matrix_test` (generated from `authz.route_perms`: 6 principals × every
non-public HTTP route, plus the no-oracle 404 comparison and authz-before-step-up),
`rbac_filter_test`, `rbac_escalation_test`, `rbac_ws_test`, `rbac_migration_test`.

---

## Appendix A: Route-by-route permission matrix

Legend:

- **Perm**: the permission required (§A.4).
- **Scope**:
  - `H(host_id)`: host from the path;
  - `H(sid)`: host of the session;
  - `H(fid)`: host of the forward;
  - `H(link)`: host of the replay link's session;
  - `H(body)`: host id(s) in the body;
  - `L`: list, filtered per §A.6.3;
  - `G`: global (needs a binding at scope `all`);
  - `S`: self-service (authenticated, own data);
  - `P`: public (unchanged; its credential is in the request).
- **2FA**: the route also runs `_require_host_stepup` (`su`), `_require_fresh_factor` (`ff`), or
  the session-host step-up (`ssu`, `_require_session_host_stepup`). Unchanged by 3.6; it runs
  after authz.
- **Tok**: reachable with an automation token today (`require_scope`).
- **⚠**: the route leaks cross-host information today for a scoped user and needs filtering.

Counts: 187 routes in `api.py` (184 HTTP + 3 WebSocket), 8 in `webauthn_api.py`
(`/api/webauthn/*`), 3 in `oidc_api.py` (`/api/oidc/*`), plus the forward proxy (an HTTP
middleware plus ASGI WS middleware in `main.py`) and the SPA/asset catch-all. Line numbers are
`api.py` unless stated otherwise.

### A.1 Public, setup, login (unchanged)

| Route | Method | Perm | Scope | Notes |
|---|---|---|---|---|
| `/healthz` (146) | GET | — | P | liveness |
| `/api/state` (157) | GET | — | P | has-account flag only |
| `/api/setup` (209) | POST | — | P | first account → **Owner @ all** |
| `/api/login` (450) | POST | — | P | |
| `/api/logout` (569) | POST | — | P | also closes the user's SSH connections (3.7) |
| `/api/shared/{token}` (8092) | GET | — | P | token = credential; revoked if the creator loses `share.live` |
| `/api/replay/meta` (8347) | GET | — | P | `X-Replay-Token` |
| `/api/replay/cast` (8361) | GET | — | P | idem |
| `/api/replay/text` (8378) | GET | — | P | idem |
| `/install/{enroll_token}` (8632) | GET | — | P | |
| `/install/group/{group_token}` (8666) | GET | — | P | auto-created host lands in the group's folder → in scope for that folder's bindings |
| `/agent/uninstalled` (8715) | POST | — | P | host token |
| `/agent/ptyd.py` (8749) | GET | — | P | |
| `/agent/shell-integration.sh` (8798) | GET | — | P | |
| `/__wtfwd/auth` (5325) | GET | — (handler checks `forward.use`) | P + H(slug→host) | PUBLIC route (the session cookie is validated in the handler); 3.6.0 checks `forward.use` on the forward's host before issuing the ticket: invisible host → the same 404 as a missing forward |
| `/api/webauthn/login/options` (wa:205) | POST | — | P | |
| `/api/webauthn/login/verify` (wa:215) | POST | — | P | |
| `/api/oidc/status` (oi:40) | GET | — | P | |
| `/api/oidc/login` (oi:46) | GET | — | P | `intent=stepup&host_id` → step-up callback must require `host.view` on that host |
| `/api/oidc/callback` (oi:64) | GET | — | P | provisioning + **group → binding re-sync** (§A.7) |

### A.2 Account and self-service (S)

| Route | Method | Perm | Scope | Notes |
|---|---|---|---|---|
| `/api/account` (631) | POST | — | S | reauth |
| `/api/totp/status` (723) | GET | — | S | |
| `/api/totp/setup` (1101) | POST | — | S | |
| `/api/totp/activate` (1123) | POST | — | S | |
| `/api/totp/disable` (1155) | POST | — | S | |
| `/api/totp/recovery-codes` (1176) | POST | — | S | |
| `/api/account/sessions` (935) | GET | — | S | |
| `/api/account/sessions/{rid}` (948) | DELETE | — | S | |
| `/api/account/sessions/revoke-others` (968) | POST | — | S | also SSH connections (3.7) |
| `/api/alerts` (1561) | GET | — | S | rows are per user; the fan-out decides |
| `/api/alerts/unread` (1568) | GET | — | S | |
| `/api/alerts/read` (1574) | POST | — | S | |
| `/api/alerts` (1582) | DELETE | — | S | |
| `/api/alerts/prefs` (1589) | GET | — | S | |
| `/api/alerts/prefs` (1594) | POST | — | S | |
| `/api/version` (2057) | GET | — | S | |
| `/api/changelog` (3611) | GET | — | S | |
| `/api/split-views` (4476) | GET | — | S | panes without access show "no access" |
| `/api/split-views` (4497) | POST | — | S | pane sids must be visible (`session.watch`) |
| `/api/split-views/{sv_id}` (4512) | PATCH | — | S | idem |
| `/api/split-views/{sv_id}` (4538) | DELETE | — | S | |
| `/api/shell-integration/command` (8809) | GET | — | S | |
| `/api/webauthn/register/options` (wa:81) | POST | — | S | |
| `/api/webauthn/register/verify` (wa:176) | POST | — | S | second gate |
| `/api/webauthn/stepup/options` (wa:268) | POST | `host.view` | H(body) | host_id 0 = account scope (S) |
| `/api/webauthn/stepup/verify` (wa:284) | POST | `host.view` | H(body) | idem; also resolves pending SSH approvals (3.7) |
| `/api/webauthn/credentials` (wa:321) | GET | — | S | |
| `/api/webauthn/credentials/{cred_id}` (wa:334) | DELETE | — | S | |
| `/api/me/permissions` | GET | — | S | §A.9 (3.6.0) |
| *new* `/api/account/ssh-keys` (3.7) | GET/POST/DELETE | — | S | second gate on POST/DELETE |

### A.3 Users, roles, tokens, enroll groups (G)

| Route | Method | Perm | Scope | Notes |
|---|---|---|---|---|
| `/api/users` (768) | GET | `users.manage` | G / S | without the perm → `[self]` ⚠ |
| `/api/users` (779) | POST | `users.manage` | G | body gains role + scope; no-escalation |
| `/api/users/{uid}/delete` (809) | POST | `users.manage` | G | Owners only by Owners; tokens are already deleted, add bindings + SSH keys |
| `/api/users/{uid}/bindings` | GET | `users.manage` | G | 3.6.0 |
| `/api/users/{uid}/bindings` | POST | `users.manage` | G | §A.6.6; reauth + second gate (3.6.0) |
| `/api/users/{uid}/bindings/{bid}/delete` | POST | `users.manage` | G | POST with a body (reauth), like account deletion — a DELETE with a body is badly supported by clients (3.6.0) |
| `/api/roles` | GET | `users.manage` | G | catalogue + built-in roles (3.6.0) |
| *new* `/api/roles`, `/api/roles/{id}` | POST/PATCH/DELETE | `roles.manage` | G | 3.6.1 |
| *new* `/api/authz/explain` | GET | `users.manage` (or self) | G | |
| *new* `/api/settings/oidc-roles` | GET/POST | `users.manage` | G | 3.6.1 |
| `/api/tokens` (987) | GET | `tokens.create` | S / G | own; all with `tokens.manage` ⚠ |
| `/api/tokens` (993) | POST | `tokens.create` | G | role ⊆ creator |
| `/api/tokens/{tid}/revoke` (1026) | POST | `tokens.create` | S / G | own, or any with `tokens.manage` |
| `/api/enroll-groups` (1036) | GET | `hosts.create` | G | ⚠ |
| `/api/enroll-groups` (1058) | POST | `hosts.create` | G | the folder decides future access |
| `/api/enroll-groups/{gid}/revoke` (1090) | POST | `hosts.create` | G | |

### A.4 Instance settings, backups, signing (G)

| Route | Method | Perm | Scope | Notes |
|---|---|---|---|---|
| `/api/settings/command-guard` (1367) | GET | `settings.manage` | G | (Operators may need a read for UI hints: return rules count only) |
| `/api/settings/command-guard` (1372) | POST | `settings.manage` | G | |
| `/api/settings/watermark` (1402) | GET | — | S | everyone needs it to render the watermark |
| `/api/settings/watermark` (1407) | POST | `settings.manage` | G | |
| `/api/settings/smtp` (1421) | GET | `settings.manage` | G | |
| `/api/settings/smtp` (1433) | POST | `settings.manage` | G | |
| `/api/settings/webhook/test` (1490) | POST | `settings.manage` | G | |
| `/api/settings/smtp/test` (1502) | POST | `settings.manage` | G | |
| `/api/settings/alerts` (1523) | GET | `settings.manage` | G | |
| `/api/settings/alerts` (1529) | POST | `settings.manage` | G | |
| `/api/settings/forward` (3200) | GET | `settings.manage` | G | |
| `/api/settings/forward` (3205) | POST | `settings.manage` | G | |
| `/api/settings/deploy-key-policy` (7088) | GET | `settings.manage` | G | |
| `/api/settings/deploy-key-policy` (7093) | POST | `settings.manage` | G | |
| `/api/version/check` (2064) | POST | `settings.manage` | G | |
| `/api/version/refresh` (2073) | POST | `settings.manage` | G | |
| `/api/backup/status` (3329) | GET | `backups.manage` | G | |
| `/api/backup/download` (3345) | POST | `backups.manage` | G | reauth |
| `/api/backup/stored/{name}/download` (3359) | POST | `backups.manage` | G | |
| `/api/backup/restore` (3374) | POST | `backups.manage` | G | |
| `/api/backup/schedule` (3408) | POST | `backups.manage` | G | |
| `/api/backup/stored/{name}` (3417) | DELETE | `backups.manage` | G | |
| `/api/backup/seen` (3429) | POST | `backups.manage` | G | |
| `/api/backup/cloud` (3477) | GET | `backups.manage` | G | |
| `/api/backup/cloud/config` (3482) | POST | `backups.manage` | G | |
| `/api/backup/cloud/probe` (3496) | POST | `backups.manage` | G | |
| `/api/backup/cloud/direct` (3508) | POST | `backups.manage` | G | |
| `/api/backup/cloud/authorize` (3528) | GET | `backups.manage` | G | |
| `/api/backup/cloud/callback` (3536) | GET | `backups.manage` | G | |
| `/api/backup/cloud/upload` (3561) | POST | `backups.manage` | G | |
| `/api/backup/cloud/disconnect` (3570) | POST | `backups.manage` | G | |
| `/api/signing/status` (3606) | GET | `signing.manage` | G | (a status bit for the UI badge could be S) |
| `/api/signing/generate` (3624) | POST | `signing.manage` | G | |
| `/api/signing/import` (3639) | POST | `signing.manage` | G | |
| `/api/signing/unlock` (3657) | POST | `signing.manage` | G | |
| `/api/signing/lock` (3673) | POST | `signing.manage` | G | |
| `/api/signing/backup` (3682) | POST | `signing.manage` | G | |
| `/api/security/summary` (8060) | GET | `security.view` | G / S | without it → own-account checks only ⚠ |
| `/api/audit` (4880) | GET | `audit.view` | L | without it → own rows; with it → visible hosts + NULL-host rows ⚠ |
| `/api/history` (4742) | DELETE | `history.clear` | G | global wipe |

### A.5 Fleet-wide lists and search (L)

| Route | Method | Perm | Scope | Tok | Notes |
|---|---|---|---|---|---|
| `/api/status` (2020) | GET | `host.view` (any) | L | read | ⚠ counts over visible hosts; storage/health with `security.view` |
| `/api/hosts` (2083) | GET | `host.view` | L | read | ⚠ |
| `/api/hosts/export.csv` (2219) | GET | `hosts.export` | G∩L | | ⚠ |
| `/api/sessions` (6383) | GET | `session.watch` ∪ `recording.view` | L | read | ⚠ |
| `/api/search` (5700) | GET | `recording.view` | L | | ⚠ already filters 2FA; filter in SQL before reading transcripts |
| `/api/history` (4683) | POST | `session.open` | H(body) | | write only for hosts where you have a shell; 2FA rule unchanged |
| `/api/history` (4707) | GET | `recording.view` | L | | ⚠ |
| `/api/apps` (4863) | GET | `forward.use` | L | | ⚠ |
| `/api/shares` (7892) | GET | — / `shares.manage` | S / G | | own; all with the perm |
| `/api/shares/revoke-all` (7905) | POST | — / `shares.manage` | S / G | | own; global with the perm |
| `/api/replay-links` (8244) | GET | — / `shares.manage` | S / G | | |
| `/api/replay-links/revoke-all` (8283) | POST | — / `shares.manage` | S / G | | |
| `/api/snippets` (6136) | GET | — | S | | shared library |
| `/api/snippets` (6142) | POST | — | S | | `created_by_id` |
| `/api/snippets/{sid}` (6160) | PATCH | — / `snippets.manage` | S / G | | own, or any with the perm |
| `/api/snippets/{sid}` (6175) | DELETE | — / `snippets.manage` | S / G | | idem |

### A.6 Host lifecycle and administration

| Route | Method | Perm | Scope | 2FA | Notes |
|---|---|---|---|---|---|
| `/api/hosts` (2166) | POST | `hosts.create` | G | | folder chosen must be within the creator's scope (trivial for `all`) |
| `/api/hosts/import` (2353) | POST | `hosts.create` | G | | |
| `/api/hosts/test` (6809) | POST | `hosts.create` | G (+ `forward.manage` on `via_host_id`) | su | dials arbitrary targets; SSRF-shaped |
| `/api/hosts/ssh-key/pending` (6723) | POST | `hosts.create` | G | | |
| `/api/hosts/{host_id}` (5759) | PATCH | `host.edit` (+ `hosts.create` G if folder/tags change) | H(host_id) | su | bumps authz_epoch on folder/tag change |
| `/api/hosts/{host_id}` (6194) | DELETE | `host.admin` | H(host_id) | su | |
| `/api/hosts/{host_id}/enroll` (2405) | POST | `host.admin` | H(host_id) | su | |
| `/api/hosts/{host_id}/require-2fa` (5948) | POST | `host.admin` | H(host_id) | su | turning 2FA off is a downgrade → security alert |
| `/api/hosts/{host_id}/provision` (5969) | POST | `host.admin` | H(host_id) | su | ⚑ |
| `/api/hosts/{host_id}/forget-credentials` (6047) | POST | `host.admin` | H(host_id) | su | |
| `/api/hosts/{host_id}/update` (5681) | POST | `host.admin` | H(host_id) | su | agent update |
| `/api/hosts/{host_id}/uninstall` (6232) | POST | `host.admin` | H(host_id) | su | |
| `/api/hosts/{host_id}/autostart` (6291) | POST | `host.admin` | H(host_id) | su | |
| `/api/hosts/{host_id}/wake` (4589) | POST | `host.wake` | H(host_id) | su | |
| `/api/hosts/{host_id}/stepup` (6537) | POST | `host.view` | H(host_id) | (is the step-up) | |
| `/api/hosts/{host_id}/hostkey` (4914) | GET | `host.diagnostics` | H(host_id) | | |
| `/api/hosts/{host_id}/hostkey/accept` (4931) | POST | `host.edit` | H(host_id) | su | |
| `/api/hosts/{host_id}/ssh-key/generate` (6570) | POST | `host.edit` | H(host_id) | su | credential for an SSH-type host |
| `/api/hosts/{host_id}/ssh-key/public` (6592) | POST | `host.edit` | H(host_id) | su | |
| `/api/hosts/{host_id}/events` (4965) | GET | `host.diagnostics` | H(host_id) | su | |
| `/api/hosts/{host_id}/agent-log` (5001) | GET | `host.diagnostics` | H(host_id) | su | audited read |
| `/api/hosts/{host_id}/diagnostics/refresh` (5020) | POST | `host.diagnostics` | H(host_id) | su | |
| `/api/hosts/{host_id}/diag-probe` (4241) | GET | `host.diagnostics` | H(host_id) | su | |
| `/api/hosts/{host_id}/ports` (4186) | GET | `host.diagnostics` | H(host_id) | su | listening ports = internal map |

### A.7 Sessions, terminal, shares, recordings

| Route | Method | Perm | Scope | 2FA | Tok | Notes |
|---|---|---|---|---|---|---|
| `/api/hosts/{host_id}/sessions` (6404) | GET | `session.watch` ∪ `recording.view` | H(host_id) | su | | |
| `/api/hosts/{host_id}/sessions` (7559) | POST | `session.open` | H(host_id) | su | | a body `cmd` (docker exec / upgrade / toolbox) is still `session.open`; Toolbox launches also need `toolbox.use` |
| `/api/sessions/{sid}` (7707) | PATCH | `session.open` (own) / `session.manage` | H(sid) | | | rename/note |
| `/api/sessions/{sid}/reconnect` (7723) | POST | `session.open` | H(sid) | su | | |
| `/api/sessions/{sid}/kill` (7743) | POST | `session.open` (own) / `session.manage` | H(sid) | su | | |
| `/api/sessions/{sid}` (7757) | DELETE | `session.open` (own) / `session.manage` | H(sid) | su | | |
| `/api/sessions/{sid}/share` (7784) | POST | `share.live` (+ `share.live_write` if writable) | H(sid) | su | | |
| `/api/sessions/{sid}/share` (7813) | GET | `session.watch` | H(sid) | | | |
| `/api/sessions/{sid}/share` (7839) | DELETE | `share.live` | H(sid) | su | | |
| `/api/sessions/{sid}/transcript` (8120) | GET | `recording.view` | H(sid) | ssu | | audited read |
| `/api/sessions/{sid}/preview` (8145) | GET | `recording.view` | H(sid) | ssu | | |
| `/api/sessions/{sid}/replay-links` (8198) | POST | `share.replay` | H(sid) | su | | |
| `/api/replay-links/{link_id}` (8268) | DELETE | `share.replay` (own) / `shares.manage` | H(link) | su | | |
| `/ws/sessions/{sid}` (9149) | WS | `session.open` → rw; `session.watch` → ro; `recording.view` → closed replay | H(sid) | window (passive) + lock | | 60-second revalidation re-runs authz (§A.6.4) |
| `/ws/shared/{token}` (8990) | WS | — | P | hub lock applies | | revoked when the creator loses `share.live` |
| `/agent/ws` (8852) | WS | — | P (host token) | | | not a user principal |

### A.8 Files and transfers

| Route | Method | Perm | Scope | 2FA | Notes |
|---|---|---|---|---|---|
| `/api/hosts/{host_id}/fs` (2427) | GET | `files.read` | H(host_id) | su | |
| `/api/hosts/{host_id}/fs/cwd` (2438) | GET | `files.read` | H(host_id) | su | (session cwd) |
| `/api/hosts/{host_id}/fs/download` (2483) | GET | `files.read` | H(host_id) | su | audited |
| `/api/hosts/{host_id}/fs/archive` (2559) | GET | `files.read` | H(host_id) | su | |
| `/api/hosts/{host_id}/fs/preview` (2864) | GET | `files.read` | H(host_id) | su | |
| `/api/hosts/{host_id}/fs/upload` (2637) | POST | `files.write` | H(host_id) | su | |
| `/api/hosts/{host_id}/fs/upload/status` (2671) | GET | `files.write` | H(host_id) | su | |
| `/api/hosts/{host_id}/fs/upload/commit` (2688) | POST | `files.write` | H(host_id) | su | |
| `/api/hosts/{host_id}/fs/upload` (2709) | DELETE | `files.write` | H(host_id) | su | |
| `/api/hosts/{host_id}/fs/mkdir` (5641) | POST | `files.write` | H(host_id) | su | |
| `/api/hosts/{host_id}/fs/rename` (5653) | POST | `files.write` | H(host_id) | su | (rename over an existing file = delete → also `files.delete` when `overwrite`) |
| `/api/hosts/{host_id}/fs/delete` (5667) | POST | `files.delete` | H(host_id) | su | |
| `/api/fs/copy` (2752) | POST | `files.read` (src) + `files.write` (dst) | H(body: src, dst) | su (both) | job stores `user_id` |
| `/api/fs/copy/{job_id}` (2807) | GET | — (job owner / Owner) | S | | ⚠ today any account sees any job |
| `/api/fs/copy/{job_id}` (2816) | DELETE | — (job owner / Owner) | S | | |
| `/api/fs/copy/{job_id}/retry` (2828) | POST | — (job owner; re-checks `files.read` + `files.write`) | S + H(job) | su | |

### A.9 Run, Docker, services, Toolbox, serial

| Route | Method | Perm | Scope | 2FA | Tok | Notes |
|---|---|---|---|---|---|---|
| `/api/hosts/{host_id}/run` (3712) | POST | `run` | H(host_id) | su | run | the fleet console = N calls; each host is checked |
| `/api/hosts/{host_id}/git` (3765) | POST | `run` | H(host_id) | su | | |
| `/api/hosts/{host_id}/docker` (3865) | GET | `docker.view` | H(host_id) | su | | |
| `/api/hosts/{host_id}/docker/stats` (4025) | GET | `docker.view` | H(host_id) | su | | |
| `/api/hosts/{host_id}/docker/action` (4052) | POST | `docker.act` | H(host_id) | su | | |
| `/api/hosts/{host_id}/services` (4125) | GET | `services.view` | H(host_id) | su | | |
| `/api/hosts/{host_id}/services/action` (4166) | POST | `services.act` | H(host_id) | su | | |
| `/api/hosts/{host_id}/connections` (4369) | GET | `toolbox.use` | H(host_id) | su | | |
| `/api/hosts/{host_id}/connections` (4380) | POST | `toolbox.manage` | H(host_id) | su | | |
| `/api/hosts/{host_id}/connections/{conn_id}` (4398) | PATCH | `toolbox.manage` | H(host_id) | su | | check that conn belongs to host_id |
| `/api/hosts/{host_id}/connections/{conn_id}` (4420) | DELETE | `toolbox.manage` | H(host_id) | su | | |
| `/api/hosts/{host_id}/serial/discover` (5174) | POST | `serial.use` | H(host_id) | su | | |
| `/api/hosts/{host_id}/serial/open` (5189) | POST | `serial.use` | H(host_id) | su | | |

### A.10 Forwards

| Route | Method | Perm | Scope | 2FA | Notes |
|---|---|---|---|---|---|
| `/api/hosts/{host_id}/forwards` (4851) | GET | `forward.use` | H(host_id) | su | targets shown only with `forward.manage` |
| `/api/hosts/{host_id}/forwards` (5037) | POST | `forward.manage` | H(host_id) | su | |
| `/api/forwards/{fid}` (5075) | PATCH | `forward.manage` | H(fid) | su | |
| `/api/forwards/{fid}` (5101) | DELETE | `forward.manage` | H(fid) | su | |
| `/api/forwards/{fid}/probe` (3087) | GET | `forward.use` | H(fid) | su | |
| `/api/forwards/{fid}/telnet` (5129) | POST | `forward.manage` + `session.open` | H(fid) | su | opens a session through the forward |
| `<slug>.<forward-domain>/*` (`route_forward`, main.py `forward_router`) | any | `forward.use` for the ticket's `uid` | H(slug) | window (2FA hosts) | re-checked per request (epoch cache) |
| `<slug>.<forward-domain>` WS (`ForwardWSMiddleware` → `handle_forward_ws`, 5433) | WS | `forward.use` | H(slug) | window | re-checked in its revalidate loop |

### A.11 Deploy keys

All of these use `deploykey.manage`. Deploy, deploy-batch and rotate need the permission on
**every target** as well as the source.

| Route | Method | Perm | Scope | 2FA | Notes |
|---|---|---|---|---|---|
| `/api/hosts/{host_id}/deploy-key` (7013) | GET | `deploykey.manage` | H(host_id) | su | |
| `/api/hosts/{host_id}/deploy-key/generate` (7218) | POST | `deploykey.manage` | H(host_id) | su | |
| `/api/hosts/{host_id}/deploy-key/deploy` (7273) | POST | `deploykey.manage` | H(host_id) + H(body target) | ff | |
| `/api/hosts/{host_id}/deploy-key/deploy-batch` (7300) | POST | `deploykey.manage` | H(host_id) + each target | ff | |
| `/api/hosts/{host_id}/deploy-key/revoke` (7322) | POST | `deploykey.manage` | H(host_id) + target | su | |
| `/api/hosts/{host_id}/deploy-key/verify` (7351) | POST | `deploykey.manage` | H(host_id) + target | su | |
| `/api/hosts/{host_id}/deploy-key` (7378) | DELETE | `deploykey.manage` | H(host_id) | su | |
| `/api/hosts/{host_id}/deploy-key/test` (7417) | POST | `deploykey.manage` | H(host_id) + target | su | |
| `/api/hosts/{host_id}/deploy-key/ssh-config` (7438) | POST | `deploykey.manage` | H(host_id) + target | su | |
| `/api/hosts/{host_id}/deploy-key/rotate` (7470) | POST | `deploykey.manage` | H(host_id) + all targets | ff | |

### A.12 Not routes, but in scope

- **SPA catch-all** `GET /{path}` and `/assets` (main.py): public static files. Unchanged.
- **Audit middleware** (main.py): reads `request.state.principal` and `audit_host`.
- **CSRF guard / origin check:** unchanged.
- **Alerts fan-out** (`alert_history._target_users`): §A.6.8.
- **Background:** fscopy jobs (§A.6.8), the janitor (expiring bindings, 3.6.2), `sweep_*`
  (unchanged; they act on hubs).
- **3.7 SSH entry:** not an HTTP route. `route_auth_test` gains a sibling `ssh_channel_auth_test`
  asserting that every accepted channel type (session, sftp, direct-tcpip, exec) maps to a
  permission.

---

## Appendix B: Prior art (what we take, what we don't)

| Idea | Source | Take? | Why |
|---|---|---|---|
| Roles ↔ targets; user sees only targets of their roles | Warpgate roles | **Yes** (as bindings with scope) | simplest model that matches folders and tags |
| Admin roles separate from access roles | Warpgate ≥ 0.23 | **Partly**: global vs host-scoped perms, honoured only at scope `all` | |
| Allow/deny with deny priority; label selectors in the role | Teleport roles | **No deny in 3.6**; scope on the binding, not in the role | easier to explain; folders/tags are our labels |
| Role templates with traits (`{{internal.logins}}`) | Teleport | **No** | no per-user Unix logins; the agent runs as one user |
| `max_session_ttl` (shortest wins), `require_session_mfa` per role | Teleport | **Equivalent exists**: per-host `require_2fa` + 60-minute cap; per-role MFA is a possible later addition | |
| Access requests with approval thresholds, TTL, no self-approval | Teleport (web UI Enterprise-only) | **Later** (§A.10), small version | |
| Per-connection admin approval, approval cache | Warpgate 0.29 | **Later**, reuses the SSH web-approval mechanics | |
| `user:target@host` / `user#target` SSH selector | Warpgate | **Accepted as an alias**; the primary form is `target@gw` | the key identifies the user; emails make bad SSH usernames |
| Web approval (URL + security key printed in the terminal, approve in browser) | Warpgate web auth | **Yes**, in-band after key auth, approved with passkey/SSO step-up | |
| OTP as a keyboard-interactive prompt | Warpgate | **Yes, for non-interactive channels only** | interactive uses the in-band unlock |
| Tickets (one-time/expiring credentials for user+target) | Warpgate | **Not as such.** Time-bound bindings + automation tokens cover it | |
| HTTP / MySQL / Postgres targets | Warpgate | **Already covered differently**: forwards (HTTP proxy) and Toolbox DB launchers | we are a launcher, not a protocol proxy |
| Recording format (custom NDJSON + keyframes) | Warpgate | **No.** Keep asciicast v2 (`.cast`) | compatible with our player and with Tailscale's choice |
| Record output only, never input | Tailscale | **Already our rule** | protects passwords |
| `check` mode: periodic browser re-auth with `checkPeriod` | Tailscale SSH | **Equivalent**: step-up window + 60-minute absolute cap | |
| Grant strings `ids=*;type=target;actions=…` | Boundary | **No** | too general for our size; the permission catalogue is the grant language |
| Credential injection (user never sees target creds) | Boundary | **Already how WebTerm works** (agent / stored SSH creds) | |
| Recording at the proxy vs at the node; sync mode fails closed | Teleport | We record at the gateway (the "proxy"); **consider** a fail-closed option if transcript writes fail | |

## Appendix C: Sources

**Warpgate**

- Repository and README: https://github.com/warp-tech/warpgate
- Releases (0.29 session approvals, MFA enforcement): https://github.com/warp-tech/warpgate/releases
- Roles: https://warpgate.null.page/roles/
- SSH targets and username syntax: https://warpgate.null.page/targets/ssh/
- Auth (web auth, OTP, credential policies): https://warpgate.null.page/auth/
- Session approvals: https://warpgate.null.page/approvals/
- Tickets: https://warpgate.null.page/tickets/
- HTTP, MySQL and Postgres targets: https://warpgate.null.page/targets/http/ ·
  https://warpgate.null.page/targets/mysql/ · https://warpgate.null.page/targets/postgres/
- Recordings: https://warpgate.null.page/recordings/
- SSO role mappings: https://warpgate.null.page/sso/
- Source, target selector: https://raw.githubusercontent.com/warp-tech/warpgate/main/warpgate-common/src/auth/selector.rs
- Source, SSH session (web-auth and OTP prompts): https://raw.githubusercontent.com/warp-tech/warpgate/main/warpgate-protocol-ssh/src/server/session.rs
- Source, recording format: https://raw.githubusercontent.com/warp-tech/warpgate/main/warpgate-core/src/recordings/terminal.rs
- Cargo.toml (russh): https://raw.githubusercontent.com/warp-tech/warpgate/main/Cargo.toml

**Teleport**

- Roles reference: https://goteleport.com/docs/reference/access-controls/roles/
- Access requests: https://goteleport.com/docs/identity-governance/access-requests/ ·
  https://goteleport.com/docs/identity-governance/access-requests/access-request-configuration/
- Session recording: https://goteleport.com/docs/reference/architecture/session-recording/
- Moderated sessions: https://goteleport.com/docs/zero-trust-access/authentication/joining-sessions/
- Per-session MFA: https://goteleport.com/docs/ver/17.x/zero-trust-access/access-controls/guides/per-session-mfa/
- Hardware keys: https://goteleport.com/docs/zero-trust-access/authentication/hardware-key-support/

**Boundary**

- Permissions and grants: https://developer.hashicorp.com/boundary/docs/concepts/security/permissions
- Credential management: https://developer.hashicorp.com/boundary/docs/concepts/credential-management
- SSH targets: https://developer.hashicorp.com/boundary/docs/targets/create/ssh

**Tailscale**

- Tailscale SSH: https://tailscale.com/kb/1193/tailscale-ssh
- Session recording: https://tailscale.com/kb/1246/tailscale-ssh-session-recording

**SSH libraries**

- asyncssh on PyPI: https://pypi.org/project/asyncssh/
- asyncssh API: https://asyncssh.readthedocs.io/en/latest/api.html
- asyncssh changelog: https://asyncssh.readthedocs.io/en/latest/changes.html
- paramiko on PyPI: https://pypi.org/project/paramiko/
- paramiko server API: https://docs.paramiko.org/en/stable/api/server.html
- paramiko changelog: https://www.paramiko.org/changelog.html

**Research caveats**

- The release date of Warpgate 0.29 is as reported by GitHub at fetch time.
- The `ticket-` username prefix in Warpgate was inferred from source constant names, not seen
  in the docs.
- No native PROXY-protocol support in asyncssh was found. The §B.3 spike must confirm the
  existing-socket server entry point.
