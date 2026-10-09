# Roles and access

From WebTerm 3.6.0, every account has **role bindings**. A binding gives one account one role over
one *scope*: all hosts, a folder, a tag or a single host. Several people can then share one
instance, each limited to the hosts they look after.

A single-user install sees no change: when you upgrade, every existing account becomes
**Owner over all hosts**, which is exactly what it could do before.

The design, with every decision and the route-by-route permission matrix, is in
[design/ROLES-AND-SSH.md](design/ROLES-AND-SSH.md).

## What roles can and cannot do

Roles enforce two boundaries that WebTerm can really hold:

- **Which hosts you can see or touch at all.** The gateway never relays a terminal frame, a file
  operation or a command for a host outside your scope. A host you cannot see answers exactly like
  a host that does not exist (`404`), so you cannot probe for names or ids. Lists, search, history,
  audit, alerts and the status counters only ever include the hosts you can see.
- **Whether you get a shell on a host.** Without `session.open`, `run`, `files.write`, `serial.use`,
  `toolbox.use`, `docker.act`, `deploykey.manage` or `host.admin`, there is no code-execution path.

Everything finer than that is a **guardrail, not a boundary**. Once someone has a shell on a host
they can do anything the agent's user can do there: "may open a terminal but not delete files"
cannot be enforced by a web gateway, because a shell can `rm`. Permissions that amount to a shell
are marked ⚑ (shell-equivalent) in the reference below and in the app.

One more sharp edge: **a host that runs WebTerm itself** (or holds its backups) is equivalent to
Owner. Anyone with a shell there can read the database and the vault key. Only bind Owners over
such a host.

## Built-in roles

| | Owner | Admin | Operator | Viewer |
|---|---|---|---|---|
| Intended for | the instance owner(s) | team lead / co-admin | engineers doing the work | auditors, on-call watchers |
| See hosts, diagnostics, watch live sessions, recordings | ✓ | ✓ | ✓ | ✓ |
| Docker / services: view | ✓ | ✓ | ✓ | ✓ |
| Open forwarded apps | ✓ | ✓ | ✓ | ✓ |
| Open terminals ⚑, run commands ⚑, files read/write ⚑/delete | ✓ | ✓ | ✓ | — |
| Docker / services: start, stop, restart | ✓ | ✓ | ✓ | — |
| Serial consoles ⚑, database launchers ⚑ | ✓ | ✓ | ✓ | — |
| Live shares (read-only) and replay links | ✓ | ✓ | ✓ | — |
| Writable live shares ⚑, forwards, deploy keys ⚑, DB connections | ✓ | ✓ | — | — |
| Edit and administer hosts (2FA flag, provision, update, delete) | ✓ | ✓ | — | — |
| Kill or take over **other people's** sessions | ✓ | ✓ | — | — |
| Add hosts, export the host list | ✓ | ✓ | — | — |
| Instance settings, accounts and roles, all tokens and shares, audit log, security summary | ✓ | ✓ (cannot touch Owners) | — | — |
| Own automation tokens | ✓ | ✓ | ✓ | — |
| Clear the global command history | ✓ | — | — | — |
| Backups and the agent signing key | ✓ | — | — | — |

Notes:

- **Admin** is "everything except taking over the instance". Downloading or restoring a backup
  hands out the vault key, and the signing key signs agent updates for the whole fleet, so both
  stay with Owners. An Admin cannot create, change or delete an Owner.
- An Admin is still a **co-admin for sessions and tokens**: with `session.manage` it can kill,
  rename, share or type into any session — an Owner's included — and with `tokens.manage` /
  `shares.manage` it can see and revoke everyone's tokens and links. Give Admin only to people
  you would trust with the Owners' terminals.
- **Operators** watch anyone's session on their hosts but type only into their own. Sessions
  opened before 3.6 count as everyone's.
- **Viewers** cannot read files: file content is the most sensitive thing on a host.
- Custom roles (for example an "Auditor" or a "Files-only" preset) come in 3.6.1.

## Scopes

A binding's scope decides **where** its role applies:

- **All hosts** — the whole fleet, including hosts added later.
- **Folder** — every host whose folder is exactly that name.
- **Tag** — every host carrying that tag.
- **Host** — one host.

On a given host your permissions are the union of every binding whose scope matches it. There are
no deny rules.

**Instance permissions** (settings, accounts, tokens, the audit log, backups…) count only from a
binding over **all hosts**. "Admin over folder lab" lets you administer the hosts in `lab`, but not
the instance.

Because folders and tags decide who sees a host, moving a host to another folder or changing its
tags needs **Add hosts** over all hosts, not just **Edit host**. A "connect once" jump target
inherits the scope of the agent it goes through.

## Giving someone access

Open **Settings → Users & roles**.

1. **Add account**, choose a role and a scope in the same dialog. The default is *no access yet*:
   a new account is never an Owner by default.
2. To change access later, add or remove **bindings** on the account (shown as chips such as
   "Operator · folder prod").

These changes are treated like credential changes: they ask for your password (or a fresh SSO /
passkey confirmation) and your second factor, they are written to the audit log, and both the
person affected and everyone who sees the security summary get an alert.

The rules the server enforces:

- you can only grant what you hold yourself, over a scope you hold it on;
- only an Owner can grant, change or remove the Owner role;
- you cannot change your own access;
- the last Owner cannot be removed or deleted.

When a binding is removed, its effect is immediate: open terminals of that person switch to
read-only or close, their forwarded-app tickets stop working on the next request, and any live
share or replay link they can no longer create is revoked.

## No access yet

An account with no binding — a new account, or a new SSO login — can sign in but sees an empty
fleet and a message to ask an administrator (the names of Owners and Admins are deliberately
not shown to an account without access). A link to a host you cannot see shows
"not found or no access", deliberately the same as a host that does not exist.

SSO group-to-role mapping arrives in 3.6.1. Until then a new SSO user gets no access until an
Owner or Admin adds a binding. Accounts that existed before the upgrade (including SSO accounts)
became Owners.

## Read-only terminals

With **watch** rights (Viewer, or an Operator on someone else's session) the terminal attaches
**read-only**: a "watching (read-only)" pill is shown and the keyboard is inert. The server drops
any input from a read-only client, so this is not just a hidden button.

Closed sessions open as a replay for anyone with **recording.view** on the host.

On a host that requires 2FA a watcher needs its own step-up like anyone else, and its factor only
unlocks **its own** view: a read-only client cannot unlock a locked terminal for the person
typing, and attaching without a step-up window locks only the watcher, never the writer.

## Automation tokens and roles

Automation tokens keep their `read` / `run` scopes and are additionally capped:

- a token can never do more than **its creator can do now**. Demote the creator and the token
  shrinks; delete the creator and the token stops working;
- when you create a token you can narrow it further with a role and a scope (for example
  "Viewer on host web01");
- tokens are still accepted only on the status, host list, session list and run endpoints, and
  still cannot reach hosts that require 2FA.

## Upgrading from 3.5

- Every existing account becomes **Owner over all hosts** (`source: migration`). Nothing changes
  for anyone until you add other roles.
- Existing automation tokens keep working unchanged.
- Restoring a 3.5 backup on 3.6 seeds the roles again: **every account in that backup becomes
  Owner over all hosts** — including accounts you demoted since the backup was taken. Review
  Settings → Users & roles after such a restore.
- **Rolling back to 3.5 silently makes every account a full administrator again**: 3.5 ignores the
  role tables.

## Break-glass: promote from the server

If no Owner is left (for example after a partial restore), make an account Owner from the server:

```sh
docker exec -it webterm-app-1 python3 -m app.admin promote you@example.com
docker exec -it webterm-app-1 python3 -m app.admin roles you@example.com
docker exec -it webterm-app-1 python3 -m app.admin list
```

Anyone with a shell on the server already has the database and the vault key, so this grants
nothing new. The running gateway picks up the change within about a minute; the action is
recorded in the audit log.

## Permission reference

⚑ = shell-equivalent: holding it on a host gives the agent user's full power there.

Host permissions (granted per host through bindings):

| Permission | Covers |
|---|---|
| `host.view` | See the host, its state and versions. Implied by every other host permission. |
| `host.diagnostics` | Events, agent log, probes, listening ports, host-key status. |
| `session.watch` | Read-only attach to live sessions. |
| `recording.view` | Transcripts, previews, search hits, command history, replay of closed sessions. |
| `session.open` ⚑ | Open terminals (incl. container shell, OS upgrade), type into your own sessions. |
| `session.manage` | Rename, kill, delete or type into **anyone's** session on the host. |
| `files.read` | Browse, preview, download, archive. |
| `files.write` ⚑ | Upload, mkdir, rename; destination of a host-to-host copy. |
| `files.delete` | Delete files and folders. |
| `run` ⚑ | Run commands (single and fleet), git actions. |
| `docker.view` / `docker.act` ⚑ | List and stats / start, stop, restart. |
| `services.view` / `services.act` | List / start, stop, restart, enable. |
| `forward.use` | Open forwarded apps, probe. |
| `forward.manage` | Create, edit, delete forwards; telnet through a forward; jump targets via this host. |
| `serial.use` ⚑ | Serial consoles. |
| `toolbox.use` ⚑ / `toolbox.manage` | Launch / manage saved database connections. |
| `deploykey.manage` ⚑ | Deploy keys — needed on both the source and the target host. |
| `share.live` / `share.live_write` ⚑ / `share.replay` | Read-only live shares / writable shares / replay links. |
| `host.wake` | Wake-on-LAN. |
| `host.edit` | Rename, note, credentials, SSH key, host-key accept. |
| `host.admin` ⚑ | 2FA flag, enrollment, provision, agent update, autostart, uninstall, delete. |

Instance permissions (only from a binding over all hosts): `hosts.create`, `hosts.export`,
`settings.manage`, `users.manage`, `roles.manage`, `tokens.create`, `tokens.manage`,
`shares.manage`, `snippets.manage`, `history.clear`, `audit.view`, `security.view`,
`backups.manage`, `signing.manage`.
