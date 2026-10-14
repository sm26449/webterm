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
such a host — and mark it as a [crown jewel](#crown-jewel-hosts) so WebTerm asks before anyone
else gets a shell there.

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
| Renew TLS certificates from Settings (terminal on the gateway host) | ✓ | — | — | — |

Notes:

- **Admin** is "everything except taking over the instance". Downloading or restoring a backup
  hands out the vault key, and the signing key signs agent updates for the whole fleet, so both
  stay with Owners. Renewing a TLS certificate from Settings (`certs.renew`, 3.6.7) is Owner-only
  too: it types a `sudo` command that edits Traefik's certificate store on the gateway host. An
  Admin still sees the certificate status. Only the Owner who opened a renewal terminal can type
  into it (others, an Admin with `session.manage` included, can only watch), and it cannot be
  shared. An Admin cannot create, change or delete an Owner.
- **"Fresh second factor" is per account and host, not per action.** Deploy keys and certificate
  renewal require a factor presented within the last 2 minutes. That freshness belongs to the
  pair (you, that host): a factor you gave for one of these actions also satisfies another one on
  the same host during those 2 minutes. It never carries over to another host or another account.
- An Admin is still a **co-admin for sessions and tokens**: with `session.manage` it can kill,
  rename, share or type into any session — an Owner's included — and with `tokens.manage` /
  `shares.manage` it can see and revoke everyone's tokens and links. Give Admin only to people
  you would trust with the Owners' terminals.
- **Operators** watch anyone's session on their hosts but type only into their own. Sessions
  opened before 3.6 count as everyone's.
- **Viewers** cannot read files: file content is the most sensitive thing on a host.
- Custom roles (for example from the "Auditor" or "Files-only" preset) are built in Settings
  since 3.6.2 — see [Custom roles](#custom-roles).

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

Open **Settings → Users & roles → Accounts**. Since 3.6.6 the page has three sub-tabs —
**Accounts**, **Roles** and **SSO groups** (each with a count; you only see the ones your
permissions let you use) — under a short **Your access** summary that everyone sees. The last
sub-tab you opened is remembered in this browser, and Settings search lands on the right one.

1. **Add account** opens the form: choose a role and a scope in the same form. The default is
   *no access yet*: a new account is never an Owner by default.
2. To change access later, click the account to expand it, then add or remove **bindings** there
   (shown as chips such as "Operator · folder prod"). The list has a search box (email) and
   filters for role, sign-in type (local password / SSO only) and *no role*; accounts without a
   role are flagged, with a shortcut to list only them.

These changes are treated like credential changes: they ask for your password (or a fresh SSO /
passkey confirmation) and your second factor, they are written to the audit log, and both the
person affected and everyone who sees the security summary get an alert.

The rules the server enforces:

- you can only grant what you hold yourself, over a scope you hold it on;
- only an Owner can grant, change or remove the Owner role;
- you cannot change your own access;
- the last **permanent** Owner cannot be removed, deleted or made time-bound (a time-bound Owner
  does not count: when it ends, someone must still own the instance);
- what you grant cannot outlast your own right to grant it (see [Time-bound
  roles](#time-bound-roles)).

Each account in the list shows when it **last signed in** and how (password, password + 2FA,
passkey or SSO), or "never". Accounts created before 3.6.10 show "not recorded" until their next
sign-in: earlier releases did not record it. Only accounts with `users.manage` see this.

## Time-bound roles

When you give a role, pick how long it lasts: **Permanent**, **4 hours**, **1 day**, **7 days** or
**until a date** (at most 366 days). A time-bound role shows "expires in …" on its chip.

- Access ends at the second it expires. Every request checks the end time (cached permissions
  are dropped at the earliest end among them), so a late or stopped background job cannot extend
  it. Open terminals and forwarded-app connections of that person are re-checked at that moment
  too: they switch to read-only or close.
- Within about a minute the gateway removes the binding, revokes live shares and replay links the
  person can no longer create (until then, someone who already opened such a link keeps watching),
  writes `role binding expired` to the audit log and tells the person.
- **Make permanent** turns a time-bound role into a permanent one. It follows the same rules as
  giving the role. (The API, `POST /api/users/{uid}/bindings/{bid}/expiry`, can also move the end
  earlier; that follows the rules for removing a role.)
- **A grant never outlasts the granter.** When your right to grant something (`users.manage` over
  all hosts, plus the role's permissions over the scope, plus Owner for the Owner role) comes only
  from time-bound roles, anything you grant must end no later than that right does. The server
  refuses the rest with `403 authz.granterExpires`, naming the end: a permanent role, an end
  date after yours, **Make permanent**, a later end on someone else's role, a new account whose
  first role is permanent (the add-account form has the same duration picker), an SSO group
  mapping (mappings are always permanent), and adding permissions to a custom role that is in use.
  Nothing is capped silently. This covers a time-bound Owner too. If no permanent Owner is left,
  the way back is `python3 -m app.admin promote` on the server.
- The last permanent Owner can never be made time-bound. A time-bound Owner, or any time-bound
  role with `users.manage` (Admin, or a custom role), still has its full power while it lasts. It
  can remove other people's access, create accounts, read the audit log, and do everything else
  the role allows; only the *lifetime* of what it grants is capped. Only give one to someone you
  would trust permanently.
- Roles that come from an SSO group stay permanent: they follow the group. Change the mapping
  instead. A time-bound role over the same role and scope as an SSO-derived one is refused.
- Break-glass `python3 -m app.admin promote` always leaves a permanent Owner binding.

## Explain access

"Why can Ana open files on web01?" — open the account in **Accounts** and use **Explain access**,
then pick a host. You get one sentence ("Ana can open terminals, open and change files on web01
because of: Operator · tag db (SSO group wt-db)") and, for each role that applies there: where it
comes from (given directly, an SSO group, the 3.6 upgrade), its scope, when it expires, and what it
allows. Notes explain the rest: a time-bound role that expired and no longer counts, instance
permissions that are ignored because the binding is not over all hosts, a crown-jewel host, 2FA,
automation tokens that are capped by this access.

Everyone can ask about themselves under **Your access → Why can (or can't) I…?**. Asking about
another account needs `users.manage`, and the host must be one *you* can see: a host outside your
scope answers exactly like a host that does not exist, so the tool reveals nothing new
(`GET /api/authz/explain?user=<id>&host=<id>`).

## Crown-jewel hosts

A host that runs the WebTerm gateway or holds its backups is a **crown jewel**: a shell there is
the same as being Owner. An Owner marks it from the host's ⋯ menu (**Mark as crown jewel**). If the
host is the one picked as the gateway host for certificate renewals, the menu suggests it.

- Only an Owner can mark or unmark a host. Unmarking asks for your password and second factor.
  Both are audited and alerted.
- Marking answers with the roles (bindings and SSO mappings) that already give a non-Owner a shell
  there — review them; the mark does not remove anything.
- From then on, giving a **non-Owner** role that has any ⚑ permission over a scope that includes
  the host — a binding, the role of a new account, an SSO group mapping — needs an explicit
  confirmation in a blocking dialog (the API answers `409 authz.crownJewel` with the hosts until
  the request carries `confirm_crown_jewel: true`). The same applies when you move a crown-jewel
  host into a folder or give it a tag over which such roles exist (`409 authz.crownJewelMove`).
  The confirmed change is written to the audit log as such.
- Viewer-like roles (no ⚑ permission) and Owner need no confirmation.
- A crown badge shows next to the host for everyone who can see it.

What the confirmation does **not** cover, deliberately or for now:

- mappings from `WEBTERM_OIDC_ROLE_MAP` in the server's `.env` (the Owner's own decision on the
  host; they can never grant Owner anyway);
- a custom role that is edited to add a ⚑ permission while it is already bound over a crown jewel
  (the role editor already requires `roles.manage` and no-escalation);
- making an existing time-bound role permanent.

Agents do not report which containers or volumes run on a host, so WebTerm cannot detect a
crown jewel by itself beyond the gateway-host hint.

When a binding is removed, its effect is immediate: open terminals of that person switch to
read-only or close, their forwarded-app tickets stop working on the next request, and any live
share or replay link they can no longer create is revoked.

## No access yet

An account with no binding — a new account, or a new SSO login — can sign in but sees an empty
fleet and a message to ask an administrator (the names of Owners and Admins are deliberately
not shown to an account without access). A link to a host you cannot see shows
"not found or no access", deliberately the same as a host that does not exist.

A new SSO user gets the roles its IdP groups are mapped to ([SSO group
mapping](#sso-group-mapping)); with no mapped group it has no access until an Owner or Admin adds
a binding. Accounts that existed before the 3.6 upgrade (including SSO accounts) became Owners.

## Custom roles

Settings → Users & roles → **Roles** (editing needs **Custom roles**, `roles.manage`; with only
`users.manage` the sub-tab is read-only). The same sub-tab lists the built-in roles with what
they allow and how many bindings / SSO mappings use each role. Role names that
only *look* like another role's — letters from another alphabet such as a Cyrillic `О` in
`Оwner`, or a name mixing alphabets — are refused (`role.nameConfusable`). A custom role is a
named set of permissions from the [catalogue](#permission-reference); where it applies is still
decided by the scope of each binding, exactly like a built-in role. The editor groups the
permissions as in the reference below and marks the shell-equivalent ones with ⚑; ticking any of
them shows a banner, because a role with ⚑ on a host *is* a shell there. Two presets give a
quick start: **Auditor** (`host.view`, `recording.view`, `audit.view` — no live sessions) and
**Files-only** (`files.read`, `files.write` — still ⚑ through `files.write`).

The rules the server enforces (each one re-checked under a lock right before writing, on your
rights *at that moment*):

- **No escalation.** A role can only contain permissions you hold over the **whole instance**:
  instance permissions, plus host permissions from a binding over **all hosts**. Editing checks
  the old *and* the new set — you cannot edit (or delete) a role that holds anything you lack,
  even to remove it. So an Admin can never build a role with backups, the signing key or the
  history wipe.
- **Built-in roles are immutable** (Owner, Admin, Operator, Viewer). Their permissions come from
  the code.
- **A role in use** (given to someone, or mapped to an SSO group) changes other people's access,
  so editing it also needs **Accounts and their roles** (`users.manage`), and the target rule
  below for every account that has it — an Admin cannot edit a role that an Owner holds.
- **Deleting a role that is in use is refused** (it lists how many bindings, SSO mappings and
  tokens still use it). Remove those first. This is deliberate: a single click never revokes a
  group of people silently.
- **Instance permissions in a role only count over all hosts.** Given over a folder, a tag or a
  host, they are ignored (the editor says so).
- **Nobody changes the access of an account that holds more than they do.** Granting, removing
  or deleting fails with *outranked* when the target account holds a permission (over the whole
  instance) that you do not — the 3.6.0 rule "only an Owner touches an Owner", generalised to
  custom roles.
- Every change asks for your password (or a fresh SSO / passkey confirmation) and your second
  factor, is audited, and alerts the security-summary holders. A role edit takes effect
  **immediately**: open terminals of the people who have it switch to read-only or close, and
  their forwarded-app tickets and shares are re-checked.

A custom role that happens to contain every permission is **not** an Owner: the last-Owner
protection, "only an Owner grants Owner" and the Owner-only paths count only the built-in Owner
role.

## SSO group mapping

Settings → Users & roles → **SSO groups** (shown only when SSO is enabled; needs
`users.manage`). Mappings are grouped by group name; the ones from `WEBTERM_OIDC_ROLE_MAP` carry a
**from configuration** badge and cannot be removed there. Map a group name from the id_token's `groups` claim to a role and a scope.

**Example with Authentik.** Create the groups in Authentik (Directory → Groups) and add people:

| Authentik group | WebTerm mapping | Effect |
|---|---|---|
| `wt-owners` | Owner · all hosts | the instance owners (keep this group tiny) |
| `wt-admins` | Admin · all hosts | co-admins |
| `wt-ops-prod` | Operator · folder `prod` | shell, files and run on the hosts in `prod` |
| `wt-oncall` | Viewer · tag `web` | watch live sessions and recordings on `web` hosts |
| `*` | Viewer · host `status-page` | every SSO user can watch one host |

`*` means *every authenticated SSO user*. Authentik sends the `groups` claim through the default
`profile` scope mapping.

**Out of the box (3.6.5).** You do not have to build the mappings by hand: with
`WEBTERM_OIDC_ROLE_MAP` in `.env` (printed by Authentik's `provision.py`) WebTerm creates them at
startup — `wt-admins` → Admin · all hosts, `wt-readonly` → Viewer · all hosts, `wt-db` → Operator ·
tag `db`, `wt-network` → Operator · tag `network` (`wt-access` gives sign-in only). They appear in
the list with a **from configuration** badge and cannot be removed in the UI (`ssoMap.fromConfig`):
change `.env` and restart. Owner is never accepted there. Walkthrough, syntax and the
quick-revocation settings: [SSO.md → Groups out of the box](SSO.md#groups-out-of-the-box-365).

**Team examples.** Tag the hosts, then put people in one group each:

| Team | Hosts tagged | Group → role | They can |
|---|---|---|---|
| Database team | `db` | `wt-db` → Operator · tag `db` | shell, files, run, Docker/services on the DB hosts; nothing on the other hosts |
| Network team | `network` | `wt-network` → Operator · tag `network` | the same, on routers/firewalls/VPN hosts |
| Auditors / on-call | — | `wt-readonly` → Viewer · all hosts | watch live sessions and recordings everywhere, no shell, no files |

A host with both tags is reachable by both teams. **Viewer can open forwarded apps**
(`forward.use`) — a web UI behind a forward (Grafana, a router admin page) may itself allow
changes. For a strictly read-only group, create a custom role without `forward.use` (e.g. from
the **Auditor** preset: `host.view`, `recording.view`, `audit.view`, plus `session.watch` if they
should watch live sessions) and map the group to it — in the UI, or in `.env` as
`wt-readonly=<role name>@all`.

**When it applies.**

- At every **SSO sign-in** and every **SSO step-up**, the account's SSO-derived bindings
  (`source: sso`) are re-synced to the groups the IdP just sent: a mapped group the person is in
  adds its binding, a binding whose group is gone is **removed at once** (open terminals switch
  to read-only or close). Bindings given by hand (and the 3.6 migration's Owner bindings) are
  **never touched**.
- **Adding a mapping** takes effect at each person's next SSO sign-in or step-up — WebTerm never
  grants from old group data.
- **Removing a mapping** takes effect **immediately** for the accounts that got their binding
  from it (from the groups recorded at their last sync — only the mapped ones are stored), unless
  another remaining mapping still justifies the same binding.
- Giving someone by hand a binding they already have through SSO turns it into a manual one: it
  stays when the group goes. Removing an SSO-derived binding by hand lasts only until the next
  SSO sign-in, which adds it back while the mapping and the group membership exist — remove the
  mapping, or the person from the group, instead.

**Accounts with a local password never receive roles from groups.** Only accounts that sign in
with SSO only get group roles: an account created by the first SSO sign-in has no local password;
an existing local account that SSO *adopted* by email keeps its password (and its passkeys and
2FA), so its groups give it **nothing** — removals still apply, and the gateway logs and audits
`sso.sync.skippedLocalPassword`. The reason: whoever set that password — for example an Admin who
created `ceo@corp.example` before the real CEO's first SSO sign-in — could otherwise sign in with
it and inherit what the CEO's groups grant (Owner). To receive group roles, the person removes
the local password under Settings → Users & roles → **Your access** (after a fresh SSO
confirmation). That also removes the account's passkeys, 2FA and other signed-in devices, because
anyone who knew the password could have added a passkey; they can be set up again after signing
in with SSO. Setting a local password again removes the SSO-derived roles immediately. Accounts
from before 3.6.2 count as having a local password (WebTerm cannot tell which were adopted), so
existing SSO users remove it once. The Users list marks such SSO accounts *local password*.

**Who can map.** Mapping a group grants its role to everyone in the group, so it follows the same
rules as giving a binding: `users.manage`, no escalation over the scope, and **only an Owner can
map a group to Owner** (or remove such a mapping). A **`*`** mapping (every SSO user) to a role
with any instance permission or any ⚑ permission, or over all hosts, is **Owner-only** too, and
every `*` mapping raises a critical alert. Removing a mapping is refused (`outranked`, with the
number of accounts) when it would take roles away from an account that holds more than you.
Every change needs your password and second factor, is audited and alerts the security-summary
holders.

**Edge cases, decided on the safe side.**

- **Group names match exactly**, character for character, against the raw claim: upper and
  lower case count (`Ops` is not `ops`), and nothing is trimmed or Unicode-normalised
  (`wt-owners ` with a trailing space is not `wt-owners`). A mapping name that trimming or
  Unicode normalisation (NFC) would change, or that has control or invisible (format) characters,
  is refused when you create it; names are at most 256 characters.
- **The `groups` claim is absent** from the id_token (the IdP does not send it): nothing changes
  for that sign-in, and the gateway logs a warning — a misconfigured IdP must not strip everyone's
  access. **Present but empty**, or **unreadable** — anything but a list of strings, such as a
  bare string: the person is in no group, so their SSO-derived bindings are removed (an unreadable
  claim is also audited). Items of a list that are not strings are ignored, never converted.
- **Huge group lists**: only the first 5000 entries are read; a truncated list can only grant
  less.
- **The last Owner**: if the only remaining Owner holds Owner only through SSO and leaves the
  Owner group, the binding is **kept** (WebTerm never locks itself out), logged as an error,
  audited and alerted as critical. Make another account Owner, then fix the group.
- **Signing in with a passkey** instead of SSO does not re-sync: an SSO account keeps its
  SSO-derived roles until its next SSO sign-in or step-up. To revoke at once, remove the mapping
  (immediate) or the binding. Since 3.6.5, `WEBTERM_OIDC_SSO_ONLY=1` refuses the passkey as the
  first factor for SSO-only accounts and `WEBTERM_OIDC_SESSION_MAX_HOURS` bounds how long one
  sign-in lasts, so the groups are re-read at least that often
  ([SSO.md → Quick revocation](SSO.md#quick-revocation)).
- A mapping from `WEBTERM_OIDC_ROLE_MAP` that is no longer listed is removed at the next start,
  with the roles it alone gave — the same as removing it in the UI.
- A mapping on a single host is deleted together with the host.

## Read-only terminals

With **watch** rights (Viewer, or an Operator on someone else's session) the terminal attaches
**read-only**: a "watching (read-only)" pill is shown and the keyboard is inert. The server drops
any input from a read-only client, so this is not just a hidden button.

Closed sessions open as a replay for anyone with **recording.view** on the host.

On a host that requires 2FA a watcher needs its own step-up like anyone else, and its factor only
unlocks **its own** view: a read-only client cannot unlock a locked terminal for the person
typing, and attaching without a step-up window locks only the watcher, never the writer.

When several people **type** into the same 2FA terminal:

- unlocking it (after the idle lock or the 60-minute cap) restarts the **60-minute cap from the
  unlocking account's factor**;
- every other account's view **stays locked** unless that account holds its own open step-up
  window — it unlocks with its own factor, never with someone else's;
- a second account that attaches without a window while someone is already working locks only
  its own view; the person working is not interrupted. Alone on the terminal, attaching without a
  window shows it locked, as before.

## Automation tokens and roles

Automation tokens keep their `read` / `run` scopes and are additionally capped:

- a token can never do more than **its creator can do now**. Demote the creator and the token
  shrinks; delete the creator and the token stops working;
- when you create a token (Settings → Infrastructure) you pick a **role** and a **scope** (for
  example "Viewer on host web01"). The default is Viewer over all hosts — the least. Built-in
  roles except Owner and, if you can read them, custom roles are offered; "No role cap" creates a
  token like before 3.6.10 (only its read/run scopes and its creator limit it). The list shows each
  token's role and scope;
- what a token can do = its read/run scopes ∩ its role ∩ its scope ∩ what its creator can do now;
- a token never gets administration or Owner-only permissions, whatever its role: `users.manage`,
  `roles.manage`, `settings.manage`, `tokens.*`, `shares.manage`, `snippets.manage`,
  `history.clear`, `backups.manage`, `signing.manage`, `certs.renew`, `hosts.create`,
  `hosts.export`, `audit.view`, and on hosts `host.admin`, `host.edit`, `deploykey.manage`,
  `share.live_write`, `share.live`, `share.replay`, `session.manage`, `forward.manage`,
  `toolbox.manage`, `serial.use`, `host.wake` (`authz.TOKEN_NEVER`);
  the Owner role is refused for new tokens. A token that was created with the Owner role before
  3.6.10 keeps working exactly as before, as if it had no role cap (its read/run scopes, the list
  above and its creator still limit it); at every start the gateway logs a warning with the ids and
  names of such tokens so you can recreate them with a narrower role;
- tokens are still accepted only on the status, host list, session list and run endpoints, and
  still cannot reach hosts that require 2FA (a token cannot present a second factor).

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
`backups.manage`, `signing.manage`, `certs.renew`.
