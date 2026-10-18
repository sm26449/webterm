# SSO / OIDC (e.g. Authentik)

WebTerm can delegate login to an OpenID Connect identity provider — Authentik, Keycloak,
Okta, or anything that speaks OIDC. This is **optional**: with no OIDC config, WebTerm works
exactly as before (local email + password, passkeys, TOTP).

## The model, in one paragraph

Each WebTerm deployment keeps a **local admin** (created at first-run with the setup token) as
a **break-glass** account — password + optional passkey, always able to log in even if the IdP
is down. Everyone else clicks **"Sign in with <provider>"** and is provisioned on first login.
SSO controls *who gets in*; **roles** ([ROLES.md](ROLES.md), 3.6) control *what they can do once
in*. A newly provisioned SSO account starts with **no access** unless one of its IdP groups is
mapped to a role (Settings → Users & roles → **SSO groups**, 3.6.2 — see
[ROLES.md](ROLES.md#sso-group-mapping)); otherwise an Owner or Admin binds it by hand. Accounts
that already existed when you upgraded to 3.6 became Owners.

## What SSO gives you (and what it does not)

- **Central identity + MFA + offboarding.** One identity across every WebTerm instance;
  add/remove a person once in the IdP and their access to all instances changes at once.
- **Per-instance access control, in the IdP.** Each WebTerm instance is one OIDC *application*
  in your IdP. Bind each application to a group (e.g. `wt-prod`, `wt-dev`); a user reaches an
  instance only if they're in its group. This is real, coarse-grained RBAC at the
  *which-servers-can-I-log-into* level — configured entirely in the IdP, no WebTerm code.
- **Per-host authorization inside an instance comes from roles, not from the IdP.** Since 3.6
  an Owner or Admin binds each account to a role over all hosts, a folder, a tag or one host
  ([ROLES.md](ROLES.md)). Separate instances per trust level remain a valid, stronger split —
  they also separate the gateway itself.

## Groups → roles (3.6.2)

WebTerm reads the id_token's **`groups`** claim — the same claim `WEBTERM_OIDC_ALLOWED_GROUPS`
checks. In Settings → Users & roles → **SSO groups**, map a group name to a role and a
scope. At every SSO sign-in and every SSO step-up WebTerm re-syncs the account's SSO-derived
roles to the groups the IdP just sent: missing ones are added, ones whose group is gone are
removed at once. Roles given by hand are never touched. **Only SSO-only accounts
receive group roles**: a local account that SSO adopts by email keeps its password, and with a
local password the groups give it nothing until the person removes the password (Settings →
Users & roles → Your access), which also removes its passkeys and 2FA. The rules, examples with
Authentik groups, and the edge cases (absent or unreadable claim, exact names, the last Owner) are
in [ROLES.md → SSO group mapping](ROLES.md#sso-group-mapping).

With Authentik the `groups` claim is part of the default **profile** scope mapping, so nothing
extra is needed as long as `WEBTERM_OIDC_SCOPES` includes `profile` (it does by default). If the
gateway logs `the id_token for … has no groups claim`, the IdP is not sending it: the mapping
then changes nothing for that sign-in.

## Groups out of the box (3.6.5)

`deploy/authentik/provision.sh` (or `provision.py`) creates five groups in Authentik and binds the
WebTerm application to one expression policy, `wt-groups`, that passes for a member of **any** of
the five (being in **one** of them is enough to sign in). It never changes the application's
policy engine mode or its other bindings — an MFA or network policy you bound stays mandatory —
and it lists them at the end so you see what else the application requires. An older install's
direct `wt-access` binding is replaced by the policy. Then it prints the `.env` block, including
the group → role map. Nothing to click in WebTerm's mapping editor.

| Authentik group | What it gives in WebTerm |
|---|---|
| `wt-access` | sign-in only — **no role** (give access by hand in WebTerm) |
| `wt-admins` | Admin @ all hosts |
| `wt-readonly` | Viewer @ all hosts |
| `wt-db` | Operator @ hosts tagged `db` |
| `wt-network` | Operator @ hosts tagged `network` |

**Owner is never granted by a group.** The Owner stays the local break-glass account; WebTerm
refuses `owner` (and any custom role with Owner-only permissions) in the configured map.

**Day to day:**

1. In Authentik, create the user (Directory → Users) and put them in **one** group, e.g. `wt-db`.
2. They click **Sign in with Authentik** in WebTerm. The first SSO sign-in creates the account and
   gives it the group's role (here: Operator on every host tagged `db`).
3. Moving them to another group changes the role at their next SSO sign-in; removing them from the
   group removes it then. To revoke **now**, see *Quick revocation* below.

**Extra access for one person** is given by hand in WebTerm (Settings → Users & roles) and is
**independent and additive**: a role bound by hand is never removed by a group sync, and a group
never removes it.

**The block provision prints** (paste it into WebTerm's `.env`, then restart the app):

```
WEBTERM_OIDC_ISSUER=https://auth.example.com/application/o/webterm/
WEBTERM_OIDC_CLIENT_ID=…
WEBTERM_OIDC_CLIENT_SECRET=…          # or secrets/webterm_oidc_client_secret
WEBTERM_OIDC_PROVIDER_NAME=Authentik
WEBTERM_OIDC_ALLOWED_GROUPS=wt-access,wt-admins,wt-readonly,wt-db,wt-network
WEBTERM_OIDC_ROLE_MAP=wt-admins=admin@all,wt-readonly=viewer@all,wt-db=operator@tag:db,wt-network=operator@tag:network
WEBTERM_OIDC_SSO_ONLY=1
WEBTERM_OIDC_SESSION_MAX_HOURS=12
```

`WEBTERM_OIDC_ALLOWED_GROUPS` must list **all five**: with only `wt-access` there, someone who is
only in `wt-db` would pass Authentik and then be refused by WebTerm.

**`WEBTERM_OIDC_ROLE_MAP`** — comma- or newline-separated `group=role@scope` entries:

- *role* — `admin`, `operator`, `viewer`, or the name of an existing custom role (not case
  sensitive). `owner` is refused.
- *scope* — `all`, `folder:<name>`, `tag:<name>` or `host:<name>` (a host name; a host that does
  not exist yet is skipped with a warning, two hosts with the same name are skipped as ambiguous).
- *group* — the exact name the IdP sends (case-sensitive; no surrounding spaces). `*` (every SSO
  user) is not accepted here — an Owner maps it in the UI. A group name containing `,` or `=`
  cannot be written here; map it in the UI.

It is applied **when WebTerm starts, and only then**. Host and custom-role **names** are resolved
then: renaming or deleting a host it names, or renaming a custom role it names, keeps the mapping
on the same host/role until the next restart (a deleted host takes its mapping with it), logs a
warning and is audited — update `.env` before restarting, or the entry is skipped. A custom role
it uses cannot gain an Owner-only permission (`role.usedByConfigMap`); remove it from the map
first. At each start the mappings it created (shown in the UI with
a **from configuration** badge, not removable there) are made to match the variable exactly —
missing ones are added, ones no longer listed are removed together with the roles they alone gave
(at once, like removing a mapping in the UI). Mappings created in the UI are never touched. A bad
entry (syntax, unknown role, `owner`, control characters, a group name with surrounding spaces) is
**skipped**: it grants nothing, WebTerm still starts, and the gateway log shows
`WEBTERM_OIDC_ROLE_MAP: entry … SKIPPED — <reason>`; every skipped entry is audited, and `owner`
also raises a critical alert. The rules of [ROLES.md → SSO group mapping](ROLES.md#sso-group-mapping)
(only SSO-only accounts receive group roles, absent claim, last Owner) apply unchanged.

**Several instances on one Authentik:** set `WT_GROUP_PREFIX` in Authentik's `.env` before running
provision (e.g. `WT_GROUP_PREFIX=wt-prod`): the groups become `wt-prod-access`, `wt-prod-admins`, …
and the printed `ALLOWED_GROUPS` / `ROLE_MAP` use the same names, so an Admin of `prod` is not an
Admin of `dev`.

### Quick revocation

Groups are read at each **SSO** sign-in and step-up. Two settings make sure that happens often:

| Variable | Effect |
|---|---|
| `WEBTERM_OIDC_SSO_ONLY=1` | SSO-only accounts (no local password) can sign in **only through SSO**: a passkey is refused as the *first* factor (`auth.ssoOnly`), so every sign-in re-reads the groups. Passkeys still work as a second factor / step-up. Local accounts (the break-glass Owner) are not affected. A value that is neither 0 nor 1 counts as **on**. |
| `WEBTERM_OIDC_SESSION_MAX_HOURS=12` | A web session of an account linked to SSO ends after this many hours, however active, forcing a fresh SSO sign-in (→ group re-sync). Open terminals of that session follow the usual session-expiry behaviour (they close at the next check). Applies to sessions already open when you set it. Forwarded-app tickets issued from such a session expire with it. Empty/0 = off; an invalid value means 12. |

To cut someone off **immediately**, without waiting for either: remove them from the group in
Authentik **and** remove their role bindings by hand in Settings → Users & roles (takes effect at
once: open terminals go read-only or close; the next SSO sign-in does not add them back, because
the group is gone), or run `python3 -m app.admin logout-all <email>` on the server to end their
sessions.
Automation tokens an SSO user created are capped by that user's roles as they stand in WebTerm,
which change only at an SSO sign-in — revoke the tokens too when it matters. With **SCIM
provisioning** (3.6.11, [below](#scim-provisioning-3611)) the IdP pushes these changes at once:
deactivating the person in Authentik disables the WebTerm account, ends its sessions and terminals
and revokes its tokens, and a group change re-syncs its roles immediately.

`python3 -m app.admin sso-only <email>` does from the server what *remove local password* does in
Settings: the account loses its local password, passkeys, 2FA, recovery codes and sessions, and
signs in with SSO only from then on — so its groups start giving it roles. It is refused for an
account that never signed in with SSO, and for the last Owner that still has a local password (the
break-glass account) unless you pass `--force`. Only a **permanent** Owner with a local password
counts as another break-glass account; a time-bound Owner does not.

## SCIM provisioning (3.6.11)

With SSO alone, WebTerm learns about a person only when they sign in: a deactivated or deleted
IdP user keeps their WebTerm sessions, open terminals and automation tokens until those expire,
and a group change waits for the next SSO sign-in. **SCIM** turns that around: the IdP *pushes*
user creation, deactivation, deletion and group membership to WebTerm the moment they happen.
WebTerm implements the part of SCIM 2.0 (RFC 7643/7644) that IdP provisioning clients use —
Authentik's SCIM provider is the reference — at `<WEBTERM_PUBLIC_URL>/scim/v2`.

SCIM needs SSO (OIDC) configured: an account SCIM creates can only ever sign in through SSO, so
without OIDC WebTerm refuses SCIM requests (403).

### What syncs, and what never does

| The IdP does | WebTerm does |
|---|---|
| creates a user | creates an **SSO-only** account (no local password; no role until a mapped group gives one). An existing SSO-only account with the same email (and, if it is already linked to SSO, whose `sub` equals the IdP's `externalId`) is **adopted** instead of duplicated — a critical alert says so. An `externalId` that matches an account's `sub` but comes with another email is refused (400 `invalidValue`) — unless the same request deactivates the person (`active: false`): then the account is adopted under its **own** email, disabled, and a warning goes out (once an hour per account). The same when the `externalId` links one WebTerm account while the email now belongs to another (400 `… belong to different WebTerm accounts`): with `active: false` the account the *identity* links is the one disabled, under its own email — the email-matched account is someone else's and is never touched. A user the IdP sends as **inactive** (`active: false`) that matches no WebTerm account is **not created** (400 `invalidValue`, audited at most once an hour per email, no alert) — it is created when the IdP activates it. |
| changes email / username / name | updates the account. The **email** only of accounts SCIM *created* — never of an account it adopted, nor of one holding an Owner-level role given in WebTerm (400 `mutability`, 403 for the Owner-level one); an email (or `externalId`) another account already has → 400 `invalidValue` — never blocking a deactivation (next row) |
| deactivates a user (`active: false`) | **disables** the account at once: web sessions deleted, open terminals and forwards closed, automation tokens **revoked**, live shares and replay links revoked, no permission left. Nothing is deleted: audit history, role bindings and passkeys stay for a re-enable. A refused email / `externalId` change never blocks a deactivation — an email or `externalId` another WebTerm account already has included (a local break-glass account with that address, two people who swapped addresses in the IdP): when the same request carries both (Authentik sends the whole user), the account is disabled, the identity change is ignored, audited and alerted (warning, once an hour per account). Without `active: false` the refused change stays refused (400). |
| reactivates a user (`active: true`) | re-enables a SCIM-managed account that SCIM disabled; it gets back the roles it had. Not an account WebTerm itself disabled, nor one holding an Owner-level role given in WebTerm (403: an Owner re-enables those) |
| deletes a user | disables the account **and** unlinks it from SCIM (it stays, disabled, for its history). If the IdP provisions the same person again, the account is adopted and re-enabled. |
| adds / removes group members, renames or deletes a group | re-runs the [SSO group → role mapping](ROLES.md#sso-group-mapping) for those accounts **immediately**, with the rules of an SSO sign-in |

A SCIM account signs in with SSO. At its first SSO sign-in it is linked to the OIDC identity by
`externalId == sub` — Authentik's SCIM `externalId` and its OIDC `sub` (`sub_mode =
hashed_user_id`, which provision sets) are the same value — and otherwise by the usual email
adoption, which requires `email_verified`.

What SCIM **never** does — these are refused, audited and shown as the *last error* in WebTerm:

- **touch an account with a local password** (the break-glass Owner, or any local account): such
  accounts are invisible to SCIM; creating a user with the same email or identity answers **403**
  and raises a critical alert (at most once an hour per account).
  The 3.6.2 rule still holds — an account with a local password never receives roles from groups.
- **take over, disable, delete or re-enable an account holding an Owner-level role given in
  WebTerm** — Owner, or a custom role with an Owner-only permission, granted by hand (not by an SSO
  group): only an Owner can take an Owner out (§A.5). Every one of these answers 403; a
  critical alert goes out (at most once an hour per account and action — the IdP retries at every
  sync). Give Owner through an SSO group if the IdP should manage it.
- **disable or delete the last permanent Owner** (403, plus a critical alert). A disabled Owner no
  longer counts towards "the last Owner", but it is still an Owner for who may change its access:
  an Admin cannot edit or delete a disabled Owner.
- **grant Owner**: a group mapped to Owner (or to a custom role with Owner-only permissions) is
  kept if the person already has it but never *added* by a push; it is added at the person's next
  interactive SSO sign-in, as before. Removing someone from that group through SCIM removes it at
  once (removing access is always allowed; the last Owner is kept, as for a sign-in).
- reach any other part of WebTerm: the SCIM token is not an automation token and not a session;
  settings, roles, mappings, hosts and every `/api/` route refuse it.

**How refusals look in Authentik.** A refusal that stays true until someone changes something
(a policy or identity rule above) is answered **400** (`invalidValue` / `mutability`) or **403**
(the IdP may not touch that account) — never **409**. Authentik shows a 400/403 as a
**per-object warning** in the provider's sync status and carries on with the next user. A 409
means "it already exists, find it": Authentik then searches `filter=userName eq "…"`, and when
the account is not a SCIM account (a break-glass or an Owner it may not manage) the search finds
nothing and Authentik **aborts the rest of that sync page** (up to 100 users). Authentik 2026.8.2 cannot even read
the search result for users, so WebTerm **never answers 409 to a user create**: an account that
is already provisioned is a 400 "already provisioned" (Authentik's *discovery*, on by default,
re-links it by username or email at the next full sync), and one linked under another userName
is a 400 "already linked to another identity-provider user". The only 409 left is a group name
that already exists on create — Authentik's group search resolves it. A user an SSO sign-in created in the very same instant is a
**503** with `Retry-After` (transient: a warning, the next sync adopts it). WebTerm audits a
repeated refusal once an hour per user and reason; the SCIM panel's *last error* shows every one.

**A deactivation that matches by SSO identity only.** When the IdP deactivates (`active:false`) a
user whose SSO identity (`externalId` = `sub`) matches a WebTerm account that SCIM did not create,
but whose email differs, WebTerm does **not** hand that account to SCIM: it disables it where it is
and answers 400 (without naming the account's email — the SCIM token must not learn it). Settings
→ Users & roles shows "the identity provider deactivated a user with this account's SSO identity
but a different email"; **only an Owner can re-enable it** — SCIM `active:true` never does.

**Keep break-glass and Owner accounts out of the provider's scope.** The refusals are safe, but
each sync repeats them (a warning in Authentik; in WebTerm an audit row and an alert, at most once
an hour per account). Better not to push those people at all: create an Authentik group, e.g.
`wt-scim-exclude`, put in it every IdP user whose email is a WebTerm break-glass (local-password)
account and every person who holds an Owner-level role given **in WebTerm**. provision (2a) makes
it the first test of the users filter; by hand, put it first yourself (step 2b.1 below):

```python
if ak_is_group_member(user, name="wt-scim-exclude"):
    raise SkipObject          # managed in WebTerm by an Owner, never by the IdP
```

Owners that should follow the IdP get Owner through an SSO group instead — those SCIM may manage.
The group is **only** for accounts SCIM must never manage: a user SCIM already manages that you put
in it is skipped entirely — their deactivation in the IdP no longer reaches WebTerm.

### Set it up with Authentik

**1. Create the SCIM token in WebTerm.** As an **Owner**: Settings → Users & roles → **SSO groups**
→ *SCIM provisioning* → **Create token** (your password, and your second factor if you have one).
The token (`wtscim_…`) is shown **once**; WebTerm stores only its SHA-256 hash. The panel also
shows the URL to use, the last request the IdP made, and the last error.

**2a. Let provision do the Authentik side** (recommended). Save the token in a file only you can
read and point provision at it — never put it on the command line (argv shows up in `ps` and in
the shell history):

```bash
install -m 600 /dev/null /root/webterm-scim-token && nano /root/webterm-scim-token   # paste the token
cd deploy/authentik
WEBTERM_SCIM_TOKEN_FILE=/root/webterm-scim-token ./provision.sh     # or put it in .env
```

It creates (or updates) the SCIM provider **`wt-scim`** pointing at
`https://<WEBTERM_DOMAIN>/scim/v2` (`WEBTERM_SCIM_URL` overrides it), with two filters so that only
**members of the five WebTerm groups** and only the **`wt-*` groups** are pushed (otherwise
Authentik would push *every* user it knows), and adds it as a **backchannel provider** of the
WebTerm application (other backchannel providers are kept). Re-running it is safe; after a token
rotation, run it again with the new token. With `WT_GROUP_PREFIX=wt-prod` the provider is
`wt-prod-scim` and only `wt-prod-*` groups are pushed.

**2b. Or by hand in Authentik:**

1. *Customization → Property Mappings → Create → SCIM Provider Mapping*, name
   `WebTerm SCIM: users`, expression (list your WebTerm groups):
   ```python
   # never pushed: accounts managed in WebTerm by an Owner (harmless if the group does not exist)
   if ak_is_group_member(user, name="wt-scim-exclude"):
       raise SkipObject
   # a user already pushed (or deactivated) always passes, so its deactivation reaches WebTerm
   try:
       synced = connection is not None
   except NameError:
       synced = not user.is_active
   if synced:
       return {}
   for name in ("wt-access", "wt-admins", "wt-readonly", "wt-db", "wt-network"):
       if ak_is_group_member(user, name=name):
           return {}
   raise SkipObject
   ```
   A filter that only checks group membership (the one before this review) skips a user once they
   leave the WebTerm groups — and then never pushes their deactivation. With such a filter,
   **deactivate the user first**, then remove them from the groups.
   and a second one, `WebTerm SCIM: groups`:
   ```python
   if not group.name.startswith("wt-"):
       raise SkipObject
   return {}
   ```
2. *Applications → Providers → Create → SCIM Provider*: **URL** `https://<your-webterm>/scim/v2`,
   **Token** the one from step 1, *Verify certificates* on, *Exclude service accounts* on.
   User property mappings: `authentik default SCIM Mapping: User` + `WebTerm SCIM: users`; group
   property mappings: `authentik default SCIM Mapping: Group` + `WebTerm SCIM: groups`.
3. *Applications → WebTerm → Edit → Backchannel Providers*: add the SCIM provider.

**3. Check.** Authentik runs a full sync when the provider is saved, then periodically and on every
change (*Applications → Providers → the SCIM provider* shows the sync status). In WebTerm the SCIM
panel shows the last request; Settings → Users & roles → Accounts marks the accounts it manages
with **SCIM**.

**Group names must match the `groups` claim exactly.** The group → role mapping compares names
byte for byte, so the name SCIM pushes (`displayName`, in Authentik the group's name) must be the
name the OIDC `groups` claim carries — with Authentik both are the group's name, so nothing extra
is needed. SCIM sends **direct** membership: a person who is only in a *child* group is not a
member of the parent as far as SCIM is concerned, while a `groups` claim built from `all_groups()`
includes the parents. Map the groups people are directly in (provision's groups are flat), or a
parent's role may come and go between a sign-in and the next push.

SCIM manages only the groups it pushes: for each account, WebTerm keeps the groups recorded at
its last SSO sign-in that SCIM does not push, and takes the pushed ones from SCIM. Filtering
groups out of SCIM therefore never strips roles; it only leaves those groups to the next SSO
sign-in.

### Re-enabling a disabled account

- From the IdP: reactivate the user (SCIM-managed accounts that SCIM disabled, without an
  Owner-level role given in WebTerm). An account disabled in WebTerm stays WebTerm's: a SCIM
  `active:false` or DELETE afterwards does not make it SCIM's to re-enable.
- In WebTerm: an **Owner** opens the account (Settings → Users & roles → Accounts, marked
  **Disabled**) → **Re-enable** (password + second factor). If the IdP still has the person
  inactive, its next sync disables the account again — fix it there too.
- From the server, break-glass: `python3 -m app.admin enable <email>`.

Every disable and re-enable is in the audit log (`via = scim` for the IdP's) and in the in-app
alert history of everyone with `security.view`.

### The SCIM token

Owner-only: create, **rotate** (the old token stops working at once) and **revoke** in the SCIM
panel; each is audited and alerted. **Pause** stops provisioning without revoking the token
(resuming asks for your password again). Wrong tokens are rate-limited per IP (10 failures in
15 minutes lock that IP out for 15 minutes), authenticated traffic is capped at 1200 requests a
minute, bodies at 1 MiB. Lockouts are audited (actor `unauthenticated`), at most 20 rows an
hour in total — the next row says how many were held back — and the first lockout each hour raises
a **warning alert** for everyone with `security.view` (a stale or leaked token tried from another
address must not stay invisible). A failed authentication *below* the threshold is audited too
(status 401): one row per address and hour, at most 20 rows an hour in total, the next row counting
the addresses held back. Both the alert and the 401 rows exist only while a SCIM token is
configured: without one `/scim/v2` is a closed door, and a scanner probing it is just another
401 (the lockout itself is still audited). Unauthenticated traffic keeps its own bounded memory —
it can never reset the once-an-hour throttles of the authenticated paths. Cookies are ignored on `/scim/v2` — a browser session can never act
through SCIM. The lockout is per client IP: if the IdP reaches WebTerm through the same proxy
address as untrusted traffic, set `WEBTERM_TRUSTED_PROXY_CIDRS` so WebTerm sees the real address.

**Treat the token like an Admin's password.** Whoever holds it can create an account whose
`externalId` is their own IdP identity and put it in any group SCIM pushes — so it can reach every
role a group is mapped to, except Owner (never added by a push). Keep it in the IdP and nowhere
else, rotate it when someone who could read it leaves, and map powerful roles only to groups you
watch. Guards limit what it can do to *existing* accounts: it adopts one only with that account's own
email (alerted, critical), never one holding an Owner-level role given in WebTerm; it changes the
email only of accounts it created; an account's `externalId` cannot change once set; an account
that has not signed in with SSO yet and holds a role given by hand cannot have its email changed
by SCIM (otherwise the next sign-in with that email would adopt it). The `externalId == sub` link
at sign-in also requires the same email. A PATCH path WebTerm does not recognise is refused (400
`invalidPath`), never silently ignored; fully qualified names (`urn:…:core:2.0:User:active`)
are understood, standard attributes WebTerm does not keep (`name.*`, `phoneNumbers`, the
enterprise extension…) are accepted and ignored.

A SCIM account cannot set a local password from Settings (`account.scimManaged`): with one, SCIM
would no longer manage it and it would escape deactivation in the IdP. On the server,
`python3 -m app.admin passwd <email>` still works for break-glass — it detaches the account from
SCIM (audited).

### SCIM troubleshooting

| Symptom | Cause / fix |
|---|---|
| Authentik: `401` | wrong or rotated token — paste the current one into the provider (or re-run provision with it) |
| Authentik: `403 … turned off` | SCIM is paused in WebTerm — *Resume* in the SCIM panel |
| Authentik: `403 … SSO (OIDC) is not configured` | set the `WEBTERM_OIDC_*` variables first |
| Authentik: per-object warning `403 … local password` | a local (break-glass) account has that email: SCIM never manages it. Keep that IdP user out of the provider's scope (`wt-scim-exclude`, above), use another email in the IdP, or remove that account's local password (it becomes SSO-only and can then be adopted) |
| Authentik: per-object warning `403 … Owner-level role given in WebTerm` | the person holds Owner (or an Owner-only permission) granted by hand: only an Owner manages that account. Put the IdP user in `wt-scim-exclude`, or give the role through an SSO group instead |
| Authentik: per-object warning `400 … already provisioned` | Authentik lost its link to an account it created; keep *discovery* on in the SCIM provider (the default) and the next full sync re-links it by username or email. If that create also carried `active: false`, the account was already deactivated (the 400 says "the account was deactivated as requested"); a colliding email in the same body is ignored and audited |
| Authentik: per-object warning `400 … already linked to another identity-provider user` | the WebTerm account matching that user (by email or SSO identity) is already managed by SCIM under another userName: two IdP users share an email, or the user was renamed after Authentik lost its link. Give each IdP user its own email, or delete the stale WebTerm account (Settings → Users & roles) so the next sync provisions it again. If that create also carried `active: false`, the account was already deactivated (the 400 says so) |
| Authentik: per-object warning `503`, `Retry-After` | the user signed in with SSO at the very moment SCIM created them; the next sync adopts the account — nothing to do |
| Authentik: per-object warning `400 … has a different email … WebTerm disabled that account` | the IdP deactivated a user whose SSO identity matches a WebTerm account with another email; WebTerm disabled that account without linking it to SCIM. If it is the same person, fix the email (IdP or WebTerm) and have an Owner re-enable the account in Settings → Users & roles |
| Authentik: `403 … last permanent Owner` | make another account a permanent Owner first |
| `429` | too many failed authentications from that IP (wait 15 min) or too many requests |
| a user is not created | not in a WebTerm group (provision's filter), a service account, no valid email in the IdP, or inactive in the IdP (Authentik: `400 … inactive in the identity provider` — expected; it is created once activated) |
| Authentik: `400 … email can only be changed in WebTerm` | the IdP renamed the email of an account SCIM adopted (or one that holds a role given by hand and never signed in with SSO): change it in WebTerm (Settings → Users & roles) or in the IdP back. A deactivation is never blocked by this |
| Authentik: `400 … externalId cannot change once set`, and the user stays disabled after being reactivated in the IdP | the person was deleted and re-created in the IdP (new `externalId`) while WebTerm still has the old account. The deactivation went through (the new `externalId` was ignored), but WebTerm never re-links an account to a different identity, so it refuses the whole request — re-activation included (fail closed). Delete the old account in WebTerm (Settings → Users & roles → Accounts) and let the next sync provision the new one, or re-enable it there as an Owner if it really is the same person |
| Authentik: `400 … externalId and the email belong to different WebTerm accounts` | two WebTerm accounts claim that person (one by `sub`, one by email): fix or delete the wrong one in WebTerm. A deactivation is never blocked by this: the account the `sub` links is disabled, the email ignored |
| roles do not appear | the group name differs from the mapping (exact match), the group is not pushed (filter), the account has a local password, or the role is Owner (granted at the next SSO sign-in only) |
| where to look | the SCIM panel (last request / last error), the audit log (`via = scim`), gateway logs (`SCIM:`), Authentik's provider sync status |

**Not supported (by design or not yet):** SCIM Bulk, ETags, sorting, filters other than
`<attribute> eq "<value>"` (on `userName`, `externalId`, `emails`, `id`; `displayName` for groups),
password sync (SCIM accounts have no password), SCIM without OIDC, and nested-group expansion.

## Topology: one IdP, many WebTerm instances

Authentik (or your IdP) runs **once, centrally**. Each WebTerm deployment is registered as its
own OIDC application and points at that IdP with `WEBTERM_OIDC_*`. Start with one; adding the
Nth instance is the same three steps each time.

## Register a WebTerm instance in your IdP

The reliable path is the IdP's UI (blueprints are convenient but version-sensitive — see below):

1. Create an **OAuth2/OpenID provider**:
   - Client type: **confidential**.
   - **Redirect URI**: `https://<your-webterm-domain>/api/oidc/callback` (exactly).
   - Note the **client ID** and **client secret**.
   - Scopes: `openid`, `email`, `profile`.
2. Create an **application** bound to that provider, and **bind it to a group** (e.g.
   `wt-<name>`) so only that group can use it.
3. (Optional, defence-in-depth) add a scope mapping that emits a `groups` claim, and set
   `WEBTERM_OIDC_ALLOWED_GROUPS` — WebTerm then *also* checks the group, on top of the IdP's
   binding.

## Configure WebTerm

Set these in `.env` (all of them pass through `docker-compose`):

| Variable | Meaning |
|---|---|
| `WEBTERM_OIDC_ISSUER` | The provider's issuer URL (e.g. `https://idp.example.com/application/o/webterm/`) |
| `WEBTERM_OIDC_CLIENT_ID` | From the IdP |
| `WEBTERM_OIDC_CLIENT_SECRET` | From the IdP |
| `WEBTERM_OIDC_PROVIDER_NAME` | Button label, e.g. `Authentik` |
| `WEBTERM_OIDC_SCOPES` | Default `openid email profile` is fine |
| `WEBTERM_OIDC_ALLOWED_GROUPS` | Optional, comma-separated; if set, the token must carry one |
| `WEBTERM_OIDC_ROLE_MAP` | Optional (3.6.5): group → role mappings applied at startup — [Groups out of the box](#groups-out-of-the-box-365) |
| `WEBTERM_OIDC_SSO_ONLY` | Optional (3.6.5): `1` = SSO-only accounts sign in only through SSO — [Quick revocation](#quick-revocation) |
| `WEBTERM_OIDC_SESSION_MAX_HOURS` | Optional (3.6.5): absolute session age for SSO accounts — [Quick revocation](#quick-revocation) |

SCIM provisioning (3.6.11) has no environment variable: an Owner turns it on in Settings —
[SCIM provisioning](#scim-provisioning-3611).

SSO turns on only when issuer + client_id + client_secret are all set. The redirect URI is
derived from `WEBTERM_PUBLIC_URL` — it is never taken from a request (anti open-redirect).

## Break-glass

The local admin keeps its password (and passkey, if enrolled) and can always log in — the
"Sign in with password" form stays on the login page even when SSO is on. Keep those
credentials safe: they're your way back in if the IdP is unreachable.

> **First-run note:** the **"Sign in with &lt;provider&gt;" button appears only after a local
> account exists.** WebTerm's first-run always creates the break-glass admin first (via the setup
> token), so on a brand-new instance you'll see only the setup form until that account is made —
> *then* the SSO button shows. This is by design: the break-glass anchor comes before delegation. If you want the local
admin to be **immune to SSO**, give it an email that does not exist in your IdP (WebTerm links
an SSO identity to an existing local account only when the emails match).

**Adoption requires a verified email.** Linking an SSO identity to an existing local account happens
only if the IdP asserts `email_verified` for that address — otherwise an IdP that allows unverified
emails would let someone claim an existing account (e.g. the admin's) just by setting its email.
Authentik asserts this by default; if your IdP omits the `email_verified` claim, adoption is refused
(a brand-new SSO account for a non-colliding email is still created). Newly created SSO users get a
locked local password, so they can only ever sign in through the IdP.

### Locked out: the IdP is down and nobody has a password

With `WEBTERM_OIDC_SSO_ONLY=1` (or when every Owner comes from a group mapping) there may be no
account that can use the password form. The login page then says *"The identity provider could not
be reached … see docs/SSO.md → Break-glass"* — the SSO button shows **currently unreachable** as
soon as the gateway's own IdP probe fails (System health runs it hourly, and re-probes within
minutes — at most once per 5 minutes — when it sees unconfirmed SSO failures; a failed `/api/oidc/login`
by itself does not re-probe, so the badge can lag behind a fresh outage), and a failed redirect comes
back with the same message instead of "use your password".
The way back in is a shell on the server, never the browser:

```bash
# what is wrong, without logging in (the same list as Settings → System health)
docker exec -it webterm-app-1 python3 -m app.admin health

# give one account a local password (prompts; never on the command line).
# This makes it a break-glass account: SCIM stops managing it and its SSO-group roles are
# removed (an account with a local password gets no roles from groups) — so promote it next.
docker exec -it webterm-app-1 python3 -m app.admin passwd you@example.com

# make that account Owner over all hosts (permanent, audited)
docker exec -it webterm-app-1 python3 -m app.admin promote you@example.com
```

Then sign in with the password form (2FA still applies if the account has TOTP; `app.admin
disable-2fa <email>` if the phone is gone). Once the IdP is back, the account can give itself up to
SSO again with *Remove local password* (Settings → Users & roles → Your access) — but keep **one**
permanent Owner with a local password: that is the rule `app.admin sso-only` enforces, for exactly
this day.

## 2FA hosts (step-up) under SSO

For a host marked `require_2fa`, sensitive actions need a fresh second factor. An SSO user has
no local passkey/password, so step-up is a **fresh re-authentication at the IdP** (WebTerm
redirects with `prompt=login` and `max_age=0`; the IdP re-checks its own MFA — which can be a
passkey there). On return WebTerm checks the `auth_time` claim of the new id_token: an
authentication older than the step-up request is refused. If the IdP does not emit `auth_time`
at all, the step-up is **refused** (since 3.5.13; OIDC Core requires the claim when `max_age` is
sent) and the gateway logs `SSO step-up REFUSED: the IdP did not return auth_time…` once —
configure the IdP to include the claim. `WEBTERM_OIDC_REQUIRE_AUTH_TIME=0` restores the old
lenient behaviour (accepted on `prompt=login` alone, with a warning) for an IdP that cannot emit
it. Then you land back in the app and repeat the action. The **local break-glass admin** still
uses WebTerm's own passkey/TOTP step-up (the account password alone is not a step-up).

**Access changes** (granting or revoking a role, deleting or re-enabling an account, editing a
custom role, mapping an SSO group, removing a local password) use the same idea for an SSO
account: WebTerm never asks it for a password. With a WebAuthn passkey enrolled and no TOTP, the
confirmation is that passkey; otherwise the action is sent and, when the server asks for a fresh
sign-in, you are taken to the IdP and back — reopen Settings and repeat the action (the
account-scope window is open then). One exception today: **creating an automation token** still
verifies a local password only, so an SSO account without one cannot create tokens from the UI
(the form says so); an SSO account that kept a local password types it as before.

## Logging & audit

- **Per instance:** every login (local and SSO) and every host-session attach is written to
  WebTerm's audit log (actor = email, IP, time, path), queryable at `/api/audit`. So on any
  instance you can see *who logged in* and *which hosts they reached* — useful for debugging.
- **Central "who reached which instance":** your IdP's own event log records each application
  authorization. That is the cross-instance view.
- For a single aggregated view across every instance and host, ship the WebTerm audit logs and
  the IdP events to a central store (Loki/ELK/…). That's outside WebTerm itself.

## Deploy Authentik in production

There are two shapes, both behind WebTerm's own Traefik (TLS via the same `le`/`ledns` resolver,
no published ports, Postgres + Redis on an internal network). Authentik is pinned to a current
stable line (`2026.8.x`); `provision.py` and the blueprint tolerate Authentik's cross-version model
changes (flow slugs, `grant_types`, redirect-URI shape).

### Fewest steps: bundle it (compose profile)

The bundled Authentik lives in WebTerm's **main** `docker-compose.prod.yml` under a compose
**profile**, so one flag turns it on and the installer does the rest:

```
sudo ./install.sh --domain term.example.com --email you@example.com \
     --with-authentik --authentik-domain auth.example.com
#  already installed:  cd /opt/webterm && ./deploy.sh --with-authentik   (AUTHENTIK_DOMAIN in .env)
```

This sets `COMPOSE_PROFILES=authentik` in `.env` (so every later `docker compose up -d` and
`./upgrade.sh` bring Authentik along), **generates** `AUTHENTIK_SECRET_KEY` / `PG_PASS` /
`AUTHENTIK_BOOTSTRAP_PASSWORD` / `AUTHENTIK_BOOTSTRAP_TOKEN` unique to that install (never shared
defaults), starts the stack, waits for Authentik, runs `provision.py` and writes the
`WEBTERM_OIDC_*` lines back. Standalone stays the default — with no profile, none of these
services are even created.

### Separate stack (central Authentik, many WebTerms)

`deploy/authentik/docker-compose.prod.yml` runs Authentik as its **own** stack (one central IdP
serving N WebTerm deployments — the `down` of one WebTerm never takes the shared IdP with it). On a
host that already runs WebTerm:

```
# 1. DNS: an A/AAAA record for auth.example.com -> this host.
# 2.
cd deploy/authentik
cp .env.prod.example .env      # AUTHENTIK_DOMAIN, WEBTERM_DOMAIN, secrets (openssl rand -base64 48),
                               # WEBTERM_CERT_RESOLVER = same value as WebTerm's .env (le or ledns)
docker compose -f docker-compose.prod.yml up -d
# 3. create the OIDC app + print the WEBTERM_OIDC_* block:
./provision.sh
# 4. paste those lines into WebTerm's .env, then:  docker compose -f docker-compose.prod.yml up -d app
```

`provision.sh` reads `.env`, mints an API token via `ak shell` if needed, then (idempotently)
creates a `groups` scope mapping, the `wt-access` group, a confidential OAuth2 provider with the
**exact** redirect URI `https://<WEBTERM_DOMAIN>/api/oidc/callback`, and the application bound to
`wt-access`. Re-run it any time — it patches in place and re-prints the values.

**The `webterm_webterm` network.** The compose joins Authentik to WebTerm's Traefik network, whose
name is `<compose-project>_webterm` — `webterm_webterm` when WebTerm lives in `/opt/webterm`. If you
installed elsewhere, set `WEBTERM_TRAEFIK_NETWORK` in `.env` (find it with
`docker network ls | grep webterm`).

**One Authentik, many WebTerms.** For the Nth instance, repeat only steps 3–4 from that instance's
directory (a second application, its own redirect URI, its own group) against the same Authentik.

### Upgrade Authentik

One minor at a time, a verified backup first, and a restore as the only way back: see
[AUTHENTIK-UPGRADE.md](AUTHENTIK-UPGRADE.md) and `scripts/authentik-upgrade.sh`. With the bundled
profile, `./upgrade.sh` moves Authentik straight to the new pin. Read §2 there first if your
Authentik is more than one minor behind it.

### Back up Authentik

Authentik holds your users, their passkeys, the OIDC config and the signing key — a dependency
worth backing up. `deploy/authentik/backup.sh` dumps Postgres + `.env` (needed to decrypt the DB's
encrypted fields on restore) into an **openssl-AES-256 archive** (refuses to run without
`AUTHENTIK_BACKUP_PASSPHRASE`), keeps the newest 14, and can push the encrypted copy **off-host**
over rsync-over-SSH (`AUTHENTIK_BACKUP_RSYNC=user@host:/path/`) or FTPS
(`AUTHENTIK_BACKUP_FTPS=ftp://host/path/`). Install it as a daily systemd timer:

```
sudo install -m0755 deploy/authentik/backup.sh /opt/authentik/backup.sh
sudo cp deploy/authentik/authentik-backup.{service,timer} /etc/systemd/system/
echo "AUTHENTIK_BACKUP_PASSPHRASE=$(openssl rand -base64 30 | tr -dc A-Za-z0-9)" | sudo tee /etc/default/authentik-backup >/dev/null
sudo chmod 600 /etc/default/authentik-backup   # add AUTHENTIK_BACKUP_RSYNC=… here for off-host
sudo systemctl daemon-reload && sudo systemctl enable --now authentik-backup.timer
```

Restore: `openssl enc -d …` → `tar xzf` → `docker compose exec -T postgresql psql -U authentik -d
authentik < authentik.sql` on a stack started with the **same** `AUTHENTIK_SECRET_KEY` (from the
backed-up `.env`).

### Already running Authentik? Point WebTerm at it

Don't bundle a second one. `provision.py` works against **any** Authentik — give it the domain, the
WebTerm domain, and an API token (Authentik → Directory → Tokens, or `ak shell`):

```
cd deploy/authentik
AUTHENTIK_DOMAIN=auth.yourcompany.com WEBTERM_DOMAIN=term.example.com \
  AUTHENTIK_API_TOKEN=<token> python3 provision.py    # AUTHENTIK_URL=http://host:9000 also works
```

It prints the `WEBTERM_OIDC_*` block — paste it into WebTerm's `.env`, leave `COMPOSE_PROFILES`
empty, and `./deploy.sh`. Or skip the script entirely and register the application from Authentik's
UI (confidential OAuth2/OpenID provider, redirect URI `https://<WEBTERM_DOMAIN>/api/oidc/callback`,
scopes `openid email profile`), then set the four `WEBTERM_OIDC_*` values by hand.

## Try it locally (reference stack)

[`deploy/authentik/`](../deploy/authentik/) is a self-contained **evaluation** stack: Authentik
(server + worker + postgres + redis) **plus** a WebTerm, wired together, so you can see the flow
end-to-end on one machine. It is **not** the production topology (there the IdP is central and
shared). Steps:

```
cd deploy/authentik
cp .env.example .env      # fill in the passwords (openssl rand -base64 48)
docker compose up -d
# Authentik UI:  http://localhost:9000   (admin: akadmin / $AUTHENTIK_BOOTSTRAP_PASSWORD)
# WebTerm:       http://localhost:8000
```

The `blueprints/webterm.yaml` file preconfigures the OIDC application (known
`webterm-client-id`/`secret`), a `wt-access` group and a **test user** `alice`
(`alice@example.com` / `alice-test-pass-1234`), so WebTerm starts already wired.

**To actually test the login end-to-end:**
1. Open WebTerm (`http://localhost:8000`) and create the break-glass admin with the setup token
   (`changeme-setup` from `.env`). The **"Sign in with Authentik" button appears only after this**
   first account exists.
2. Click **Sign in with Authentik** and log in as `alice` (or `akadmin`) — you're provisioned and
   land in WebTerm. That's the full flow.

**The one Docker tweak (important).** OIDC needs the **issuer URL to resolve to the same Authentik
from both the browser and the WebTerm container**. The container already reaches it by its compose
name `authentik-server:9000` (that's the `.env.example` default) — so just make the **browser**
resolve that same name to the published port: add one line to your host's `/etc/hosts`:

```
127.0.0.1  authentik-server
```

Then open WebTerm at `http://localhost:8000` and Authentik at `http://authentik-server:9000` — both
sides now agree on the issuer. (Don't use the `host-gateway`/`extra_hosts` trick — routing to a
published port that way is unreliable across Docker setups.) For a faithful test with no
`/etc/hosts` edit at all, use the bundled path (`--with-authentik`) on a real, even throwaway,
domain — that's the validated production flow.

**Blueprint caveat:** blueprint field names are version-sensitive (this one targets the Authentik
line pinned in the compose file, currently 2026.8.3) and can fail to apply if they run before the
default flows exist — if the provider doesn't appear, run `provision.sh` or register the
application via the Authentik UI (the steps above), which always works.
