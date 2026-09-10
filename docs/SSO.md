# SSO / OIDC (e.g. Authentik)

WebTerm can delegate login to an OpenID Connect identity provider — Authentik, Keycloak,
Okta, or anything that speaks OIDC. This is **optional**: with no OIDC config, WebTerm works
exactly as before (local email + password, passkeys, TOTP).

## The model, in one paragraph

Each WebTerm deployment keeps a **local admin** (created at first-run with the setup token) as
a **break-glass** account — password + optional passkey, always able to log in even if the IdP
is down. Everyone else clicks **"Sign in with <provider>"**, is provisioned on first login, and
becomes a **full administrator on that instance**. WebTerm has **no in-app RBAC** (see
[THREAT-MODEL.md](THREAT-MODEL.md)): SSO controls *who gets in*, not *what they can do once in*.

## What SSO gives you (and what it does not)

- **Central identity + MFA + offboarding.** One identity across every WebTerm instance;
  add/remove a person once in the IdP and their access to all instances changes at once.
- **Per-instance access control, in the IdP.** Each WebTerm instance is one OIDC *application*
  in your IdP. Bind each application to a group (e.g. `wt-prod`, `wt-dev`); a user reaches an
  instance only if they're in its group. This is real, coarse-grained RBAC at the
  *which-servers-can-I-log-into* level — configured entirely in the IdP, no WebTerm code.
- **It does NOT give per-host authorization inside an instance.** Every user who gets into an
  instance is a full admin over all of its hosts. To separate hosts by trust, split them across
  **separate WebTerm instances** (e.g. a `wt-prod` instance with the critical hosts, a `wt-dev`
  instance with the rest) and gate each with its own group. That gives host-group isolation
  without in-app RBAC.

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

Set these in `.env` (all six pass through `docker-compose`):

| Variable | Meaning |
|---|---|
| `WEBTERM_OIDC_ISSUER` | The provider's issuer URL (e.g. `https://idp.example.com/application/o/webterm/`) |
| `WEBTERM_OIDC_CLIENT_ID` | From the IdP |
| `WEBTERM_OIDC_CLIENT_SECRET` | From the IdP |
| `WEBTERM_OIDC_PROVIDER_NAME` | Button label, e.g. `Authentik` |
| `WEBTERM_OIDC_SCOPES` | Default `openid email profile` is fine |
| `WEBTERM_OIDC_ALLOWED_GROUPS` | Optional, comma-separated; if set, the token must carry one |

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

## 2FA hosts (step-up) under SSO

For a host marked `require_2fa`, sensitive actions need a fresh second factor. An SSO user has
no local passkey/password, so step-up is a **fresh re-authentication at the IdP** (WebTerm
redirects with `prompt=login`; the IdP re-checks its own MFA — which can be a passkey there).
On return you land back in the app and repeat the action. The **local break-glass admin** still
uses WebTerm's own passkey/password step-up.

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
line pinned in the compose file, tested on 2026.8.2) and can fail to apply if they run before the
default flows exist — if the provider doesn't appear, run `provision.sh` or register the
application via the Authentik UI (the steps above), which always works.
