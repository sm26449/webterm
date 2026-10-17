# Installing and operating WebTerm

The short path is in the [main README](../README.md#quick-start). This page has the
details: every install route, the image deploy, single sign-on, putting agents on hosts,
the Makefile shortcuts and backups. Recovery procedures live in [RUNBOOK.md](RUNBOOK.md);
every environment variable in [CONFIGURATION.md](CONFIGURATION.md).

## Quick install

Prerequisites: Docker + Docker Compose, a domain (recommended) or an IP, and `make`
if you want the shortcuts below (`make token`, `make upgrade` — everything they wrap
can also be run by hand).

**Architecture.** The published image is `linux/amd64`. On anything else — a Raspberry Pi,
an ARM VPS, an Apple Silicon machine running Docker natively — use `setup.sh`, which builds
from source locally (about half a minute) and never touches the registry; the base images are
multi-arch and nothing in the build is architecture-specific. `install.sh` is the path that
pulls the prebuilt image, so that one wants amd64. The agent is a single stdlib Python file
and runs on any architecture either way.

Ports **80** and **443** must be free: `docker-compose.yml` binds them for TLS. If
something else already holds them, add a `docker-compose.override.yml`. Note the
`!override` tag: compose **concatenates** port lists, so without it 80 and 443 stay
published and the container still fails to start.

```yaml
services:
  caddy:
    ports: !override
      - "8080:80"
      - "8443:443"
```

Then pass the port to `setup.sh` as part of the host — `./setup.sh 192.168.1.10:8443`.
It keeps the port in `WEBTERM_PUBLIC_URL` (the agent install command shown in the UI is
generated from that URL, so it is wrong without it) and strips it from `WEBTERM_DOMAIN`,
which becomes Caddy's site address and must not carry one.

```sh
git clone https://github.com/sm26449/webterm && cd webterm
./setup.sh term.example.com          # or ./setup.sh 192.168.1.10 to test on an IP
```

The script checks Docker, writes `.env`, builds the image, starts everything
(Caddy does TLS automatically for a domain) and prints the **setup token** for
the first account. Open the URL, enter the token + email + password, then add a
passkey from **⚙ Settings**.

Without the interactive script: copy `.env.example` → `.env`, fill it in, and
`docker compose up -d --build`. The setup token:

```sh
make token          # or, without make:
docker compose exec -T app cat /data/setup-token
```

### Installing verifiably

`install.sh` supports a `curl … | sudo bash` form (its header shows it, for cloud-init and
Ansible). It is convenient, and it is also the most privileged thing you will do with this
project: it fetches from `main` — a branch that can move — and runs as root. The path below is
the same script, only one you can read first and pin to a release.

```sh
git clone https://github.com/sm26449/webterm.git
cd webterm
git checkout v3.6.16           # the release tag (see the version badge); a tag cannot move under you, a branch can
less install.sh              # it is meant to be read
sudo ./install.sh --domain term.example.com --email you@example.com
```

Reading it also tells you the one thing that surprises people: the installer contacts
`api.ipify.org` once, to compare your public IP with what the domain resolves to and warn you
early if DNS points somewhere else. It is the only third party the installer touches, and the
check is skipped if the request fails.

## Deploy from an image (production, no build)

Every push to `main` publishes an image to the GitHub Container Registry
(`ghcr.io/sm26449/webterm`). On the server you build nothing: pull the image
and start, with **Traefik** issuing the Let's Encrypt certificate. By default that is
**HTTP-01** — no DNS provider involved; the domain must resolve to this server and
port 80 must be reachable. Give it a Cloudflare token and it switches to **DNS-01**
(`install.sh` and `deploy.sh` both write `WEBTERM_CERT_RESOLVER` from whether the token
is present): that works behind the Cloudflare proxy or through NAT with no port 80
exposed, and it is the only way to get the **wildcard** that port-forward subdomains need.

**One token** for the common case: the app setup token (auto-generated). The Cloudflare
token is optional (see above). Pulling the public image needs no authentication; a GitHub
`read:packages` token is only needed if you **fork and keep your own image private**.

> **Not on Cloudflare?** You do not need it. Leave `CF_DNS_API_TOKEN` empty and Traefik
> uses HTTP-01. The only thing you give up is TLS on port-forward subdomains (they need a
> wildcard, and only DNS-01 can issue one); the application itself gets its certificate
> normally.

### Clean server? One command: `install.sh`

On a freshly installed Ubuntu/Debian, the installer does the whole chain: Docker
(official repo), runtime files in `/opt/webterm`, `.env` (chmod 600), firewall
(ufw: OpenSSH + 80/443), the Traefik + app stack, daily backup (systemd timer,
03:30, keeps 14 archives) and a health check. Idempotent — running it again keeps
`.env` and the data.

```sh
# interactive (asks for domain and email; the Cloudflare token is optional):
git clone https://github.com/sm26449/webterm && cd webterm
sudo ./install.sh

# or non-interactive (cloud-init, Ansible, etc.):
sudo ./install.sh --non-interactive \
  --domain term.example.com --email you@example.com
#   (+ --ghcr-token-file <file> only for a private/forked image; the public one needs no login)
```

**TLS needs no Cloudflare account.** With no token, Let's Encrypt is obtained over
**HTTP-01**: all it needs is that `term.example.com` resolves to this server and that
port 80 is reachable from the internet. Add `--cf-token` only if you are behind the
Cloudflare proxy or behind NAT without port 80 — or if you use **port forwarding**:
those live on subdomains matched by a pattern, so Traefik cannot
derive their names and only a wildcard covers them — and only DNS-01 can issue a wildcard.
On HTTP-01 the application itself gets TLS normally; forwards do not.

`sudo ./install.sh --help` lists all options (`--dir`, `--image`, `--no-ufw`,
`--no-backup`…). At the end you get the URL and the setup token.

### Already have Docker? `deploy.sh`

```sh
# on the server, with Docker installed
git clone https://github.com/sm26449/webterm && cd webterm
cp .env.prod.example .env
#   WEBTERM_DOMAIN      = term.example.com
#   LETSENCRYPT_EMAIL   = you@example.com
#   CF_DNS_API_TOKEN    = (optional) Cloudflare token, Zone:DNS:Edit — leave empty for HTTP-01
#   GHCR_TOKEN_FILE     = (optional) GitHub token, read:packages — only for a private/forked image
./deploy.sh            # or: make deploy
```

`deploy.sh` generates the setup token if missing, authenticates to ghcr.io, pulls
the image and starts the stack (Traefik + docker-socket-proxy + app). It reuses
the data volume, so moving from a previous Caddy stack keeps SQLite + the
transcripts. Open `https://your-domain`, enter the setup token (`deploy.sh`
prints it), create the account + passkey. Secrets (setup token, Cloudflare token, OIDC
client secret, SMTP password, Authentik keys) live as files in `/opt/webterm/secrets/`
(0700) mounted at `/run/secrets`, not in `.env`: Traefik reads container metadata through
docker-socket-proxy and that metadata includes every container's environment. `deploy.sh`
moves any value it still finds in `.env` into its file.

Update with `./upgrade.sh` — it takes a backup, syncs the host-side scripts and hands off to
`deploy.sh`. (`make pull` exists for a quick image swap, but it bypasses `deploy.sh`, so it
records no rollback point and runs no health gate.) Deploy a specific version
with a recorded rollback point: `./deploy.sh v3.6.16` (or a digest:
`./deploy.sh ghcr.io/sm26449/webterm@sha256:…`) — if the new container does
not become healthy, the script rolls back automatically; any time afterwards,
`./rollback.sh` returns you to the previous image with a single command.

<a id="upgrading"></a>
**Upgrading: one command.** `cd /opt/webterm && sudo ./upgrade.sh` takes the
latest published version; pass a tag to target one. It resolves the version, checks ghcr auth
and disk space, pulls the image, **takes a backup**, **syncs the files that run on the host**
(compose, the operator scripts — `backup.sh`, `restore.sh`, `rollback.sh`, `deploy.sh`,
`remove.sh`, `cert-check.sh`, `cert-renew.sh` — and `upgrade.sh` itself; `/opt/webterm` is not a git checkout, so
otherwise they stay frozen at whatever the installer put there). When `deploy/` holds a newer
`webterm-backup`/`webterm-cert-check` unit than the one installed for this directory in
`/etc/systemd/system`, it re-installs that too (`daemon-reload`, timer re-enabled) — the units
were previously written once by the installer and never touched again. Then it hands off to `deploy.sh`
for the pinned deploy with automatic rollback. The pin is the image **digest**, not the tag:
`upgrade.sh` resolves `vX.Y.Z` to `ghcr.io/…/webterm@sha256:…` once, after the pull, and
everything downstream — the kit it extracts, `.env`, `.prev-image`, the rollback — uses that
(tags can be re-pointed; digests cannot). Published images are signed with keyless cosign and
carry provenance + SBOM; with `cosign` installed and `WEBTERM_COSIGN_IDENTITY` set in `.env`,
`upgrade.sh` verifies the signature before running anything from the image, and otherwise
prints that it skipped it (see [docs/RUNBOOK.md](RUNBOOK.md), "Verifying an image"). The full
recovery procedure (including when the UI is completely unreachable):
[docs/RUNBOOK.md](RUNBOOK.md).

**The three tokens, in short:**

| Token | Where | Scope | Role |
|---|---|---|---|
| Cloudflare (optional) | `CF_DNS_API_TOKEN` in `.env` | Zone : DNS : Edit (your zone) | the TLS certificate via DNS-01 (wildcard for forwards); empty → HTTP-01 |
| GitHub *(optional)* | file in `GHCR_TOKEN_FILE` | `read:packages` | only to pull a **private/forked** image |
| Setup | generated by `deploy.sh` in `secrets/webterm_setup_token` | — | the gate for creating the first account |

### TLS certificates: monitoring and renewal

Traefik gets and renews the Let's Encrypt certificates on its own, through one of two resolvers
(both always defined in `docker-compose.prod.yml`; `WEBTERM_CERT_RESOLVER` picks the one the
routers use):

| Resolver | Store (volume `traefik-acme`) | Challenge | Can issue a wildcard? |
|---|---|---|---|
| `le` | `acme.json` | HTTP-01 (port 80 reachable) | **no** |
| `ledns` | `acme-dns.json` | DNS-01 via Cloudflare | yes: `*.your-domain`, which forwards on subdomains need |

**A wildcard can only be issued and renewed via DNS-01.** The Cloudflare token needs
*Zone : DNS : Edit* on the zone; if you created it with an expiry date, renewals stop when it
expires, so note that date (or create it without one).

**Watching.** The gateway reads the certificate Traefik serves (a TLS handshake to Traefik
inside the stack; the public name as a fallback) for the app domain, the forward wildcard (DNS-01
installs) and Authentik (with the `authentik` profile). Settings → Infrastructure →
**Certificates** shows days left, issuer and names, with **Check now**. Alerts (in-app, email,
webhook) go out at under 14 days, again at under 3, and right away when a certificate has
expired, when Traefik serves its self-signed default certificate, or when the served
certificate does not cover the name. One alert per threshold and certificate, plus one when it
is fine again. The app needs no new access for this: no certificate store, no Docker.

**Renewing.** `scripts/cert-renew.sh` runs on the host, as root:

```bash
cd /opt/webterm
sudo ./scripts/cert-renew.sh --report                       # which store holds what (read-only)
sudo ./scripts/cert-renew.sh --domain term.example.com      # force a new certificate for one name
sudo ./scripts/cert-renew.sh --domain '*.term.example.com'  # quote a wildcard
sudo ./scripts/cert-renew.sh --prune-unrouted               # entries no router uses (dry run; --yes applies)
```

`--domain` first copies the store files to `acme-backups/acme-<UTC time>/` (0600; the last 5
are kept), removes **only** the entries naming that domain (it refuses when nothing matches, or
when one store holds more than one match), stops and starts **only** the Traefik container, and
waits up to 3 minutes for a valid certificate. It asks before changing anything (`--yes` skips
the question). In Settings, an **Owner** gets a **Renew** button next to an expiring
certificate: after you pick the gateway host (the enrolled host WebTerm itself runs on), it
asks for your second factor and opens a terminal there with the command **typed, not run**:
you read it and press Enter, and `sudo` on the host decides whether you may. The command is
`sudo -k …`, so the password you type there leaves no cached sudo credentials behind; only you
can type into that terminal and it cannot be shared. Without a picked host it shows the command
to copy.

The script refuses to run unless the install directory, every directory above it (sticky ones
like `/tmp` excepted), `scripts/`, the script itself, `acme-backups/`, `.env` and
`docker-compose.prod.yml` belong to root and are not writable by group or others (`.env` as
`install.sh` writes it: 0600, or 0640 with group root). The environment overrides its test suite
uses are never honoured for root.

One limit to know: the terminal is a tmux session of the agent's Unix user. Anyone with a shell
as that same user on the gateway host can attach to it outside WebTerm. Because the command is
`sudo -k`, they gain nothing from that without the sudo password: no cached credentials are left
behind.

The case this was built for (2026-10-12): a wildcard that ended up in the HTTP-01 store
(`le`). HTTP-01 cannot renew it, so Traefik logged *"Error renewing ACME certificate … could
not determine solvers"* every day, and because a certificate for that name existed in `le` it
never asked `ledns` for one. Browsers then also showed the expired wildcard on the main domain.
`--report` flags it as `WILDCARD-IN-HTTP01`, and `upgrade.sh` warns about it after every upgrade
(read-only: it never changes the stores). The fix is `--domain` with that name.

**Restoring a backup.** `sudo ./scripts/cert-renew.sh --restore acme-backups/acme-<time>`
backs up the current files, puts those back (0600) and restarts Traefik. By hand: stop Traefik
(`docker compose -f docker-compose.prod.yml stop traefik`), copy the file over the one in the
volume (`docker volume inspect webterm_traefik-acme` shows the path), `chmod 600` it, start
Traefik again.

### System health

**Settings → System health** (Owner/Admin, `security.view`) lists everything that can fail
quietly, with why it matters, what to do and — when the fix needs root on the gateway host — the
exact command. The gear icon shows a dot and "N items need attention" for unmuted warnings and
critical items. `python3 -m app.admin health` prints the same list (upgrade.sh runs it at the end).

What is checked: the host timers (backup, certificate check, Docker cleanup), the Cloudflare DNS
token, the Authentik version against the pin, gateway disk (warning at `WEBTERM_DISK_WARN_PCT`,
default 20 %, critical at `WEBTERM_DISK_CRIT_PCT`, default 10 %), alert delivery (in the app only —
never through the failing channel), whether any alert channel exists, agents behind for more than
`WEBTERM_AGENT_OUTDATED_DAYS` (default 7) days, agents that do not start at boot, agents that
refuse updates, agent and gateway clocks, hosts near the 32-session limit, the agent signing key,
SSO (classified failures plus an hourly probe of the IdP; critical with `WEBTERM_OIDC_SSO_ONLY=1`
once confirmed — a failure only the IdP can cause, failures from two or more addresses, or a failed
probe; a rejected login code is a user error and never counts),
risky configuration (forwards on http://, SSO without a group gate), the daily cleanup, database
size, backup coverage / off-host copy / last verification, the TLS certificates, the dead-man
switch, a new WebTerm version, and the forward-domain DNS (daily).

Warnings and critical items alert once per transition (email/webhook and the in-app history,
kind "System health"), and once more when they are resolved. Any item can be muted for 7 days,
30 days, or until it changes. An item that is, or can become, critical can be muted only by an
Owner (`certs.renew`); when anyone else mutes an item, everyone with `security.view` gets an in-app
alert, and the list shows who muted it and until when.

**The host helper.** Facts only root on the host can see come from `scripts/host-health.sh`, an
hourly systemd timer (`webterm-host-health.timer`) that install.sh and upgrade.sh install
(`sudo ./scripts/host-health.sh --install` does it by hand; it also installs the nightly
`webterm-docker-cleanup.timer`, which replaces a hand-made `/etc/cron.d/webterm-docker-cleanup`).
The nightly cleanup never touches volumes or containers and keeps every image a container uses,
the tool image, the Authentik images and the WebTerm rollback images; it does remove **other**
unused images created more than 14 days ago (`RETENTION` in `scripts/docker-cleanup.sh`; creation time, not
pull time), so keep an image you need by running a container from it or by tagging it into a
compose file.
It writes small JSON status files into the data volume (`host-status/`) and nothing else; the
gateway gets no new privilege and treats those files as untrusted (fixed names, size cap, schema
check, never executed, never a source of commands). The Cloudflare token is checked against
`/user/tokens/verify` without ever appearing on a command line or in a log.

*Trust model of `host-status/`.* The directory lives in the data volume, which the container user
owns, so a compromised gateway can write a fake "ok" there. That is accepted on purpose: the
gateway is the only reader of these files, and a gateway that is already compromised can show
whatever it likes in its own UI anyway. The other direction is what matters, and it holds: root on
the host only **writes** there (atomically, refusing a symlinked directory and replacing a planted
symlinked file) and never reads anything back from it, so nothing the container writes can steer
what root does.

**Commands.** Every command shown comes from a fixed server-side list of templates with validated
parameters; nothing typed by a client ever reaches it. An Owner who picked the gateway host
(Settings → Infrastructure → Certificates) can have a command typed — not run — into a terminal
there, after a fresh second factor; the terminal is private to that Owner.

**Verifying a backup.** Settings → Backup → *Verify* unpacks a stored snapshot and runs an
integrity check on the database inside (nothing is restored). On the host:
`sudo ./scripts/restore.sh --verify /var/backups/webterm/<archive>` does the same for a host
archive without touching the app or the volume. Both record the verification for System health.

#### Dead-man switch

Nothing inside WebTerm can report that WebTerm itself is down. Set `WEBTERM_HEARTBEAT_URL` in
`.env` to a ping URL of an outside monitor (healthchecks.io, Uptime Kuma "push", …) and the
gateway sends a GET every `WEBTERM_HEARTBEAT_MINUTES` (default 5) while it is healthy (event
loop and database answer). When the pings stop, the monitor alerts you. The URL is treated as a
secret (`WEBTERM_HEARTBEAT_URL_FILE` works too) and never shown or logged. Apply with
`docker compose -f docker-compose.prod.yml up -d app`.

### Optional: single sign-on with Authentik

WebTerm ships **standalone by default** — nothing above mentions an identity provider, and the
login page shows no SSO button unless you configure one. For central identity + MFA + offboarding
across one or many instances, add [Authentik](https://goauthentik.io/). Three ways in, pick one:

**A) Bundle Authentik with WebTerm (fewest steps).** One flag runs Authentik in the same stack,
behind the same Traefik, generates its secrets **unique to this install**, and auto-creates the
OIDC application:

```sh
# DNS: an A/AAAA record for auth.example.com → this host, then:
sudo ./install.sh --domain term.example.com --email you@example.com \
     --with-authentik --authentik-domain auth.example.com
#   already installed?  cd /opt/webterm && ./deploy.sh --with-authentik   (set AUTHENTIK_DOMAIN in .env)
```

Under the hood it sets `COMPOSE_PROFILES=authentik` in `.env` (so every later `docker compose up
-d` / `./upgrade.sh` keeps Authentik too), generates `AUTHENTIK_*`/`PG_PASS`, waits for Authentik,
then runs the provisioner and writes the `WEBTERM_OIDC_*` lines back. Re-running is safe.

**B) You already run Authentik.** Don't bundle a second one — point WebTerm at yours. Either create
the OIDC application from Authentik's UI (an OAuth2/OpenID provider, confidential, redirect URI
`https://term.example.com/api/oidc/callback`, scopes `openid email profile`) and copy its client id
+ secret into WebTerm's `.env`; **or** let the provisioner do it against your Authentik:

```sh
cd /opt/webterm/deploy/authentik
AUTHENTIK_DOMAIN=auth.yourcompany.com WEBTERM_DOMAIN=term.example.com \
  AUTHENTIK_API_TOKEN=<an Authentik API token> python3 provision.py
#   → prints WEBTERM_OIDC_* ; paste into /opt/webterm/.env, then: ./deploy.sh
#   (WT_GROUP_PREFIX=wt-prod … to give this instance its own wt-prod-* groups)
```

Since 3.6.5 the provisioner also creates five groups — `wt-access` (sign-in only), `wt-admins`
(Admin), `wt-readonly` (Viewer), `wt-db` (Operator on hosts tagged `db`), `wt-network` (Operator
on hosts tagged `network`) — and prints `WEBTERM_OIDC_ALLOWED_GROUPS`, `WEBTERM_OIDC_ROLE_MAP`,
`WEBTERM_OIDC_SSO_ONLY=1` and `WEBTERM_OIDC_SESSION_MAX_HOURS=12`. Copy those too if you want
people to get their role from their group ([SSO.md → Groups out of the box](SSO.md#groups-out-of-the-box-365)).

Set `WEBTERM_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_PROVIDER_NAME` (and, for roles from
groups, `_ALLOWED_GROUPS`, `_ROLE_MAP`, `_SSO_ONLY`, `_SESSION_MAX_HOURS`) in `.env` and
`./deploy.sh`. Leave `COMPOSE_PROFILES` empty — you are not running the bundled Authentik.

**C) Central Authentik, many WebTerms (production topology).** Run Authentik once as its own stack
(`deploy/authentik/docker-compose.prod.yml`, behind the same Traefik), then register each WebTerm
against it. See [docs/SSO.md](SSO.md).

**First login & verifying it works** (any of the three): the **"Sign in with &lt;provider&gt;"
button only appears once a local account exists** — WebTerm's first-run always creates the
break-glass admin first. So: open `https://term.example.com`, create the local admin with the
setup token (printed by `install.sh`/`deploy.sh`), *then* the SSO button shows. Add the person you
want to a **`wt-access` group** in Authentik, click **Sign in with Authentik**, authenticate — you
land back provisioned on that instance — with **no access** until an Owner or Admin gives the
account a role in Settings → Users & roles, or one of its Authentik groups is mapped to a role
(SSO group mapping; with the provisioner's `WEBTERM_OIDC_ROLE_MAP`, putting the person in
`wt-admins`, `wt-readonly`, `wt-db` or `wt-network` instead of `wt-access` is enough). If the
button is missing, the account
isn't created yet or SSO env isn't set; if the IdP shows "access denied", that user isn't in
`wt-access`.

Whichever you pick: the provisioner gates the app on its groups (`wt-access` and, since 3.6.5, the four role groups; a user reaches the
instance only once you add them to one of them), the local admin stays a **break-glass** account that can
always log in even if Authentik is down, and what each person can do once in is decided by
their role ([ROLES.md](ROLES.md)); separate instances remain the stronger split. To evaluate the whole
flow on one laptop first (localhost, no domain), use `deploy/authentik/docker-compose.yml` (see the
"Try it locally" section of [docs/SSO.md](SSO.md) — it notes the one hostname tweak Docker needs).

> Authentik version: the compose files pin a current stable line (`2026.8.x`). The provisioner and
> the reference blueprint are written to tolerate Authentik's cross-version model changes; if you
> run a much older or newer Authentik and provisioning complains, register the app from the UI.

## Provisioning a server

In the UI: **+ host** → you get a `curl … | sh` command. Copy/paste → Enter on the
server, **as the user you want to work as** (the agent's user = the sessions'
shell). (Onboarding many machines at once? Use a **group enrollment token** instead — create one
from **+ host → "Many machines"**: a single reusable one-liner, each machine self-registers as its
own host. See [Bulk enrollment](FLEET.md#bulk-enrollment).) The script downloads the agent into `~/.webterm/`, starts it and sets up
automatic restart (systemd `--user` with Restart=always, otherwise cron `@reboot`
+ watchdog). It also **appends one line to `~/.bashrc` and `~/.zshrc`** so shell integration
(OSC 133) works — the commands panel, per-command exit codes and `cd` tracking depend on it.
Set `WEBTERM_NO_SHELL_INTEGRATION=1` before running the command to skip that; everything else
works without it. Requires **Python ≥ 3.6** — a host whose `python3` is missing or older gets a
portable Python automatically (see [Supported hosts](#supported-hosts)); **`tmux` is what makes
sessions persistent** — without it the agent runs on a plain PTY and sessions die with it.
On-server diagnostics: `python3 ~/.webterm/ptyd.py info`.

### Supported hosts

What a host needs to run the agent, and what happens when it has less:

| | Requirement | When it is missing or too old |
|---|---|---|
| OS | Linux (any distribution) | Windows/macOS hosts: not supported — use SSH to a Linux jump host |
| **Python** | **3.6 or newer** (the agent is one stdlib-only file) | missing or **< 3.6** → the installer puts a **portable Python 3.12** in `~/.webterm/python/` (below) and leaves the system one alone |
| C library (portable Python only) | glibc **≥ 2.17**, or musl (Alpine) | older glibc (CentOS 6) → the installer refuses with a clear message; install Python 3.6+ yourself and pass `WEBTERM_PYTHON=` |
| CPU (portable Python only) | x86_64, aarch64 (glibc or musl), armv7 hard-float (glibc) | anything else → refused with a clear message; same way out |
| tmux | optional, **strongly recommended** | sessions run on a plain PTY and end when the agent restarts |
| Shell | `/bin/sh` for the installer; any login shell for sessions | shell integration (OSC 133) is wired for **bash** and **zsh** |
| Fetching | `curl` or `wget`, `sha256sum` or `shasum`, `tar` | the installer says which one is missing |
| Fetching the portable Python | `curl`, or GNU `wget` | BusyBox `wget` (minimal Alpine) can send the host's token only on its command line, which other users can read in `/proc` — the installer stops and asks for `apk add curl` |

Known to work: Debian 10–13, Ubuntu 18.04–24.04, RHEL/Rocky/Alma 8–9, Fedora, openSUSE, Arch,
Alpine — with their own python3. **Ubuntu 16.04, Debian 9, Ubuntu 14.04, Debian 8, CentOS 7
without python3** work with the portable Python.

**Why 3.6, and what breaks below it.** On Python 3.5 (Ubuntu 16.04, Debian 9) the agent starts,
connects and runs terminals, but every **file listing fails** (`os.scandir` is used as a context
manager, 3.6+) — and with it the Files panel, uploads and downloads; WebTerm shows "Agent error:
'__exit__'" and marks the host **Python < 3.6** (host card + System health). On 3.4 (Ubuntu 14.04,
Debian 8) the agent does not start at all (`subprocess.run`, `os.set_blocking`). Rather than keep a
second agent compatible with old interpreters, such hosts run the agent on the portable Python.

**The portable Python.** [python-build-standalone](https://github.com/astral-sh/python-build-standalone)
CPython **3.12.15**, release `20261009`, `install_only_stripped` builds. The exact file names and
**SHA-256** of each build are pinned in `gateway/app/pyruntime.json`. The **gateway** downloads a
build from that pinned URL the first time a host asks, checks the SHA-256 **before** caching it
under its data volume (`pyruntime/`, ~25–35 MB per architecture) and serves it to installing hosts
— so hosts without internet access work. The **install script** checks the same SHA-256 again,
refuses archive entries outside `python/`, absolute paths, `..` and links pointing outside, extracts
into a fresh temp directory without the archive's owners (`tar -o`), removes group/world write
permission everywhere (and, when installing as root, gives the whole tree to `root:root`), and moves
it into `~/.webterm/python/`, as the installing user (nothing is escalated). The agent then runs
with `~/.webterm/python/bin/python3`; the systemd unit / cron
lines, its self-update and its restarts all keep using that interpreter (`sys.executable`).

Installer switches (put them after `| `, e.g. `… | WEBTERM_PYTHON=/opt/python3.8/bin/python3 sh`):

| Switch | Effect |
|---|---|
| `WEBTERM_PYTHON=/path/to/python3.x` | use that interpreter (it must be 3.6+, or nothing is installed). An absolute path of plain characters (letters, digits, space, `._/+@=:,-`): it is written, quoted, into the systemd unit and the crontab. **Installing as root**, the interpreter, its resolved path and every folder above them must be owned by root and not group/world-writable (a sticky `/tmp`-style folder above is fine) — otherwise the installer refuses: whoever can write it would get root through the agent |
| `sh -s -- --portable-python` or `WEBTERM_PORTABLE_PYTHON=1` | always use the portable Python, even when python3 is new enough |
| `WEBTERM_ALLOW_OLD_PYTHON=1` | no portable build fits (arch/glibc): keep the old python3 anyway — terminals only, Files will not work |

#### Offline / by hand: portable Python on an existing install

For a host that cannot reach the gateway's download, or an agent **already installed** with an old
system python3 (example: Ubuntu 16.04, Python 3.5.2, x86_64, agent user `webterm`). On a machine
with internet access:

```sh
F='cpython-3.12.15+20261009-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz'
curl -fL -o "$F" 'https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.12.15%2B20261009-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz'
echo "ffa8f85f1b56e88b687f08d743d817015524b86a9365fd921243132b80f1a36d  $F" | sha256sum -c -
scp "$F" mailer:/tmp/
```

On the host, **as the agent's user** (`sudo -iu webterm`):

```sh
F='/tmp/cpython-3.12.15+20261009-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz'
echo "ffa8f85f1b56e88b687f08d743d817015524b86a9365fd921243132b80f1a36d  $F" | sha256sum -c -   # must print OK
T=$(mktemp -d ~/.webterm/.pyrt.XXXXXX)
tar xzf "$F" -C "$T"
"$T/python/bin/python3" --version                     # Python 3.12.15
rm -rf ~/.webterm/python && mv "$T/python" ~/.webterm/python && rmdir "$T" && rm -f "$F"

# switch the running agent over (sessions survive: tmux keeps them)
python3 ~/.webterm/ptyd.py info | grep -i -A2 supervision   # systemd or cron?
python3 ~/.webterm/ptyd.py stop
```

Then, **systemd** (`webterm-agent.service`, the installer's default):

```sh
export XDG_RUNTIME_DIR=/run/user/$(id -u)              # needed after sudo -iu
sed -i "s#^ExecStart=[^ ]*#ExecStart=$HOME/.webterm/python/bin/python3#" ~/.config/systemd/user/webterm-agent.service
systemctl --user daemon-reload && systemctl --user restart webterm-agent
```

or **cron** (no systemd --user):

```sh
crontab -l | sed "s#^\(@reboot\|\* \* \* \* \*\) [^ ]*python3[^ ]* #\1 $HOME/.webterm/python/bin/python3 #" | crontab -
~/.webterm/python/bin/python3 ~/.webterm/ptyd.py start
```

Check: `~/.webterm/python/bin/python3 ~/.webterm/ptyd.py status`. In WebTerm the Files panel lists
again, and the **Python < 3.6** mark disappears at the agent's next connect. Re-running a fresh
install command from the host card with `sh -s -- --portable-python` does all of the above by
itself (it downloads through the gateway and rewrites the unit or cron lines).

**Agent OS support.** The agent is Linux-first: the core (sessions, files, port-forwards, serial)
runs on any Linux with **Python ≥ 3.6** (system or portable) and **tmux**. Everything else
**degrades cleanly** by capability rather than failing:

| Feature | Needs | Elsewhere |
|---|---|---|
| Pending-updates badge + "upgrade in a terminal" | `apt-get`, `dnf`, `zypper`, `checkupdates` (pacman) or `apk` | none of these → no badge, feature hidden |
| Database connections (Toolbox) | the DB client on the host (`psql` / `mysql` / `mongosh` / `clickhouse-client` / `redis-cli`) | client missing → a clear "not installed" message |
| Services panel | `systemctl` (systemd) | non-systemd → "systemctl not available" |
| Listening ports (Diagnostics) | `ss` (iproute2) | absent → a clear "ss (iproute2) is not available" message |
| Metrics / network diagnostics | `/proc`, `/sys`, `ip` | partial on non-Linux |

So the full feature set is a **systemd distro** (Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch) — pending-updates detection also covers Alpine (`apk`); on a non-systemd system, a BSD or
a minimal container the terminal and files still work and the rest simply doesn't appear — nothing
crashes. Windows hosts are not supported (use SSH to a Linux jump host instead). The "upgrade in a
terminal" action runs as the agent's user: as root it upgrades directly, otherwise it uses
passwordless sudo if available, and if neither applies it prints the exact command to run yourself
(the default dedicated `webterm` user has no sudo).

The install link itself is hardened: it is **single-use**, expires after a
**configurable TTL** (default 1 hour, 5 min–30 days — set it when creating the
host, renewable from the host card), and can additionally require an **install
password** (letters/digits/`._-`), sent as a header by the one-liner — never in
the URL — hashed at rest and rate-limited against guessing. Both options exist
for group enrollment tokens too. A link that was created but **never used** shows
a badge on the host card, so a forgotten (or leaked) one-liner gets noticed.

### The dedicated user cannot `sudo` — decide what it may do

The recommended install runs the agent as a dedicated `webterm` user, created with
`useradd -m -s /bin/bash webterm`. That user has **no password and no sudo**, which is the
whole point: whoever gets past the login gets that user's access and nothing more. It also
means your first `sudo apt install` in a session fails with *"Sorry, try again"* — sudo is
asking for a password the account does not have.

Grant it deliberately, from a root shell on that host. Three shapes, most restrictive first:

```sh
# 1. Narrow — only the commands you actually need. Best ratio: a compromised gateway
#    gets those commands, not the machine.
sudo tee /etc/sudoers.d/webterm >/dev/null <<'EOF'
webterm ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/journalctl
EOF
sudo chmod 440 /etc/sudoers.d/webterm && sudo visudo -c

# 2. Full sudo, password required — you type it, an attacker with your session cookie
#    cannot become root without it. Use this if you administer the host from WebTerm.
sudo passwd webterm
sudo usermod -aG sudo webterm        # RHEL/Fedora: -aG wheel

# 3. Full sudo, no password — convenient, and gives up most of what the dedicated user
#    bought you: the agent is root again in practice.
echo 'webterm ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/webterm
sudo chmod 440 /etc/sudoers.d/webterm
```

Option 2 is worth understanding rather than copying: the password is typed into a WebTerm
terminal. It is **not** written to the transcript — input is never recorded, precisely so
prompts with echo off do not leak — but it is still a password travelling through the
gateway. If that is the wrong trade for a given host, use option 1.

Serial consoles need one more group, since `/dev/ttyUSB*` is not world-readable:

```sh
sudo usermod -aG dialout webterm     # some distros: uucp
```

Group changes apply to **new** sessions; close the tab and open a new one.

### Removing the agent from a host

```sh
python3 ~/.webterm/ptyd.py uninstall        # asks first; -y to skip
```

It stops the agent and its supervision, kills the WebTerm tmux server (sessions on that host
end) and deletes `~/.webterm`. It does **not** remove the host from WebTerm — it tells the
gateway it is gone, and the host list shows *agent removed on the server* with a button to
remove it. Two reasons: you may only be reinstalling, in which case the notice clears by
itself when the agent reconnects; and deleting the host takes its name, forwards and session
links with it, so that decision stays with someone signed in rather than with whoever has a
shell on the machine.

## Commands (Makefile)

```sh
make help      # full list
make up        # build + start (dev)    make logs-app  # gateway logs
make down      # stop                   make token     # the setup token
make restart   # restart gateway        make backup    # data backup to ./backups
make update    # git pull + rebuild     make test      # the test suite
make deploy    # production (image)     make pull      # pull the latest image
#                                        (backup needs WEBTERM_BACKUP_PASSPHRASE)
```

## Backup

Everything that matters is in the `webterm-data` volume (`/data`): `webterm.db`,
`transcripts/`, `secret`, and `agent-signing.key` — the last being the one artefact whose
loss is irreversible: without it the fleet can never be updated again.

What is **not** in the volume, and therefore not in the archive: the archive's own
passphrase (`/etc/default/webterm-backup`), `/opt/webterm/.env`, and the TLS certificates.
That matters only when you rebuild the machine — and then it matters a great deal, because
the passphrase lives on the machine you are about to wipe. The checklist and the full
rebuild procedure are in [docs/RUNBOOK.md](RUNBOOK.md#what-the-archive-does-not-contain).

`make backup` writes to `./backups`. Set **`WEBTERM_BACKUP_PASSPHRASE`** (in
`/etc/default/webterm-backup` for the scheduled timer) and it writes an encrypted
`.tar.gz.enc`. Without it, an interactive run warns and writes plaintext, but a
**non-interactive run refuses and exits 1** — the archive would contain the vault key
in the clear. That is deliberate; it also means an unconfigured cron job produces
nothing at all. `WEBTERM_BACKUP_ALLOW_PLAINTEXT=1` overrides it, and is not advised.

**From the app (Settings → Backup)** — no server access needed:

- **Download a backup** any time: a crash-consistent DB snapshot (`VACUUM INTO`) +
  the vault key + optionally the transcripts. Because it includes the key (which
  decrypts all credentials), the download is **encrypted with a password you
  choose** (scrypt → AES-256-GCM) — **without the password you cannot restore,
  don't lose it**.
- **Automatic backup** daily/weekly, kept 7 days on the server. When it's ready
  you get an in-app notification and can download it (encrypted on download).
- **Restore** from a `.wtbk`: after validation (password + DB integrity), the app
  restarts and replaces the data; a pre-restore snapshot is saved automatically as
  a safety net.

Your job is to move the copies **off-site** — a backup left on the same server
does not protect you from losing the VPS. See [RUNBOOK](RUNBOOK.md).
