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
git checkout v3.5.13           # the release tag (see the version badge); a tag cannot move under you, a branch can
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
with a recorded rollback point: `./deploy.sh v3.5.13` (or a digest:
`./deploy.sh ghcr.io/sm26449/webterm@sha256:…`) — if the new container does
not become healthy, the script rolls back automatically; any time afterwards,
`./rollback.sh` returns you to the previous image with a single command.

<a id="upgrading"></a>
**Upgrading: one command.** `cd /opt/webterm && sudo ./upgrade.sh` takes the
latest published version; pass a tag to target one. It resolves the version, checks ghcr auth
and disk space, pulls the image, **takes a backup**, **syncs the files that run on the host**
(compose, the operator scripts — `backup.sh`, `restore.sh`, `rollback.sh`, `deploy.sh`,
`remove.sh`, `cert-check.sh` — and `upgrade.sh` itself; `/opt/webterm` is not a git checkout, so
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
```

Set `WEBTERM_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_PROVIDER_NAME` in `.env` and
`./deploy.sh`. Leave `COMPOSE_PROFILES` empty — you are not running the bundled Authentik.

**C) Central Authentik, many WebTerms (production topology).** Run Authentik once as its own stack
(`deploy/authentik/docker-compose.prod.yml`, behind the same Traefik), then register each WebTerm
against it. See [docs/SSO.md](SSO.md).

**First login & verifying it works** (any of the three): the **"Sign in with &lt;provider&gt;"
button only appears once a local account exists** — WebTerm's first-run always creates the
break-glass admin first. So: open `https://term.example.com`, create the local admin with the
setup token (printed by `install.sh`/`deploy.sh`), *then* the SSO button shows. Add the person you
want to a **`wt-access` group** in Authentik, click **Sign in with Authentik**, authenticate — you
land back provisioned as a full admin of that instance. If the button is missing, the account
isn't created yet or SSO env isn't set; if the IdP shows "access denied", that user isn't in
`wt-access`.

Whichever you pick: the provisioner gates the app on a `wt-access` group (a user reaches the
instance only once you add them to it), the local admin stays a **break-glass** account that can
always log in even if Authentik is down, and there is no in-app RBAC — everyone who gets in is a
full admin of that instance (separate trust by running separate instances). To evaluate the whole
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
works without it. Requires python3 ≥ 3.6; **`tmux` is what makes sessions persistent** — without it
the agent runs on a plain PTY and sessions die with it.
On-server diagnostics: `python3 ~/.webterm/ptyd.py info`.

**Agent OS support.** The agent is Linux-first: the core (sessions, files, port-forwards, serial)
runs on any Linux with **python3 ≥ 3.6** and **tmux** — the installer checks for python3 and stops
with a clear message if it is missing. Everything else **degrades cleanly** by capability rather
than failing:

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
