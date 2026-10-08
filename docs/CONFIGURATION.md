# Configuration

Everything the gateway reads comes from `.env` next to the compose file
(`.env.example` for a local build, `.env.prod.example` for an image deploy). The
[main README](../README.md#configuration) lists the handful you set on day one; this page
is the full reference.

<a id="gateway-variables"></a>
## Gateway (`.env`)

| Variable | Role |
|---|---|
| `WEBTERM_PUBLIC_URL` | public URL (browser, agents, WebAuthn), e.g. `https://term.example.com` |
| `WEBTERM_DOMAIN` | the domain for TLS (Caddy on a local build, Traefik on an image deploy) |
| `LETSENCRYPT_EMAIL` | email for the Let's Encrypt certificate (Traefik deploy) |
| `CF_DNS_API_TOKEN` | Cloudflare token (Zone:DNS:Edit), **optional**. Empty → Let's Encrypt over HTTP-01, no DNS provider needed (domain resolves here + port 80 reachable). Set it behind the CF proxy or NAT, and for a wildcard covering all forward subdomains |
| `WEBTERM_AGENT_INSECURE` | `1` only for IP access (self-signed). **Local build only** — `docker-compose.prod.yml` deliberately does not pass it, so an image deploy cannot turn off TLS verification toward the agent (`tests/compose_env_test.py` records the exception). It also leaves the **agent bootstrap unauthenticated**: the install one-liner fetches with `curl -k`, and certificate pinning only begins on the first connection — so whoever can intercept that single download installs their own agent, with their own update key, at the rights you run it as. Enrol over a network you trust, or issue a real certificate first. The UI says so next to the command |
| `WEBTERM_SETUP_TOKEN` | fixed for the first account; empty = generated into `/data/setup-token` (owner-only, 0600) inside the container, and only a short prefix is logged. Read it with `make token` |
| `WEBTERM_CLIENT_BUFFER` | per-browser backlog before resync (default 1 MiB) |
| `WEBTERM_TRUSTED_PROXY_HOSTS` | comma-separated proxy **host names** allowed to set `X-Forwarded-For`, resolved through docker DNS to the proxy container's exact IP. The compose files default it to `traefik` (`docker-compose.prod.yml`) and `caddy` (`docker-compose.yml`). With neither this nor the CIDRs set, the header is ignored and the socket peer is used |
| `WEBTERM_TRUSTED_PROXY_CIDRS` | comma-separated CIDRs (e.g. `172.18.0.0/16`) also allowed to set `X-Forwarded-For` — an alternative or addition to the host names |
| `WEBTERM_TRUSTED_PROXY_HOPS` | how many trusted proxies sit in front of the gateway (default 1; Cloudflare → Traefik = 2). The client IP is read that many entries from the right of `X-Forwarded-For` |
| `WEBTERM_TRUST_CF_IP` | `1` to take the client IP from `CF-Connecting-IP` (behind Cloudflare). Honoured only on a request from a trusted proxy (above) |
| `WEBTERM_ARCHIVE_DAYS` | days an archived transcript is kept before it is deleted for good (default 120) |
| `WEBTERM_CLOSED_ARCHIVE_DAYS` | days after which a **closed** session's transcript moves to the archive (default 30; `0` = off) |
| `WEBTERM_TRANSCRIPT_MAX_BYTES` / `WEBTERM_TRANSCRIPT_KEEP_BYTES` | per-session transcript cap: past MAX (default 64 MiB) only the last KEEP bytes (default 16 MiB) are kept, with a gap marker |
| `WEBTERM_ALERT_WEBHOOK` | Slack/Discord/Teams or any JSON endpoint for security alerts. Independent of SMTP — with chat configured you never need a mail server. Also settable in Settings → Notifications |
| `WEBTERM_UPDATE_CHECK` | `0` disables the "a newer version exists" check entirely (it overrides the UI switch). WebTerm never updates itself; the check only tells you |
| `WEBTERM_UPDATE_COMMAND` | the upgrade command the UI **displays** when a new version exists. It is never executed |
| `WEBTERM_UPDATE_REPO` | the GitHub `owner/repo` the version check asks (default `sm26449/webterm`) — set it on a fork |
| `WEBTERM_SIGNING_AUTOGEN` | `1` (default) \| `0` = don't generate an agent signing key on the first boot of a new install — for an offline, build-time key (see [Signed agent updates](SECURITY-FEATURES.md#signed-agent-updates)) |
| `WEBTERM_CERT_MIN_DAYS` | how many days before expiry the `webterm-cert-check` timer starts warning (default 15). **Not read from `.env`** — the timer reads `/etc/default/webterm-cert-check`, which `install.sh` writes |
| `WEBTERM_CERT_RESOLVER` | `le` (HTTP-01, needs port 80 reachable) or `ledns` (DNS-01 via Cloudflare). Written by `install.sh`/`deploy.sh` from whether you gave a Cloudflare token — see the note under `CF_DNS_API_TOKEN` |
| `WEBTERM_OIDC_ISSUER` | SSO issuer URL, e.g. `https://auth.example.com/application/o/webterm/`. **Optional** — SSO is off until issuer + client id + secret are all set |
| `WEBTERM_OIDC_CLIENT_ID` / `WEBTERM_OIDC_CLIENT_SECRET` | the OIDC client credentials from your IdP (`provision.py` prints them for Authentik) |
| `WEBTERM_OIDC_PROVIDER_NAME` | the button label, e.g. `Authentik` (default `SSO`) |
| `WEBTERM_OIDC_SCOPES` | requested scopes, default `openid email profile` |
| `WEBTERM_OIDC_ALLOWED_GROUPS` | optional, comma-separated; if set, the token's `groups` claim must contain one (defence-in-depth on top of the IdP's own gate) |
| `WEBTERM_OIDC_REQUIRE_AUTH_TIME` | default `1`: an SSO **step-up** whose `id_token` has no `auth_time` claim is refused (WebTerm asks for `max_age=0`, and OIDC Core then requires the claim — without it the "re-authentication" is an unverifiable `prompt=login`). The gateway logs `SSO step-up REFUSED: the IdP did not return auth_time…`: configure the IdP to emit `auth_time` (Authentik does by default). `0` = the pre-3.5.14 lenient behaviour (accept with a warning). Ordinary logins are not affected |

See [SSO.md](SSO.md) for the full single-sign-on model (break-glass, per-instance access, 2FA step-up).

<a id="security-and-sessions"></a>
### Sign-in, sessions, audit

| Variable | Role |
|---|---|
| `WEBTERM_IP_MAX_FAILS` | failed logins per client IP before the lockout (default 5) |
| `WEBTERM_IDLE_LOCK_SECS` | on hosts that require 2FA, the terminal locks after this much inactivity and needs a step-up to resume (default 300) |
| `WEBTERM_SESSION_TTL_DAYS` | maximum life of a browser sign-in (default 30) |
| `WEBTERM_SESSION_IDLE_HOURS` | a browser sign-in unused for this long expires (default 12) |
| `WEBTERM_AUDIT_DAYS` | audit-log retention (default 120) |

<a id="email-alerts"></a>
### Email alerts (optional)

With no SMTP host the email alerts are off; everything else works, and the webhook above is
independent of it. Details and the list of events: [ALERTS.md](ALERTS.md).
Alerts are recorded in the app either way (the bell in the sidebar); which event types are
emailed or kept in the history is a per-account choice in Settings → Notifications → *Alert
events*, not an environment variable — see
[ALERTS.md](ALERTS.md#in-app-history-and-per-event-preferences). There is nothing to
configure for the history itself: last 500 alerts per account, 30 days.

| Variable | Role |
|---|---|
| `WEBTERM_SMTP_HOST` / `WEBTERM_SMTP_PORT` | mail server (port default 587) |
| `WEBTERM_SMTP_USER` / `WEBTERM_SMTP_PASSWORD` | credentials (the password is better kept as a file, below) |
| `WEBTERM_SMTP_STARTTLS` | `1` (default) to use STARTTLS |
| `WEBTERM_ALERT_FROM` | sender (defaults to the SMTP user) |
| `WEBTERM_ALERT_TO` | the address that receives the alerts |

### Port forwarding

| Variable | Role |
|---|---|
| `FORWARD_DOMAIN` | the parent domain for forward subdomains (`<slug>.<domain>`); defaults to `WEBTERM_DOMAIN`. Also changeable in Settings — see [PORT-FORWARDING.md](PORT-FORWARDING.md) |

<a id="secrets-as-files"></a>
## Secrets as files

`WEBTERM_SETUP_TOKEN`, `WEBTERM_OIDC_CLIENT_SECRET`, `WEBTERM_SMTP_PASSWORD`,
`WEBTERM_ALERT_WEBHOOK` and `WEBTERM_UPDATE_CHECK_TOKEN` can also be read from a file named by the
same variable with a `_FILE` suffix (e.g. `WEBTERM_SETUP_TOKEN_FILE=/run/secrets/webterm_setup_token`),
so they stay out of the container's environment. A non-empty value in the environment wins; a missing
or empty file means "not set". `docker-compose.prod.yml` uses this for the setup token, the OIDC
secret and the SMTP password.

On an image deploy those files live in `/opt/webterm/secrets/` (0700), mounted at `/run/secrets`:
Traefik reads container metadata through docker-socket-proxy, and that metadata includes every
container's environment. `deploy.sh` moves any secret it still finds in `.env` into its file.

<a id="agent-side"></a>
## On the hosts (agent side)

| Variable | Role |
|---|---|
| `WEBTERM_INSTANCE_ID` | overrides the per-machine id the agent derives from `/etc/machine-id` (the gateway fences each host token to that id) — set it on cloned VMs or containers that share a machine-id |
| `WEBTERM_NO_SHELL_INTEGRATION` | `1` before the install one-liner: don't append the shell-integration line to `~/.bashrc` / `~/.zshrc` ([SHELL-INTEGRATION.md](SHELL-INTEGRATION.md)) |
| `WEBTERM_UPDATES_CHECK_SECS` | how often the agent counts pending OS updates (default 21600 = 6 h; `0` turns the badge off) |
| `WEBTERM_SESSION` | set **by** the agent in every session it starts (the session id), so scripts can tell they run inside WebTerm |

<a id="backup-script"></a>
## Backup script (`scripts/backup.sh`, the scheduled timer)

The timer reads `/etc/default/webterm-backup`, not `.env`.

| Variable | Role |
|---|---|
| `WEBTERM_BACKUP_PASSPHRASE` | encrypts the archive (`.tar.gz.enc`). Without it a non-interactive run **refuses** — the archive holds the vault key |
| `WEBTERM_BACKUP_ALLOW_PLAINTEXT` | `1` overrides that refusal. Not advised |
| `WEBTERM_BACKUP_RSYNC` | `user@host:/path/` — copy the encrypted archive off-host over rsync/SSH (key auth) |
| `WEBTERM_BACKUP_FTPS` | `ftp://host/path/` — off-host over FTPS (`curl --ssl-reqd`; plain FTP is refused) |
| `WEBTERM_BACKUP_REMOTE` | any rclone remote (S3/B2/…) |

More in [RUNBOOK.md](RUNBOOK.md) and [INSTALL.md → Backup](INSTALL.md#backup).

## Upgrade verification

| Variable | Role |
|---|---|
| `WEBTERM_COSIGN_IDENTITY` | with `cosign` installed, `upgrade.sh` verifies the image's keyless signature against this identity before running anything from it; unset, it says it skipped the check ([RUNBOOK.md](RUNBOOK.md), "Verifying an image") |
