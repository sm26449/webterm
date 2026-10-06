# Alerts — email and webhook (Settings → Notifications)

Get told when something happens that you would otherwise only find in a log: an IP locked
out, a login from a new place, a host that stopped reporting, a disk filling up, a backup
that keeps failing. WebTerm sends the same alert to two independent channels — **email
(SMTP)** for the archive and a **webhook** (Slack, Discord, Mattermost, Teams or any JSON
endpoint) for reacting. Configure either, both or neither: with nothing configured every
alert is a silent no-op.

Alerts are deliberately **rare**. There is no email per failed login (that would be a
mail-bombing vector) — only the signals worth reading, each throttled so a persistent
condition stays one message, not a stream.

## Channels: email and webhook

Both live in **Settings → Notifications**, under *Email alerts (SMTP)*.

**Email.** Fields: SMTP host, port (default 587), user, password, *From*, *To*, and *Use
STARTTLS*. An email is sent only when **host, From and To** are all set; the user is
optional (no `login` when it is empty). Mail goes out through a plain SMTP connection
(15 s timeout), upgraded with `STARTTLS` when the box is ticked — and STARTTLS **verifies
the server certificate** (hostname + CA), so a self-signed relay fails. **Port 465** uses
implicit TLS (SMTPS) instead — the connection is TLS from the first byte, with the same
certificate check, and the STARTTLS box is ignored (since 3.5.2). The subject is prefixed `[WebTerm] `.

**Webhook.** One URL, independent of SMTP (works with no mail server at all). It must be
`http://` or `https://`; private-network addresses (a Mattermost in your LAN) are fine,
the cloud metadata addresses (`169.254.169.254`, `metadata.google.internal`,
`fd00:ec2::254`) are refused. Every alert is POSTed as JSON (`Content-Type:
application/json`, `User-Agent: WebTerm`, 10 s timeout):

```json
{
  "text":    "[WebTerm] <subject>\n<body>",
  "content": "**[WebTerm] <subject>**\n<body>",
  "subject": "<subject>",
  "body":    "<body>"
}
```

`text` is what Slack and Mattermost display, `content` is what Discord displays, and
`subject`/`body` are there for your own consumers. There is no Teams-specific card format:
Teams (or anything else) receives the same JSON and shows it only if it reads `text`.

**Saving.** Any change to these fields — including the webhook — asks for your **account
password** (the SMTP server carries the email confirmation codes, and the webhook sends
data out, so both are exfiltration targets for a stolen cookie). Saving without changes
does not ask. The SMTP password is write-only: leave the field empty to keep the stored
one; it is stored encrypted.

**Test.** *Send test email* first **saves** the form (so it tests what you typed, not the
old config), then sends a test message synchronously and shows the SMTP error if it fails.
*Test webhook* (shown when a webhook URL is set, since 3.5.2) does the same for the
webhook: it saves, posts a test alert and shows the error if the POST fails.

**Delivery status.** Under the buttons the tab shows the last email/webhook **sent** and
the last one that **failed** (with the error), persisted by the gateway. A failure newer
than the last success is shown in red. This is how you notice an SMTP relay that died
months ago — delivery itself is best-effort and never blocks the action that triggered it.

## Events

Every alert goes to both channels (whichever are configured). Throttles are in memory, per
key, so a gateway restart resets them.

| Subject (after `[WebTerm] `) | Fires when | Throttle |
|---|---|---|
| IP blocked after failed login attempts | An IP reaches the failed-auth cap and is locked out (15 min lockout). Only real IPs, not per-account internal counters. | 1 per IP / 15 min |
| New login on your account | Successful login from an IP never seen for this account. | none (first time per IP only) |
| A new device attached to a live session | Someone attaches to a live session from an IP not seen on a successful login for the account, or a guest attaches through a share link. | 1 per IP / 15 min |
| Security change: … | Account created; automation token created (name + scopes); group enrollment token created; TOTP enabled / disabled; passkey enrolled / deleted; SSH host key re-pinned for a host; account password and/or email changed (since 3.5.2). | none |
| A 2FA-protected host was unlocked | Step-up passed on a host marked *Require 2FA*. | 1 per host+IP / 15 min |
| SSH deploy key DEPLOYED / REVOKED: source → target | A deploy key was added to or removed from a target's `authorized_keys`. | none |
| SSH host key changed — connection refused | An SSH-direct or SSH-jump target offered a host key that does not match the pinned one; the connection was refused. | 1 per host / 15 min |
| Agent rejected: relocation/cloning attempt | A pinned host's agent token was used from a different machine; refused. | 1 per host / 15 min |
| Agent reconnected from a new IP | An agent reconnected from a different IP — only on hosts **not** pinned to a machine (on pinned hosts the change is only logged). | 1 per host / hour |
| A host auto-enrolled into the fleet | A new host registered itself with a group enrollment token. | 1 per group / 10 min |
| [host] host offline | An agent host has not sent a heartbeat for more than 90 s. If the agent reported an uninstall first, the subject is *host offline after an uninstall report* — the alert is never suppressed, only reworded. | once per outage (persisted) |
| [host] host back online | The host reports again **and** an offline alert had been sent. | once per outage |
| [host] CPU / memory / disk at N% (threshold T%) | See [Resource thresholds](#resource-thresholds). | 1 per host+metric / 30 min, plus hysteresis |
| [host] … back to N% | The metric dropped to threshold − 10 points. | — |
| Gateway disk is filling up (N% free) | The gateway's data volume has less than 10 % free (checked every minute). | 1 / 6 h |
| The signing key is locked — agents are NOT updating | The encrypted fleet signing key is locked since the last restart **and** at least one agent is on an older version (checked daily). | 1 / 12 h |
| Agent: update REFUSED (code) | An agent refused a signed update, or the gateway refused to push one because `ptyd.py.sig` is missing. | 1 per host / 6 h |
| Off-host backup is FAILING (provider) | The scheduled upload to the off-host destination failed **2 or more times in a row**. | 1 / 12 h |
| Scheduled backup is FAILING | The scheduled local snapshot itself failed (disk full, DB locked, read-only volume). | 1 / 12 h |

The offline sweep runs every 60 s from the session reaper, which waits ~3 minutes after
gateway start so reconnecting agents are not reported as down. Only **agent** hosts are
swept; SSH, telnet and jump hosts have no heartbeat and never raise offline alerts. A host
that has never connected is not "offline". The "already notified" flag is stored on the
host, so a gateway restart does not re-send alerts for hosts that are still down.

Not an alert channel: one-time email confirmation codes go to the **account's** address,
synchronously, and never to the webhook.

## Resource thresholds

Under **Settings → Notifications → Resource alerts**: three percentages, **CPU**, **RAM**
and **Disk**, default **90** each, `0` disables that metric, accepted range 0–100. They
apply to every agent host (there are no per-host thresholds) and are evaluated on each
agent heartbeat (every 30 s) from the metrics the agent reports: CPU %, used/total memory,
used/total disk.

- **CPU must stay above the threshold for 3 heartbeats in a row** (about 90 s), so a short
  build spike does not alert. RAM and disk move slowly and alert on the first reading at
  or above the threshold.
- **Single alert.** Once an alert fires for a host+metric, nothing more is sent while the
  value stays high.
- **Recovery.** When the value drops to **threshold − 10 points** or lower (e.g. ≤ 80 % for
  a 90 % threshold), a *back to N%* message is sent and the metric re-arms. A value
  hovering between 80 and 90 neither re-alerts nor recovers — that margin is the
  hysteresis that stops flapping.
- On top of that, at most one threshold alert per host+metric every **30 minutes**.

Saved thresholds take effect at once (the gateway's 30 s cache is invalidated on save).
The breach state is in memory: after a gateway restart a host still above the threshold
alerts once more.

The **gateway's own disk** is separate and not configurable: under 10 % free on the data
volume raises *Gateway disk is filling up*, at most every 6 h.

## Muting

Muting is **per host, for offline alerts only** — it silences *host offline* and *host
back online* for that host. It does not mute threshold, security, update or any other
alert, and there is no global mute other than clearing the channels.

- In the sidebar, the bell next to an **agent** host toggles it: 🔔 (visible on hover) =
  offline alerts on, 🔕 (always visible) = muted. Use it for a machine you switch off on
  purpose.
- **Muting a host that has *Require 2FA* asks for a step-up** — lowering monitoring of a
  protected host must not be possible with just a stolen cookie. Un-muting never does.
- **Un-muting re-arms** the alert: a host that is still offline alerts again on the next
  sweep, so you learn it is still down rather than staying silent by inertia.
- While muted, a host coming back online sends no *back online* message either.

## Configuration via environment

Everything in the tab can also be preset from the gateway environment (`/opt/webterm/.env`,
passed through by the compose files). Values saved in the UI are stored in the database
and **take precedence**, field by field:

| Variable | Default | Notes |
|---|---|---|
| `WEBTERM_SMTP_HOST` | empty | Empty = no email. |
| `WEBTERM_SMTP_PORT` | `587` | |
| `WEBTERM_SMTP_USER` | empty | Empty = send without SMTP AUTH. |
| `WEBTERM_SMTP_PASSWORD` | empty | Also `WEBTERM_SMTP_PASSWORD_FILE`. |
| `WEBTERM_SMTP_STARTTLS` | `1` | `1`/`true`/`yes` = on, anything else = off; empty = default (on). |
| `WEBTERM_ALERT_FROM` | `WEBTERM_SMTP_USER` | Sender address; empty falls back to the SMTP user. |
| `WEBTERM_ALERT_TO` | empty | Recipient (the instance's alert mailbox). |
| `WEBTERM_ALERT_WEBHOOK` | empty | Also `WEBTERM_ALERT_WEBHOOK_FILE` — the URL is itself a secret. |

**`_FILE` variants.** For the two secrets, a non-empty `WEBTERM_X` wins; otherwise, if
`WEBTERM_X_FILE` names a readable file, its contents (trimmed) are used. A missing or empty
file means "unset", not an error. This keeps the secret out of the container's
`Config.Env`. `docker-compose.prod.yml` already sets `WEBTERM_SMTP_PASSWORD_FILE=/run/secrets/webterm_smtp_password`;
it does **not** set `WEBTERM_ALERT_WEBHOOK_FILE`, so to use that one add it (and the
secret mount) yourself, or set the webhook in the UI.

**Precedence details** (once the form has been saved, every key exists in the database):

- host, port, From, To and webhook: a non-empty UI value wins; an empty one falls back to
  the environment;
- user and STARTTLS: the UI value wins even when empty/off;
- password: the stored (encrypted) UI password wins; with none stored, the environment
  value is used.

So clearing a field in the UI does not necessarily disable it — if the same variable is set
in `.env`, the environment value comes back. Remove it from `.env` (and redeploy) too.

## Maintenance notes

- Backend: `gateway/app/email_alerts.py` (all `notify_*`, `_post_webhook`, `check_metrics`),
  settings routes `/api/settings/smtp`, `/api/settings/smtp/test`, `/api/settings/webhook/test`, `/api/settings/alerts` in
  `gateway/app/api.py`, offline sweep `core.sweep_hosts_offline`, gateway disk / signing-key
  checks in `gateway/app/main.py`; mute = `PATCH /api/hosts/{id}` with `alerts_muted`.
- Frontend: `frontend/src/components/settings/NotificationsTab.tsx`, bell in `Sidebar.tsx`.
