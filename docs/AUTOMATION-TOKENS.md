# Automation tokens (Settings → Infrastructure & tokens)

API keys for scripts that have no browser and no passkey: a cron job that checks which hosts are
offline, a CI step that runs one command on a host after a deploy, a monitoring probe that reads
the gateway's status. A token is **not an account**: it opens a small, explicit whitelist of four
endpoints and nothing else, it always expires, and it can never reach a host marked
*Require 2FA*.

Use a token when a machine needs to ask WebTerm something or run a non-interactive command.
For anything a person does (terminals, files, settings), use the browser.

## What they are for

- **Monitoring** — `GET /api/status` (hosts online/offline, session counts, storage, gateway
  health and versions) and `GET /api/hosts` (per-host `online`, `last_heartbeat`, `metrics`,
  `updates`, `tags`…) from a cron job or an uptime checker.
- **Inventory** — `GET /api/sessions` lists live and recent sessions.
- **Fleet automation** — `POST /api/hosts/{id}/run` runs one non-interactive command on one
  agent host and returns its exit code, stdout and stderr. This is the same endpoint **Run on hosts**
  calls once per host.

Every other route of the API accepts only the browser session cookie.

## Creating a token

1. **Settings → Infrastructure & tokens → Automation tokens.**
2. **Name** — required, at most 60 characters (longer names are cut). Pick something that tells
   you later what you would be breaking by revoking it (e.g. `cron-uptime`).
3. **days** — lifetime, default 90. The server clamps it to **1–365**; there is no "never
   expires".
4. Tick the **scopes**: `read` (checked by default) and/or `run`. At least one is required.
5. Enter your **current account password**, then **Create token**. Creating a token is treated
   like enrolling a passkey (it is a durable credential on your account), so after the password
   the server asks for a second factor: your **2FA (TOTP) code** if TOTP is enabled on the
   account (a recovery code also works); without TOTP, an **emailed code** but only when you are
   on a device WebTerm considers new and SMTP is configured. The form prompts for whichever is
   needed and retries.
6. The token (`wt_…`) is shown **once**, with a Copy button. Only its SHA-256 hash is stored; if
   you lose the value, revoke the token and create a new one.

Creating a token sends a security alert by email/webhook (*"an automation token was created
(name, scopes: …)"*) if alerts are configured, the same as a new passkey or account.

Send the token in the `Authorization` header on every request:

```
Authorization: Bearer wt_…
```

A missing, unknown or expired token falls through to the normal cookie check and gets
`401 not authenticated`. Bearer requests skip the browser CSRF (Origin) check, because they
carry no ambient cookie.

## Scopes

| Scope | Endpoints | Notes |
|---|---|---|
| `read` | `GET /api/status`, `GET /api/hosts`, `GET /api/sessions` | `/api/sessions` hides **every** session of a host marked *Require 2FA* when called with a token. |
| `run` | `POST /api/hosts/{id}/run` | One command, one host, non-interactive. |

A token used on a whitelisted endpoint without the matching scope gets
`403 the token does not have the '<scope>' scope`. A token used on any other endpoint is simply
not recognised there (401).

### The `run` request body (`RunIn`)

| Field | Type | Default | Meaning |
|---|---|---|---|
| `command` | string | required | The command line. Leading/trailing whitespace is trimmed; empty → `400 empty command`; over 8000 characters → `400 command too long`. |
| `timeout` | integer, seconds | `60` | Clamped to **1–300**. |
| `confirmed` | boolean | `false` | Your explicit "yes" for a command that matches a guardrail **confirm** rule (see [GUARDRAIL.md](GUARDRAIL.md)). |
| `stepup_grant`, `stepup_password` | string | `""` | Used by the browser for hosts with *Require 2FA*. Useless with a token: those hosts refuse tokens before these are looked at. |

The command runs through the agent's `run` op, as the agent's OS user, without a terminal.
Response:

```json
{"exit_code": 0, "timed_out": false, "stdout": "…", "stderr": "", "duration": 0.04}
```

The command is also recorded in the searchable command history with source `fleet` (labelled *Run on hosts* in the UI).

Errors you should handle in a script:

| Status | Code | When |
|---|---|---|
| 403 | `host.needs2faNoToken` | The host has *Require 2FA*. |
| 403 | `run.guardBlocked` | A guardrail **block** rule matched. |
| 409 | `run.guardConfirm` | A guardrail **confirm** rule matched and `confirmed` was not `true`. |
| 409 | `host.offline` | The host is offline, or is not an agent host (SSH/telnet/jump hosts have no `run`). |
| 504 | `host.noAnswer` | The agent did not answer in time. |
| 502 | `run.failed` | The agent reported a failure. |

## Examples

Keep the token out of the command line and shell history, for example in a root-only file:

```bash
export WT=https://webterm.example.com
export WT_TOKEN="$(cat /etc/webterm-token)"     # chmod 600
```

**Gateway status** (`read`):

```bash
curl -fsS -H "Authorization: Bearer $WT_TOKEN" "$WT/api/status" | jq .hosts
# {"total": 12, "online": 11, "offline": 1}
```

**Host list** (`read`) — names of offline hosts:

```bash
curl -fsS -H "Authorization: Bearer $WT_TOKEN" "$WT/api/hosts" \
  | jq -r '.[] | select(.online | not) | .name'
```

**Sessions** (`read`) — live sessions:

```bash
curl -fsS -H "Authorization: Bearer $WT_TOKEN" "$WT/api/sessions" \
  | jq -r '.[] | select(.state == "live") | "\(.host_id) \(.title)"'
```

**Cron health check** (`read`) — mail only when something is offline (cron mails any output):

```bash
# /etc/cron.d/webterm-health
*/10 * * * * root WT_TOKEN=$(cat /etc/webterm-token); \
  curl -fsS -H "Authorization: Bearer $WT_TOKEN" https://webterm.example.com/api/hosts \
  | jq -r '.[] | select(.online | not) | "OFFLINE: \(.name)"'
```

**Run a command on a host** (`run`) — find the id, then call `/run`:

```bash
ID=$(curl -fsS -H "Authorization: Bearer $WT_TOKEN" "$WT/api/hosts" \
     | jq -r '.[] | select(.name == "web-01") | .id')

curl -sS -X POST -H "Authorization: Bearer $WT_TOKEN" -H "Content-Type: application/json" \
  -d '{"command": "systemctl is-active nginx", "timeout": 30}' \
  "$WT/api/hosts/$ID/run" | jq -r '.exit_code, .stdout'
```

**A command a guardrail asks to confirm** — the first call gets `409 run.guardConfirm`; send it
again with `"confirmed": true` only if the script really means it:

```bash
curl -sS -X POST -H "Authorization: Bearer $WT_TOKEN" -H "Content-Type: application/json" \
  -d '{"command": "reboot", "confirmed": true}' "$WT/api/hosts/$ID/run"
```

## What tokens cannot do

Only the four endpoints above accept a token (`security.require_scope`); everything else depends
on the browser session. In particular a token cannot:

- **Read the audit log.** `GET /api/audit` is cookie-only on purpose: its entries hold the full
  text of commands run on the fleet, search queries, and each operator's email and IP. A token
  ends up in CI logs, `.env` files and scripts, which is the wrong place for operational history.
  The same applies to transcripts, previews, search and the agent log.
- **Create, change or delete accounts**, or create/revoke tokens (`/api/tokens` is cookie-only).
- **Touch the agent signing key** (unlock, lock, export).
- **Download backups** (they contain the vault key).
- **Open or create shares.**
- **Reach a host with *Require 2FA*.** Step-up needs a passkey or a person, so `/run` on such a
  host is refused outright (`403 host.needs2faNoToken`) and `/api/sessions` omits that host's
  sessions. (`/api/hosts` still lists the host itself.)
- **Get around the guardrail.** `/run` checks the guardrail rules server-side for every caller,
  tokens included: a **block** rule → `403`, a **confirm** rule → `409` unless the body has
  `"confirmed": true`.
- Open terminals, files, port forwards, Docker, services or anything else that is not `/run`.

## Expiry, revocation and auditing

- **Expiry is mandatory**: 1–365 days, fixed at creation. An expired token stops working at once
  (checked on every request) and stays in the list marked **expired** until you revoke it.
  There is no renewal; create a new token.
- **Revoke** (the *revoke* link on the row, after a confirm dialog) deletes the token. It is
  checked on every request, so the next call fails.
- **Deleting an account** also deletes every token that account created, and the server log
  records how many.
- **last_used** — the list shows *last used* (or *never used*). It is updated at most once a
  minute, so it is accurate to about a minute. Use it to find tokens nothing calls any more.
- **Audit log.** Requests that change something (`POST /api/hosts/{id}/run`) are written to the
  audit log with the actor **`token:<name>`** instead of an email, and the detail
  `cmd: <first 200 characters of the command>`. Refused runs (403/409) are recorded too, with
  their status. The `read` endpoints are plain listings and are not audited, like the same
  calls from the browser. Audit entries are kept `WEBTERM_AUDIT_DAYS` days (default 120).
- Creating and revoking a token are logged in the gateway's server log
  (`automation token created/revoked: …`); creation also triggers the security alert above.

> The [single-account invariant](../README.md#security) applies to whoever creates tokens: anyone
> past login can create a `run` token, which is a shell on every agent host without *Require
> 2FA*. Give tokens the narrowest scope and the shortest lifetime that works.

## Maintenance notes

- Backend: `gateway/app/security.py` (`TOKEN_PREFIX`, `api_token_principal`, `require_scope`),
  `gateway/app/api.py` (`TOKEN_SCOPES`, `TOKEN_MAX_DAYS`, `/api/tokens*`, `host_run`), audit actor
  in `gateway/app/main.py` (`audit_log` middleware); table `api_tokens`.
- UI: `frontend/src/components/settings/SecurityTab.tsx`.
