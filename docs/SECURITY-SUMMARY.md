# Security summary and share links

The **Security** card on the Dashboard answers one question at a glance: *is everything
OK right now?* Before 3.5.4 that took four trips (Settings → Security, each shared session,
the guardrail, the signing key), and nothing listed the live share links across the fleet.

## What the card checks

Each row is one check. The status is shown as an icon **and** a word (OK / Attention /
Problem / Info), never by colour alone. Every row links to the place where you fix it.

| Check | What it looks at | Status |
|---|---|---|
| **Your 2FA** | how many passkeys your account has, and whether TOTP is on | **Problem** with neither; **Attention** with exactly one passkey and no TOTP while some host requires 2FA (losing that one key locks you out of those hosts); SSO accounts without a local factor show **Info** — their second factor lives at the IdP |
| **Share links** | active (not expired) share links, and how many are writable | **OK** with none; **Attention** with any; **Problem** if any is writable |
| **Command guardrail** | enabled, number of rules | **Attention** if disabled or with no rules |
| **Signing key** | the fleet signing key: present, locked, missing (the same signal as the dot on the Settings gear) | **Problem** when locked (agents cannot update); **Attention** when missing |
| **Hosts requiring 2FA** | X of Y hosts have *Require 2FA* | **Info** only — it is a per-host choice |
| **Backup** | last successful backup (local snapshot or off-host copy), last failure, whether an encrypted off-host copy exists | **Problem** if the last attempt failed or there has never been a backup; **Attention** if the last good one is older than the schedule period plus a day (about 2 days with daily or no schedule, 8 with weekly) |
| **Alert channels** | whether SMTP and/or a webhook are configured (never their values) | **Attention** if neither |
| **Agents** | online agents on the version shipped with this gateway vs. older | **Attention** if any *online* agent is outdated; offline agents are counted separately and are not a problem — they update when they reconnect |

The card collapses to one line ("All good · 8 checks") when every row is OK or Info, and
opens on its own when something needs attention. It refreshes when the Dashboard is shown
and every 60 seconds while the tab is visible.

**TLS certificate expiry is not a row on purpose.** The certificate is served by Traefik,
outside the application; the gateway has no reliable view of it. The host-side check is
`scripts/cert-check.sh`, installed as the `webterm-cert-check` systemd timer (see "Certificate expiry watch" in the [main README](../README.md)).

The data comes from `GET /api/security/summary` — a list of `{id, status, value}` with no
prose (the UI writes the text in your language). It is browser-only: automation tokens get
`401`.

## Share links inventory

**Share links** on the card opens the inventory: every active link in the fleet, with the
session title, host, who created it, read-only or writable, when it expires, and how many
guests are connected **right now**.

- The link itself is **never shown again**. Only a hash of the token is stored; the URL is
  shown once, when the link is created. The inventory cannot reconstruct it, and the API
  (`GET /api/shares`) never returns a token or a URL.
- Sessions on a host with *Require 2FA* follow the same rule as the session list: they appear
  only while you have a step-up window open on that host. Until then they are **counted**
  ("1 more on 2FA hosts") but not described.
- **Revoke** on a row ends that one link and disconnects its connected guests immediately.
  On a 2FA host it asks for step-up, like creating the link did.

### Revoke all

**Revoke all** is the incident button: it ends **every** active share link in the instance —
all accounts, all hosts, including the ones hidden on 2FA hosts — and disconnects every guest
that is watching or typing.

It asks you to confirm, then for your **account password** (SSO accounts: a fresh SSO or
passkey re-authentication instead). A stolen session cookie alone cannot do it. The action
is written to the audit log with the number of links revoked, and an alert goes out on the
configured email/webhook channels.

Revoke all is the same internal operation the gateway runs when you change your password.
