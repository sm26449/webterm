# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report privately via **GitHub Security Advisories**: the *Security* tab → *Report a vulnerability*
(or `.../security/advisories/new`). You will get a private channel for discussion and a coordinated fix.

Include, if you can: the affected version, reproduction steps, the impact, and a proof of concept.

**No GitHub account?** Email `stefan.maldaianu@gmail.com` with `WebTerm security` in the subject.
Advisories are preferred — they give us a private thread and a coordinated fix — but not having an
account should never be the reason a problem goes unreported.

**What to expect.** The project is maintained by one person, in his spare time, so this is a promise
about honesty rather than speed: an acknowledgement within **7 days**, and an assessment (in scope or
not, and roughly when) within **30 days**. If you have not heard back in 30 days, assume the message
was lost and ping again — that is a failure on my side, not impatience on yours. Fixes ship in the
next release; you decide whether to be credited in the advisory.

**Safe harbour.** Test only against your own installation. Do not access other people's data, do not
degrade a service someone else depends on, and give me a reasonable window before publishing. Within
those limits I will not pursue anything against a good-faith report, and I would rather hear about a
finding that turns out to be nothing than not hear about one that was real.

## What is in scope

Bugs that break the **documented trust boundaries** (see [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)):

- authentication / session / lockout bypass;
- Cross-Site WebSocket Hijacking, CSRF, XSS, injection (SQL/ANSI/OSC/header);
- path traversal, SSRF, secret leakage;
- accepting unsigned / downgraded agent updates, cert pinning bypass;
- forward isolation (token bound to slug), cross-host escalation.

## What is NOT a vulnerability (by design)

WebTerm is designed for **a single trusted administrator**. The following are **deliberate decisions**,
explained in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), not bugs:

- **The agent runs with its user's privileges** on every host and never escalates; fs/command
  operations are NOT sandboxed. Anyone who gets past login has that user's access across the whole
  fleet — like holding an SSH key for it. The install command offered by default creates a dedicated
  unprivileged `webterm` user; installing as the current user while root makes it root's.
- **There is no per-object authorization / RBAC.** You may create several accounts, but **every
  account is a full administrator** over the whole fleet: any of them can add hosts, run commands
  anywhere, and read the audit log. Multiple accounts buy **attribution**, not isolation — this
  used to read "the model is single-account", which understated what a second account can do.
- **The gateway is a single point of total compromise** (it commands the agents). A compromised gateway =
  a compromised fleet.
- **Scheduled server-side backups are unencrypted** (the server holds the vault key anyway).
- The `insecure` mode (TLS without validation) is an **opt-in**, documented footgun.

If you find a way to break one of these **without** the premises above (e.g. escalation from
unauthenticated, or from one account to another's in a future multi-user setup), **that is in scope** —
please report it.

## Supported versions

Actively developed; security fixes go into the latest version (`main` / the latest `vX.Y.Z` tag).
Run the most recent official image or build from `main`.

## Deployment best practices (read before exposing)

- Run with a **domain + HTTPS + passkeys**, not just IP/password.
- Install agents as a **dedicated least-privilege user**, not root, wherever you can.
- Generate your **fleet signing key** (Settings → Security) before enrolling agents.
- Do not expose `insecure` mode in production.
