# Agent mTLS (design, 3.7.0 · agent 60)

Status: **implemented in 3.7.0 (agent 60)**. User-facing summary: [HOSTS.md → Client certificates (mTLS)](../HOSTS.md#client-certificates-mtls).

## Why

Since 3.6.38, `/agent/ws` is protected by rate limits in Traefik, an in-memory gate in the gateway and
allow/deny lists ([AGENT-HANDSHAKE-LIMITS.md](../AGENT-HANDSHAKE-LIMITS.md)). They have three limits:

1. **Traefik cannot tell a valid agent from a bot.** It only sees an address, so a botnet with fresh
   addresses gets a few free tries per address, and the global limit is shared with real agents.
2. **The token alone authenticates an agent.** It is a bearer secret, in `~/.webterm/agent.json` and
   once in the install script. Whoever copies it can connect as that host from anywhere.
3. **Agents and browsers share one name and one TLS policy**, so the agent route cannot be treated
   differently at the TLS layer.

With mutual TLS, every agent holds a **client certificate** signed by a CA that belongs to this
installation. Traefik asks for it **during the TLS handshake**, before any HTTP is spoken:

- **A client without such a certificate never reaches HTTP.** Traefik refuses the handshake. No
  request, no gateway, no database, whatever the number of addresses.
- **A copied token is not enough any more.** The private key of the certificate is needed too, and
  it never travels again after the install.
- **The agent route gets its own name and its own TLS policy.** Rate limits there become a second
  line, not the first.

What mTLS does **not** change:

- **A TLS handshake still costs Traefik some CPU.** Saturating the link or Traefik's TLS needs
  upstream filtering, as today.
- **A cloned VM carries its key with it.** The anti-clone fence (instance id) stays as it is.
- **The token stays.** It is the second check, and the only one Traefik cannot do.

## Overview

```
agent (v60) ──TLS + client cert──▶ Traefik  agents.<domain>   tls.options: RequireAndVerifyClientCert(agent CA)
                                     │  passTLSClientCert → X-Forwarded-Tls-Client-Cert
                                     ▼
                                   gateway /agent/ws  ── checks: cert chains to the CA, serial = host's current,
                                                         cert host id = token's host, then the token (as today)
```

| Piece | Where | What |
|---|---|---|
| Agent CA | gateway, `/data` (key encrypted at rest with `security.encrypt_secret`) | ECDSA P-256, 10 years. Its **public** certificate is written to the shared `edge-lists` volume, which Traefik already reads |
| Host certificate | issued by the gateway per host | ECDSA P-256 key, 1 year. Subject `CN=webterm-agent`. SAN `URI:urn:webterm:host:<id>`. Random serial, stored on the host row |
| Agent hostname | `WEBTERM_AGENT_HOST`, default `agents.<WEBTERM_DOMAIN>` | Its own router. For this installation, `agents.wt.safegrid.net` is already covered by the wildcard DNS and certificate |
| Traefik | file provider (`/edge/agent-mtls.yaml`, written by the gateway) | `tls.options.webterm-agents` with the CA, `clientAuthType: RequireAndVerifyClientCert`, TLS ≥ 1.2. A router `Host(agents.<domain>) && Path(/agent/ws)` uses those options plus `passTLSClientCert` |
| Proof of the route | the mTLS router | It sets `X-Webterm-Mtls-Router` to a secret of the installation (generated once, kept in the DB and in the file Traefik reads), overwriting any value a client sends. The gateway considers the certificate header only when that secret matches: a certificate is public, and a client could send the header on the token route, or with SNI = agents name and `Host` = the main name |
| Gateway check | `agent_ws` | When the request came through the agents router: parse the certificate from the header, check that it chains to the CA, is within its validity, and that its serial is the host's current one and its host id is the token's host. Then the token check and the instance fence, unchanged |
| Agent (v60) | `agent/ptyd.py` | Loads `agent-mtls.pem` with `ssl.SSLContext.load_cert_chain` (stdlib, Python 3.6+) and connects to `mtls_url`. After a failed attempt on one route it tries the other (mTLS ↔ token); the gateway decides, and a ratcheted host refuses the token route |

## Getting certificates to agents

The agent is stdlib-only and cannot generate keys, so **the gateway generates the key pair** and hands
it over once, over the agent's already authenticated, encrypted WebSocket:

- **Every agent from version 60, new or existing**, receives the control op `mtls_provision` after its
  first `hello` (`edgemtls.provision_hook`). The agent writes `agent-mtls.pem` (key and certificate in
  one file, 0600, so the swap is one atomic step), adds `mtls_url` and `mtls_serial` to `agent.json` and
  reconnects through the agents name.
  - There is deliberately **no certificate in the install script**: the private key never appears in
    a downloadable file.
  - The agent refuses a `mtls_url` outside its gateway's domain, so a message cannot send it
    elsewhere.
  - The agent also refuses a pair that does not load.
- **The gateway does not keep the key.** It keeps only the serial and the expiry.
- **The agent reports the serial it holds in every `hello`.** The gateway re-sends only when the
  agent does not have the certificate (a lost message, a failed install), at most once a day. An
  agent that has it but cannot reach the agents name gets nothing new. It stays on its token route
  until the host is required, and retries mTLS after an hour, then after twice as long each time it
  fails, up to once a day.
- **Renewal.** With a third of its validity left, the gateway sends a new certificate the same way.
  It is stored as `mtls_serial_next`, with the time it was sent.
  - The old serial stays valid until the agent connects with the new one. That connection makes the
    new serial current and stores its expiry.
  - The agent keeps the last **confirmed** pair (`agent-mtls.prev.pem`, with its URL; confirmed =
    it connected with it, recorded as `mtls_confirmed`) until it has connected with the new one. A
    second renewal that arrives before the first was ever used does not replace that backup. After a failed attempt with the new pair it tries the previous one, then the
    token route. A renewal that cannot be used therefore never locks out a required host while the
    old certificate is valid.
  - If the agent does not report the new serial within an hour, the gateway sends another one. A
    lost renewal therefore cannot leave a required host without a valid certificate.
  - The check runs at every `hello` and, for agents that stay connected for months, every 10
    minutes (`edgemtls.renew_sweep`).
- **The rollback (`WEBTERM_AGENT_MTLS=off`) is decided before the CA is loaded**, so it works even when
  the CA cannot be decrypted (a restore onto a server with another vault key).
- **Agents older than 60** ignore the op. They keep working with their token as today.

## The ratchet: no downgrade once a host has used mTLS

Like instance pinning, enforcement is per host and only goes one way:

1. **Before the first mTLS connection**, the host connects either way: token over the old route, or
   certificate + token over the agents name.
2. **After the first successful mTLS connection**, the gateway sets `mtls_required` on the host. From
   then on, a token-only connection for that host is refused (`4403`, recorded as an event). A stolen
   token can no longer be used without the key.
3. **Re-enrolling the host** clears the flag and revokes the serials **when the new install claims
   the link** (`api.install_script`), not when the link is generated. An unused link therefore does
   not reopen the token route. The claim also **rotates the host's permanent token**: the installer
   receives a new one, the old one stops working, and an agent still connected with it is
   disconnected. The new token is accepted alone until the new agent's first mTLS connection.

The final check runs **before** the WebSocket is accepted and the connection is published as the host's
source. The promotion after an mTLS handshake is one UPDATE conditional on the presented serial (`WHERE …
AND (mtls_serial = ? OR mtls_serial_next = ?)`): a handshake that raced with a re-enrolment is refused
instead of switching the ratchet back on. A token-only handshake re-reads the ratchet at that point and is
refused if another connection switched it on meanwhile.

A global setting, **Require mTLS for all agents**, comes last. It is off by default and can only be
turned on when no online agent is missing a certificate. It then closes `/agent/ws` on the main name
entirely: the main route answers `403` at Traefik, and only the agents name remains.

## Revocation

Traefik cannot check revocation lists for client certificates. The gateway is the revocation point:

- **The serial is checked against the host row on every new connection.** Deleting the host,
  re-enrolling it or re-issuing its certificate makes the old one useless for new connections. An
  already open connection is not closed by the reset.
- **A revoked certificate still gets through Traefik's handshake**, then stops at the gateway. That
  costs one indexed read, and at most one event row per host per minute. Only someone holding a
  real, once-valid key can trigger it.

## Rotating the CA

**Not supported in 3.7.0.** The CA lasts 10 years, client certificates never outlive it (`issue`
caps their expiry), and System health warns before it expires. A rotation would need trust overlap:
Traefik's `caFiles` accepts several CAs, but the gateway verifies against one CA and System health
does not count agents per CA. It is planned for a later release, well before the first CA expires.

## What the administrator sees

- **Host page:** *mTLS: required / available / token only*, plus the certificate's expiry.
- **System health:**
  - agents still connecting without a certificate;
  - certificates expiring within 30 days that did not renew;
  - the CA's own expiry.
- **Refused connections:** new rules `mtls_missing` (token-only connection for a ratcheted host) and
  `mtls_revoked` (old serial). Handshakes Traefik refuses for lack of a certificate never reach HTTP, so
  they leave no request behind. Whether Traefik exposes a usable counter for failed TLS handshakes is
  to be checked in staging; if not, they are simply invisible, which is acceptable: they cost nothing
  past Traefik.

## Edge cases

- **TLS-intercepting proxies** (some corporate networks) cannot pass a client certificate through.
  Such a host stays token-only until someone decides otherwise. It is never ratcheted by accident,
  because the ratchet needs a successful mTLS connection first.
- **HTTP-01 installs (no wildcard).** The agents name needs its own DNS record pointing at the server.
  Until it resolves, agents fail over to their token route and the host is not required, because
  the ratchet needs a successful mTLS connection first. Once a host is required, the agents name must
  keep resolving: System health warns about agents that stay on their token.
- **The agents name must be a subdomain of the main name** (`agents.<WEBTERM_DOMAIN>` by default). The
  agent refuses any other `mtls_url`, and the gateway turns mTLS off (reason `host`) if
  `WEBTERM_AGENT_HOST` is not one.
- **When mTLS breaks** (the CA cannot be loaded, the file cannot be written), the ratchet stays (fail
  closed) and System health raises a critical alarm. Only an intentional off lifts the ratchet:
  `WEBTERM_AGENT_MTLS=off`, a CDN in front, or no valid agents name. Turning it off is the documented
  way out.
- **Forward routing.** When the forward domain equals the main domain, the forward router's
  `HostRegexp` also matches `agents.<domain>`. The agents router gets a higher priority, and the slug
  `agents` is reserved in forward validation.
- **Behind a CDN that terminates TLS**, client certificates cannot reach Traefik. mTLS is off there and
  the documentation says so. A CDN with TLS passthrough (layer 4) works.

## Rollout

| Release | What | Risk |
|---|---|---|
| **3.7.0 · agent 60** | CA, issuance, agents router, gateway check, ratchet per host, `mtls_provision`, UI, docs. Old route kept | Agent update, signed by Stefan, rolling out as usual. Hosts move to mTLS one by one, as they update |
| later | "Require mTLS for all agents", once System health shows no token-only agent | Closes the old route |

## Tests

- **Unit:**
  - CA generation and encryption at rest;
  - issuance (SAN, serial, validity);
  - header parsing and chain verification, plus refusals: wrong CA, expired, wrong host, old serial;
  - the ratchet;
  - header stripping: a forged header on the main route is ignored.
- **Agent:**
  - `load_cert_chain` with the gateway's key format on Python 3.6 and on the portable 3.12;
  - fallback while not ratcheted;
  - `mtls_provision` written atomically, 0600.
- **Staging** (the label-safe method from AGENT-HANDSHAKE-LIMITS.md):
  - Traefik 3.7.10 and 3.7.19;
  - with and without a certificate, a forged header, a revoked serial, renewal;
  - a v59 agent next to a v60 one.
- **Independent reviews:** at least two, since this is the most sensitive path in the product.

## Decisions (Stefan, 2026-11-20)

1. **Agents name:** `agents.<WEBTERM_DOMAIN>` by default (`WEBTERM_AGENT_HOST`). For this installation,
   that is `agents.wt.safegrid.net`, already covered by the wildcard DNS and certificate.
2. **Certificate lifetime:** 1 year, renewed automatically.
3. **Ratchet per host:** automatic, after the first mTLS connection (INV-12).
4. **"Require mTLS for all agents":** later, once System health shows the whole fleet on mTLS. It is not
   part of 3.7.0.

Every installation generates its own CA. The project, and evershell.dev, hold no key and issue
nothing for anyone else's installation.
