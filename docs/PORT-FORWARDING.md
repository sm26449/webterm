# Port forwarding

Expose a web service through the browser, behind WebTerm's authentication — no
`ssh -L`, no opening ports on the host. The target can be on the host (a Docker
container bound to `localhost`, Grafana, an admin panel) **or any IP on the
host's LAN** (the web interface of a router / switch / AP). It also works from an
iPad or phone, where SSH tunnels aren't an option.

## Why through the agent, not a plain TCP proxy

Hosts **phone home**: the agent opens a WSS connection *toward* the gateway, and
the host sits behind NAT with no exposed ports. An nginx/Traefik on the gateway
has no way to reach `127.0.0.1:3000` on a laptop in another network. Instead, we
reuse the exact tunnel the agent already keeps open: the gateway tells the agent
"open a TCP connection to `host:port`", and the agent reverse-proxies those bytes
back through the tunnel. Same path as the PTYs, just a new frame type
(`FRAME_FWD`).

The browser can't speak raw TCP, so the gateway terminates HTTP/WebSocket and
passes the **content** through the tunnel — it's not a generic TCP tunnel, it's an
HTTP(S)/WS reverse proxy.

For **https** targets (admin panels that speak only TLS on localhost — Proxmox,
Portainer, a router), the gateway brings up TLS on the last hop (gateway →
target) over the tunnel, via `ssl.SSLObject` plus in-memory BIOs. The target is on
the host's loopback (it never hits the wire) and typically uses a self-signed
certificate, so we don't verify it — on-the-wire confidentiality is already
guaranteed by browser→Traefik TLS and by the gateway→agent WSS.

## How to use it

1. In a session's toolbar, the **Port Forwards** button (on the right, next to
   Files and Commands) opens the panel.
2. **Add a forward**: name (e.g. "Grafana"), target `host:port` (default
   `127.0.0.1`), scheme `http`/`https`, and an optional description.
3. The status dot shows whether the target responds (green = reachable, red = not
   responding, gray = stopped). The probe uses the **stored** target, not a URL.
4. **Open** takes you to `https://<slug>.<domain>` in a new tab. The first access
   performs the auth handshake automatically, and then you see the service.

A *declared* forward holds no open connection. The agent opens a TCP connection
**only on real traffic** (when you actually open the tab); idle = zero cost. Up to
64 concurrent forwards per agent.

## Devices on the host's LAN (routers, switches, APs)

`target_host` doesn't have to be `localhost` — it can be any IP on the host's
network. The agent opens a TCP connection to that IP, so you reach a device's web
interface without being on the same network: `target_host = 192.168.88.1`, port
80/443, scheme `http`/`https`. The host running the agent effectively becomes a
**jump host** into its LAN.

Two fixes (v1.0.50–1.0.51) made this work with real device UIs:

- **No CSP on forwarded content.** UIs like **MikroTik Webfig** use inline scripts
  plus `eval()`; WebTerm's strict CSP on the app (`script-src` has no `unsafe-inline`/`unsafe-eval`; `style-src` does allow inline styles) broke them
  — login worked, but the page stayed stuck on "connecting". Being a different
  origin, the forward no longer receives our CSP/headers; the device brings its own
  headers. The main app keeps its CSP (verified).
- **Long-poll tolerated.** Webfig keeps connections open (`/jsproxy`, long-poll)
  until an event fires; the 30s response timeout killed them → 500 → session lost →
  re-login. Raised to 120s (`FWD_RESP_TIMEOUT`) — enough for long-poll; a dead
  target still fails after that long.

Verified on a real MikroTik (192.168.88.1) on the LAN of a host running an agent.
This unlocks **web** access to the device.

### Telnet to the device's CLI (bastion, DELIVERED)

For the device's **CLI** (not the web UI), pick the **`telnet`** scheme when
creating the forward: the **Open** button then launches a **terminal tab**, not a
browser tab. The gateway tunnels telnet through the host's agent (the same
`open_forward`), with its own IAC shim (`gateway/app/telnet.py`). No opening a
terminal on the host and running `telnet` by hand, no new subdomain/DNS/cert — the
access surface is the terminal on the main origin. Details and threat model:
[telnet/SSH bastion](design/TELNET-BASTION.md).

- **The password never reaches the transcript** (F3): input is redacted in the
  password prompt.
- **OSC 133/52 filtered out** (F5): a hostile device can't forge command markers or
  poison the clipboard.
- **1-click reconnect:** if the agent drops, the telnet session becomes `lost` (not
  `exited`) and a **↻ Reconnect** button opens a new telnet to the same target, in
  the same tab. (Device state isn't resurrected — telnet is stateful on the socket;
  you land at a fresh login.)

SSH-via-agent to devices remains deferred (as "SSH host via jump", not as a
forward).

## Security (priority #1)

Each forward lives on **its own subdomain** (`<slug>.<domain>`), isolated as an
origin from the main application and from the other forwards:

- **The WebTerm session cookie is `__Host-`** (host-only, no `Domain`): it never
  leaks to the forward subdomains. The forwarded service can't read your admin
  session.
- **Auth on every request.** No valid forward cookie → redirect to the handshake,
  never a proxy. The handshake: subdomain → `/__wtfwd/auth` on the main domain
  (where the session lands) → a **slug-bound HMAC token** with expiry →
  `Set-Cookie` scoped to the subdomain. A token for `grafana` is rejected (403) on
  any other subdomain.
- **Anti-SSRF**: the proxy uses the target from the DB, never from a URL or header.
  There's no endpoint that accepts an arbitrary target.
- **Anti-CRLF / request smuggling** on path and headers, **anti open-redirect** on
  `next`, cookie hygiene (the forwarded app's cookies pass through to the target,
  our forward cookie is stripped).
- Forwarded content is served **without** WebTerm's CSP (it's a different origin),
  so it doesn't weaken the main application's policy — and it's necessary for device
  UIs that require inline/`eval` (see the LAN devices section).
- A **stopped** forward → 404, even with a valid cookie.

> The [single-account invariant](../README.md#security) applies: anyone who gets
> past login administers all hosts and all forwards. There is no per-object
> authorization.

## SSH hosts

Forwarding works on SSH hosts too — it reuses the host's `asyncssh` connection and
opens a **direct-tcpip** channel to the target (traffic is encrypted the whole way;
the last hop is loopback on the SSH host). The lifecycle is hybrid:

- **Open session** on the host → the forward reuses the connection, instantly.
- **No session, but a STORED credential and no 2FA** → the gateway brings up the
  connection on first access and closes it after an inactivity timeout (5 min).
- **2FA or non-stored credentials** (`ask`/`ephemeral`) → the forward requires an
  open session (we can't ask for a TOTP/password in the subdomain flow); the panel
  says so clearly.

No new surface: the same origin isolation plus handshake, anti-SSRF (target from
the DB), and only credentials that are already stored/pinned (host key verified
before auth).

## Deploy (Traefik + wildcard DNS)

The routing is already in `docker-compose.prod.yml`:

- Router `webterm-fwd` catches `HostRegexp(^[a-z0-9-]+\.<domain>$)` and sends it to
  the same application (which does the handshake + proxy). The app re-validates the
  Host against the exact domain suffix — defense-in-depth on top of the regex.
- A **wildcard** certificate via DNS-01 (Cloudflare): `tls.domains` requests
  `<domain>` + `*.<domain>` on the existing `le` resolver.

The only manual step is the wildcard DNS record (one time):

```
*.<domain>   A   <server-ip>   (DNS-only / no proxy on Cloudflare)
```

`WEBTERM_PUBLIC_URL` / `WEBTERM_DOMAIN` from `.env` determine the forward domain —
the subdomains are derived from it, not configured separately.

## Testing

`scripts/fwd-test.sh` (run in CI against a real agent): the full
handshake redirect→token→cookie→proxy, HTTP proxy through the tunnel, **WebSocket**
through the tunnel (round-trip echo), **https targets** (TLS on the last hop),
**configurable domain**, **SSH hosts** (real sshd: auto-dial and the 2FA gate),
plus security — slug-bound token, no cookie→redirect, invalid cookie→redirect,
stopped forward→404, anti-SSRF via the stored target, **anti-CSWSH** (hostile
Origin rejected). The panel also has a UI test in `scripts/e2e-session.mjs`.

## Configurable domain (Settings)

The forward domain can be changed under **Settings → Port forwarding — domain**
(default = the application's domain). The application uses it immediately for URLs
and Host matching; the panel shows live status (does the wildcard DNS resolve? is
the certificate issued?). To use a domain different from the application's, you
need, once: a wildcard DNS record, `FORWARD_DOMAIN=<domain>` in
`/opt/webterm/.env` (with the Cloudflare token that covers the zone), and a
redeploy — Traefik issues the wildcard cert for the new domain. **The Cloudflare
token stays in `.env`, not in the application** — a secret with DNS privileges
doesn't enter the app's blast radius.
