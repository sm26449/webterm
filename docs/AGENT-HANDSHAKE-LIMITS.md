# Agent handshake limits (`/agent/ws`)

Agents connect to the gateway over one public route, `wss://<domain>/agent/ws`. Anyone on the internet
can reach it. Since 3.6.38, a client that floods it, with no token or a wrong one, is stopped in two
layers before it can cost the gateway a database read or write per request. Agents with a valid
token keep connecting, even from an address shared with an attacker.

**Since 3.7.0 (agent 61), agents also connect through their own name with a client certificate**
([HOSTS.md → Client certificates](HOSTS.md#client-certificates-mtls)). There, a client without a
certificate is refused during the TLS handshake and never reaches these limits. The limits below
keep protecting the token route, which older agents and agents not yet on mTLS still use.

## The two layers

| Layer | Where | What it does | What it costs the gateway |
|---|---|---|---|
| Proxy | Traefik, router `webterm-agent` (exact path `/agent/ws`) | A per-address rate limit and a global one. Over the limit: `429` (per address) or `529` (global), answered by Traefik. The global limit is keyed on a fixed header Traefik sets itself, so changing the `Host` header (another forward slug) does not open a new budget. | Nothing. The request never reaches the gateway. |
| Gateway | `gateway/app/agentgate.py`, in memory | Valid token hashes are kept in memory. No token: refused at once. Wrong token: 5 strikes in 10 minutes block the address for 10 minutes, doubling on each repeat up to 24 hours. A blocked address with an unknown token is refused from memory. | At most 5 database reads per address per 10 minutes, then none. No write per request. |

**A valid token always passes the gateway layer**, even from a blocked address. A shared NAT where one
machine misbehaves does not take the other agents offline. The proxy layer cannot see tokens, so its
per-address limit applies to everyone behind that address. Size it for your largest NAT (below).

**Already connected agents are never counted.** Both Traefik limits count new handshakes only. An open
WebSocket does not use up budget. `inFlightReq` is deliberately not used: on Traefik 3.7.10 and 3.7.19
it holds a slot for the whole life of the WebSocket, so connected agents would block reconnects.

**Forward hostnames.** The port-forward router sends every `<slug>.<domain>` to the app. When the
forward domain set in Settings differs from the one in `.env`, the app does not treat such a name as
a forward, and `/agent/ws` on it reached the agent handler with no proxy limit. The `webterm-agent`
router therefore matches the path on the main name and on every forward name.

**One router, on purpose.** In Traefik, a rate limiter keeps separate counters for each router that
uses it (verified on 3.7.19). Two routers for the same path would double every budget for a client
that alternates the `Host` header. The allow router is the one deliberate exception: it has its own
budgets, so known agents do not compete with a flood for the global one.

**Encoded paths.** `/agent%2Fws` does not match Traefik's exact path, but uvicorn decodes it and used
to reach the handler, bypassing the proxy limit. The gateway now refuses any path that is not the
literal `/agent/ws`, before any lookup (`4400`), and counts it as a strike.

## The gateway tells Traefik who to trust: allow and deny lists

Traefik cannot see tokens, but the gateway can. It writes a small Traefik configuration file into a
volume shared with Traefik (`edge-lists`, mounted read-only in Traefik). Traefik reloads it by itself:

| List | Who | What Traefik does | Expires |
|---|---|---|---|
| allow | addresses a **valid** agent connected from | a wide per-address limit (`WEBTERM_AGENT_ALLOW_BURST` / `_AVERAGE`), plus the global one | while an agent is connected, then `WEBTERM_AGENT_ALLOW_TTL` (24 h) after the last one |
| deny | addresses the gateway blocked for wrong tokens, **except any address a valid agent connected from in the last 30 days** | refuses them itself (`403`), before the gateway | when the block ends, and at most about 1 hour after the block began |
| everyone else | — | the strict limits above | — |

- **An address that has had a valid agent in the last 30 days is never denied at the proxy** (the
  list of such addresses is kept in the database, so it survives a gateway restart). That covers agents behind
  a NAT shared with an attacker, and a stale agent of a deleted host retrying from the same NAT. The
  attacker's handshakes still reach the gateway, which refuses them from memory.
- **A brand-new address** (no valid agent yet) that an attacker keeps blocked is denied at the proxy
  for at most about 1 hour from when the block began. A host enrolling from there right then waits that
  long; the panel shows the address as blocked.
- **The file only ever holds routers for the exact path `/agent/ws` on this installation's names**
  (the main domain, and the forward domain from `.env` and from Settings), with addresses validated by
  the gateway (IPv4, or IPv6 per /64), at most 500 per list. The gateway rewrites it atomically, at most
  every 10 s after a change and every minute anyway, so expired entries leave even when nothing
  happens.
- **If the file is missing or broken**, Traefik ignores it and the strict limits apply. Nothing opens.
- **When both lists are empty, the file is an empty document.** Traefik rejects an empty `routers`
  section, and with it the whole directory.
- **Restarts.** After a gateway restart, the allow list comes back from the file and the deny list
  starts empty, because the in-memory block decides it. After a Traefik restart, both stay: the file
  is still there.

Verified on Traefik 3.7.10 and 3.7.19:

- `ClientIP()` takes one address or CIDR, so several are chained with `||`.
- Reloading the file keeps open connections.
- An invalid rule only drops its own router.
- Deny is answered by an allow-nothing `ipAllowList`, not by `noop@internal`. Traefik does not count
  `noop@internal` in its router metrics, so those refusals would have been invisible.

**Behind a CDN or another proxy the lists are off.** Traefik's `ClientIP()` matches the address of
the TCP peer, which would be the CDN, while the gateway sees the real client. Their addresses would
never match, so the gateway does not write the lists when `WEBTERM_TRUSTED_PROXY_HOPS` > 1,
`WEBTERM_TRUST_CF_IP=1` or `WEBTERM_AGENT_RL_IP_DEPTH` > 0. The fixed limits still apply.

## Thresholds

| Variable (`.env`) | Default | Meaning |
|---|---|---|
| `WEBTERM_AGENT_RL_IP_BURST` | 60 | Handshakes one address may make at once |
| `WEBTERM_AGENT_RL_IP_AVERAGE` | 60 | …and per minute after that |
| `WEBTERM_AGENT_RL_GLOBAL_BURST` | 300 | Handshakes all addresses together may make at once |
| `WEBTERM_AGENT_RL_GLOBAL_AVERAGE` | 600 | …and per minute after that (10/s) |
| `WEBTERM_AGENT_RL_IP_DEPTH` | 0 | 0 = the TCP peer Traefik sees. Behind a CDN, see below. |
| `WEBTERM_AGENT_RL_METRICS_URL` | `http://traefik:8082/metrics` | Where the gateway reads Traefik's counters; `off` disables it |
| `WEBTERM_AGENT_LISTS_DIR` | `/edge` | Where the gateway writes the allow/deny file; `off` turns the lists off |
| `WEBTERM_AGENT_ALLOW_TTL` | 86400 | Seconds an address stays allowed after its last valid agent |
| `WEBTERM_AGENT_ALLOW_BURST` / `_AVERAGE` | 300 / 600 | The wide per-address limit for allowed addresses |

Why these numbers:

- **Agents reconnect without jitter.** After an outage, every agent tries again within a second, then
  backs off: 1, 2, 4… up to 60 seconds between tries (`agent/ptyd.py`, `BACKOFF_MAX`). The burst must
  cover the largest group that reconnects at the same moment from one address: all the agents behind
  one NAT. 60 covers 60 agents behind one address in a single wave. A larger group still gets in: the
  ones over the burst get `429`, back off, and come in as the budget refills (1 per second).
- **During a gateway outage the limits are not used up.** When the gateway is down, Traefik has no
  route for it and answers without reaching the limiter.
- **The global burst** covers a whole fleet reconnecting after a restart (300 agents). After that,
  10 handshakes per second is far above any real fleet and far below what would load the gateway.
- **One address flooding** gets 1 handshake per second through the proxy. At the gateway, 5 of those
  cost a database read, then the address is blocked and the rest cost nothing.

Measured in staging (synthetic data, small limits: per-address burst 15, global burst 30):

- 20 agents behind one address, plus 2 on their own, all connected within 13 s. After a gateway
  restart, all 22 were back within 26 s. Five of them got `429` and came in on their next try.
- An attacker on the same address as those 20 agents sent 120 wrong tokens. The gateway blocked the
  address. The 20 agents, restarted from that blocked address, were all back within 7 s.
- One address sending 200 handshakes: 15 reached the gateway and 185 were stopped at the proxy. Of the
  15, 5 cost a database read and 10 were refused from memory.
- 40 wrong tokens arriving at the same moment from one address cost at most 5 database reads (unit
  test). The strike is taken before the read and given back if the token turns out valid.
- Other routes from a limited address: `/login`, SSO status, browser terminal WebSockets and port
  forwards were all unaffected.
- The admin view's counts matched Traefik's counters exactly, including across two Traefik restarts.

## Behind a CDN or another proxy

By default the address is the TCP peer Traefik sees. If a trusted proxy sits in front of Traefik:

1. Add its addresses to `forwardedHeaders.trustedIPs` on the `websecure` entry point.
2. Set `WEBTERM_AGENT_RL_IP_DEPTH=1`.

A request whose source cannot be established then falls into one shared budget. A header sent by the
client never opens a new one: Traefik drops `X-Forwarded-For` from untrusted peers before the limiter
reads it (verified on 3.7.10 and 3.7.19, including the shared budget for requests with no
forwarded address). IPv6 addresses are limited per /64, in both layers.

**`WEBTERM_TRUST_CF_IP=1` needs the origin closed to everyone but Cloudflare.** With it, the gateway
takes the client address from `CF-Connecting-IP`. If the origin can also be reached directly, a client
can send a different value with each request: every request then looks like a new address to the
gateway's block, which costs one database read per request (still capped by the proxy limit).

## What the administrator sees

**Settings → System health → Agent handshakes** lists episodes: when each started, when it was last
seen, how long it lasted, how many handshakes were refused, which rule refused them, and the source.

- **Proxy (Traefik)**: authentication was **not checked**. The request was stopped before anyone looked
  at its token. It may be a real agent in a reconnect storm.
- **Gateway**: authentication **refused**. Rules: unknown token, wrong machine for the token, encoded
  path, or blocked address.

The panel also shows how many addresses are blocked right now and the size of the Traefik lists.

The same panel ("Refused connections and sign-ins") also shows, as episodes with their most frequent
sources (address, and for WebSockets the first two path segments, never a token):

- failed sign-ins, and sign-ins tried during a lockout;
- invalid API tokens;
- browser WebSockets refused before they were accepted.

Before this, none of them left a trace that showed where they came from. On 2026-11-19, 498 retries on
a path that is not even ours went unnoticed. The *Agent handshakes* check turns
yellow while a proxy episode is active.

**How the data is kept.** Episodes are aggregated:

- one row per episode, updated at most every 30 seconds per rule;
- an episode ends after 5 minutes without refusals;
- kept for 30 days, at most 200 rows;
- the start and end of each episode go to the audit log (actor `system:edgeguard`).

No token, header or query string is logged anywhere in this path.

The proxy counts come from Traefik's Prometheus endpoint on an internal entry point (`:8082`, not
published). If it is unreachable, the panel says so, with the time it stopped. The limits keep working
without it. Traefik's counters are cumulative, so refusals made meanwhile are counted when the counts
come back. A Traefik restart, which resets the counters, is recognised from its start time.

## Verifying

```sh
# Traefik loaded the router and its middlewares (no errors since the last start):
docker logs webterm-traefik-1 --since 10m 2>&1 | grep -i -E "webterm-agent|error" | head
# The counters (from inside the compose network):
docker compose -f docker-compose.prod.yml exec app python3 -c \
  "import urllib.request;print([l for l in urllib.request.urlopen('http://traefik:8082/metrics').read().decode().splitlines() if 'webterm-agent' in l][:5])"
```

Then open **System health**. *Agent handshakes* should show "Proxy counts: up to date".

## Rollback

The change has two parts, and either one can be undone on its own.

- **Proxy layer.** Set very high limits in `.env`, for example `WEBTERM_AGENT_RL_IP_BURST=100000`,
  `WEBTERM_AGENT_RL_IP_AVERAGE=100000`, `WEBTERM_AGENT_RL_GLOBAL_BURST=100000` and
  `WEBTERM_AGENT_RL_GLOBAL_AVERAGE=100000`, then `./deploy.sh`. Same image; the app
  container is recreated, so the gateway restarts for a few seconds and agents reconnect. For a full rollback, go back to the previous release with `rollback.sh`: the router and
  middlewares disappear with the labels, and the agent path falls back to the main `webterm` router.
- **Gateway layer.** It lives in the image; `rollback.sh` to the previous release removes it.
- **Allow/deny lists only.** Set `WEBTERM_AGENT_LISTS_DIR=off` and run `./deploy.sh`, then
  empty the file: `docker compose exec app sh -c ': > /edge/agent-lists.yaml'`. Traefik drops the two
  routers at once.

Agents need no change in either direction.

## Limits of this protection

- **A distributed flood** from many addresses is capped by the global limit, not stopped. While it
  lasts, new handshakes from real agents compete for the same global budget: they get `529`, back
  off for up to a minute, and retry. Connected agents and every other route are unaffected.
- **Saturating the network link or the TLS handshake capacity** happens before Traefik's limits apply.
  That needs filtering upstream: the provider's firewall, or a CDN in front.
- **A firewall (iptables/nftables) on the host** can limit connections per address, but it cannot see
  the HTTP path or the result of authentication inside TLS. Every service on port 443 (the app, port
  forwards, Authentik) would share its limits. It is not used here: Traefik and the gateway already
  give per-route limits with no new component or privilege.
- **Blocks live in memory.** A gateway restart clears them. The proxy limits stay in place, and a bot
  is blocked again after 5 more wrong tokens. At most 50 000 addresses are tracked; past that, the
  one seen longest ago is forgotten first. The repeat level resets after a day without a block.
- **An attacker behind the same address as your agents** uses up that address's proxy budget too:
  Traefik cannot see tokens. While the flood lasts, an agent there that needs to reconnect waits
  (`429`, retries up to a minute apart). Connected agents are not affected. If that matters more than
  the protection, raise `WEBTERM_AGENT_RL_IP_BURST` / `_AVERAGE` for your setup.

## Testing on a host that runs production

Never start a test container with `traefik.enable=true` on the Docker daemon that runs production. The
production Traefik reads every container on the host, and a second definition of the router `webterm`
makes it drop the real one. This took production down for 20 minutes on 2026-11-19. For a staging
stack on the same host:

- remove `traefik.enable` from the test containers;
- run the staging Traefik with `exposedbydefault=true` and a constraint on its own compose project;
- check `docker logs webterm-traefik-1 --since 5m | grep -c "defined multiple times"` returns 0 after
  every change.
