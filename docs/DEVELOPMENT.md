# Development, tests and release gates

How to build and run WebTerm from source, the test suites and the CI chain. Contribution
rules (signing the agent, style, the CI gates you must keep green) are in
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install \
  -r gateway/requirements.txt -r gateway/requirements-dev.txt
cd frontend && npm ci && npm run build && cd ..

# backend with reload + frontend vite dev (proxy to :8000)
PYTHONPATH=gateway .venv/bin/uvicorn app.main:app --reload &
cd frontend && npm run dev
```

### Tests

One runner, used by both CI and you — `scripts/run-tests.sh`. The list of suites lives
there, in one place: when it was duplicated, `make test` silently ran 2 files while CI ran
22.

```sh
make test         # hermetic suite — EXACTLY what CI gates the image on
make test-local   # + the suites that need real tmux/agent on this machine
```

The `local` group starts a real agent. It is **sandboxed from any production agent** on the
same box (`tests/tmux_sandbox.py`): `$HOME` does not isolate tmux — the socket lives in
`$TMUX_TMPDIR/tmux-<uid>/`, keyed by UID — so tests get their own `TMUX_TMPDIR` and refuse
to run if the computed socket is the production one while an agent is alive. Without that,
a test run adopts and then kills the live sessions (it did, on 2026-08-05).

Suites needing a running stack (`instance_fence`, `storm`) or system users (`ssh`,
`provision`, which create/delete accounts via sudo) are listed by the runner but not run
automatically.

**E2E in a browser** (Playwright, real agent). CI runs `scripts/e2e-session.mjs`; to run it
locally without Node installed:

```sh
docker run -d --name smoke -p 8000:8000 -e WEBTERM_SETUP_TOKEN=ci-e2e-token \
  -e WEBTERM_PUBLIC_URL=http://127.0.0.1:8000 -e WEBTERM_AGENT_INSECURE=1 webterm-smoke:ci
# tmux inside the container: WITHOUT it the agent falls back to the `pty` backend and the
# E2E tests a different backend than production — that gap hid a whole class of bugs
docker exec -u root smoke sh -c 'apt-get update -qq && apt-get install -y -qq tmux'
docker exec smoke sh -c 'printf "%s" "{\"url\":\"ws://127.0.0.1:8000/agent/ws\",\"token\":\"$TOK\",\"insecure\":true}" > /root/.webterm/agent.json'
# the Playwright image ships the BROWSERS, not the npm package — install it first,
# or the script dies with ERR_MODULE_NOT_FOUND: Cannot find package 'playwright'
docker run --rm --network host -v "$PWD/scripts:/w" -w /w \
  -e AGENT_TOKEN_FILE=/w/token -e E2E_SETUP_TOKEN=ci-e2e-token \
  mcr.microsoft.com/playwright:v1.63.0-noble \
  sh -c 'npm i --no-save playwright@1.63.0 >/dev/null 2>&1 && node e2e-session.mjs http://127.0.0.1:8000 smoke'
```

`AGENT_TOKEN_FILE` makes the script write the enrol token to disk instead of shelling out to
`docker` (it has no Docker CLI inside the Playwright image); start the agent yourself with
that token, as above.

## Layout

```
agent/
  ptyd.py                  single-file agent (stdlib, Python 3.6+), Ed25519-signed
  shell-integration.sh     OSC 133 markers (bash/zsh), installed with the agent (opt out
                           with WEBTERM_NO_SHELL_INTEGRATION=1); appends one line to ~/.bashrc
gateway/app/
  main.py                  FastAPI, security headers, static, periodic reapers
  api.py                   REST + WS agent/browser + installer + idle-lock 2FA
  core.py                  session hubs, liveness reconciliation, file transfer,
                          telnet-via-agent, port forwarding
  telnet.py                IAC shim + OSC filter for the telnet bastion (untrusted device)
  security.py              passwords, sessions, rate-limit, brute-force, passkey step-up
  email_alerts.py          security alerts + resource thresholds (hysteresis)
  webauthn_api.py          passkeys
  backup.py                backup/restore from Settings (VACUUM INTO snapshot,
                          scrypt→AES-GCM encryption, restore at boot)
  db.py / config.py        SQLite + configuration
frontend/src/
  components/              SessionView, TabBar, CommandsPanel, ForwardsPanel,
                          FleetRunModal, HistoryModal, TranscriptPlayer…
  lib/                     shortcuts (single registry), commands (OSC 133),
                           termtheme (schemes + iTerm/VSCode import), metrics
scripts/
  e2e-session.mjs          E2E with a REAL agent (runs in CI)
  e2e-jump.mjs             jump-host UI: nesting, form, host hub (CI, no agent)
  fs-test.sh · fwd-test.sh file operations · port forwarding (CI)
  mobile-audit.mjs         responsive audit on real devices (CI)
  smoke-boot.mjs           boot smoke test (UI starts with no JS errors)
  sso-login.mjs            SSO login UI contract when OIDC is on (CI)
  sign-agent.py            signs the agent at release (the key stays offline)
tests/                     unit + integration suite (dev): telnet (shim/bastion),
                          session reconciliation, agent hygiene+hardening, idle-lock,
                          security, ssh, transcript, provisioning…
docs/                      RUNBOOK · SHORTCUTS · SHELL-INTEGRATION ·
                          PORT-FORWARDING · FLEET (Run on hosts) · SERIAL-CONSOLE ·
                          SSH-KEYS · SSH-JUMP · DATABASE-TOOLBOX · SSO ·
                          TRANSFERS · THREAT-MODEL · HOSTS ·
                          AUTOMATION-TOKENS · ALERTS · GUARDRAIL · AI-TOOLS
  design/                  architecture notes: ARCHITECTURE · SIGNED-UPDATES ·
                          SESSION-LIFECYCLE · SPLIT-VIEWS ·
                          TELNET-BASTION · FUTURE-DIRECTIONS
deploy.sh · rollback.sh    production: pin, health gate, rollback
```

## Testing & release gates

A broken build must not be able to reach production — least of all on a tool you
administer your servers with. The CI chain, in order:

0. **Unit tests and hygiene** (`unit-tests`, which everything else depends on) —
   the Python + shell suite, `ruff`, a gitleaks scan, a check that the version badge
   matches the code, a `requirements.lock` drift check, and **`pip-audit --strict`**,
   which is blocking.
1. **Agent signature verification** — if `agent/ptyd.py` changed without
   re-signing, the build fails (agents would refuse the update anyway).
2. **Boot smoke test** (`scripts/smoke-boot.mjs`) — the image starts in an
   ephemeral container, a headless Chromium checks that the UI reaches a working
   screen, with no JS errors. Catches exactly the class of bug that produced the
   white screen in v1.0.11.
3. **E2E with a REAL agent** (`scripts/e2e-session.mjs`; the check count is kept in the README, where CI verifies it) — starts an
   agent in a container **with tmux installed, i.e. the backend production uses**,
   opens sessions through the UI, types commands, verifies the output, tab
   switching, pause/re-sync, shortcuts, parametrized snippets, alert thresholds,
   transcript replay, the OSC 133 flow + **block actions**, the file panel,
   **port forwarding**, **Run on hosts**, **command history**, and a **reconnect with
   history replay** (no duplicate entries, no prompts captured as commands, new
   commands still recorded). Running this on the `pty` fallback would test a
   different backend than production — that gap hid a whole class of bugs.
4. **FS API** (`scripts/fs-test.sh`, 53) — end-to-end file operations with a real agent.
5. **Port forwarding** (`scripts/fwd-test.sh`) — auth handshake, HTTP +
   WebSocket proxy + **https targets**, **configurable domain**, **SSH hosts**
   (real sshd), and security tests (slug-bound token, anti-SSRF, the 2FA gate,
   anti-CSWSH).
6. **Mobile audit** (`scripts/mobile-audit.mjs`) — 10 real devices (iPhone/iPad/
   Android, WebKit + Chromium); any layout regression blocks the image.
7. **Accessibility** (axe-core, `A11Y_MAX_SERIOUS=0`) — a single serious violation
   fails the build.

Only if all pass does the image publish to ghcr. On deploy, `deploy.sh` keeps the
previous image and does an **automatic rollback** if the new container doesn't
become healthy; `rollback.sh` is the panic button over SSH. Full recovery:
[docs/RUNBOOK.md](RUNBOOK.md).
