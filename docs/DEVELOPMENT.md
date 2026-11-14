# Development, tests and release gates

How to build and run WebTerm from source, the test suites and the CI chain. Contribution
rules (signing the agent, style, the CI gates you must keep green) are in
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install \
  -r gateway/requirements.txt -r gateway/requirements-dev.txt
cd frontend && npm ci && npm run build && cd ..   # needs Node (the image builds with 26); without it, see below

# backend with reload + frontend vite dev (proxy to :8000)
PYTHONPATH=gateway .venv/bin/uvicorn app.main:app --reload &
cd frontend && npm run dev
```

No Node on the machine? The Playwright image used by the gates has it:

```sh
cd frontend && docker run --rm -v "$PWD":/work -w /work mcr.microsoft.com/playwright:v1.63.0-noble \
  bash -c 'npx tsc --noEmit && npm run lint && npx vitest run'
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

The big picture first; every gateway module starts with a docstring that says what it owns.

```
agent/
  ptyd.py                  single-file agent (stdlib, Python 3.6+), Ed25519-signed.
                           class Agent → handle_ctrl (every op the gateway can ask for)
  shell-integration.sh     OSC 133 markers (bash/zsh), installed with the agent (opt out
                           with WEBTERM_NO_SHELL_INTEGRATION=1); appends one line to ~/.bashrc
gateway/app/
  main.py                  FastAPI app, security headers, static files, periodic reapers
  api.py                   every REST route + the agent / browser / shared websockets + the
                           installer. 12k lines: navigate by its "# ── Section ──" banners
  core.py                  runtime: SessionHub, AgentConnection, liveness reconciliation, the
                           per-connection sources (SSH, SSH-jump, telnet, serial), forwards,
                           file transfer
  db.py · config.py        SQLite (aiosqlite, no ORM) + migrations · env configuration, version
  errors.py · audit.py     API errors with stable codes · audit log of every changing request
  -- identity and access --
  security.py              passwords, web sessions, host tokens, secret vault, brute-force
  authz.py                 roles and scoped bindings: the one place that decides who may do what
  accounts.py              disabled accounts
  totp.py · webauthn_api.py   second factor · passkeys
  oidc.py · oidc_api.py · ssomap.py   SSO (OIDC + PKCE) · its endpoints · group → role mapping
  scim.py                  SCIM 2.0 provisioning
  -- terminal and hosts --
  telnet.py                IAC shim + OSC filter for the telnet bastion (untrusted device)
  osc133.py                shell-integration state seen by the hub (command guardrail)
  replay.py                public read-only replay links
  fscopy.py · rootmove.py  host → host copy · uploads into folders the agent user cannot write
  gitpanel.py              the Git panel's fixed, read-only operations
  pyruntime.py             portable Python for agent hosts
  signing.py               per-deployment agent signing key
  -- operations --
  backup.py · backup_dest.py · cloudbackup.py   backup/restore · SFTP/FTPS · Drive/Dropbox
  email_alerts.py · alert_history.py · push.py  e-mail alerts · in-app history · Web Push
  syshealth.py · healthcmd.py · hoststatus.py · health.py   System health and its fixed commands
  certmon.py               TLS certificate monitoring + renew
  updatecheck.py           "is there a newer version?"
  admin.py                 recovery from the server: python3 -m app.admin …
frontend/src/
  App.tsx                  shell: tabs, split views, hash routing, toasts, global shortcuts
  components/              one file per surface. SessionView = a terminal pane (the largest);
                           settings/*Tab.tsx = Settings; ui/ = design-system primitives
  lib/                     pure logic, one module per concern, each with <name>.test.ts beside
                           it (vitest): commands (OSC 133), echo + broadcastGuard (guardrail),
                           uploads/downloads/transfers, shortcuts, termtheme, splitLayout,
                           touchsel/seltext (selection), i18n…
  lang/en.ts · lang/ro.ts  the two string catalogs (kept symmetric by tests/i18n_catalog_test.py)
scripts/
  run-tests.sh             THE list of Python suites (ci · local · all) — CI and `make test` use it
  ci-local.sh              the CI job, locally: unit sig lint build smoke e2e a11y fs fwd mobile
                           sso backup features jump (or `all`)
  e2e-session.mjs          E2E with a REAL agent (runs in CI)
  e2e-jump.mjs · e2e-features.mjs · e2e-backup.mjs · e2e-restore.mjs   UI flows gated in CI
  e2e-links*.mjs · e2e-clipboard-*.mjs · e2e-tab-reorder.mjs · e2e-host-edit-input.mjs
                           focused browser checks, run by hand
  fs-test.sh · fwd-test.sh file operations · port forwarding (CI)
  mobile-audit.mjs         responsive audit on emulated devices (CI)
  smoke-boot.mjs           boot smoke test (UI starts with no JS errors)
  sso-login.mjs            SSO login UI contract when OIDC is on (CI)
  sign-agent.py · gen-signing-key.py · check-rollover.py   agent signing (the key stays offline)
  check-reqs-lock.py       requirements.txt ↔ requirements.lock drift (CI)
  changelog-section.py     a release's CHANGELOG section → GitHub Release notes (CI)
  route-matrix.py          every route with its declared permission
  load-test.mjs            load test, by hand
  backup.sh · restore.sh · host-health.sh · cert-check.sh · cert-renew.sh ·
  docker-cleanup.sh · authentik-upgrade.sh   host-side helpers shipped to production
  social-preview/          renders docs/social-preview.png (GitHub social card)
tests/                     <feature>_test.py: plain Python scripts (no pytest), run through
                           scripts/run-tests.sh — a test file that is not listed there fails
                           the runner. ui_review.mjs = the axe-core accessibility gate
docs/                      user and operator docs, indexed in docs/README.md
  design/                  architecture notes: ARCHITECTURE · SESSION-LIFECYCLE ·
                           ROLES-AND-SSH · SPLIT-VIEWS · SIGNED-UPDATES · TELNET-BASTION ·
                           GIT-PANEL-SUPERVISION · DESIGN-SYSTEM · FUTURE-DIRECTIONS
deploy.sh · upgrade.sh · rollback.sh   production: first install · upgrade (backup, host files,
                           image pin, health gate) · the panic button
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
6. **Mobile audit** (`scripts/mobile-audit.mjs`) — 11 emulated device profiles (iPhone/iPad/
   Android, WebKit + Chromium, plus a 320 px reflow case); any layout regression blocks the image.
7. **Accessibility** (axe-core, `A11Y_MAX_SERIOUS=0`) — a single serious violation
   fails the build.
8. **SSO login UI** (`scripts/sso-login.mjs`) — the frontend contract when OIDC is on.
9. **Backup UI + restore round-trip** (`scripts/e2e-backup.mjs`, `e2e-restore.mjs`) — against
   SFTP/FTPS fixture servers.
10. **Feature UI** (`scripts/e2e-features.mjs`) — group enrollment tokens and host tags.
11. **Jump-host UI** (`scripts/e2e-jump.mjs`) — nesting, the form, the host hub.

Frontend `eslint` and `vitest` run in the `unit-tests` job with the Python suite. Two CI checks
have no local equivalent in `ci-local.sh`: the **counts in the docs** (`unit-tests`: the number of
`check(` calls in `e2e-session.mjs` must match the README, the number of suites in `run-tests.sh`
must match CONTRIBUTING.md — a mismatch fails the job, and then no image is built) and
**`AGENT_VERSION` bumped when `agent/ptyd.py` changed** (`build`, compared with the previous push).

Run the same chain locally with `scripts/ci-local.sh` (steps: `unit sig lint build smoke e2e a11y
fs fwd mobile sso backup features jump`, or `all` — about half an hour). `build` produces the image
the browser steps run against, so repeat it after a code change; `a11y` and `mobile` log in with
the account that `e2e` creates, so run them together with it (`ci-local.sh build e2e mobile`).

Only if all pass does the image publish to ghcr. On deploy, `deploy.sh` (which `upgrade.sh` calls after its backup and host-file sync) keeps the
previous image and does an **automatic rollback** if the new container doesn't
become healthy; `rollback.sh` is the panic button over SSH. Full recovery:
[docs/RUNBOOK.md](RUNBOOK.md).

### GitHub Releases (release notes)

Pushing a `v*` tag also runs `.github/workflows/release-notes.yml`, **separately** from the image
workflow (it neither waits for nor gates the image). It takes the tag's `## [x.y.z]` section from
`CHANGELOG.md` with `scripts/changelog-section.py`, joins the hard-wrapped lines, makes
repository-relative links absolute at the tag, appends a footer with the image
(`ghcr.io/sm26449/webterm:vX.Y.Z`) and the upgrade command, and creates the GitHub Release — or
**edits** it if it already exists, so re-running is harmless. The title names the agent only when
the release changes it (`WebTerm 3.5.16 · agent 58`); the newest stable tag is marked *Latest*. A
tag whose version has no CHANGELOG section fails the run (a release without notes is a mistake).

```sh
python3 scripts/changelog-section.py v3.5.16 --title    # WebTerm 3.5.16 · agent 58
python3 scripts/changelog-section.py v3.5.16 --notes    # exactly the release body
```

To create the releases that older tags never got: *Actions → Release notes → Run workflow*, with
`backfill` = how many of the newest tags to look at (default 10); tags that already have a release
are left untouched. `tests/changelog_section_test.py` checks the extraction against the real
CHANGELOG and the workflow's YAML (trigger, permissions, SHA-pinned actions).

### Social preview image

`docs/social-preview.png` (1280×640, < 1 MB) is the card GitHub shows when the repository link is
shared. It is generated, not drawn: `scripts/social-preview/preview.html` lays out the logo mark
(`frontend/public/favicon.svg`), the wordmark in JetBrains Mono, the README's tagline and a crop of
`docs/screenshots/02-terminal-dark.png` on the app's dark palette, and
`scripts/social-preview/run.sh` renders it in the Playwright image and shrinks it with pngquant.
Re-run it after the README screenshots or the tagline change. **GitHub has no API for it:** upload
the PNG by hand in *Settings → General → Social preview*.
