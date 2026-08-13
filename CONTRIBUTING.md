# Contributing

Thanks for wanting to help out. WebTerm is a security tool that runs code across fleets of servers, with the rights of whatever
user its agent was installed as —
so we hold a high bar for correctness and testing. Please also read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Structure

- `agent/ptyd.py` — the agent, single-file, **stdlib only** (Python 3.6+). It runs as the user that
  installed it (a dedicated `webterm` user by default) and never escalates.
  Ed25519-signed (see "Re-signing the agent").
- `gateway/app/` — async FastAPI gateway + SQLite (aiosqlite, WAL).
- `frontend/src/` — React + TypeScript + Vite + xterm.js.
- `tests/` — Python suite (unit + integration) plus `.mjs`/`.sh` end-to-end scripts.
- `docs/design/` — architecture notes (`ARCHITECTURE`, `SIGNED-UPDATES`, `SESSION-LIFECYCLE`,
  `TELNET-BASTION`, `FUTURE-DIRECTIONS`).
- `scripts/` — agent signing, backup/restore, e2e/smoke for CI.

## Build & run (dev)

```sh
# backend with reload + Vite frontend (proxied to :8000)
make dev          # or: uvicorn app.main:app --reload  (from gateway/, in .venv) + npm run dev (from frontend/)
```

Prod: `docker compose -f docker-compose.prod.yml up` (see README).

## Tests

Run the tests before opening a PR — one runner, the same one CI uses:

```sh
python3 -m venv .venv && .venv/bin/pip install \
  -r gateway/requirements.txt -r gateway/requirements-dev.txt   # once
make test         # hermetic suite: exactly what gates image publishing
make test-local   # + suites that need a real tmux/agent on this machine
```

The browser gates (smoke boot, session E2E, accessibility, FS API, port forwarding,
mobile audit) need Docker and Playwright rather than the venv:

```sh
scripts/ci-local.sh            # all of them, ~10 min
scripts/ci-local.sh e2e a11y   # or a subset, in CI order
```

Add new suites to `scripts/run-tests.sh` (the list lives there, once — it used to be
duplicated in the Makefile and in CI, and drifted).

**If your test starts the real agent**, take its environment from
`tests/tmux_sandbox.py` (`agent_env()` / `kill_server()`). Isolating `$HOME` is **not
enough**: tmux keys its socket by UID (`$TMUX_TMPDIR/tmux-<uid>/`), so a test lands on the
production agent's tmux server, adopts its sessions and kills them at teardown. That
happened on 2026-08-05; the helper also refuses to run when it detects a live agent.

**If your test creates system users** (`ssh`, `provision`): tear them down with
`loginctl disable-linger` → `terminate-user` → `pkill -9 -u` → `userdel -r`. `userdel`
refuses accounts with live processes and fails *silently* — one such account survived 21
days with 13 shells.

Frontend: `cd frontend && npm run build` (also runs `tsc --noEmit`).

**Environment gotcha for tests that call `ptyd.Agent(...)`:** on a machine with `tmux` + `/etc/machine-id`
(as on the CI runner), `Agent.__init__` writes `~/.webterm/tmux.conf`; the test must isolate `HOME`
and call `os.makedirs(ptyd.WEBTERM_DIR, exist_ok=True)` after import. See `tests/agent_reliability_test.py`.

## CI gates (what must pass)

The `.github/workflows/docker-publish.yml` workflow **blocks image publishing** if:

1. **The agent signature** does not match `agent/ptyd.py` (see below).
2. **The Python unit tests** (`unit-tests` job — 51 suites; `scripts/run-tests.sh` is the
   single source of truth for the list, and guards it in both directions) fail.
3. **Smoke boot** (headless Chromium) — the UI fails to start.
4. **Session E2E** (REAL agent) / **FS API** / **port forwarding** / **mobile audit** fail.
5. **Housekeeping gates** that are easy to trip without touching anything you meant to:
   `gitleaks` over the history, the README version badge and the image pins matching
   `GATEWAY_VERSION`, `requirements.txt` in sync with `requirements.lock`, `ruff --select F`,
   `npx eslint .`, and a bumped `AGENT_VERSION` whenever `agent/ptyd.py` changes.
6. **`pip-audit --strict`** over the shipped dependencies. This one can turn your PR red for
   something you did not touch: a CVE published in a dependency reddens every open PR until the
   pin is bumped. If that is what you are looking at, say so in the PR and we will bump it —
   it is not your bug.

Actions are pinned to their **full SHA** (supply chain). Do not add secrets to the repo — `.env`/`*.pem`/
`backups/` are in `.gitignore`; never commit keys or tokens.

## Re-signing the agent (REQUIRED for any change to `ptyd.py`)

Agents refuse unsigned updates. The signature in the repo (`agent/ptyd.py.sig`) must match the source,
otherwise CI fails. After you modify `agent/ptyd.py`:

```sh
scripts/sign-agent.py /path/to/private-key.pem      # rewrites agent/ptyd.py.sig
git add agent/ptyd.py agent/ptyd.py.sig
```

**Also bump `AGENT_VERSION`** (top of `ptyd.py`) in the same change. Without a bump, the gateway
compares versions as equal, pushes nothing, and the whole fleet silently keeps running the old
agent while the release claims otherwise. The signature gate does not catch this — a signature
covers the source, not the version — so CI has a separate gate for it.

**If you are contributing from a fork, you cannot re-sign, and you are not expected to.** The
private key is offline. Open the PR with `agent/ptyd.py` and `AGENT_VERSION` changed but the
signature untouched; the blocking signature check is skipped for pull requests **from a fork**,
which is where outside contributions come from, and a maintainer re-signs at merge. Note the
exact shape: a PR from a branch **inside this repository** still hits the blocking check, so a
collaborator with push access should work on a fork when touching `ptyd.py`, or expect to
re-sign before the PR can go green. Do **not** replace `UPDATE_PUBKEY` with your own key in a PR —
that would be correct for running your own fork, and wrong to merge here.

Deployers can generate or import **their own deployment key** from the UI (Settings → Security)
without touching the source; for your own fork, generate a key pair and substitute `UPDATE_PUBKEY`
locally — see the README's "Security" section.

## Style & PRs

- **Language.** Commits, CHANGELOG, docs and user-facing strings are in English. Code comments
  are currently a mix: much of the codebase is commented in Romanian, because that is how it was
  written. Nobody is going to rewrite those, and you should not either — but **write new comments
  in English**. Over time the mix resolves itself in the right direction, without a churn commit
  that would destroy the history behind every explanation.
- Write code that matches its surroundings (naming, comment density, idiom).
- Comments explain **why**, not **what** (constraints, pitfalls); they should not narrate the next line.
- One PR = one coherent change, with tests. Describe the impact and how you tested it.
- **Security** issues: NOT in a public PR/issue — see [SECURITY.md](SECURITY.md).
