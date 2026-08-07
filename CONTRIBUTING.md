# Contributing

Thanks for wanting to help out. WebTerm is a security tool that runs code as root across fleets of servers —
so we hold a high bar for correctness and testing. Please also read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Structure

- `agent/ptyd.py` — the agent, single-file, **stdlib only** (Python 3.6+), runs as root on every host.
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
make test         # hermetic suite: exactly what gates image publishing
make test-local   # + suites that need a real tmux/agent on this machine
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
2. **The Python unit tests** (`unit-tests` job, ~13 files + auth) fail.
3. **Smoke boot** (headless Chromium) — the UI fails to start.
4. **Session E2E** (REAL agent) / **FS API** / **port forwarding** / **mobile audit** fail.

Actions are pinned to their **full SHA** (supply chain). Do not add secrets to the repo — `.env`/`*.pem`/
`backups/` are in `.gitignore`; never commit keys or tokens.

## Re-signing the agent (REQUIRED for any change to `ptyd.py`)

Agents refuse unsigned updates. The signature in the repo (`agent/ptyd.py.sig`) must match the source,
otherwise CI fails. After you modify `agent/ptyd.py`:

```sh
scripts/sign-agent.py /path/to/private-key.pem      # rewrites agent/ptyd.py.sig
git add agent/ptyd.py agent/ptyd.py.sig
```

The private key does **NOT** live in the repo (it is offline / in the CI secrets). For your own fork, generate
your own key pair and replace `UPDATE_PUBKEY` in `ptyd.py` — see the README's "Security" section.
Deployers can generate or import **their own deployment key** from the UI (Settings → Security) without
touching the source.

## Style & PRs

- Write code that matches its surroundings (naming, comment density, idiom).
- Comments explain **why**, not **what** (constraints, pitfalls); they should not narrate the next line.
- One PR = one coherent change, with tests. Describe the impact and how you tested it.
- **Security** issues: NOT in a public PR/issue — see [SECURITY.md](SECURITY.md).
