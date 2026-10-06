# Toolbox — database connections, command library & history

The **Toolbox** is a per-host side panel, reached from a host's page or from the
toolbar inside a session. It has four tabs:

- **Connections** — saved launchers for the database CLIs on the host.
- **SSH keys** — host-to-host deploy keys; covered in [SSH-KEYS](SSH-KEYS.md).
- **Library** — built-in command recipes you copy and paste.
- **History** — the host's own command history, searchable.

Connections is the tab with a security model worth understanding here; Library and
History are conveniences and are covered briefly at the end.

## Connections — one click to a database CLI

A connection is a small saved record — engine, host, port, user, database, and a
credential policy. Clicking it opens a normal session that runs the matching
client on the host, already pointed at the target:

| Engine | Client run on the host |
|---|---|
| PostgreSQL | `psql -h … -p … -U … -d …` |
| MySQL / MariaDB | `mysql -h … -P … -u … -p …` |
| MongoDB | `mongosh "mongodb://…"` |
| ClickHouse | `clickhouse-client --host … --port … --user … --database …` |
| Redis | `redis-cli -h … -p … -n …` |

The client runs **on the host, through the agent** — the same path as any other
session. WebTerm does not connect to your database itself and there is no extra
port or daemon exposed. If the client isn't installed, the session prints a clear
"not installed" message instead of failing cryptically.

Every field is validated (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` for host/user/db,
a port in range) and every argument is shell-quoted, so a label or hostname can
never break out of the command that's built.

## Two credential policies

### Ask (default) — WebTerm stores nothing

The client prompts for the password when it opens, exactly as it would on the
command line. Nothing is stored, nothing is transmitted. This is the right choice
for most connections.

### Stored — encrypted, and never on the wire in the clear

For a database you open constantly, you can store the password. It is kept in the
**same encrypted vault as your SSH credentials** (Fernet — AES-128-CBC + HMAC-SHA256 — unlocked by
the server key). It is **never returned by the API** — editing a stored connection
shows a blank password field; leaving it blank keeps the existing secret.

When you launch a stored connection, the agent does the one thing that keeps the
password out of every place it could leak:

- it **types the password once into the client's own password prompt** on the PTY
  (matching `Password:` / `password for`), then forgets it;
- so the password **never appears** in `argv`, in `ps`, in an environment
  variable, in a file, or in the session transcript.

A short deadline arms the injection only around the initial prompt, and a stored
connection **does not** fall back to an interactive shell if the client is
missing — the session ends instead, so an armed password can never be typed into
a shell you're using. Redis has no password prompt, so it is not offered a stored
policy; it stays on *ask*.

> Storing a database password is a real trade-off: convenience against a secret at
> rest. It is opt-in per connection, and the safeguards above exist so that
> "stored" means "in the vault and on the PTY prompt," never "in a log."

## Step-up on 2FA hosts

A saved connection is a credentialed hole into the host, so on a host marked
**require 2FA** it is gated exactly like a port-forward:

- **Launching** a connection requires a step-up factor (the stored password is
  only decrypted *after* the check passes).
- **Creating, editing or deleting** a connection also requires step-up — otherwise
  a stolen session cookie could re-target a stored connection at an attacker's
  server and harvest the password at the next launch.

On hosts without 2FA these actions behave as normal authenticated requests.

## Lifecycle

- Switching a connection back to *ask* (or deleting it) wipes the stored secret.
- Deleting or uninstalling a host removes its connections too, so a reused host id
  can never inherit another host's stored credentials.

## Library — command recipes, copy & paste

A built-in set of common commands grouped by tool (git, docker, systemd, system,
db) with `{placeholder}`s. Click one to copy it; paste it into any terminal. The
Library works from the host page with no session open — it's a memory aid, it runs
nothing on its own.

## History — the host's commands, searchable

The host's command history, captured through [OSC 133 shell
integration](SHELL-INTEGRATION.md): each entry with its exit state, searchable,
click to copy. It is gated behind step-up on 2FA hosts, like the rest of the
history API.
