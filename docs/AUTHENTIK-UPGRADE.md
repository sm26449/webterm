# Upgrading Authentik

How to upgrade the Authentik that WebTerm uses for SSO without losing users, passkeys or the OIDC
setup, and how to get back if it goes wrong. Rehearsed end to end on a disposable copy on
2026-10-13 (see [the rehearsal log](#appendix-b--rehearsal-log-2026-10-13)).

> **The reference production (checked 2026-10-13, read-only; `auth.example.com` below):** it runs **2026.8.2** as a
> *separate stack* in `/opt/authentik` (compose project `authentik`, containers
> `authentik-{server,worker,postgresql,redis}-1`, volumes `authentik_pg` and `authentik_redis`,
> `postgres:16-alpine`, `redis:7-alpine`), behind the WebTerm Traefik on `webterm_webterm`. It was
> reinstalled fresh on 2026-09-10; the old 2024.10.5 install is gone. The repo pins **2026.8.3**,
> so the production upgrade is **one patch step, 2026.8.2 → 2026.8.3**, about 35 seconds of SSO
> downtime. No Postgres upgrade is needed.

## 1. The rules

From the upstream [upgrade guide](https://docs.goauthentik.io/install-config/upgrade/):

- **Never skip a minor.** Go through each `YEAR.MONTH` release in order, on the latest patch of
  each one. For example, from 2025.2.1: latest 2025.2.x, then 2025.4.x, then 2025.6.x.
  Inside one minor you can jump straight to the latest patch.
- **There is no downgrade.** Once the new version has run its migrations, the only way back is to
  restore a database backup taken *before* the upgrade (see [§8](#8-rollback)).
- **Back up Postgres first**, every time.

The release sequence: 2024.10 → 2024.12 → 2025.2 → 2025.4 → 2025.6 → 2025.8 → 2025.10 →
2025.12 → 2026.2 → 2026.5 → 2026.8 (latest patch 2026.8.3, 2026-09-17). There is no newer release
as of 2026-10-13.

**Found in the rehearsal:** going from **2026.5.7 to 2026.8.2** fails. The server crash-loops with
`InconsistentMigrationHistory: Migration authentik_core.0064_user_… is applied before its
dependency …`. 2026.5.7 carries a backported migration that 2026.8.2 orders differently. 2026.8.3
fixes it ("core: fix migrations (version-2026.8)"), and 2026.5.7 → 2026.8.3 passed. So from any
2026.5.x, go **directly to 2026.8.3 or later**, never to 2026.8.0–2026.8.2. `authentik-upgrade.sh`
now refuses that jump with this message, so you can't walk into it by taking "the next minor".

## 2. Which install do you have?

| Shape | Where | How the Authentik tag is set | Upgrade with |
|---|---|---|---|
| **Separate stack** (production) | `/opt/authentik/docker-compose.yml` (a copy of `deploy/authentik/docker-compose.prod.yml`) | literal `image: ghcr.io/goauthentik/server:<tag>` | this runbook (`--dir /opt/authentik`) |
| **Bundled profile** (`--with-authentik`) | `/opt/webterm/docker-compose.prod.yml`, `COMPOSE_PROFILES=authentik` in `.env` | the pin in WebTerm's compose file | this runbook (`--dir /opt/webterm --file docker-compose.prod.yml`), **before** `./upgrade.sh` |
| Evaluation | `deploy/authentik/docker-compose.yml` | the pin | throw it away and recreate it |

**`./upgrade.sh` and the bundled profile.** `upgrade.sh` copies the new
`docker-compose.prod.yml` out of the new WebTerm image, then `deploy.sh` runs
`docker compose pull && up -d --remove-orphans`. With `COMPOSE_PROFILES=authentik`, that moves
Authentik **straight to whatever the new WebTerm release pins**, with no Authentik backup. That is
fine when the pin moves by one patch or one minor. It is unsafe when your Authentik is more than
one minor behind the new pin: Authentik either refuses to start or, worse, migrates halfway. In that
case:

1. Before `./upgrade.sh`, bring Authentik up to one minor below the new pin, one step at a time,
   with `sudo /opt/webterm/scripts/authentik-upgrade.sh --dir /opt/webterm --file docker-compose.prod.yml upgrade <tag>`.
2. Then run `./upgrade.sh`. It does the last step to the pin, so take a backup right before it
   (`… backup`).

The separate production stack in `/opt/authentik` is **not** touched by `upgrade.sh`, since it is
a different compose project. Its tag changes only when you change it.

## 3. Pre-checks (production)

All of these are read-only. Run them as root on the production host.

```bash
cd /opt/authentik
docker compose ps                                            # all 4 Up (healthy)
docker compose images                                        # server/worker = ghcr.io/goauthentik/server:2026.8.2
grep -n 'goauthentik/server' docker-compose.yml              # the same tag in the file (both lines)
docker compose exec -T postgresql psql -U authentik -d authentik -Atc 'show server_version'   # 16.x
docker compose exec -T postgresql psql -U authentik -d authentik -Atc \
  "select pg_size_pretty(pg_database_size('authentik'))"     # dump size order of magnitude
df -h /                                                      # ≥ 5 GB free (the new image is ~2 GB)
free -h                                                      # ≥ 1 GB available (server+worker ~1 GB)
systemctl status authentik-backup.timer --no-pager           # nightly backup is alive
ls -lt /var/backups/authentik | head -3                      # and recent
grep -c '^AUTHENTIK_BOOTSTRAP_TOKEN=.' .env                  # 1 = an API token exists for provision.py
```

Also check the OAuth2 provider before you re-run `provision.py` after the upgrade
([§7](#7-post-checks)). `provision.py` **overwrites** these fields, and a change of `sub_mode`
would change every user's `sub`. To see them: Authentik admin → Applications → Providers →
`webterm`. Expected values: Subject mode *Based on the User's hashed ID*, one redirect URI
`https://wt.example.com/api/oidc/callback` (Strict), signing key set.

Pick a quiet moment. During the downtime window, **new** SSO logins fail. Existing WebTerm
sessions keep working, and so does local break-glass login.

## 4. Backup

The helper script makes one backup directory per step and verifies it:

```bash
sudo /opt/webterm/scripts/authentik-upgrade.sh --dir /opt/authentik backup
```

Run the **root-owned copy** in the WebTerm install directory (`install.sh` and `upgrade.sh` put it
in `/opt/webterm/scripts/` from 3.6.8 on), never `sudo` a script in a checkout your own user can
write: whoever can edit that file would get root. Check it first:
`stat -c '%U %a %n' /opt/webterm /opt/webterm/scripts /opt/webterm/scripts/authentik-upgrade.sh`
must show `root` and no group/other write bit.

It writes `/var/backups/authentik-upgrade/authentik-<tag>-<timestamp>/` (directory `0700`, files
`0600`, root):

| File | What |
|---|---|
| `authentik.dump` | `pg_dump -Fc` of the `authentik` database (custom format, compressed) |
| `docker-compose.yml` | the compose file as it was, with the **old** tag. Rollback puts it back |
| `env` | `.env`: `AUTHENTIK_SECRET_KEY` is required to decrypt fields in the DB after a restore |
| `blueprints.tgz` | the `./blueprints` directory |
| `media.tgz` / `certs.tgz` | only if the server has `/media` or `/certs` mounted. Production mounts neither (only `./blueprints`); check with `docker compose config` if you added one |
| `meta`, `SHA256SUMS` | tag, Postgres major, user count, number of table-data entries; checksums |

Verification is built in. The script refuses to continue unless `pg_restore -l` can read the dump
and it contains the `authentik_core_user` data. To check by hand:

```bash
B=/var/backups/authentik-upgrade/authentik-2026.8.2-<ts>
(cd $B && sha256sum -c SHA256SUMS)
docker compose -f /opt/authentik/docker-compose.yml exec -T postgresql pg_restore -l < $B/authentik.dump | grep -c 'TABLE DATA'   # > 200
cat $B/meta
```

The same thing by hand, if you do not use the script:

```bash
cd /opt/authentik
B=/var/backups/authentik-upgrade/manual-$(date +%Y%m%d-%H%M%S); sudo install -d -m 700 $B
docker compose exec -T postgresql pg_dump -U authentik -d authentik -Fc > $B/authentik.dump
cp -p docker-compose.yml .env $B/ && tar -czf $B/blueprints.tgz blueprints
docker compose exec -T postgresql pg_restore -l < $B/authentik.dump | grep -q 'TABLE DATA public authentik_core_user ' && echo BACKUP OK
```

This backup is **not encrypted**, because it has to be usable in a hurry. It contains the signing
key and `.env`. After the rollback window (a week), delete it or encrypt it like
`deploy/authentik/backup.sh` does. The nightly encrypted backup (`backup.sh`, plain SQL) keeps
running and is a second, independent copy.

## 5. Upgrade production: 2026.8.2 → 2026.8.3

### With the helper script (recommended)

```bash
sudo /opt/webterm/scripts/authentik-upgrade.sh --dir /opt/authentik status
sudo /opt/webterm/scripts/authentik-upgrade.sh --dir /opt/authentik upgrade 2026.8.3
```

The script prints the plan and waits for you to type `yes`. Then it:

1. checks that the stack is healthy and that the running tag equals the file's tag, that the hop is
   allowed (patch in the same minor, or exactly the next minor), that Postgres is ≥ 14 and that
   there is enough disk;
2. takes and verifies the backup ([§4](#4-backup));
3. pulls the new image **while 2026.8.2 still serves** (about 1 min, no downtime);
4. changes `ghcr.io/goauthentik/server:2026.8.2` to `:2026.8.3` on the server and worker lines;
5. runs `docker compose up -d --no-deps server worker`. **Downtime starts here.** Postgres and
   Redis are not recreated;
6. waits until both containers are healthy and `/-/health/ready/` answers. **Downtime ends here.**
   It fails fast on a crash loop instead of waiting out the timeout;
7. checks that the app reports 2026.8.3, that there are 0 unapplied migrations
   (`ak showmigrations`), and that every OAuth2 application's discovery document answers;
8. prints the downtime and the exact rollback command.

It never touches Postgres, Redis, volumes or images, and never deletes anything.

### By hand (what the script does)

```bash
cd /opt/authentik
docker pull ghcr.io/goauthentik/server:2026.8.3                       # no downtime
cp -p docker-compose.yml docker-compose.yml.2026.8.2
sed -i 's|ghcr.io/goauthentik/server:2026.8.2|ghcr.io/goauthentik/server:2026.8.3|' docker-compose.yml
grep -n 'goauthentik/server' docker-compose.yml                       # both lines say 2026.8.3
docker compose up -d --no-deps server worker                          # downtime starts
watch -n2 docker compose ps                                           # until both are (healthy), ~35 s
docker compose exec -T server python -c 'import authentik; print(authentik.VERSION)'      # 2026.8.3
docker compose exec -T worker ak showmigrations --plan | grep -c '^\[ \]'                 # 0
curl -fsS https://auth.example.com/application/o/webterm/.well-known/openid-configuration | head -c 200
```

Migrations run automatically when the new containers start, so there is no separate migrate
command. If a container restarts in a loop, read `docker compose logs --tail 100 server` and go to
[§8](#8-rollback).

## 6. Postgres major upgrades

**Not needed now.** Production runs Postgres 16, the same major as the official Authentik compose
file today (`postgres:16-alpine`, checked 2026-10-13). Leave Postgres alone during an Authentik
upgrade. Two moving parts at once make a failure impossible to attribute.

When one is due (Postgres 16 is supported upstream until November 2028), do it as a separate
change, on a working Authentik:

```bash
cd /opt/authentik
sudo /opt/webterm/scripts/authentik-upgrade.sh --dir /opt/authentik backup   # B=… (the printed path)
docker compose stop server worker                                     # downtime starts
docker compose exec -T postgresql pg_dump -U authentik -d authentik -Fc > /root/ak-pgmajor.dump
docker compose stop postgresql
# 1. image: postgres:16-alpine → postgres:17-alpine in docker-compose.yml
# 2. a NEW volume: rename `pg:` to `pg17:` in both places (the old authentik_pg stays as the rollback)
docker compose up -d postgresql && sleep 10                           # initdb on the empty volume
docker compose exec -T postgresql pg_restore -U authentik -d authentik --no-owner --role=authentik --exit-on-error < /root/ak-pgmajor.dump
docker compose up -d server worker                                    # downtime ends when healthy
```

Rollback: put the old image and the old volume name back, then `docker compose up -d`.

## 7. Post-checks

1. **Health:** `docker compose ps` shows 4 containers (healthy) and the discovery URL from §5
   answers.
2. **WebTerm SSO login:** in a private window, open `https://wt.example.com`, click
   **Sign in with Authentik**, log in as a normal (non-akadmin) user and land in WebTerm.
3. **The groups claim:** WebTerm logs `SSO roles synced for <email>: …` for that login
   (`docker logs webterm-app-1 2>&1 | grep 'SSO roles'`). Settings → Users & roles → Your access
   shows the role that comes from the group. If the log says `the id_token for … has no groups
   claim`, the profile scope mapping is broken: roll back. (WebTerm asks for `openid email profile`.
   In Authentik the `groups` claim comes from the default **profile** mapping. The rehearsal
   checked that it still does on 2026.8.3.)
4. **A user outside every `wt-*` group is refused** by Authentik with "Permission denied", which
   shows that the application's policy binding still holds.
5. **Re-run `provision.py` in 3.6.5 mode** (five groups and the `wt-groups` policy). This also
   migrates production away from the pre-3.6.5 direct `wt-access` binding if it still has it:

   Root reads the token (only root can read `/opt/authentik/.env`), and it runs the
   **root-owned** copy of `provision.py` in the install directory (`upgrade.sh` refreshes it) with
   `python3 -I` from `/`: no `PYTHON*` variables, no user site-packages, and no module picked up
   from the current directory. Never run `provision.py` as root from a checkout your user can
   write. Check the copy first:
   `stat -c '%U %a %n' /opt/webterm/deploy/authentik /opt/webterm/deploy/authentik/provision.py`
   must show `root` and no group/other write bit.

   ```bash
   sudo sh -c 'cd / && AUTHENTIK_DOMAIN=auth.example.com WEBTERM_DOMAIN=wt.example.com \
     AUTHENTIK_API_TOKEN=$(sed -n "s/^AUTHENTIK_BOOTSTRAP_TOKEN=//p" /opt/authentik/.env) \
     exec python3 -I /opt/webterm/deploy/authentik/provision.py'
   ```

   Expected: `grup wt-access: există`, four groups created, `provider webterm: actualizat`,
   `aplicaţia webterm: actualizată`, `politica wt-groups: creată`,
   `binding wt-groups → app: creat`, `binding direct wt-access → app: scos`. The client ID and
   secret do **not** change. Copy `WEBTERM_OIDC_ALLOWED_GROUPS` and `WEBTERM_OIDC_ROLE_MAP` into
   `/opt/webterm/.env` if they are not there yet, then `docker compose -f docker-compose.prod.yml
   up -d app`. Re-run steps 2–4.

   With a `provision.py` older than this branch, the line `aplicaţia webterm: 400 … slug already
   exists` appears. It is harmless: the app list endpoint hid the policy-gated app from akadmin.
   It is fixed here with `superuser_full_list=true`.
6. **Keep the old image for the rollback window.** `docker image ls ghcr.io/goauthentik/server`
   still lists 2026.8.2. The daily cleanup cron prunes unused images after 14 days. If it is gone,
   it can be pulled again from ghcr (public).

## 8. Rollback

**Changing the tag back is not a rollback.** Migrations are one-way: once 2026.8.3 (or any newer
version) has started, the database schema belongs to it, and older code on a newer schema is
undefined. Upstream does not support it. In the rehearsal, 2026.8.3 → 2026.8.2 by tag alone
happened to start, because this patch adds no schema migration for a fresh 2026.8.2 database.
Across a minor it will not, and you cannot tell in advance. The supported way back is to restore
the dump taken before the step, into the old version:

```bash
sudo /opt/webterm/scripts/authentik-upgrade.sh --dir /opt/authentik restore /var/backups/authentik-upgrade/authentik-2026.8.2-<ts>
```

It checks the checksums, asks for `yes`, stops server and worker, runs `DROP DATABASE authentik
WITH (FORCE)` and `CREATE DATABASE`, then `pg_restore --exit-on-error`. It puts back the compose
file with the old tag, starts server and worker, and waits for healthy and the discovery
documents. Anything changed in Authentik after the backup is lost: new users, new passkeys,
password changes. Rehearsed: 41 s until healthy, 28 s of observed outage.

**The backup directory is root input** (audit 2026-10-17, OP-03): whatever compose file it holds is
what root will `docker compose up`. So, before it stops anything, `restore` refuses — with a
`refusing:` line naming the path — a directory that is not under the backup root
(`/var/backups/authentik-upgrade`, or the same `--backup-dir` the backup was made with; real
paths, so a symlink or `..` into somewhere else does not help), one that is not owned by root or is
group/world-writable, and one whose `authentik.dump`, `meta`, `SHA256SUMS` or compose file is not
root's. A backup the script made itself passes (directory `0700`, files `0600` — the compose copy keeps its `0644` —, root). Never
`restore` from a directory someone sent you or from `/tmp`: copy it into the backup root as root,
check `stat -c '%U %a %n' <dir> <dir>/*`, and only then. `SHA256SUMS` sits in the same directory,
so it proves the backup is self-consistent, not that it is yours. The compose file goes back as
`root:root 0644` whatever the copy in the backup says (`cp -p` used to carry the backup file's
owner onto the live file, which the next run would then refuse). If the live compose file is a
symlink (`docker-compose.yml -> compose.yml`), `upgrade` and `restore` both write through it: the
link stays, the target gets the tag.

`--backup-dir` itself is checked **before** anything is created or `chmod`ed there: it must be a
plain path — no symlink, `.` or `..` anywhere in it (`refusing: --backup-dir must be a plain path
… -> <what it resolves to>`; type the resolved path instead) — and, as with the compose directory,
it and every parent up to `/` must be root's and not group/world-writable. Only a directory the
run creates itself gets `chmod 700`; a pre-existing one has already passed that test. (Before,
`chmod 700` followed a planted symlink to its target first and the check then looked at the
resolved, root-owned path — the user-owned link was never seen.)

It also checks the Postgres major **before** stopping anything: `DROP DATABASE … WITH (FORCE)`
exists from Postgres 13 (OP-10), so on an older server it says so and leaves the stack running
(see [§6](#6-postgres-major-upgrades)). The version is read from the `postgres` maintenance
database, not from `authentik`, so a re-run still works when the `authentik` database does not
exist; if Postgres does not answer at all the message is `cannot read the Postgres version … is it
running?` (nothing stopped), not a version complaint. If the `DROP`/`CREATE` step fails after the
stop (the database is still intact at that point: the dump has not been loaded), it starts server
and worker again on the current tag and tells you to fix the cause and re-run `restore`.

These `restore` guards are exercised by `tests/host_health_script_test.py` against a fake `docker`;
the block needs root (CI runs the suite as the runner user and prints `skipped: not root`), so
after touching the script run `sudo .venv/bin/python tests/host_health_script_test.py` yourself.

By hand (as root; the compose file goes back without preserving the backup file's ownership):

```bash
cd /opt/authentik; B=/var/backups/authentik-upgrade/authentik-2026.8.2-<ts>
docker compose stop server worker
docker compose exec -T postgresql psql -U authentik -d postgres -c 'DROP DATABASE authentik WITH (FORCE)' -c 'CREATE DATABASE authentik OWNER authentik'
docker compose exec -T postgresql pg_restore -U authentik -d authentik --no-owner --role=authentik --exit-on-error < $B/authentik.dump
cp --no-preserve=all $B/docker-compose.yml docker-compose.yml && chown root:root docker-compose.yml && chmod 0644 docker-compose.yml   # old tag; root:root, through the link if it is one
docker compose up -d --no-deps server worker
```

## 9. Time, downtime, risks

| | Rehearsed (3 MB DB, this host) | Production estimate |
|---|---|---|
| Backup + verify | ~2 s | seconds (the prod DB is small; check with §3) |
| Pull 2026.8.3 | ~60 s, **no downtime** | same |
| `up` → healthy + ready (2026.8.2 → 2026.8.3) | 35 s and 34 s (two runs) | **~30–45 s** |
| Observed SSO outage (discovery non-200, 1 s probe) | 22 s | **~20–30 s** |
| Post-checks incl. a real login + provision.py | — | ~5 min |
| Rollback (restore + old tag) | 41 s (28 s outage) | ~1 min |
| **Total, start to finish** | ~1 min scripted | **~10 min with checks; < 1 min SSO downtime** |

Risks, in order:

- **A failed migration or crash loop on start.** It did happen on 2026.5.7 → 2026.8.2 (§1), but
  not on 2026.8.2 → 2026.8.3 (rehearsed twice). Mitigation: a verified backup, the script's
  crash-loop detection, and the restore path above.
- **`provision.py` overwriting a hand-made provider change** (sub mode, extra redirect URIs).
  Check §3 first. The upgrade itself does not change `sub`: the same user had the same
  `hashed_user_id` sub before and after, in both rehearsal paths.
- **Disk:** +~2 GB for the new image. There is 28 GB free today.
- **Forwarded headers (2026.8 change):** since 2026.8, Authentik trusts `X-Forwarded-*` only from
  `AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS`. Production is already on 2026.8.2 behind Traefik and
  works, so a patch does not change this. Keep it in mind for future minors.
- **`email_verified` is `false`** in the default email mapping since 2025.10. WebTerm adopts a
  local account by email only when `email_verified` is true, so SSO users are created or linked by
  `sub`. This is not new and not changed by the upgrade.

## 10. Optional: drop Redis

Authentik has not used Redis since **2025.10** (caching, tasks, WebSockets and the embedded
outpost all moved to Postgres). Production still runs `authentik-redis-1` and sets
`AUTHENTIK_REDIS__HOST`. That is harmless but dead weight. As a separate change, after the
upgrade:

```bash
cd /opt/authentik && cp -p docker-compose.yml docker-compose.yml.with-redis
# delete: the `AUTHENTIK_REDIS__HOST: redis` line, the whole `redis:` service,
#         both `redis: {condition: service_healthy}` lines, and `redis:` under `volumes:`
docker compose config -q && docker compose up -d --remove-orphans   # recreates server+worker (~35 s, 21 s outage in rehearsal)
docker volume rm authentik_redis                                    # once happy
```

The same cleanup applies to `deploy/authentik/docker-compose*.yml` and the `authentik` profile in
`docker-compose.prod.yml` in this repo. That change is not made here.

## 11. Future minor upgrades (2026.8 → next)

1. Read the release notes of the next minor (`https://docs.goauthentik.io/releases/<minor>/`) for
   breaking changes in OAuth2 providers, property mappings, expression policies, blueprints,
   forwarded headers and the compose file.
2. Rehearse on a disposable copy, the way this runbook was rehearsed: same Postgres major,
   `provision.py`, one user in a `wt-*` group and one in none, the upgrade, then the checks in
   §7.
3. `scripts/authentik-upgrade.sh` knows minors up to 2026.8. For a newer minor, update
   `KNOWN_MINORS` in the script. Or, after you have checked that it really is the *next* release,
   pass `--unlisted-minor` (it still refuses a version older than the running one).
   `authentik-upgrade.sh check-hop <from> <to>` answers whether a hop is allowed, without Docker.
4. Bump the pin in `docker-compose.prod.yml` and `deploy/authentik/*.yml` in the same WebTerm
   release, and note it in the CHANGELOG. Bundled-profile installs follow it through
   `./upgrade.sh` (§2).

## Appendix A — the legacy path from 2024.10 (not rehearsed)

Production left this path on 2026-09-10 by reinstalling. For another install still on 2024.10.x,
the supported path is **10 hops**: 2024.12 → 2025.2 → 2025.4 → 2025.6 → 2025.8 → 2025.10 →
2025.12 → 2026.2 → 2026.5 → **2026.8.3** (not 2026.8.0–2: see §1). Use the latest patch of each
minor and the script once per hop (`upgrade <tag>`, the same commands as §5). Notable changes on
the way:

- **2024.12:** `USE_PGBOUNCER` / `USE_PGPOOL` removed in favour of `CONN_MAX_AGE` and related
  options.
- **2025.8:** tasks move from Redis/Celery to Postgres. The worker changes, and the hop takes longer.
- **2025.10:** Redis is no longer used; remove `AUTHENTIK_REDIS__*` and the service, then
  `up -d --remove-orphans` (§10). The default `email_verified` claim becomes `false`. There are
  about 50% more Postgres connections.
- **2026.8:** forwarded headers are trusted only from `AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS`. The
  explicit-consent default flow is gone (`provision.py` picks implicit-consent). OAuth2 providers
  need `grant_types` set explicitly (`provision.py` sets them). The server entrypoint is
  rewritten in Rust.

At 10 hops of about 1–2 min of downtime each, plus a backup and checks between them, plan half a
day. For a small install like ours, the faster and better-tested alternative was a **fresh
install** of the current pin plus `provision.py`. It loses Authentik users and passkeys, so
recreate them and add them to their `wt-*` group. Every `sub` changes with a new install, so after
each person's first SSO login, check in WebTerm (Settings → Users & roles) that it landed on their
existing account, not on a new one.

## Appendix B — rehearsal log (2026-10-13)

The rehearsal was a disposable copy of `/opt/authentik/docker-compose.yml`: compose project
`akupg`, `127.0.0.1:19000` only, the same `postgres:16-alpine`, `redis:7-alpine` and
`AUTHENTIK_WEB__WORKERS=2`, with memory and CPU limits. Production was never touched. The checks
after each step were:

- the discovery document;
- version and 0 unapplied migrations;
- that the provider, application, groups, `wt-groups` policy and its binding exist;
- a headless authorization-code login through the flow executor as a user in a `wt-*` group,
  with WebTerm's scopes: the `groups` claim present, `iss` correct, `sub` unchanged;
- a user in no group refused ("Permission denied").

1. **2026.5.7** fresh install, seeded with `provision.py` (3.6.5 mode) plus `dbuser` (in `wt-db`)
   and `nogroup`. All checks passed.
2. **→ 2026.8.2: failed.** `InconsistentMigrationHistory` crash loop (§1). The script detected it
   and printed the rollback.
3. **`restore`** → back on 2026.5.7 in 28 s. All checks passed, data intact.
4. **→ 2026.8.3** (from 2026.5.7): 64 s to healthy, 50 s observed outage. All checks passed.
5. A fresh **2026.8.2**, seeded like production: the pre-3.6.5 provisioner (`wt-access` and a
   direct binding, a `groups` mapping on `ak_groups.all()`). All checks passed.
6. **→ 2026.8.3** (the production step): 35 s to healthy, 22 s observed outage. All checks
   passed; `sub` was identical before and after.
7. **`provision.py` (3.6.5 mode)** re-run: the five groups, the policy, and the direct binding
   removed. A `wt-db`-only user got in with `groups=['wt-db']`. Found and fixed the
   `slug already exists` 400 (§7.5).
8. **A real browser login** via WebTerm v3.6.6 (throwaway container) → Authentik 2026.8.3 → back,
   as `dbuser`. WebTerm granted *Operator @ tag:db* from the `wt-db` group.
9. **`restore`** 2026.8.3 → 2026.8.2: 41 s (28 s outage). All checks passed.
10. Upgraded again, then **tag-only revert** 8.3 → 8.2: it started (see §8 for why this proves
    nothing).
11. **Removed Redis** on 2026.8.3: 35 s (21 s outage). All checks passed.

Everything was removed afterwards (containers, volumes, networks, the pulled 2026.5.7 and
2026.8.3 images).
