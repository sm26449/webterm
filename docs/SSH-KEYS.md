# SSH keys — host-to-host deploy keys (Toolbox → SSH keys)

Let one fleet host (`dev`) `ssh` into other fleet hosts (`prod`, `staging`) with a key that
WebTerm creates, deploys, inventories and revokes — without copying private keys around and
without giving the gateway one. Shipped in 3.0.0; everything goes through the existing agent
`run` / `fs_read` ops, so the agent is unchanged.

The model in one sentence: **the private key is generated on the source host and never leaves
it**; WebTerm stores only the public key, its fingerprint and the **deployment graph** (which
targets carry it, with which options), so access is visible and revocable per edge.

## Where it is

On a session of an **agent** host: the toolbar's **Toolbox** button → **SSH keys** tab. The same
panel is embedded in the host page under **Databases** (the Toolbox tabs are Connections ·
SSH keys · Library · History). Both source and target must be agent hosts; an SSH-direct host
is refused with *"deploy keys work on agent hosts only"*.

## Usage flow

1. **Generate key on this host.** Runs on the source, as the agent user:
   `ssh-keygen -q -t ed25519 -N '' -C webterm-deploy -f ~/.ssh/webterm_ed25519` (under
   `umask 077`). An existing `~/.ssh/webterm_ed25519` is **adopted**, not overwritten. The
   gateway then reads back only the `.pub` file (`fs_read`), validates it strictly (an
   `ssh-ed25519` line, decodable blob, nothing else — a compromised source cannot smuggle extra
   `authorized_keys` lines onto targets) and computes the `SHA256:` fingerprint itself. One key
   per source host. If `ssh-keygen` is missing: *"ssh-keygen failed on the host — is
   openssh-client installed?"*
2. **Deploy to** one or more targets (checkbox list of the other agent hosts; offline ones are
   disabled). Options per deployment:
   - **from=** an IP or CIDR list (digits, hex, `:` `.` `,` `/` only — no hostnames);
   - **Restriction:** *Full shell (unrestricted)* · *Locked down* (`restrict`: no pty, no
     forwarding, no agent, no X11) · *Run only one command* (`restrict,command="…"` — one
     printable line, up to 300 characters, escaped for the `authorized_keys` quoting).
   Deploying asks for a **fresh factor** — a passkey/TOTP step-up no older than 120 s, or the
   account password — **even on hosts without `require_2fa`**: granting durable SSH access
   outlives any WebTerm session, so a stolen cookie alone must not be enough. Automation tokens
   are refused here outright. One fresh factor authorizes a whole **multi-target** deploy
   (up to 64 targets per call) and the result is reported **per target** — one failure does not
   stop the others. Each successful deployment also sends an email/webhook alert
   (`SSH deploy key DEPLOYED: source → target`) if alerts are configured.
3. On the target, the public key is appended to the **agent user's** `~/.ssh/authorized_keys`
   (`~/.ssh` 700, file 600), **idempotently**: the exact line already present → nothing; the
   same key with different options → the old line is replaced; so there is one line per key
   even across option changes.
4. **Deployed on** lists every edge with its status and three actions:
   - **Test** — on the source, `ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new
     -o ConnectTimeout=8 -o PasswordAuthentication=no -i ~/.ssh/webterm_ed25519 <user@hostname> true`
     (port 22; the target must have reported a hostname). Reports *Connection OK* / *failed*
     with the ssh output. Two things it does touch: the source's `known_hosts` on first contact
     (`accept-new`), and — if the edge carries a forced command — that command runs instead of `true`.
   - **Verify** — reconciles reality on the target: `deployed` (exact line present),
     `edited on target` (same key, line changed by hand), `missing on target`.
   - **Alias** — writes an idempotent block into the **source's** `~/.ssh/config`
     (`Host <target-name>` / `HostName` / `User` / `IdentityFile ~/.ssh/webterm_ed25519`, between
     `# >>> webterm <alias> >>>` markers, old block replaced), so `ssh <name>` works without `-i`.
     Nothing removes the block later; delete it by hand if you retire the key.
   - **Revoke** — removes every `authorized_keys` line containing the key **blob**, so a line you
     edited by hand on the target still goes, and foreign keys are untouched. A revoke whose
     result cannot be confirmed is reported as such (*"the key may still be live on the target"*).
5. **Rotate** — guided, in an order that never leaves the source without access: a fresh keypair
   is generated **next to** the current one (`~/.ssh/webterm_ed25519.new`), the new public key is
   deployed to every active edge **with that edge's stored options**, and only then does the
   source switch to the new private key and the record to the new fingerprint; last, the old
   key's lines are removed from the targets where the new one landed. A target that is offline or
   fails does not stop the rotation: it is marked `missing`, keeps its old line (which the source
   can no longer use), and is listed in the response (`left_with_old_key`) and in the panel's
   per-target results, with *Retry the failed targets* once it is back. Edges already marked
   `missing`, and edges whose target host was removed from the fleet, are skipped.
6. **Delete the key** removes the key files from the source and the record — refused while
   active deployments exist (revoke them first). Deleting does not touch any target.

**Keys deployed on this host** at the bottom of the tab shows the inbound side: which sources
can reach this host, by fingerprint.

## Guardrails

- **Anti-pivot.** A host that is both a source and a target becomes a pivot — compromising one
  host reaches the next. Generating a key on a host that is already a deploy target, or
  deploying onto a host that holds its own active key, warns (*"this creates an access CHAIN
  … Continue anyway?"*) and proceeds only on confirmation. A host never deploys its own key to
  itself.
- **The private key is passphrase-less** by design (it is used non-interactively). The tab says
  so up front: every process on the source host — including any AI agent you run there — has
  SSH access to the targets. Keep private keys only on source hosts; never deploy *toward* a host
  that holds one.
- **Sudo on the target.** You log in as the agent user, which has no sudo by default. The tab
  offers a copyable, narrow sudoers snippet (`docker` + `systemctl` only) for the common case.
- **Removed targets.** If a target host is deleted from the fleet while a key is deployed there,
  the edge stays listed as *"host removed from the fleet — the key is still authorized on that
  machine"*: WebTerm can no longer revoke it for you; do it on the machine.
- Every action is in the audit log (`deploy-key generated/… -> …/revoke/rotated/deleted/ssh-config alias`).
- No endpoint ever returns the private key. (The generic file browser on the source host can
  still read `~/.ssh/webterm_ed25519` like any other file of the agent user — the usual
  "anyone past login has the agent user's access" premise of the threat model.)

## Deploy-key policy (Settings → Infrastructure & tokens)

Optional hardening, **off by default**, two switches saved on change:

- **Require 2FA on source hosts** — *"A host that holds a deploy key can reach its targets — the
  crown jewel."* When on, **Generate** is refused on a host until that host has 2FA enabled
  (*"policy requires 2FA on deploy-key sources — enable 2FA on this host first"*). It is checked
  at generate time; existing keys are not affected.
- **Require restricted keys** — refuse full-shell deploy keys: every deployment must carry
  `restrict` and/or a forced command (*"policy requires a restriction on deploy keys — pick
  'locked down' or a forced command"*). Enforced on every deploy (per target in a multi-target
  deploy); Rotate re-deploys each edge with the options it already had.

Neither switch writes options for you: with the policy on, you still pick the restriction in the
deploy form — the policy only refuses the unrestricted choice.

## Not the same thing

- **Add host → SSH → "generate a key"** creates a credential the *gateway* uses to log in to an
  SSH-direct host (private key encrypted in the vault). Deploy keys are host→host and the gateway
  never holds them.
- Reaching LAN gear *through* an agent (no key on the target) is the SSH-jump host type:
  [SSH-JUMP.md](SSH-JUMP.md).

## Maintenance notes

- Backend: `gateway/app/api.py` (`/api/hosts/{id}/deploy-key/*`, `/api/settings/deploy-key-policy`),
  tables `ssh_keys` and `ssh_key_deployments`; tests in `tests/ssh_keys_test.py` (the rotate
  case runs only where `ssh-keygen` is installed).
- Only ed25519 keys are generated and accepted; the path `~/.ssh/webterm_ed25519` is fixed.
- Two deploy routes: the UI uses `POST /api/hosts/{source}/deploy-key/deploy-batch` (routed by
  the SOURCE, one fresh factor for all targets). `POST /api/hosts/{target}/deploy-key/deploy`
  (routed by the TARGET, factor bound to it) is the single-target compatibility route for API
  clients; both go through `_dk_deploy_one`, and `ssh_keys_test.py` exercises the deploy logic
  through it. Keep them in step.
