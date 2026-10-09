# WebTerm documentation

Start with the [main README](../README.md) for install and overview. This folder
holds the user-facing guides and the internal architecture notes.

## Guides

- [INSTALL](INSTALL.md) — every install route, the image deploy, single sign-on, putting agents on hosts, Makefile shortcuts, backups
- [CONFIGURATION](CONFIGURATION.md) — every environment variable (gateway, agent side, backup script)
- [FEATURES](FEATURES.md) — the full feature list, the reasoning behind the design, what persistence covers
- [SECURITY-FEATURES](SECURITY-FEATURES.md) — every security control in detail: devices, step-up, tokens, audit, signed agent updates
- [DEVELOPMENT](DEVELOPMENT.md) — building from source, the test suites, the repository layout, the CI release gates
- [RUNBOOK](RUNBOOK.md) — operations and recovery procedures
- [HOSTS](HOSTS.md) — connection types, tags, 2FA step-up, credential policies, install links, Wake-on-LAN, the OS-updates badge
- [AUTOMATION-TOKENS](AUTOMATION-TOKENS.md) — API tokens for cron/CI/monitoring: scopes, curl examples, what they can never do
- [ALERTS](ALERTS.md) — email and webhook alerts: every event, resource thresholds, muting
- [GUARDRAIL](GUARDRAIL.md) — confirm/block rules for dangerous commands, and where they apply
- [AI-TOOLS](AI-TOOLS.md) — managing Claude Code subagents, skills and CLAUDE.md on a host
- [SHORTCUTS](SHORTCUTS.md) — keyboard shortcuts
- [SHELL-INTEGRATION](SHELL-INTEGRATION.md) — OSC 133 "commands as objects" setup
- [PORT-FORWARDING](PORT-FORWARDING.md) — exposing host services through the browser
- [TRANSFERS](TRANSFERS.md) — uploads and downloads: the floating Transfers widget, resume semantics, drop on the terminal (session cwd), paste an image → inbox + path typed at the prompt (for Claude Code, aider, …), inbox convention and retention
- [DATABASE-TOOLBOX](DATABASE-TOOLBOX.md) — database connection launchers, stored-credential model, command library & history
- [FLEET](FLEET.md) — Run on hosts (one command on several hosts), saved commands, bulk enrollment, command history
- [SERIAL-CONSOLE](SERIAL-CONSOLE.md) — serial devices (RS232/RS485/USB) through the agent
- [SSH-KEYS](SSH-KEYS.md) — Toolbox → SSH keys: host-to-host deploy keys, multi-target deploy, test/verify/alias/rotate, the deploy-key policy
- [SSH-JUMP](SSH-JUMP.md) — SSH-jump and Telnet-jump targets reached through an agent, nesting under the agent, "Connect once", the host-key-change alarm
- [ROLES](ROLES.md) — roles and scoped access (Owner / Admin / Operator / Viewer over all hosts, a folder, a tag or one host): what they enforce and what they cannot
- [SSO](SSO.md) — OIDC single sign-on (Authentik), step-up and break-glass
- [SECURITY-SUMMARY](SECURITY-SUMMARY.md) — the Dashboard's Security card (what each check means) and the share-links inventory with Revoke all
- [THREAT-MODEL](THREAT-MODEL.md) — what the security model defends, and what it does not

## Architecture notes (`design/`)

Why the system is shaped the way it is. Written for someone about to change it.

- [ARCHITECTURE](design/ARCHITECTURE.md) — the three parts, the trust boundaries, what roles enforce and what they cannot
- [ROLES-AND-SSH](design/ROLES-AND-SSH.md) — the roles design (3.6.x) with the route-by-route permission matrix, and the native SSH entry proposal (3.7.x)
- [SIGNED-UPDATES](design/SIGNED-UPDATES.md) — how agent updates are signed, and how to rotate the key without touching a host
- [SESSION-LIFECYCLE](design/SESSION-LIFECYCLE.md) — session states, reconciliation, transcripts, and why the screen is not the source of truth
- [SPLIT-VIEWS](design/SPLIT-VIEWS.md) — named multi-pane layouts, the "only the active view is mounted" invariant, and why the same session can appear in many places safely
- [TELNET-BASTION](design/TELNET-BASTION.md) — reaching network equipment through a host
- [DESIGN-SYSTEM](design/DESIGN-SYSTEM.md) — UI tokens (type scale, radii, semantic colours), the shared components, icon and size rules, the themes, and the guard that enforces them
- [FUTURE-DIRECTIONS](design/FUTURE-DIRECTIONS.md) — sketches that are deliberately not built

