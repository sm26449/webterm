# Future directions

**Status: not started.** These are sketches, not commitments. They are written down so the
reasoning is not lost, and so that anyone proposing them knows what was already considered.

Nothing here touches WebTerm as it exists. Each would be an external, opt-in layer, built only if
a concrete need appears.

## Multi-user through isolation, not roles

WebTerm has accounts, but they are all equal, and `docs/THREAT-MODEL.md` says so plainly. The
reason is that role-based access control inside a terminal is close to meaningless: a "read-only"
user with a shell can read every file the process can, including private keys. Restricting the UI
would be theatre.

If several people genuinely need separated access, the separation has to be below WebTerm:

- one agent per Unix user on the host, each running as that user, so the operating system enforces
  the boundary that WebTerm cannot;
- or one WebTerm instance per team, which is cheap — a container and a volume.

Either is honest. Adding a `role` column would not be.

## SSH certificate authority

Today an SSH host stores a credential in the vault. An external SSH CA would replace that with
short-lived certificates: WebTerm would ask the CA for a certificate valid for minutes, use it,
and hold nothing worth stealing.

Attractive, and clearly out of scope for a self-hosted tool that must work with no infrastructure
beyond a Docker host. It would be an integration, not a feature: WebTerm asks something else for a
certificate. Worth building the day someone already runs a CA.

## SSH through the agent

The telnet bastion tunnels TCP through an agent to reach equipment on its network. The same tunnel
could carry SSH, but SSH is a much larger surface: host key trust-on-first-use and rotation,
credential storage per device, agent forwarding, and the question of what the transcript should
contain. Telnet is raw bytes plus IAC negotiation; SSH is a protocol stack.

Reaching an SSH device through a host already works: open a session on the host, type `ssh`. The
gain would be a nicer entry point, not a new capability.

## What is deliberately not on this list

Anything that adds an always-on dependency: a message broker, a second database, an external
identity provider as a requirement rather than an option. The product's constraint is that it runs
on one machine with Docker and nothing else, and that is worth more than most features.
