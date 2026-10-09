# Future directions

**Status: not started.** These are sketches, not commitments. They are written down so the
reasoning is not lost, and so that anyone proposing them knows what was already considered.

Nothing here touches WebTerm as it exists. Each would be an external, opt-in layer, built only if
a concrete need appears.

## Multi-user through isolation, below the roles

Since 3.6.0 WebTerm has roles ([ROLES.md](../ROLES.md)), scoped to hosts: an account can be
limited to some hosts, and to watching instead of typing. What roles deliberately do **not**
pretend is separation *inside* a host: a user with a shell there can read every file the agent's
user can, including private keys. Restricting the UI on such a host would be theatre, which is why
the role catalogue marks shell-equivalent permissions (⚑).

If several people genuinely need separated access on the **same** host, the separation still has
to be below WebTerm:

- one agent per Unix user on the host, each running as that user, so the operating system enforces
  the boundary that WebTerm cannot;
- or one WebTerm instance per team, which is cheap — a container and a volume.

Either is honest. A role that claimed to separate two people sharing one shell account would
not be.

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
