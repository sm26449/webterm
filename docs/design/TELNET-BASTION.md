# Telnet bastion

**Status:** shipped. `gateway/app/telnet.py`, `tests/telnet_bastion_test.py`.

## The problem

To reach the CLI of a switch or router on a host's network, you used to open a WebTerm session on
the host and type `telnet 192.168.88.2` inside it. Two steps, an intermediate shell that serves no
purpose, and none of WebTerm's advantages on the connection you actually care about: no separate
transcript, no reconnect, no status, and awkward on a tablet.

The device is behind NAT. The gateway cannot see it. The host running the agent can — so the host
becomes a jump point, and the mental model is "like a port forward, but I pick `telnet` instead of
`http`".

## How it is built

Almost entirely from parts that already existed:

- the agent can open a **TCP tunnel** to an address on its network (that is what port forwarding
  uses);
- the gateway already knows how to run a **session** whose bytes come from somewhere other than a
  PTY;
- the browser already renders a terminal.

What was new is the middle: a telnet shim that speaks enough of the protocol for real equipment,
and a session source that pipes the tunnel into a normal session.

## The telnet shim

Telnet is not a raw byte stream. `gateway/app/telnet.py` handles:

- **IAC negotiation** — enough option handling that Cisco, MikroTik and Teltonika gear proceeds to
  a login prompt instead of waiting;
- **NAWS** — the terminal size, so full-screen tools on the device draw correctly;
- **IAC escaping on input** — a `0xFF` byte typed by the user must not be read as a command;
- **a cap on subnegotiation** — a hostile or broken device must not be able to make the gateway
  buffer without bound.

## Why the device's output is filtered

A network device is **not trusted**. Its output goes into a terminal and into a transcript, so
anything it emits that carries meaning to the browser is stripped: OSC 133 (shell prompt markers,
which would corrupt the command panel), OSC 52 (clipboard writes — a device that could write to
your clipboard would be a real problem), and OSC 7.

The filter has to work across fragmentation: a sequence split over two reads must still be caught,
and an identifier that is zero-padded must not slip past. That is what most of
`tests/telnet_shim_test.py` is about.

## Password redaction

When the device prints a password prompt, the shim marks a window over the following
keystrokes. In practice this changes nothing today, because **input is never written to a
transcript for any session** — the marker is a belt over an existing brace, kept so that the
guarantee does not depend on a single place in `core.py` continuing to behave.

## Access rules

A bastion session is created from a port forward whose scheme is `telnet`. That means it inherits
the forward's access rules, including step-up on a host marked "require 2FA", and it must respect
the forward's `enabled` flag — the "off" switch in the UI is the only lever for cutting access
quickly, and it has to work on every path, not just the HTTP one.

## SSH through the agent

Deliberately not built. The same tunnel would carry it, but SSH brings host-key management,
credential storage and agent forwarding — a much larger surface than telnet's "raw bytes plus IAC".
Reaching an SSH device through a host is already possible by opening a session on that host. See
[FUTURE-DIRECTIONS.md](FUTURE-DIRECTIONS.md).
