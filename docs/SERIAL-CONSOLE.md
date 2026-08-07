# Serial console (RS232 / RS485 / USB) via the agent

Access a serial device attached to a host in the fleet (switch/router, embedded equipment,
UART board, RS485/Modbus inverter…) inside a terminal tab — through the agent's tunnel.
It's the sibling of the telnet bastion ([design/TELNET-BASTION.md](design/TELNET-BASTION.md)), but **RAW**: raw bytes,
with no protocol shim.

Delivered in v1.0.83 (base), v1.0.84 (fleet propagation fix), v1.0.85 (professional discovery).

## Usage flow

1. Host menu (**⋯**) on an **agent** + **online** host → **🔌 Serial console**.
2. The modal runs **automatic discovery** (`POST /api/hosts/{id}/serial/discover`) and lists
   the real ports on the host.
3. Pick one from the list (radio) **or** type a device manually (`/dev/ttyUSB0`).
4. Set the **baud rate** (115200 by default) and, under "Advanced", bits/parity/stop/flow (8N1, no flow, by default).
5. **Open** → 2FA step-up if the host requires it → a terminal tab wired directly to the serial line.

## Discovery — what it sees and what it filters

`serial_ports()` in the agent (`agent/ptyd.py`), still entirely from the **stdlib** (reading `/sys`, no pyserial/pyudev):

- Enumerates `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/ttyAMA*` (USB/embedded) plus any `/dev/ttyS*` backed by
  **real hardware** (filtered via `TIOCGSERIAL.type != 0` — removes the serial8250 phantoms).
- Rich per-port metadata (from sysfs), useful especially when you have several identical adapters:
  - **VID:PID** (`idVendor`/`idProduct`), **manufacturer/product**, **USB serial** (`iSerial` — unique;
    FTDI has it, CH340 often doesn't), **driver** (ftdi_sio/ch341/cp210x…)
  - **physical path** (`/dev/serial/by-path`) — tells two identical adapters apart by the physical USB port
  - **stable name** (`/dev/serial/by-id`)
  - **UART type** for onboard ports (`TIOCGSERIAL` → 16550A etc.)
  - **"in use"** — whether the port is held open by a process (scan `/proc/*/fd` → `comm[pid]`;
    includes in-progress WebTerm serial sessions)

### Physical identification (for identical adapters)

In `SerialModal`, the **🔍 Identify** button (pure frontend, reuses discovery):
unplug the adapter from USB → we show you which `/dev/tty*` node disappeared ("this is the one") → plug it back in
→ it gets selected automatically. Plus highlighting of newly appeared ports on rescan. It solves the "I have
three identical CH340s with no serial, which is which" case.

## Transport & security

- **Reuses FRAME_FWD** (the same transport as port-forwarding): the agent opens the fd
  (`os.open(... O_RDWR|O_NOCTTY|O_NONBLOCK)`), checks `os.isatty`, configures **raw** termios
  (cfmakeraw-equivalent + baud/bits/parity/stop/flow), and bridges raw bytes to the gateway.
- Gateway: `ForwardSerialSource` (like `ForwardTelnetSource`, but without the IAC shim). It keeps
  the guards for an **untrusted** device: `OscFilter` (F5 — filters OSC 133/52 coming from
  the device) plus password redaction in the transcript (F3). `resize` is a no-op (serial has no winsize).
- The `/api/hosts/{id}/serial/open` endpoint requires **host step-up** (`_require_host_stepup`) and
  validates the device (`/dev/` prefix, no NUL), parity, and flow.
- Separate cap: `MAX_SERIALS = 16` (agent) / `MAX_SERIAL_SESSIONS = 16` (gateway).
- The session config is saved in the `sessions.serial_config` column (JSON) for restoration.

## Maintenance notes

- **Any change to `agent/ptyd.py` requires bumping `AGENT_VERSION` + re-signing** — otherwise the update
  won't propagate to the fleet (see the lesson from v1.0.84 about bumping `AGENT_VERSION`).
- The E2E test with a **fake device** (a PTY pair) only validates the byte flow + `open()`. The real
  metadata (VID:PID/serial/by-path) and physical identification can only be validated **on real hardware**.
- RS485 half-duplex (direction/timing) is not tested on a cable — to be confirmed on first real-world use.
- No pyserial: if some exotic device needs a non-standard baud rate absent from `termios.B*`, `serial_open`
  fails with `unsupported baud: <n>` — to be extended only as needed.
