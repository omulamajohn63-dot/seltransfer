# SELTRANSFER

**Transfer files between PCs and phones over a local network. No Internet required, ever.**

SELTRANSFER runs a small HTTP server on your PC. Other devices on the same Wi-Fi
or hotspot open a URL, usually by scanning a QR code, and transfer files
directly. Nothing leaves your network: there is no cloud service, no account, and
no outbound connection to anything.

---

## Table of contents

- [Quick start](#quick-start)
- [How a transfer works](#how-a-transfer-works)
- [Transports: HTTP and WebRTC](#transports-http-and-webrtc)
- [Supported network topologies](#supported-network-topologies)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
- [Security model](#security-model)
- [Storage layout](#storage-layout)
- [Web interface](#web-interface)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [License](#license)

---

## Quick start

### Prerequisites

- **Python 3.12 or newer** — [python.org](https://www.python.org/downloads/)
- A local network: a shared Wi-Fi router, a PC hotspot, or a phone hotspot
- Windows Firewall permission for the transfer port (see step 3)

### 1. Install

```powershell
git clone <your-repository-url>
cd seltransfer
pip install -e ".[dev]"
```

For a runtime-only install, drop the `[dev]` extra.

### 2. Allow the port through Windows Firewall

Windows marks hotspot networks as **Public**, which blocks inbound connections
until you allow the port. Run this once, from an **Administrator** PowerShell:

```powershell
seltransfer allow-firewall
```

If the automatic rule fails, the command prints the equivalent `netsh` line to
run by hand.

### 3. Start the server

```powershell
seltransfer start
```

```
╭──────────────────────────────────────────╮
│            SELTRANSFER                   │
│       OFFLINE FILE TRANSFER              │
╰──────────────────────────────────────────╯

✓ Network detected Wi-Fi (Wi-Fi)
  IP Address: 192.168.1.126
✓ Server binding: 0.0.0.0:8765
Phone URL: http://192.168.1.126:8765

SCAN TO CONNECT
```

### 4. Connect the other device

1. Put the phone on the **same** Wi-Fi or hotspot as the PC.
2. Scan the QR code with the phone camera, or type the URL by hand.
3. The device appears in the web interface. Select it, then send files.

### 5. Check it works

```powershell
seltransfer doctor
```

```
SELTRANSFER NETWORK DIAGNOSTICS

✓ Network adapter detected
✓ IPv4 address detected
✓ Server is listening on 0.0.0.0:8765
✓ Local HTTP request successful (200)

Detected interfaces:
  Wi-Fi: 192.168.1.126 (Connected, Wi-Fi)
  Ethernet: 192.168.56.1 (Connected, Ethernet)

Recommended interface: Wi-Fi
Phone connection URL: http://192.168.1.126:8765
```

`doctor` only ever tests loopback and the local adapter table. It never contacts
the Internet, so it will report a healthy system with the WAN cable unplugged.

---

## How a transfer works

The model is different from most file-sharing apps, so it is worth understanding.

**Browsers cannot receive inbound connections.** A web page has no way to listen
for a socket. So the phone does not wait for the PC to push to it. Instead, the
PC's server is the meeting point for both sides:

```
   ┌──────────────┐                      ┌──────────────┐
   │   PC server  │  both devices are    │    Phone     │
   │  (FastAPI)   │ ──── clients of ───► │   browser    │
   │  :8765       │ ◄──── the same ───── │              │
   └──────────────┘      server          └──────────────┘
          │
          │  1. PC creates the transfer
          │  2. Phone sees it as pending and accepts
          │  3. PC uploads the bytes to the server
          │  4. Phone downloads them and saves locally
          ▼
   ~/.seltransfer/downloads/<transfer-id>/
```

The consequence: for the default HTTP transport, the phone only needs to *reach*
the PC. That is why a phone-hosted hotspot works well even though the phone is
also the network's router.

Received files land in one of two places, depending on the receiver:

| Receiver | Where files end up |
|---|---|
| Browser (phone) | The phone's own download folder, using browser settings |
| Native SELTRANSFER | `~/.seltransfer/downloads/<transfer-id>/` on that machine |

---

## Transports: HTTP and WebRTC

Two transports are available. **HTTP is the default and the recommended path.**

### HTTP (default)

The PC uploads the file to its own server; the receiver pulls it down over an
authenticated `GET`. This is the PC → phone path, and it works with every
device, including phones.

### WebRTC (opt-in, experimental)

Peer-to-peer data channel between the two browsers, with the server acting only
as a signalling relay. Selectable in the web interface under **Transport**, or
pre-set in the browser:

```javascript
localStorage.setItem("seltransfer-transport", "webrtc");
```

Notes before you rely on it:

- **Browser receivers only.** The server rejects WebRTC for native nodes.
- **No STUN or TURN server is configured**, deliberately. `iceServers` is empty,
  so the browser gathers host candidates only and never attempts a network
  lookup. This is why it works with the Internet disconnected.
- Without STUN there are no server-reflexive candidates, so WebRTC **cannot
  traverse NAT between different subnets**.
- Some browsers emit mDNS-obfuscated (`.local`) host candidates. If the access
  point blocks mDNS multicast, the WebRTC path can fail to connect. The default
  HTTP transport is unaffected.
- WebRTC buffers received chunks in memory. It is not the right transport for
  very large files.

---

## Supported network topologies

| Topology | Works | Notes |
|---|---|---|
| Shared Wi-Fi router | Yes | Easiest to test |
| PC hotspot → phone joins | Yes | Windows marks it Public; run `allow-firewall` |
| Phone hotspot → PC joins | Yes | The phone is the router; run `allow-firewall` |
| Ethernet | Yes | PCs on the same switch or router |
| No router at all | Yes | PC hotspot and phone join directly |
| Different subnets | No | Routing and NAT; use the HTTP path on one LAN |
| AP with client isolation | No | The network blocks device-to-device traffic |
| Internet disconnected | Yes | Nothing in the tool reaches the Internet |

When a PC has more than one usable adapter, SELTRANSFER picks by type priority:

```
Wi-Fi hotspot  →  Wi-Fi  →  Ethernet  →  Other
```

Override the choice explicitly:

```powershell
seltransfer devices
seltransfer start --interface "Wi-Fi"
```

---

## CLI reference

```
seltransfer start           Start the server and show a connection QR code
seltransfer devices         List network interfaces and the recommended adapter
seltransfer doctor          Diagnose adapters and the local server
seltransfer allow-firewall  Add an inbound Windows Firewall rule
seltransfer discover        List devices found by the running server
seltransfer send            Send files to a discovered device
seltransfer history         Show durable transfer history
seltransfer status          Show local server status
seltransfer version         Show the version
```

### `start`

```
--port, -p       Port to listen on (default 8765)
--interface, -i  Prefer a specific network interface
--host, -h       Bind address (default 0.0.0.0, all interfaces)
```

### `send`

Sends directly from the command line to a discovered device, with no browser
involved.

```powershell
seltransfer send report.pdf --to DEVICE_ID
seltransfer send report.pdf notes.txt --to DEVICE_ID --port 9000
```

Get device IDs from `seltransfer discover`. The destination must be online and
paired; the CLI pairs it automatically. Files must be under the configured size
limits.

### `doctor`

Checks the local adapter table and whether the server is listening and answering
on loopback. Reports the recommended interface and the URL a phone should open.
Fully offline.

---

## Configuration

Settings are read from environment variables prefixed with `SELTRANSFER_`, or
from a `.env` file in the working directory.

| Variable | Default | Purpose |
|---|---|---|
| `SELTRANSFER_SERVER_HOST` | `0.0.0.0` | Bind address |
| `SELTRANSFER_SERVER_PORT` | `8765` | Server port |
| `SELTRANSFER_PREFERRED_INTERFACE` | *(none)* | Prefer a named interface |
| `SELTRANSFER_EXCLUDE_INTERFACES` | Loopback, VirtualBox, VMware, Hyper-V, Docker, vEthernet | Adapters to ignore |
| `SELTRANSFER_CORS_ORIGINS` | *(empty)* | Extra literal origins allowed |
| `SELTRANSFER_EXPOSE_DOCS` | `false` | Serve `/docs` and `/openapi.json` |
| `SELTRANSFER_MAX_FILE_BYTES` | 8 GiB | Largest single file |
| `SELTRANSFER_MAX_TRANSFER_BYTES` | 64 GiB | Largest total transfer |
| `SELTRANSFER_MAX_FILES_PER_TRANSFER` | `1000` | Largest file count per transfer |
| `SELTRANSFER_DEVICE_DISCOVERY_TIMEOUT_SECONDS` | `120` | When an unseen device is considered stale |
| `SELTRANSFER_APP_DIR` | `~/.seltransfer` | Override the storage directory |

Example `.env`:

```
SELTRANSFER_SERVER_PORT=9000
SELTRANSFER_MAX_FILE_BYTES=2147483648
```

---

## Security model

SELTRANSFER is built for a trusted local network. It is **not** encrypted in
transit, and it is not hardened against a hostile network.

What it does implement:

- **Pairing is required.** A transfer can only target a device that has been
  paired and is currently online.
- **Scoped authorization.** Every state change, history read, and file download
  is checked against the caller's session. A sender cannot read the receiver's
  copy, and history is filtered to the devices the caller participated in.
- **Per-transfer upload tokens.** Uploading bytes requires a credential issued
  for that specific transfer. The receiver is deliberately never told it.
- **Size and path validation.** Declared sizes are checked against limits before
  any bytes are written, and again while streaming. Uploaded paths are
  sanitised and traversal is rejected.
- **Content verification.** SHA-256 is verified on receipt, and bytes are
  written to a `.part` file that is only renamed on success. Failed, oversized,
  or interrupted uploads are cleaned up and the transferred total is rolled back.
- **Browser output is never trusted.** Peer-supplied device names, IDs, IPs, and
  transport values are rendered as text nodes, never as markup.
- **CORS is restrictive.** Only private and link-local origins are permitted,
  and API documentation is off unless explicitly enabled.
- **No telemetry.** Nothing is reported anywhere. Logs go to your terminal.

Known limits:

- Traffic is plain HTTP. Anyone on the same network can read file contents in
  transit. Use a trusted network.
- The server binds to `0.0.0.0` by default, so anything that can route to the
  machine can reach it. Pairing and CORS limit what a browser can do, but this is
  not a substitute for a trusted network.
- TLS is not implemented.

---

## Storage layout

```
~/.seltransfer/
├── history.db          SQLite transfer history
└── downloads/
    └── <transfer-id>/  Native receivers write received files here
```

Set `SELTRANSFER_APP_DIR` to relocate. The web interface displays the resolved
path for the running server.

`seltransfer history` reads from the same database:

```
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━┓
┃ Date               ┃ Sender   ┃ Receiver ┃ Files ┃  Bytes ┃ Status  ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━┩
│ 2026-09-28T10:15:0 │ e161c717 │ f28cafb4 │    1 │ 1048576│ VERIFIED│
└────────────────────┴──────────┴──────────┴──────┴────────┴─────────┘
```

---

## Web interface

Served at `http://<pc-ip>:<port>`. Responsive, works on phones and tablets, and
follows the system light or dark theme.

- Live device list with online status and type
- Per-device expandable detail panel showing ID, IP, transport, and session
- File and folder selection, including `webkitdirectory` folder uploads
- Transport selector, defaulting to HTTP
- Incoming transfer inbox with accept and reject
- Per-transfer activity and durable history

The interface is a client of the same server that hosts it, which is why the
browser can take part in transfers at all.

---

## Development

```powershell
pip install -e ".[dev]"
```

### Tests

```powershell
python -m pytest                 # 120 Python tests
node tests/web/test_app.js       # 12 browser-client tests
```

The browser tests use a minimal fake DOM and need no npm install or test runner.

### Lint and types

```powershell
python -m ruff check .
python -m mypy src
```

### Smoke test without a second device

```powershell
seltransfer start
```

In another terminal:

```powershell
seltransfer doctor
seltransfer discover
seltransfer history
curl http://localhost:8765/api/status
```

### Test files

| File | Covers |
|---|---|
| `tests/test_server.py` | API routes, transfer lifecycle, hermetic fixtures |
| `tests/test_authorization.py` | Pairing, participant scoping, token checks |
| `tests/test_phone_delivery.py` | End-to-end PC → phone over HTTP |
| `tests/test_limits.py` | Size limits, streaming guards, cleanup |
| `tests/test_cors.py` | Origin policy, documentation gating |
| `tests/test_transfers.py` | State machine and transitions |
| `tests/test_network.py` | Interface detection and selection |
| `tests/test_packaging.py` | Wheel contents and asset serving |
| `tests/test_utils.py` | QR generation and path sanitisation |
| `tests/web/test_app.js` | Escaping, filename safety, progress, WebRTC gating |

---

## Troubleshooting

### "Site can't be reached" from the phone

The most common issue. Windows classifies hotspot networks as **Public**, so
inbound TCP is blocked.

```powershell
seltransfer allow-firewall
seltransfer doctor
```

If `doctor` warns about the firewall, the port is still closed. Run the `netsh`
command it prints, from an Administrator prompt.

### The wrong IP is shown

With several adapters connected, confirm which one belongs to your network:

```powershell
seltransfer devices
seltransfer start --interface "Wi-Fi"
```

### The phone sees the page but no devices

- Confirm both devices are on the same network and that the PC has not
  disconnected from the server
- The PC's own server and browser are intentionally excluded from the device
  list; you need the other device
- Browser registration requires a heartbeat every few seconds. A phone that was
  backgrounded will re-register when you return to the page

### Transfer fails to start

- The destination must be paired and online; the web interface pairs on selection
- Check the size limits in the table above
- A browser receiver can only receive over HTTP, not WebRTC

### Large files are slow or the browser runs out of memory

WebRTC buffers received chunks in memory. Use the HTTP transport for large
files.

### Port already in use

```powershell
seltransfer start --port 9000
seltransfer allow-firewall --port 9000
```

### QR code does not render

Terminal QR output is best-effort. Type the URL into the phone's browser
manually, or read it from the terminal output.

### The phone cannot reach the PC on a phone hotspot

Some Android builds isolate the hotspot host from its own clients. If the page
will not load and the PC shows no errors, use a shared Wi-Fi network with no
Internet instead. The tool works identically there, and this tests the same code
path.

---

## Project layout

```
seltransfer/
├── pyproject.toml
├── README.md
├── MANIFEST.in
├── LICENSE
├── src/seltransfer/
│   ├── __init__.py
│   ├── cli.py                 Typer commands
│   ├── config.py              Settings and paths
│   ├── devices.py             Registry and UDP broadcast discovery
│   ├── storage.py             SQLite history
│   ├── transfers.py           Transfer state machine and file writing
│   ├── network/
│   │   ├── __init__.py        Interface enumeration and selection
│   │   └── detection.py
│   ├── server/
│   │   ├── app.py             FastAPI factory, CORS, static assets
│   │   └── routes.py          API endpoints
│   ├── web/
│   │   ├── templates/index.html
│   │   └── static/
│   │       ├── app.js         Browser client
│   │       └── style.css
│   └── utils/
│       └── __init__.py        QR helpers, path sanitisation
└── tests/
    ├── test_server.py
    ├── test_authorization.py
    ├── test_phone_delivery.py
    ├── test_limits.py
    ├── test_cors.py
    ├── test_transfers.py
    ├── test_network.py
    ├── test_packaging.py
    ├── test_utils.py
    └── web/test_app.js
```

---

## License

MIT. See [LICENSE](LICENSE).
# seltransfer
