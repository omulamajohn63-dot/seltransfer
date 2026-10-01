# SELTRANSFER

**Transfer files between PCs and phones over a local network. No Internet required, ever.**

SELTRANSFER runs a small HTTP server on your PC. Other devices on the same Wi-Fi
or hotspot open a URL, usually by scanning a QR code, and transfer files
directly. Nothing leaves your network: there is no cloud service, no account, no
telemetry, and no outbound connection to anything.

> **Traffic is plaintext by default.** This tool authorises and verifies; it does
> not encrypt. Use a network you trust, or turn on TLS. See
> [Security](#security) and [SECURITY.md](SECURITY.md).

---

## Table of contents

- [Install](#install)
- [Quick start](#quick-start)
- [How a transfer works](#how-a-transfer-works)
- [Transports: HTTP and WebRTC](#transports-http-and-webrtc)
- [Supported network topologies](#supported-network-topologies)
- [Pairing](#pairing)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
- [Data locations](#data-locations)
- [Security](#security)
- [Web interface](#web-interface)
- [Building the Windows executable](#building-the-windows-executable)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [License](#license)

---

## Install

### Option 1: the Windows executable (no Python needed)

Download `SELTRANSFER-<version>-windows-x64.zip`, extract it, and run
`SELTRANSFER.exe`. It carries its own Python runtime and needs nothing installed.

To allow the port through Windows Firewall, run `SELTRANSFER.exe
allow-firewall` once from an Administrator prompt. To uninstall, delete the
folder; the only thing left behind is `%LOCALAPPDATA%\SELTRANSFER`, which holds
your history and received files and can be removed separately.

### Option 2: from source

Requires **Python 3.12 or newer**.

```powershell
git clone <your-repository-url>
cd seltransfer
pip install -e ".[dev]"
```

Drop the `[dev]` extra for a runtime-only install.

---

## Quick start

1. Put the phone on the **same** Wi-Fi or hotspot as the PC.
2. Run `seltransfer start` (`SELTRANSFER.exe start` if using the executable).
3. Scan the QR code with the phone camera, or type the URL by hand.
4. The phone appears in the device list. Select it, then send files.
5. Accept on the phone.

If the phone cannot reach the page, run the firewall step above, then:

```powershell
seltransfer doctor
```

`doctor` only checks the local adapter table and loopback. It never contacts the
Internet, so it reports a healthy system with the WAN cable unplugged.


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
| Different subnets | No | Routing and NAT; use one LAN |
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

## Pairing

A transfer can only be created to a **paired** device, so pairing is the point at
which a device is trusted to contact you.

- **From the web interface running on this machine**, selecting a device pairs it.
  You are looking at that device's screen, so clicking is the intent.
- **From the CLI**, `seltransfer send` pairs the destination automatically. The
  CLI holds a token that only your own user account can read.
- **From anything else**, including a browser on another device, that device
  **asks** and you **approve**. Its screen shows a **Request access** button; the
  request then appears in the pairing panel on this machine with an **Approve**
  button next to it. Pressing Approve pairs it, and the other device notices within
  a couple of seconds.

Approving is the whole flow in the web interface — nothing is read out and nothing
is typed in. The click *is* the proof of intent, and only a browser on this machine
(or the CLI token) can make it, so a device on the network cannot approve itself no
matter how many requests it files.

```powershell
# A caller on another device: ask. The response deliberately carries no secret.
curl -X POST http://<host>:8765/api/devices/<device-id>/pair/request \
     -H "Content-Type: application/json" -d '{"device_id":"<device-id>"}'
# -> {"request_id":"...", "expires_in":120, ...}

# Poll to see whether it was approved.
curl http://<host>:8765/api/pairing/status/<device-id>
# -> {"device_id":"...", "paired":true,"method":"approved",...}
```

### Pairing codes (API only)

Scripts and other API callers can still pair with a one-time **8-digit code**
instead of waiting for a click: `GET /api/pairing/pending` from this machine
returns the code, and you post it back with
`POST /api/devices/<id>/pair/confirm`. The code is single-use, expires in two
minutes, and allows five attempts. No code is shown in the web interface, and the
browser client never sends one.

The important detail is that `pair/request` never returns the code. If it did,
pairing would be self-service and the code would prove nothing — any peer could
request one, read it out of its own response, and confirm it immediately.

Pairings expire after 24 hours. Revoke one from the device list in the web
interface, or with `DELETE /api/devices/<id>/pair` — both require this machine's
own local user, not just any session on the network.

To unpair at the firewall or the router level, the device simply stops appearing.


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

Settings come from environment variables prefixed with `SELTRANSFER_`, or from a
`.env` file in the working directory. List values accept a comma-separated form
(`SELTRANSFER_ALLOWED_HOSTS=a.local,b.local`) or JSON.

| Variable | Default | Purpose |
|---|---|---|
| `SELTRANSFER_SERVER_HOST` | `0.0.0.0` | Bind address |
| `SELTRANSFER_SERVER_PORT` | `8765` | Server port |
| `SELTRANSFER_PREFERRED_INTERFACE` | *(none)* | Prefer a named interface |
| `SELTRANSFER_EXCLUDE_INTERFACES` | Loopback, VirtualBox, VMware, Hyper-V, Docker, vEthernet | Adapters to ignore |
| `SELTRANSFER_CORS_ORIGINS` | *(empty)* | Extra literal origins allowed |
| `SELTRANSFER_EXPOSE_DOCS` | `false` | Serve `/docs` and `/openapi.json` |
| `SELTRANSFER_EXPOSE_PATHS` | `false` | Reveal the download directory to the browser |
| `SELTRANSFER_ALLOWED_HOSTS` | *(auto)* | Host header allowlist; `*` disables the check |
| `SELTRANSFER_TLS_ENABLED` | `false` | Serve HTTPS with the configured certificate |
| `SELTRANSFER_TLS_CERTFILE` | *(none)* | PEM certificate chain |
| `SELTRANSFER_TLS_KEYFILE` | *(none)* | PEM private key |
| `SELTRANSFER_MAX_FILE_BYTES` | 8 GiB | Largest single file |
| `SELTRANSFER_MAX_TRANSFER_BYTES` | 64 GiB | Largest total transfer |
| `SELTRANSFER_MAX_FILES_PER_TRANSFER` | `1000` | Files per transfer |
| `SELTRANSFER_MAX_TRACKED_TRANSFERS` | `2000` | Transfers held in memory |
| `SELTRANSFER_MAX_PENDING_INCOMING` | `50` | Pending announcements before a 429 |
| `SELTRANSFER_MAX_BROWSER_SESSIONS` | `500` | Browser sessions retained |
| `SELTRANSFER_MAX_WEBRTC_SESSIONS` | `200` | WebRTC sessions retained |
| `SELTRANSFER_PAIRING_CODE_TTL_SECONDS` | `120` | Pairing code lifetime |
| `SELTRANSFER_PAIRING_TTL_SECONDS` | `86400` | How long a pairing lasts |
| `SELTRANSFER_DEVICE_DISCOVERY_TIMEOUT_SECONDS` | `120` | When an unseen device is stale |
| `SELTRANSFER_APP_DIR` | `%LOCALAPPDATA%\SELTRANSFER` | Override the data directory |

`SELTRANSFER_ALLOWED_HOSTS` left unset means "loopback and any private or
link-local address", which blocks DNS rebinding from a public domain while still
letting a phone reach the PC over any of its interfaces. Setting it makes the list
**strict**: only the names you list, plus the address being served.

---

## Data locations

Application *resources* ship with the code. Application *data* never does — it
lives per user, so a packaged build never writes beside its own executable.

| What | Where |
|---|---|
| Executable | `dist\SELTRANSFER\` (or wherever you put it) |
| History database | `%LOCALAPPDATA%\SELTRANSFER\history.db` |
| Received files (native) | `%LOCALAPPDATA%\SELTRANSFER\downloads\` |
| Device identity | `%LOCALAPPDATA%\SELTRANSFER\device-id` |
| Local CLI token | `%LOCALAPPDATA%\SELTRANSFER\local.token` |
| Config overrides | `.env` in the working directory, or environment |
| Logs | stderr, i.e. your terminal |

On macOS and Linux the default is `~/.seltransfer`. `SELTRANSFER_APP_DIR`
overrides it everywhere.

Because the data is outside the install folder, **uninstalling is deleting the
folder**. The leftover `%LOCALAPPDATA%\SELTRANSFER` is only history and your
received files; remove it too if you want a clean machine.

`seltransfer history` reads the same database:

```
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━┓
┃ Date               ┃ Sender   ┃ Receiver ┃ Files ┃  Bytes ┃ Status  ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━┩
│ 2026-09-28T10:15:0 │ e161c717 │ f28cafb4 │    1 │ 1048576│ VERIFIED│
└────────────────────┴──────────┴──────────┴──────┴────────┴─────────┘
```

---

## Security

Full model and reporting process: **[SECURITY.md](SECURITY.md)**. Threat
analysis: **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**.

Summary of what is and is not protected:

| Property | Provided |
|---|---|
| Only paired devices can be contacted | Yes |
| Only participants can see a transfer | Yes |
| Received bytes are verified (SHA-256) before success | Yes |
| Failed transfers leave nothing on disk | Yes |
| Filenames cannot escape the download directory | Yes |
| Resource use is bounded | Yes |
| **Contents are confidential in transit** | **No, unless TLS is enabled** |
| **Protection from a hostile network** | **No, out of scope** |

### TLS

HTTP is the default, and HTTP traffic is plaintext. TLS is fully implemented but
**opt-in**, because a self-signed certificate produces a browser warning on every
phone connection, which is a worse first experience than plaintext on a hotspot
you chose.

```powershell
seltransfer start --tls
```

with, in `.env`:

```
SELTRANSFER_TLS_ENABLED=true
SELTRANSFER_TLS_CERTFILE=C:\certs\seltransfer.pem
SELTRANSFER_TLS_KEYFILE=C:\certs\seltransfer-key.pem
```

The QR code and printed URL switch to `https://`. If either file is missing or
unreadable, startup fails with a message naming the problem; it never silently
falls back to plaintext. Private keys are read at startup, never logged, and
never copied into the bundle.

### Firewall

```powershell
seltransfer allow-firewall              # add, from an Administrator prompt
seltransfer allow-firewall --remove     # undo
seltransfer allow-firewall --profile private,public   # narrower, if you want
```

The rule is scoped to the executable that is actually listening, to TCP only, and
to the local subnet. The rule name includes the port, so opening a second port
does not disturb the first.

`--profile` defaults to `any`, which is deliberate. Windows classifies a phone
hotspot as a **public** network, so the earlier `private,domain` default left the
rule inert on exactly the setup this command exists for. The profile decides
*when* the rule applies; `remoteip=localsubnet` decides *from where*, and is what
keeps the exposure to the local network either way.

If a rule from an older version is already present with narrower profiles,
running the command updates it in place to match. It never narrows a rule, since
that would re-break a hotspot that works today.

### Other controls

- CORS allows only private origins, never with credentials.
- The `Host` header must name a local address, which blocks DNS rebinding.
- A Content-Security-Policy plus `nosniff`, `X-Frame-Options: DENY`, and
  `Referrer-Policy: no-referrer` on every response.
- `/docs` is removed unless `SELTRANSFER_EXPOSE_DOCS=true`.
- Peer-supplied names and file names are rendered as text nodes; `innerHTML` is
  never used.
- No telemetry, no analytics, no update checks.


---

## Web interface

Served at `http://<pc-ip>:<port>`. Responsive, works on phones and tablets, and
follows the system light or dark theme.

- Live device list with online status and type
- Per-device expandable detail panel showing ID, IP, transport, and session
- Share panel: the connection QR code, the address as selectable text, plus copy,
  share, and download
- File and folder selection, including `webkitdirectory` folder uploads
- Transport selector, defaulting to HTTP
- Incoming transfer inbox with accept and reject
- Per-transfer activity and durable history

The interface is a client of the same server that hosts it, which is why the
browser can take part in transfers at all.

### The share panel

Any device with the page open can pass the address on, so the QR code is not
something only the machine that started the server can show. Open the page on a
phone, a tablet, or a second PC and the same panel is there.

The code encodes only `scheme://address:port` — nothing else. Scanning it opens
the page; it does not authorise anything. A device still has to ask to send, and
the destination's user still has to click Approve.

The address is always visible as text, and the code can be downloaded as an SVG,
because a `http://` address on a LAN IP is not a secure context: the clipboard and
the native share sheet are usually unavailable there, so the panel does not depend
on either. Copy and Share appear when the browser supports them.

---

## Building the Windows executable

Requires Python 3.12+ and PyInstaller. From the repository root:

```powershell
pip install pyinstaller
.\packaging\build.ps1
```

The script runs the full test suite, lint, and type checks first and aborts on any
failure, then builds `dist\SELTRANSFER\SELTRANSFER.exe` and
`dist\SELTRANSFER-<version>-windows-x64.zip`. It then verifies the artifact: the
bundled web assets are present, and `version`, `--help`, `devices`, and `doctor`
all run, with the reported version matching the source tree.

```powershell
.\packaging\build.ps1 -SkipTests     # build without the pre-flight checks
.\packaging\build.ps1 -NoArchive     # single-file exe instead of a folder
```

The spec lives at `packaging/seltransfer.spec` and derives every path from its own
location, so it works in any checkout. It collects the web assets as data where
`seltransfer.resources` looks for them, and excludes the test and build stack.
Pillow is excluded because nothing in the runtime path imports it — the CLI
renders the QR with `print_ascii`, and the QR served to the browser is written as
SVG by `seltransfer.qr` — but it stays a source dependency so the test suite still
works.

**A build is not a clean-machine test.** The remaining checks need a Windows
machine with no Python and a second device; see
`packaging/CLEAN_MACHINE_CHECKLIST.md`.

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

The terminal QR output is best-effort. In the web interface the code is served by
`GET /api/qr.svg`, so a blank panel means the page could not reach the server; the
address next to it is the fallback — type it into the phone's browser manually, or
use Download QR and open the file.

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
├── SECURITY.md                  Security model and reporting
├── MANIFEST.in
├── LICENSE
│
├── packaging/
│   ├── seltransfer.spec         PyInstaller build definition
│   ├── entrypoint.py            Frozen-executable entry point
│   ├── build.ps1                Build + verify script
│   └── CLEAN_MACHINE_CHECKLIST.md
│
├── docs/
│   └── THREAT_MODEL.md          Attackers, controls, residual risk
│
├── src/seltransfer/
│   ├── __init__.py              Version (single source of truth)
│   ├── cli.py                   Typer commands
│   ├── config.py                Settings, paths, local token
│   ├── devices.py               Registry and UDP broadcast discovery
│   ├── pairing.py               Pairing codes and pairings
│   ├── qr.py                    Connection QR as SVG (no Pillow)
│   ├── resources.py             Asset resolution, source and frozen
│   ├── storage.py               SQLite history
│   ├── transfers.py             State machine, limits, file writing
│   ├── network/
│   │   ├── __init__.py          Interface enumeration and selection
│   │   └── detection.py
│   ├── server/
│   │   ├── app.py               Factory, host check, CORS, headers
│   │   └── routes.py            API endpoints
│   ├── web/
│   │   ├── templates/index.html
│   │   └── static/
│   │       ├── app.js           Browser client
│   │       └── style.css
│   └── utils/
│       └── __init__.py          QR image helpers (not in the frozen build)
│
└── tests/
    ├── conftest.py              Isolation: never touches the real app dir
    ├── test_authorization.py    Participant scoping
    ├── test_app_dir.py          Data locations
    ├── test_filesystem.py       Path safety, index-keyed received files
    ├── test_http_hardening.py   Host check, headers, disclosure
    ├── test_limits.py           Size caps, streaming guards, cleanup
    ├── test_pairing.py          The pairing credential
    ├── test_pairing_http.py     Pairing and identity at the boundary
    ├── test_packaging.py        Build configuration
    ├── test_phone_delivery.py   End-to-end PC → phone
    ├── test_qr.py               Connection QR rendering and imports
    ├── test_resources.py        Asset resolution
    ├── test_tls.py              Opt-in TLS
    ├── test_transfers.py        State machine
    ├── test_network.py          Interface detection
    ├── test_server.py           Routes and lifecycle
    ├── test_utils.py            QR and path helpers
    └── web/test_app.js          Browser client, run with node
```


---

## License

MIT. See [LICENSE](LICENSE).
# seltransfer
