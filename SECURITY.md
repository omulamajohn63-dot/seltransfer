# Security Policy

## Reporting a vulnerability

Report privately rather than opening a public issue. Include the version
(`seltransfer version`), what you did, what you expected, and what happened.

There is no security contact address configured for this project yet. Until one
is, use the repository's private vulnerability reporting form if it is enabled.

Please do not test against networks you do not own.

## What SELTRANSFER is, and is not

SELTRANSFER moves files between devices on a **trusted local network**. Its
security model is authorisation and integrity on that network. It is explicitly
**not** confidentiality, because the default transport is plain HTTP.

| Property | Provided? | By what |
|---|---|---|
| Authorisation — only paired devices can be contacted | Yes | Pairing codes, session checks |
| Authorisation — only participants see a transfer | Yes | Per-request participant checks |
| Integrity — received bytes match what was sent | Yes | SHA-256, verified before success |
| Integrity — a failed transfer leaves nothing behind | Yes | `.part` → verify → rename, with rollback |
| Confidentiality — contents unreadable on the wire | **No** | Plain HTTP by default; opt-in TLS |
| Protection from a hostile network | **No** | Documented as out of scope |

Do not describe SELTRANSFER as encrypted unless TLS is explicitly configured, and
even then the certificate is one you supply.

## Threat model

Full analysis with mitigations: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

In brief: an attacker on the same LAN can see traffic, can reach the HTTP port,
and can attempt to register a browser device. They cannot pair a device without
either an out-of-band code or an existing session, cannot read or write a
transfer they are not a participant in, cannot retrieve an upload token for a
transfer they did not create, and cannot escape the download directory with a
crafted filename.

## Security controls

## Caller identity

Three kinds of caller, and nothing else:

1. **Browser session** — `x-seltransfer-session`, checked against a live session
   record and matched to the device being acted on.
2. **Local CLI** — `x-seltransfer-local`, compared in constant time against a
   per-machine token.
3. **Anonymous** — no identity.

Anonymous callers are refused (401) from history, transfer state, pairing, and
anything that reveals a stored file. They may only do two things: register a
browser device, and announce a transfer. Both are bounded (see below).

> This replaced a previous behaviour where an unauthenticated request was
> silently treated as the local server node. Any peer on the LAN could therefore
> read local history, cancel local transfers, and obtain upload tokens.

### Local user versus remote session

A browser session is **not** by itself authority to do anything sensitive.
`POST /api/browser/register` is deliberately unauthenticated — a phone has to be
able to announce itself before anything can be trusted — so "has a session" only
means "some peer asked for one". A session issued to a **loopback peer**, or to
this machine's own LAN address, is the machine's own user and may pair and
unpair. A session from anywhere else must use the pairing code.

Treating any session as authority let a device on the LAN pair any device, which
is precisely the hole the pairing code was added to close.

## Endpoint matrix

Every route, what it needs, and what an anonymous caller gets. `local` = the
local CLI token; `session` = a live browser session.

| Endpoint | Needs | Anonymous result |
|---|---|---|
| `GET /api/health` | nothing | 200, liveness only |
| `GET /api/status` | nothing | 200; version, identity of this node, no secrets |
| `GET /api/connection` | nothing | 200; address, port, and QR payload |
| `GET /api/devices` | nothing | 200; device list, but `paired_devices` empty and `local_user` false |
| `POST /api/devices/discover` | nothing | 200; starts UDP discovery |
| `POST /api/browser/register` | nothing | 200; issues a session (bounded) |
| `POST /api/browser/heartbeat` | session | 401 |
| `POST /api/browser/unregister` | session | 401 |
| `GET /api/transfers` | session or local | 401 |
| `POST /api/transfers` | session or local, **and** a pairing with the receiver | 403 unpaired, then 401 |
| `GET /api/transfers/{transfer_id}` | session or local, and a participant | 404 unknown, 401 no identity, 403 not a participant |
| `GET /api/transfers/{transfer_id}/progress` | session or local, and a participant | 404 unknown, 401 no identity, 403 not a participant |
| `POST /api/transfers/{transfer_id}/accept` | receiver only | 404 unknown, 401 no identity, 403 not the receiver |
| `POST /api/transfers/{transfer_id}/reject` | receiver only | 404 unknown, 401 no identity, 403 not the receiver |
| `POST /api/transfers/{transfer_id}/cancel` | sender only | 404 unknown, 401 no identity, 403 not the sender |
| `POST /api/transfers/{transfer_id}/pause` | sender only | 404 unknown, 401 no identity, 403 not the sender |
| `POST /api/transfers/{transfer_id}/resume` | sender only | 404 unknown, 401 no identity, 403 not the sender |
| `PUT /api/transfers/{transfer_id}/files/{n}` | nothing — it is a 410 tombstone | 410; bytes only reach a destination through `/api/incoming-transfers` |
| `DELETE /api/transfers/history` | session or local | 401 |
| `POST /api/transfers/history/clear` | session or local | 401 |
| `POST /api/incoming-transfers` | nothing | 200; creates a bounded, inert pending record aimed at the local node |
| `GET /api/incoming-transfers` | session or local | 401 |
| `GET /api/incoming-transfers/{transfer_id}` | session or local, and a participant | 404 unknown, 401 no identity, 403 not a participant |
| `POST /api/incoming-transfers/{transfer_id}/accept` | receiver only | 404 unknown, 401 no identity, 403 not the receiver |
| `POST /api/incoming-transfers/{transfer_id}/reject` | receiver only | 404 unknown, 401 no identity, 403 not the receiver |
| `PUT /api/incoming-transfers/{transfer_id}/files/{n}` | `x-seltransfer-token` | 404 unknown, 401 no token |
| `GET /api/incoming-transfers/{transfer_id}/files/{n}` | receiver only | 404 unknown, 401 no identity, 403 not the receiver |
| `POST /api/devices/{device_id}/pair` | **local user** | 403 |
| `DELETE /api/devices/{device_id}/pair` | **local user** | 403 |
| `POST /api/devices/{device_id}/pair/request` | nothing | 200; returns **no code** |
| `GET /api/pairing/pending` | **local user** | 403; this is where codes are read |
| `POST /api/pairing/requests/{request_id}/approve` | **local user** | 403; 404 unknown, expired, or already approved |
| `GET /api/pairing/status/{device_id}` | nothing | 200; pairing state, **no code** |
| `POST /api/devices/{device_id}/pair/confirm` | a valid code | 403 already paired, 404 wrong or expired code |
| `POST /api/webrtc/session` | session or local, browser peer | 401 no identity, 409 non-browser peer, 503 at the cap |
| `GET /api/webrtc/sessions` | session | 401 |
| `GET /api/webrtc/{session_id}` | session, and owner or peer | 404 unknown, 401 no identity, 403 neither |
| `POST /api/webrtc/{session_id}/{signal_type}` | session, and owner or peer | 404 unknown, 401 no identity, 403 neither |
| `POST /api/webrtc/{session_id}/files/{n}/complete` | session, and owner or peer | 404 unknown, 401 no identity, 403 neither |

The table is checked against the running application, not written from memory:
every row is exercised anonymously from a LAN peer with a request body valid
enough to reach the authorization check, and the status codes above are what
comes back.

One consequence worth stating plainly: because the lookup precedes the
authorization check, an anonymous caller learns whether a given `transfer_id`
exists (404) or not (401/403). Transfer IDs are `secrets.token_urlsafe(32)`, so
they are not guessable, but the existence bit is technically observable.

Two rows deserve emphasis:

- **`POST /api/incoming-transfers` is anonymous by necessity.** A remote sender
  has no session on this server. What it grants is not access to anything: a
  pending, inert record aimed at the local node, capped per receiver, that the
  anonymous caller cannot read back, accept, or upload to without presenting the
  upload token it chose itself.
- **`POST /api/devices/{id}/pair/request` deliberately withholds the code.** An
  earlier version returned it, which made the flow self-service: a peer could
  request a code, read it out of the response, and confirm it immediately. The
  code is readable only via `GET /api/pairing/pending`, which requires the local
  user.

### Pairing

Pairing is the precondition for creating a transfer.

- **Approval is the only path in the web interface.** The requesting device asks,
  and the destination's own user clicks Approve. That click is the proof of intent,
  so nothing is read out and nothing secret is sent to the requester.
  `POST /api/pairing/requests/{id}/approve` is local-user only and checks that
  first, so a peer cannot approve its own request no matter how many it files.
  Approving consumes the request, which means an approved request cannot also be
  confirmed with its code. The client holds no code field and never calls
  `/pair/confirm`.
- An **out-of-band code** remains available to API and script callers, which cannot
  watch for a click. It is 8 digits (~27 bits), generated with `secrets`, single
  use, and valid for 120 seconds. Attempts are capped at 5 per request, and 5
  outstanding requests per caller. Going digits-only removes the `0/O` and `1/I/L`
  transcription problem instead of paying entropy to exclude those glyphs, but it
  does cost entropy: ~27 bits against the ~40 a mixed alphabet allowed. The
  throttling above is what covers that reduction — a handful of guesses per
  request against a 10^8 space, inside a two-minute window — and the approval
  path involves no guessing at all.
- The code is verified against a **salted SHA-256 hash** — each request has its
  own salt, so identical codes across requests do not correlate. The clear code
  is *also* held in memory for the life of the request, because an API caller
  needs it to be displayable; it is not written to disk, not logged, and not
  returned to the requester. Without that in-memory copy a code could not be
  shown at all, which would make the flow unusable.
- The destination displays it via `GET /api/pairing/pending`; the requester reads it
  over a different channel, which is what makes it proof of intent rather than a
  formality. The web interface does not render it — there is no field to type it
  into any more, so a large readable code beside an Approve button would only
  invite reading it out for nothing. Characters outside `0-9` are dropped when
  normalising, never substituted: mapping a letter onto a lookalike digit would turn
  a misread glyph into a correct guess.
- `GET /api/pairing/status/{device_id}` is open to any caller so a requester can
  learn that its request was approved. It carries no code and no identity — and
  the pairing state it reports is already public in `GET /api/devices` as
  `paired_devices`.
- A **local user** (browser session registered from loopback or this machine's
  own address, or the CLI token) may pair without a code, because the user is
  looking at that device in their own interface and clicking is the explicit
  interaction.
- Pairings expire (24 hours by default) and can be revoked by the local user.
- `GET /api/devices` does **not** disclose the pairing map to an anonymous
  caller; it names who may be contacted, which is not public information.

### Transfer tokens

- Uploading bytes requires `x-seltransfer-token` for that specific transfer.
- Tokens are `secrets.token_urlsafe(32)`, compared with `secrets.compare_digest`.
- A token is disclosed only to the transfer's sender, and only after the receiver
  has accepted. The receiver is never given it: handing the receiver the sender's
  push token would let it write bytes that look like they came from the sender.
- A token does not authorise any other transfer.
- A replayed upload for an index already received is a no-op, decided before
  anything is written.
- Tokens appear in no log line.

### File handling

- Declared sizes are validated against the per-file, per-transfer, and file-count
  limits before a transfer is created.
- Sizes are re-checked **while streaming**, against the smaller of the configured
  cap and the declared size, so an oversized body is cut off rather than filling
  the disk.
- Bytes go to a `.part` file, are hashed, and are only moved into place after the
  size and SHA-256 both match. Every failure path deletes the `.part` file and
  rolls back the transfer's byte count.
- Filenames are rejected if they are absolute, contain a drive or UNC prefix,
  contain a `..` segment, contain control characters, name a Windows device
  (`CON`, `NUL`, `COM1`, …), or consist only of substituted characters.
- The resolved write path is confirmed to be inside the download root before
  anything is served from it.

### Input validation

Device IDs, transfer IDs, and session IDs must match a restricted alphabet and
length. The sender identity is a validated model rather than a free-form object.
An invalid value is a 422, not a 500, and never reaches a log line unescaped.

### Browser security

- **CORS** allows only loopback and private-network origins, never a public site,
  and never with credentials.
- **Host header validation** rejects any request naming a public host. This
  defeats DNS rebinding, where a public domain resolves to the LAN address and a
  website drives the API through the user's browser. Loopback, private, and
  link-local addresses are accepted, so a phone can still reach the PC over any of
  its interfaces.
- **Content-Security-Policy** allows scripts only from the page's own origin,
  never inline, and forbids `object-src`, `base-uri`, `form-action`, and
  `frame-ancestors`.
- Also set: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on every response.
- Peer-supplied values (device names, IDs, IPs, file names) are rendered with
  `textContent` and `createElement` only. `innerHTML` is never used, and the test
  suite fails if it appears.

### Resource limits

An unauthenticated peer must not be able to grow the process or the disk. Every
unbounded table is now capped and swept:

| Resource | Bound | Default |
|---|---|---|
| Tracked transfers | `max_tracked_transfers`, oldest finished evicted first | 2000 |
| Pending incoming transfers | `max_pending_incoming` | 50 |
| Browser sessions | `max_browser_sessions` | 500 |
| WebRTC sessions | `max_webrtc_sessions` | 200 |
| Pairing requests | bounded per caller and overall | 5 / 200 |
| Single file | `max_file_bytes` | 8 GiB |
| Whole transfer | `max_transfer_bytes` | 64 GiB |
| Files per transfer | `max_files_per_transfer` | 1000 |

### Information disclosure

- The server's absolute download path is withheld from `/api/connection` unless
  `SELTRANSFER_EXPOSE_PATHS=true`.
- `/docs`, `/redoc`, and `/openapi.json` are removed unless
  `SELTRANSFER_EXPOSE_DOCS=true`.
- Error responses carry a short message, never a traceback, a filesystem path, a
  token, or an internal type name. Detail goes to the local log.
- Logs contain device IDs, transfer IDs, and client addresses. They contain no
  tokens, no pairing codes, no key material, and no file contents.
- There is no telemetry, no analytics, and no update check. Nothing is sent
  anywhere, ever.

## Transport security

HTTP is the default, and **HTTP traffic is plaintext**. Anyone on the same
network can read the contents of files in transit, and can modify them, though
SHA-256 verification means a modified file is rejected rather than silently
accepted.

TLS is fully implemented but **opt-in**, because a self-signed certificate on a
QR-scanned page produces a certificate warning on every phone connection, which is
a worse first experience than plaintext on a hotspot the user chose:

```powershell
# .env or environment
SELTRANSFER_TLS_ENABLED=true
SELTRANSFER_TLS_CERTFILE=C:\certs\seltransfer.pem
SELTRANSFER_TLS_KEYFILE=C:\certs\seltransfer-key.pem

seltransfer start --tls
```

When TLS is on, the QR code and the printed URL both switch to `https://`.

If TLS is enabled without both files, or with a file that does not exist, startup
**fails with a message naming the problem**. It never falls back to plaintext
silently.

Private keys are read at startup and are never logged, never copied into the
bundle, and never written to the application data directory. Rotate by replacing
the files and restarting. There is no key material in this repository, and a test
enforces that.

## WebRTC

WebRTC is **experimental** and is not the recommended path. HTTP is the default.

- The signalling relay checks that the caller is the session's owner or its peer.
- `iceServers` is empty by design, so the browser never attempts a STUN lookup and
  the feature works with the Internet disconnected. This also means WebRTC cannot
  traverse NAT between subnets.
- No STUN or TURN server is contacted, so no metadata about the local network
  leaves the device.

## Out of scope

These are known and accepted, not oversights:

- **No encryption by default.** See above.
- **The server binds `0.0.0.0`.** Anything that can route to the machine can reach
  the port; pairing, Host validation, and CORS limit what an unauthorised client
  can actually *do*, but this is not a substitute for a trusted network.
- **No rate limiting per IP.** Resource use is bounded by the caps above, but a
  determined peer can still make a great many small requests.
- **No forward secrecy or certificate pinning** beyond what TLS provides.
- **A paired device can send you a file.** Pairing authorises contact, not
  content. The interface is where you decide.
- **`crypto.subtle` is unavailable over a LAN-IP origin** (it requires a secure
  context), so SHA-256 in the browser falls back to a hand-written
  implementation. It is not a security boundary: the server verifies the digest
  regardless.
