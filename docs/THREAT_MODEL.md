# Threat model

Scope: a PC running the SELTRANSFER server on a trusted local network (Wi-Fi,
hotspot, or Ethernet), with phones and other PCs connecting over HTTP. WebRTC
exists but is experimental; HTTP is the default and is what this document covers.

## Trust assumptions

What the design takes for granted, and what it does not.

**Assumed:**

1. The local network is not hostile. Anyone on it can see plaintext traffic and
   can open a TCP connection to the server.
2. The machine's user account is not compromised. The local CLI token and the
   `%LOCALAPPDATA%\SELTRANSFER` directory are readable only by that account.
3. The user is present and chooses the devices they transfer with. A transfer the
   user accepts is intended.
4. Peers are honest about their own metadata unless they are attacking.

**Not assumed:**

- That device IDs are secret. They are readable by any peer via
  `GET /api/devices`, so no authorisation decision relies on one being private.
- That a browser session is unobtainable, **or that having one implies
  authority.** `POST /api/browser/register` is unauthenticated by necessity, so a
  session only proves that some peer asked for one. A session issued to a peer
  that is not this machine carries no pairing rights; see "local user" below.
- That a paired device is trustworthy. Pairing authorises contact, not content.

### The local user

The one privilege that cannot be acquired from the network: this machine's own
user, established either by a session registered from a loopback peer (or the
machine's own LAN address), or by the local CLI token.

This distinction is the whole reason pairing needs a code at all. Treating "has
a session" as "is the owner" lets any device on the LAN pair any other device by
clicking, which is a formality with no proof of intent behind it. Local-user
authority is derived from `request.client.host`, which a remote peer cannot
forge.

## Assets

| Asset | Why it matters |
|---|---|
| File contents in transit | Confidential; **not protected** without TLS |
| Received files on disk | Confidential; protected only by filesystem permissions |
| Upload tokens | Allow writing bytes that look like the sender's |
| Pairing codes | Allow impersonating a paired device |
| Browser session tokens | Allow impersonating a browser device |
| Local CLI token | Allow acting as the local node |
| Transfer and device metadata | Reveals who talks to whom, and file names and sizes |
| The local machine | Reachable on TCP 8765 by anything that can route to it |

## Attackers

### A1 — Unknown device on the LAN

A laptop or phone with no relationship to the user. Can reach the HTTP port.

**Can:** enumerate devices and their IDs; register itself as a browser device;
announce an incoming transfer so it appears in a user's inbox with an
attacker-chosen sender name; read plaintext transfer traffic.

**Cannot:** pair a device (no local-user authority, and no pairing code); read
the code another device's pairing request generated; read or write any transfer it
is not a participant in; obtain an upload token; download a file from the server.

**Residual risk:** a spoofed transfer request can appear in a user's inbox
labelled with a chosen sender name. This is a phishing surface, not a data
exposure. *Mitigation considered:* show the sender's IP alongside the name.
*Not yet implemented.*

### A2 — Malicious browser calling the API directly

A page open in a user's browser, on the Internet, trying to drive the server.

**Cannot, by construction:**

- Make a cross-origin request the server will answer with data — CORS allows only
  private origins, and never with credentials.
- Bypass CORS by having a public domain resolve to the LAN address — the Host
  header check rejects a request naming a public host (DNS rebinding).

**Note the ordering:** CORS alone is insufficient, because a rebinding attack
makes the request look same-origin to the browser. The Host check is the control
that actually stops it, and it is on by default.

### A3 — Paired device reaching for another device's data

A device the user legitimately paired, now trying to read or modify something
that is not its own.

**Cannot:** see a transfer it is not a participant in (`403`), download a file
from it, cancel or pause it, or see it in history. Every one of those is checked
against the caller's session on each request; none relies on the ID being secret.

### A3b — A LAN peer abusing its own session

A peer that registered a browser session and then tries to use it as ownership.

This is the case a session-only model got wrong. The peer legitimately holds a
session, so a check of the form `if session: allow` passes — and it used to let
that peer pair any device on the network, including ones the user never approved.

**Cannot:** pair or unpair directly (`403`, needs local-user authority); read
pending pairing codes (`403`), so it cannot pair anything at all; approve its own
pairing request (`403`), so filing requests in a loop achieves nothing; create a
transfer towards a device it is not paired with (`403`).

**Design note:** approval is the only path, because it needs no second channel at
all. `POST /api/pairing/requests/{id}/approve` requires local-user authority, so
the destination's user clicking is the proof of intent and no secret is ever sent
to the requester. `GET /api/pairing/status/{id}` lets the requester notice the
outcome; it discloses nothing a peer did not already get from `GET /api/devices`.

**Design note:** the pairing code, which survives for API callers only, is
meaningful because the requester cannot read it. `POST .../pair/request` returns no
code and `GET /api/pairing/pending` is local-user only, so obtaining one still
requires a second channel.

**Residual risk:** an attacker who can see the destination's screen (shoulder
surfing, a compromised camera, or a video call) can pair — either by reading a
code or by asking the user to press Approve, which is a prompt-engineering
target. *Mitigation considered:* signed codes bound to the requester, or showing
the requesting device's identity in the Approve prompt. *Not implemented.*

### A4 — Malicious input

Crafted requests, one per class:

| Input | Control |
|---|---|
| `../`, `..\`, absolute, drive, UNC, device paths, null bytes, reserved names | `safe_relative_path`; nothing is written |
| Declared size too small or too large | Rejected at creation and re-checked while streaming |
| Actual bytes exceeding the declared size | Cut off mid-stream; `.part` deleted |
| Corrupt SHA-256 | Transfer marked `FAILED`; `.part` deleted; never `VERIFIED` |
| Too many files, or a total over the cap | Rejected at creation |
| Invalid or unknown transfer ID | 404, no distinction from an unauthorised one |
| Invalid device ID or session ID | 422, alphabet and length constrained |
| Token from another transfer | 401; tokens are per-transfer and constant-time compared |
| Replayed upload for a received index | No-op, decided before anything is written |
| Malformed JSON, wrong content type | 422, no traceback in the body |
| A public `Origin` | No CORS headers returned |
| Hostile device name, IP, or filename in the DOM | `textContent` only; `innerHTML` unused and tested against |

### A5 — Resource exhaustion

A peer trying to exhaust disk, RAM, CPU, connections, or SQLite.

**Bounded now:** tracked transfers (2000), pending incoming (50), browser sessions
(500), WebRTC sessions (200), pairing requests (5 per caller), file size, transfer
size, and file count. Expired state is deleted on access *and* on a 60-second timer,
so an idle server does not accumulate. Upload byte counts are rolled back on
every failure path, and a failed upload leaves no `.part` file.

**Not bounded:** request *rate*. A peer can make many small requests. SQLite
history rows are retained indefinitely, so sustained traffic grows the history
database slowly. *Accepted for a local-network tool; noted as a limitation.*

### A6 — Malicious sender, malformed or oversized file

Covered by A4 and A5. The notable property is that **integrity is decided before
success is recorded**: a file is only moved out of `.part` after its size and
SHA-256 both match, so a transfer cannot reach `VERIFIED` with unverified content.

## Data flow

```
   sender (browser or CLI)
        |  1. POST /api/transfers        (needs pairing)
        v
   [ PC server ]  -- creates transfer, mints a per-transfer upload token
        ^
        |  2. phone GET /api/incoming-transfers   (session-scoped)
        |  3. phone POST .../accept               (receiver only)
        |  4. sender PUT .../files/N              (token, receiver has accepted)
        |  5. phone GET  .../files/N              (receiver only)
        v
   [ phone browser ]  -> saves via its own download settings

   Native receiver: bytes land in %LOCALAPPDATA%\SELTRANSFER\downloads\
```

The design point: **a browser cannot listen for an inbound connection**, so both
ends are clients of the same server. For the default HTTP path the phone only
needs to *reach* the PC, which is why a phone-hosted hotspot works even though the
phone is also the network's router.

## Controls not yet implemented

Recorded so they are not mistaken for oversights:

- Per-IP rate limiting.
- History row retention or pruning.
- Sender IP shown next to a transfer name in the inbox.
- Client certificate authentication, for a network where the PC matters more than
  the network.
- Signed pairing codes, so a code cannot be shoulder-surfed from a screen.
