"""Pairing: proving intent before a device may be contacted.

Pairing used to be ``POST /api/devices/{id}/pair`` with no authentication at all.
Any peer on the LAN could pair any device, because device IDs are readable from
the unauthenticated ``GET /api/devices``. Pairing is the precondition for
creating a transfer, so that turned discovery into a send channel.

The fix is an out-of-band code. The destination produces a short code and shows
it in the web interface; the requester reads it off that screen and presents it.
Possession of the code is the proof of intent, which is the same model a door
keypad uses. The other path is approval: this machine's own user clicks Approve
on the pending request, and that click is the intent, so nothing has to be
transcribed.

The requester is never told the code. That is the whole point, and getting it
wrong is what made the first attempt at this worthless: ``request()`` returned
the code to whoever called it, so a peer with no session and no local token could
call ``/pair/request``, read the code out of the response, and immediately call
``/pair/confirm`` with it. Two unauthenticated requests, and pairing was done -
there was no out-of-band element at all. The code is now readable only through
:meth:`PairingRegistry.reveal_pending`, which the HTTP layer exposes solely to
the machine's own user (see the ``/api/pairing/pending`` route).

Design constraints this module satisfies:

* **Unpredictable.** Codes come from :mod:`secrets` over a digit-only alphabet,
  and are compared in constant time.
* **Single use.** A confirmed or approved request is consumed, so a replayed code
  does nothing.
* **Short lived.** A request expires, so a code left on a screen is worthless
  shortly afterwards.
* **Only the destination can read a code.** See above.
* **Only the destination's user can approve.** See :meth:`PairingRegistry.approve`.
* **Salted on storage**, so a dump of one hash does not confirm a guessed code.
* **Rate limited per requester**, so codes cannot be brute-forced.
* **No accidental logging.** Nothing here logs a code.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

# Digits only. A mixed letter+digit alphabet has to drop the glyphs that are hard
# to tell apart (0/O, 1/I/L), which costs entropy; going numeric removes the
# confusion at its source instead, so nothing is excluded and a numeric keypad
# covers the whole alphabet. Eight digits is ~26.6 bits, which is below what a
# mixed alphabet allowed, and that is a deliberate trade: online guessing is
# capped at MAX_ATTEMPTS per request with MAX_PENDING_PER_REQUESTER outstanding and
# a short code_ttl, so the reachable guesses per window are in the tens against a
# 10**8 space. The stronger option remains approval, which involves no guessing.
_ALPHABET = "0123456789"
CODE_LENGTH = 8
CODE_ALPHABET_SIZE = len(_ALPHABET)

MAX_ATTEMPTS = 5
MAX_PENDING_PER_REQUESTER = 5


def generate_code() -> str:
    """Return a fresh, human-transcribable pairing code."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(CODE_LENGTH))


def code_entropy_bits() -> float:
    """Estimated bits of entropy in one code, for documentation and tests."""
    return CODE_LENGTH * math.log2(CODE_ALPHABET_SIZE)


def normalise_code(candidate: str | None) -> str:
    """Fold a user-typed code to the canonical form.

    Users add spaces or dashes, or paste from a message. Comparing the normalised
    form is what makes the code usable by hand without weakening it.

    Characters outside the alphabet are dropped, never substituted. Mapping a
    letter onto a digit that looks like it would turn a misread glyph into a
    correct guess, which is exactly the ambiguity the numeric alphabet exists to
    avoid.
    """
    if not candidate:
        return ""
    return "".join(
        character for character in candidate if character in _ALPHABET
    )


def hash_code(code: str, salt: str) -> str:
    """Salted hash of a code, so a stored request cannot be replayed."""
    return hashlib.sha256(f"{salt}:{normalise_code(code)}".encode()).hexdigest()


@dataclass
class PairingRequest:
    """A pending request to pair, created by an unauthenticated requester."""

    request_id: str
    device_id: str
    requester_id: str
    code_hash: str
    salt: str
    created_at: float
    expires_at: float
    # The clear code, held only so the destination can display it. `repr=False` keeps
    # it out of tracebacks and out of any accidental log of a request object. It is
    # never part of `public()`, which is the payload the requester receives.
    code: str = field(default="", repr=False)
    attempts: int = 0
    confirmed: bool = False
    confirmed_at: float | None = None

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def is_spent(self) -> bool:
        return self.confirmed

    def can_attempt(self, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        return not (self.is_expired(now) or self.is_spent()
                    or self.attempts >= MAX_ATTEMPTS)

    def public(self, now: float | None = None) -> dict[str, Any]:
        """A description safe to show the requester.

        The code is deliberately absent: the requester must learn it from the
        destination, out of band. Sending it here would let any peer pair any
        device with two requests and no interaction at all.
        """
        now = now if now is not None else time.time()
        return {
            "request_id": self.request_id,
            "device_id": self.device_id,
            "expires_at": self.expires_at,
            "seconds_remaining": max(0, int(self.expires_at - now)),
            "status": (
                "expired" if self.is_expired(now)
                else "confirmed" if self.confirmed
                else "pending"
            ),
        }

    def reveal(self, now: float | None = None) -> dict[str, Any]:
        """A description including the code, for display at the destination only."""
        now = now if now is not None else time.time()
        return {**self.public(now), "code": self.code}


@dataclass
class Pairing:
    """A confirmed pairing, which does expire."""

    device_id: str
    granted_by: str
    created_at: float
    expires_at: float
    method: str = "code"
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def public(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "granted_by": self.granted_by,
            "method": self.method,
            "expires_at": self.expires_at,
        }


class PairingRegistry:
    """Pending requests and confirmed pairings, both bounded and expiring."""

    def __init__(self, code_ttl: float = 120.0, pairing_ttl: float = 86_400.0,
                 max_pending: int = 200, max_pairings: int = 500) -> None:
        self.code_ttl = code_ttl
        self.pairing_ttl = pairing_ttl
        self.max_pending = max_pending
        self.max_pairings = max_pairings
        self._requests: dict[str, PairingRequest] = {}
        self._pairings: dict[str, Pairing] = {}
        self._lock = threading.RLock()

    # -- housekeeping ---------------------------------------------------------

    def sweep(self, now: float | None = None) -> None:
        """Drop expired requests and pairings.

        Called on access and on a timer, because otherwise the dictionaries are a
        slow memory leak driven by an unauthenticated peer.
        """
        now = now if now is not None else time.time()
        with self._lock:
            for request_id in [
                key for key, value in self._requests.items()
                if value.is_expired(now) or value.is_spent()
            ]:
                del self._requests[request_id]
            for device_id in [
                key for key, value in self._pairings.items() if value.is_expired(now)
            ]:
                del self._pairings[device_id]

    def _bound(self) -> None:
        """Refuse to grow without bound under a flood of requests."""
        self.sweep()
        if len(self._requests) > self.max_pending:
            oldest = sorted(
                self._requests.values(),
                key=lambda request: request.created_at,
            )
            for request in oldest[:len(self._requests) - self.max_pending]:
                self._requests.pop(request.request_id, None)
        if len(self._pairings) > self.max_pairings:
            oldest_pairings = sorted(
                self._pairings.values(),
                key=lambda pairing: pairing.created_at,
            )
            for pairing in oldest_pairings[:len(self._pairings) - self.max_pairings]:
                self._pairings.pop(pairing.device_id, None)

    # -- requester side -------------------------------------------------------

    def request(self, device_id: str, requester_id: str,
                now: float | None = None) -> PairingRequest:
        """Create a pending request. The code is *not* returned.

        Returning it here is the bug this signature exists to prevent: the caller
        of this method is the untrusted requester, so handing back the code would
        let it confirm its own pairing without any out-of-band step. Use
        :meth:`reveal_pending` to read codes, and only from the destination side.
        """
        now = now if now is not None else time.time()
        with self._lock:
            self._bound()
            mine = [
                value for value in self._requests.values()
                if value.requester_id == requester_id and not value.is_expired(now)
            ]
            if len(mine) >= MAX_PENDING_PER_REQUESTER:
                raise LookupError("too many pending pairing requests")
            code = generate_code()
            # A per-request salt, so identical codes never hash alike and a stolen
            # hash cannot be replayed against a new request.
            salt = secrets.token_hex(16)
            request = PairingRequest(
                request_id=secrets.token_urlsafe(16),
                device_id=device_id,
                requester_id=requester_id,
                code_hash=hash_code(code, salt),
                salt=salt,
                created_at=now,
                expires_at=now + self.code_ttl,
                code=code,
            )
            self._requests[request.request_id] = request
            return request

    def confirm(self, device_id: str, requester_id: str, code: str,
                now: float | None = None) -> Pairing:
        """Exchange a code for a pairing.

        Raises:
            LookupError: no matching pending request.
            PermissionError: wrong code, or the attempts are exhausted.
        """
        now = now if now is not None else time.time()
        with self._lock:
            self.sweep(now)
            candidate = None
            for request in self._requests.values():
                if (request.device_id == device_id
                        and request.requester_id == requester_id
                        and not request.is_spent()
                        and not request.is_expired(now)):
                    candidate = request
                    break
            if candidate is None:
                raise LookupError("no pending pairing request for this device")
            if not candidate.can_attempt(now):
                raise PermissionError("too many failed pairing attempts")
            expected = candidate.code_hash
            candidate.attempts += 1
            supplied = hash_code(code, candidate.salt)
            if not hmac.compare_digest(supplied, expected):
                raise PermissionError("invalid pairing code")
            candidate.confirmed = True
            candidate.confirmed_at = now
            pairing = Pairing(
                device_id=device_id,
                granted_by=requester_id,
                created_at=now,
                expires_at=now + self.pairing_ttl,
            )
            self._pairings[device_id] = pairing
            # Single use: the request cannot confirm a second pairing.
            del self._requests[candidate.request_id]
            return pairing

    # -- destination side -----------------------------------------------------

    def approve(self, request_id: str, granted_by: str,
                now: float | None = None) -> Pairing:
        """Grant a pairing because the destination's own user clicked Approve.

        The click is the proof of intent, so there is no code to read out and no
        secret to hand the requester. This is strictly stronger than confirming a
        code: an attacker who floods requests still cannot approve any of them.

        Raises:
            LookupError: no such pending request. Expired and already-used requests
                report this too, because ``_bound()`` sweeps them first; collapsing
                the three cases keeps expiry from being observable.
        """
        now = now if now is not None else time.time()
        with self._lock:
            self._bound()
            request = self._requests.get(request_id)
            if request is None:
                raise LookupError("no such pending pairing request")
            pairing = Pairing(
                device_id=request.device_id,
                granted_by=granted_by,
                created_at=now,
                expires_at=now + self.pairing_ttl,
                method="approved",
            )
            self._pairings[request.device_id] = pairing
            # Single use, same as confirm(): approving must not leave a live code
            # behind that could be replayed for a second pairing.
            del self._requests[request_id]
            return pairing

    # -- queries --------------------------------------------------------------

    def is_paired(self, device_id: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        with self._lock:
            pairing = self._pairings.get(device_id)
            return bool(pairing and not pairing.is_expired(now))

    def get(self, device_id: str, now: float | None = None) -> Pairing | None:
        now = now if now is not None else time.time()
        with self._lock:
            pairing = self._pairings.get(device_id)
            if pairing and pairing.is_expired(now):
                del self._pairings[device_id]
                return None
            return pairing

    def unpair(self, device_id: str) -> bool:
        with self._lock:
            self._pairings.pop(device_id, None)
            for request_id, request in list(self._requests.items()):
                if request.device_id == device_id:
                    del self._requests[request_id]
            return True

    def paired_devices(self, now: float | None = None) -> set[str]:
        now = now if now is not None else time.time()
        with self._lock:
            self.sweep(now)
            return set(self._pairings)

    def grant_directly(self, device_id: str, granted_by: str, method: str,
                       now: float | None = None) -> Pairing:
        """Pair without a code.

        Reserved for callers that have already proven intent by a different
        route - a registered browser session confirming a device the user
        selected in its own interface. Never reachable by an unauthenticated
        peer.
        """
        now = now if now is not None else time.time()
        with self._lock:
            self._bound()
            pairing = Pairing(
                device_id=device_id,
                granted_by=granted_by,
                created_at=now,
                expires_at=now + self.pairing_ttl,
                method=method,
            )
            self._pairings[device_id] = pairing
            return pairing

    def pending_for(self, device_id: str,
                    now: float | None = None) -> list[PairingRequest]:
        now = now if now is not None else time.time()
        with self._lock:
            self.sweep(now)
            return [
                request for request in self._requests.values()
                if request.device_id == device_id
            ]

    def reveal_pending(self, device_id: str | None = None,
                       now: float | None = None) -> list[dict[str, Any]]:
        """Pending requests *with* their codes, for display at the destination.

        This is the only way to obtain a code, and the caller is responsible for
        exposing it only to the machine's own user. ``device_id=None`` returns every
        pending request, which is what the local interface polls.
        """
        now = now if now is not None else time.time()
        with self._lock:
            self.sweep(now)
            return [
                request.reveal(now) for request in self._requests.values()
                if device_id is None or request.device_id == device_id
            ]

    def stats(self) -> dict[str, int]:
        """Counts for `doctor`. Contains no codes and no hashes."""
        with self._lock:
            return {
                "pending_requests": len(self._requests),
                "active_pairings": len(self._pairings),
            }
