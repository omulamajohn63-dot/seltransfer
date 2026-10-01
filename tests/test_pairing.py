"""Pairing requires proof of intent.

Before this change ``POST /api/devices/{id}/pair`` had no authentication at all:
any peer on the LAN could pair any device, because device IDs are readable from
the unauthenticated ``GET /api/devices``, and pairing is the precondition for
creating a transfer. Discovery was therefore a send channel.

These tests cover the replacement: an out-of-band code, single use, expiring,
attempt-limited, and never stored in the clear.
"""

from __future__ import annotations

import time

import pytest

from seltransfer.pairing import (
    CODE_LENGTH,
    MAX_ATTEMPTS,
    MAX_PENDING_PER_REQUESTER,
    PairingRegistry,
    generate_code,
    normalise_code,
)

DEVICE = "victim-phone-0001"
REQUESTER = "attacker-machine"


def _read_code(registry: PairingRegistry, device_id: str = DEVICE) -> str:
    """Read the code the way the *destination* does, not the requester.

    ``request()`` deliberately does not return it - that was the bug - so tests
    have to go through the destination-side accessor to get a valid code.
    """
    pending = registry.reveal_pending(device_id)
    assert pending, "no pending request to read a code from"
    return str(pending[0]["code"])


# --- the credential itself ---------------------------------------------------


def test_code_is_the_expected_length_and_alphabet() -> None:
    code = generate_code()
    assert len(code) == CODE_LENGTH
    assert code.isdigit()


def test_code_is_digits_only() -> None:
    """Numeric, so there is no glyph to misread.

    The earlier letter+digit alphabet had to exclude 0/O and 1/I/L to stay
    transcribable. Going digits-only removes that class of error at the source
    instead of paying entropy for it, which is the whole point of the change.
    """
    for _ in range(200):
        code = generate_code()
        assert set(code) <= set("0123456789"), code
        assert not any(character.isalpha() for character in code), code


def test_codes_do_not_repeat() -> None:
    codes = {generate_code() for _ in range(500)}
    assert len(codes) == 500, "codes must not collide"


def test_code_carries_enough_entropy() -> None:
    """Brute force must be hopeless inside the request window.

    Eight digits is ~26.6 bits, which is less than the mixed alphabet allowed, so
    the throttling is what has to carry it: MAX_ATTEMPTS per request, MAX_PENDING
    per requester, and a short code_ttl. One request therefore offers a handful of
    guesses against a 10**8 space, and the probability of any of them landing is
    far below 1 in a million.
    """
    from seltransfer.pairing import CODE_ALPHABET_SIZE, code_entropy_bits

    assert CODE_ALPHABET_SIZE == 10
    assert 26 <= code_entropy_bits() <= 27
    assert MAX_ATTEMPTS / 10 ** CODE_LENGTH < 1e-6


def test_normalise_accepts_what_a_user_would_type() -> None:
    # Spaces and dashes are both plausible when copying a code off a screen or a
    # message; neither should change its value.
    assert normalise_code("1234-5678") == "12345678"
    assert normalise_code("  1234 5678  ") == "12345678"
    assert normalise_code("") == ""
    assert normalise_code(None) == ""


def test_normalise_drops_characters_outside_the_alphabet() -> None:
    """Non-digits are ignored rather than reinterpreted.

    Substituting a letter for a lookalike digit would turn a misread glyph into a
    correct guess, which is exactly the ambiguity a numeric code removes.
    """
    assert normalise_code("12O45678") == "1245678"
    assert normalise_code("l2345678") == "2345678"
    assert normalise_code("abc") == ""


# --- the request/confirm cycle ----------------------------------------------


def test_confirming_a_code_grants_a_pairing() -> None:
    registry = PairingRegistry()
    request = registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)
    assert not registry.is_paired(DEVICE)

    pairing = registry.confirm(DEVICE, REQUESTER, code)

    assert registry.is_paired(DEVICE)
    assert pairing.device_id == DEVICE
    assert pairing.granted_by == REQUESTER
    assert request.request_id  # sanity: a request really was created


def test_wrong_code_is_refused() -> None:
    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)
    wrong = "".join("Z" if character != "Z" else "Y" for character in code)

    with pytest.raises(PermissionError):
        registry.confirm(DEVICE, REQUESTER, wrong)
    assert not registry.is_paired(DEVICE)


def test_code_for_another_device_does_not_work() -> None:
    """Presenting a valid code against the wrong device must fail."""
    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)

    with pytest.raises(LookupError):
        registry.confirm("some-other-device", REQUESTER, code)
    assert not registry.is_paired("some-other-device")
    assert not registry.is_paired(DEVICE)


def test_code_from_another_requester_does_not_work() -> None:
    """A third party who observes a request cannot claim it."""
    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)

    with pytest.raises(LookupError):
        registry.confirm(DEVICE, "someone-else", code)
    assert not registry.is_paired(DEVICE)


def test_confirm_with_no_request_is_refused() -> None:
    registry = PairingRegistry()
    with pytest.raises(LookupError):
        registry.confirm(DEVICE, REQUESTER, "ABCD2345")


# --- replay ------------------------------------------------------------------


def test_a_code_cannot_be_replayed() -> None:
    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)
    assert registry.confirm(DEVICE, REQUESTER, code)

    # Same device, fresh attempt with the same code must not silently succeed.
    with pytest.raises(LookupError):
        registry.confirm(DEVICE, REQUESTER, code)


def test_confirmed_request_is_consumed() -> None:
    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)
    registry.confirm(DEVICE, REQUESTER, code)
    assert not registry.pending_for(DEVICE)


# --- expiry ------------------------------------------------------------------


def test_request_expires() -> None:
    registry = PairingRegistry(code_ttl=0.01)
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)
    time.sleep(0.05)

    with pytest.raises(LookupError):
        registry.confirm(DEVICE, REQUESTER, code)
    assert not registry.is_paired(DEVICE)


def test_pairing_expires() -> None:
    registry = PairingRegistry(pairing_ttl=0.01)
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)
    registry.confirm(DEVICE, REQUESTER, code)
    assert registry.is_paired(DEVICE)

    time.sleep(0.05)
    assert not registry.is_paired(DEVICE)
    assert registry.get(DEVICE) is None


def test_sweep_removes_expired_entries() -> None:
    registry = PairingRegistry(code_ttl=0.01, pairing_ttl=0.01)
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)
    registry.confirm(DEVICE, REQUESTER, code)
    assert registry.stats()["active_pairings"] == 1

    time.sleep(0.05)
    registry.sweep()
    stats = registry.stats()
    assert stats["active_pairings"] == 0
    assert stats["pending_requests"] == 0


# --- brute force -------------------------------------------------------------


def test_attempts_are_limited() -> None:
    """A wrong code must not be guessable by repetition."""
    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)

    for _ in range(MAX_ATTEMPTS):
        with pytest.raises(PermissionError):
            registry.confirm(DEVICE, REQUESTER, "WRONG123")

    # Even the correct code is now refused: the request is burnt.
    with pytest.raises((PermissionError, LookupError)):
        registry.confirm(DEVICE, REQUESTER, code)
    assert not registry.is_paired(DEVICE)


def test_pending_requests_per_requester_are_capped() -> None:
    registry = PairingRegistry()
    for _ in range(MAX_PENDING_PER_REQUESTER):
        registry.request(DEVICE, REQUESTER)
    with pytest.raises(LookupError):
        registry.request(DEVICE, REQUESTER)


def test_registry_is_bounded_under_flood() -> None:
    """Memory must stay bounded even if a peer floods the endpoint."""
    registry = PairingRegistry(max_pending=20)
    for index in range(500):
        try:
            registry.request(f"device-{index:04d}", REQUESTER)
        except LookupError:
            break
    assert registry.stats()["pending_requests"] <= 20


# --- secrets handling --------------------------------------------------------
#
# The destination has to be able to *display* a code, so the clear code is held in
# memory for the lifetime of the request. What matters instead is that it never
# leaks to the requester, and that it stays out of anything that could be logged or
# serialised by accident.


def test_the_clear_code_is_not_in_a_repr() -> None:
    """`repr=False` keeps it out of tracebacks and out of a logged request object."""
    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)

    assert code not in repr(registry.__dict__)
    assert code not in repr(registry.pending_for(DEVICE)[0])


def test_the_public_payload_never_carries_the_code() -> None:
    """`public()` is what the requester receives, so it must not contain it."""
    registry = PairingRegistry()
    request = registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)

    assert code not in repr(request.public())
    assert "code" not in request.public()
    assert set(request.public()) >= {"request_id", "device_id", "status",
                                     "seconds_remaining"}


def test_only_the_destination_accessor_yields_the_code() -> None:
    """`reveal_pending` is the single path to a code, and it is explicit."""
    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)

    revealed = registry.reveal_pending(DEVICE)
    assert len(revealed) == 1
    assert revealed[0]["code"]
    # It is additive, not a replacement: the public shape is unchanged underneath.
    assert revealed[0]["request_id"]
    assert "code" not in registry.pending_for(DEVICE)[0].public()


def test_stats_expose_no_codes() -> None:
    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)
    assert code not in repr(registry.stats())


def test_codes_are_salted_per_request() -> None:
    """Two requests must not produce the same stored hash for the same code."""
    from seltransfer.pairing import hash_code

    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)
    first = registry.reveal_pending(DEVICE)[0]
    code = str(first["code"])
    salt = registry.pending_for(DEVICE)[0].salt

    registry.request(DEVICE, REQUESTER)
    second_salt = registry.pending_for(DEVICE)[-1].salt

    assert salt and second_salt and salt != second_salt
    assert hash_code(code, salt) != hash_code(code, second_salt)


# --- approval (destination user clicks) --------------------------------------


def test_approving_a_request_grants_a_pairing() -> None:
    registry = PairingRegistry()
    pending = registry.request(DEVICE, REQUESTER)

    granted = registry.approve(pending.request_id, "local-browser-1")

    assert registry.is_paired(DEVICE)
    assert granted.device_id == DEVICE
    assert granted.method == "approved"
    assert granted.granted_by == "local-browser-1"


def test_approving_consumes_the_request() -> None:
    """Approving must not leave a live code behind.

    Otherwise approval and confirmation are two pairings from one request, and
    the code outlives the interaction that was supposed to authorise it.
    """
    registry = PairingRegistry()
    pending = registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)

    registry.approve(pending.request_id, "local-browser-1")

    assert not registry.pending_for(DEVICE)
    with pytest.raises(LookupError):
        registry.confirm(DEVICE, REQUESTER, code)


def test_approving_twice_is_refused() -> None:
    registry = PairingRegistry()
    pending = registry.request(DEVICE, REQUESTER)
    registry.approve(pending.request_id, "local-browser-1")

    with pytest.raises(LookupError):
        registry.approve(pending.request_id, "local-browser-1")


def test_approving_an_expired_request_is_refused() -> None:
    """Expiry reads as 'gone', not as 'too late'.

    Distinguishing the two would tell an unauthenticated caller whether a request
    id was ever real, which is a needless side channel.
    """
    registry = PairingRegistry(code_ttl=0.0)
    pending = registry.request(DEVICE, REQUESTER)

    with pytest.raises(LookupError):
        registry.approve(pending.request_id, "local-browser-1")
    assert not registry.is_paired(DEVICE)


def test_approving_an_unknown_request_is_refused() -> None:
    registry = PairingRegistry()
    with pytest.raises(LookupError):
        registry.approve("no-such-request", "local-browser-1")


def test_approval_needs_no_code_at_all() -> None:
    """The click is the intent, so nothing has to be transcribed.

    This is what lets the requester interface stop asking for a code without
    making pairing self-service: the requester cannot approve, so flooding
    requests still produces nothing.
    """
    registry = PairingRegistry()
    pending = registry.request(DEVICE, REQUESTER)

    granted = registry.approve(pending.request_id, "local-browser-1")

    assert granted.created_at >= pending.created_at
    assert registry.stats()["pending_requests"] == 0


# --- direct grant (local session path) ---------------------------------------


def test_direct_grant_is_supported_for_a_local_session() -> None:
    registry = PairingRegistry()
    registry.grant_directly(DEVICE, "local-browser-1", "session")
    assert registry.is_paired(DEVICE)
    assert registry.get(DEVICE).method == "session"


def test_unpair_removes_the_pairing_and_its_requests() -> None:
    registry = PairingRegistry()
    registry.request(DEVICE, REQUESTER)
    code = _read_code(registry)
    registry.grant_directly(DEVICE, "local-browser-1", "session")

    registry.unpair(DEVICE)

    assert not registry.is_paired(DEVICE)
    assert not registry.pending_for(DEVICE)
    with pytest.raises(LookupError):
        registry.confirm(DEVICE, REQUESTER, code)
