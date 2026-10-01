"""Every path a peer supplies must stay inside the download directory.

Two classes of defect are covered. The first is traversal: a name that escapes the
download root, whether by separator, by drive, or by UNC. The second is silent
data loss: Windows device names such as ``CON`` and ``NUL`` are accepted by
``Path`` but do not name files, so writing them either fails or discards data.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from seltransfer.storage import HistoryStore
from seltransfer.transfers import (
    TransferManager,
    safe_relative_path,
    sweep_expired_transfers,
)

# Traversal, absolute paths, and Windows-specific hazards.
HOSTILE_NAMES = [
    "../escape.txt",
    "../../escape.txt",
    "a/../../escape.txt",
    "..\\..\\windows\\system32\\evil.dll",
    "folder/..\\..\\escape.txt",
    "/etc/passwd",
    "/absolute.txt",
    "\\absolute.txt",
    "C:/Windows/evil.dll",
    "C:\\Windows\\evil.dll",
    "c:/windows/system32/config/sam",
    "\\\\server\\share\\evil.dll",
    "\\\\?\\C:\\evil.dll",
    "\\\\.\\PhysicalDrive0",
    "..",
    ".",
    "",
    "a//b.txt",
    "a/./b.txt",
]

# Names Windows treats as devices, not files.
RESERVED_NAMES = [
    "CON", "con", "Con.txt", "NUL", "nul.txt", "PRN", "AUX", "LPT1",
    "COM1", "com9.log", "LPT9", "CON.tar.gz", "folder/CON", "folder/NUL.txt",
]

# Names that are legal and must keep working.
LEGITIMATE_NAMES = [
    "report.pdf",
    "photos/img_0001.jpg",
    "a/b/c/d.txt",
    "file with spaces.txt",
    "unicode-名前.txt",
    "dots.in.the.middle.tar.gz",
    " leading-space-trimmed.txt",
    "trailing-dots...",
    "-leading-dash.txt",
    "_underscore.txt",
]


@pytest.mark.parametrize("value", HOSTILE_NAMES)
def test_hostile_names_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        safe_relative_path(value)


@pytest.mark.parametrize("value", RESERVED_NAMES)
def test_reserved_device_names_are_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="reserved|invalid"):
        safe_relative_path(value)


@pytest.mark.parametrize("value", LEGITIMATE_NAMES)
def test_legitimate_names_are_accepted(value: str) -> None:
    result = safe_relative_path(value)
    assert result.name, value
    assert ".." not in result.parts


@pytest.mark.parametrize("value", ["a\x00b.txt", "bell\x07.txt", "tab\tx.txt",
                                   "newline\nx.txt", "cr\rx.txt"])
def test_control_characters_are_handled(value: str) -> None:
    """Control characters must not survive into a filename.

    They are either rejected or replaced; what must never happen is the raw
    control byte being written to the filesystem, where it can truncate a name in
    a downstream tool.
    """
    try:
        result = safe_relative_path(value)
    except ValueError:
        return
    assert all(ord(character) >= 32 for character in str(result)), repr(result)


def test_reserved_name_in_a_folder_is_rejected() -> None:
    """The check applies to every segment, not just the leaf."""
    with pytest.raises(ValueError):
        safe_relative_path("photos/PRN/inner.txt")


def test_encoded_traversal_is_still_traversal() -> None:
    """Percent-encoding is decoded before we ever see the name.

    This test documents the assumption rather than proving it: FastAPI decodes the
    JSON body, so "%2e%2e%2f" arrives as "../" and is caught by the same check.
    """
    from urllib.parse import unquote

    decoded = unquote("%2e%2e%2fescape.txt")
    with pytest.raises(ValueError):
        safe_relative_path(decoded)


def test_double_encoded_traversal_is_still_traversal() -> None:
    from urllib.parse import unquote

    decoded = unquote(unquote("%252e%252e%252fescape.txt"))
    with pytest.raises(ValueError):
        safe_relative_path(decoded)


# --- containment on the write path ------------------------------------------


@pytest.fixture
def manager(tmp_path):
    return TransferManager(tmp_path / "downloads",
                           HistoryStore(tmp_path / "history.db"))


def _accepted(manager, name, payload, **extra):
    transfer = manager.create(
        "sender-node", "receiver-node",
        [{"name": name, "size": len(payload),
          "sha256": hashlib.sha256(payload).hexdigest(), **extra}])
    manager.update_state(transfer["transfer_id"], "ACCEPTED")
    return transfer


class Stream:
    def __init__(self, payload):
        self.payload = payload

    async def __aiter__(self):
        for index in range(0, len(self.payload), 8):
            yield self.payload[index:index + 8]


@pytest.mark.asyncio
async def test_a_nested_path_stays_inside_the_download_root(manager) -> None:
    payload = b"nested content"
    transfer = _accepted(manager, "a/b/c.txt", payload)
    await manager.receive_file(transfer["transfer_id"], 0, Stream(payload),
                               manager.get(transfer["transfer_id"])["token"])

    written = manager.get(transfer["transfer_id"])["received_files"]["0"]
    resolved = Path(written).resolve()
    assert resolved.is_relative_to(manager.download_root.resolve())


@pytest.mark.asyncio
async def test_hostile_name_is_refused_before_anything_is_written(manager) -> None:
    with pytest.raises(ValueError):
        _accepted(manager, "../escape.txt", b"x")
    assert not (manager.download_root.parent / "escape.txt").exists()
    assert not list(manager.download_root.rglob("*.part"))


@pytest.mark.asyncio
async def test_reserved_name_never_reaches_the_filesystem(manager) -> None:
    with pytest.raises(ValueError):
        _accepted(manager, "NUL.txt", b"x")
    assert not list(manager.download_root.rglob("NUL*"))


# --- index-keyed received files ---------------------------------------------


@pytest.mark.asyncio
async def test_out_of_order_uploads_are_recorded_by_index(manager) -> None:
    """The bug this pins: a positional list served the wrong file.

    The download route reads by declared index, so the record has to be keyed the
    same way. Uploading index 1 first used to make index 0 resolve to index 1's
    bytes.
    """
    payload = [b"alpha-content", b"bravo-content"]
    transfer = manager.create("sender-node", "receiver-node", [
        {"name": "ALPHA.txt", "size": len(payload[0])},
        {"name": "BRAVO.txt", "size": len(payload[1])},
    ])
    manager.update_state(transfer["transfer_id"], "ACCEPTED")
    token = manager.get(transfer["transfer_id"])["token"]

    await manager.receive_file(transfer["transfer_id"], 1, Stream(payload[1]), token)
    await manager.receive_file(transfer["transfer_id"], 0, Stream(payload[0]), token)

    received = manager.get(transfer["transfer_id"])["received_files"]
    assert Path(received["0"]).read_bytes() == payload[0]
    assert Path(received["1"]).read_bytes() == payload[1]


@pytest.mark.asyncio
async def test_duplicate_upload_does_not_double_count(manager) -> None:
    payload = b"exactly-twelve"
    transfer = _accepted(manager, "dup.txt", payload)
    token = manager.get(transfer["transfer_id"])["token"]

    await manager.receive_file(transfer["transfer_id"], 0, Stream(payload), token)
    first = dict(manager.get(transfer["transfer_id"]))
    # Rewind the state so a repeat is permitted, as a client retry would be.
    manager.get(transfer["transfer_id"])["status"] = "TRANSFERRING"
    await manager.receive_file(transfer["transfer_id"], 0, Stream(payload), token)
    second = manager.get(transfer["transfer_id"])

    assert len(second["received_files"]) == 1
    assert second["transferred_bytes"] == first["transferred_bytes"] == len(payload)
    assert second["status"] == "VERIFIED"


@pytest.mark.asyncio
async def test_partial_completion_is_not_verified(manager) -> None:
    """VERIFIED must require every declared file, not a count that lines up."""
    transfer = manager.create("sender-node", "receiver-node", [
        {"name": "one.txt", "size": 3},
        {"name": "two.txt", "size": 3},
    ])
    manager.update_state(transfer["transfer_id"], "ACCEPTED")
    token = manager.get(transfer["transfer_id"])["token"]

    result = await manager.receive_file(transfer["transfer_id"], 0,
                                        Stream(b"abc"), token)
    assert result["status"] == "TRANSFERRING"
    assert list(result["received_files"]) == ["0"]


# --- bounded state -----------------------------------------------------------


def test_transfer_table_is_bounded(tmp_path) -> None:
    """An unauthenticated peer creates transfers; the table must not grow forever."""
    manager = TransferManager(tmp_path / "downloads",
                              HistoryStore(tmp_path / "history.db"),
                              max_tracked=10)
    for index in range(60):
        transfer = manager.create(f"sender-{index}", "receiver-node",
                                  [{"name": f"f{index}.txt", "size": 1}])
        # Finish them, so eviction is allowed to touch them.
        manager.update_state(transfer["transfer_id"], "REJECTED")
    assert len(manager.transfers) <= 10, len(manager.transfers)


def test_eviction_keeps_live_transfers(tmp_path) -> None:
    """Dropping a transfer that is still active would strand a download."""
    manager = TransferManager(tmp_path / "downloads",
                              HistoryStore(tmp_path / "history.db"),
                              max_tracked=2)
    live = manager.create("sender-node", "receiver-node",
                          [{"name": "live.txt", "size": 1}])
    for index in range(10):
        transfer = manager.create(f"sender-{index}", "receiver-node",
                                  [{"name": f"f{index}.txt", "size": 1}])
        manager.update_state(transfer["transfer_id"], "REJECTED")
    assert live["transfer_id"] in manager.transfers


def test_sweep_removes_old_finished_transfers(tmp_path) -> None:
    manager = TransferManager(tmp_path / "downloads",
                              HistoryStore(tmp_path / "history.db"))
    finished = manager.create("sender-node", "receiver-node",
                              [{"name": "f.txt", "size": 1}])
    # PENDING -> REJECTED is a legal terminal transition.
    manager.update_state(finished["transfer_id"], "REJECTED")
    live = manager.create("sender-node", "receiver-node",
                          [{"name": "g.txt", "size": 1}])

    removed = sweep_expired_transfers(manager, max_age_seconds=-1)

    assert removed == 1
    assert finished["transfer_id"] not in manager.transfers
    assert live["transfer_id"] in manager.transfers


def test_sweep_without_an_age_does_nothing(tmp_path) -> None:
    manager = TransferManager(tmp_path / "downloads",
                              HistoryStore(tmp_path / "history.db"))
    manager.create("sender-node", "receiver-node", [{"name": "f.txt", "size": 1}])
    assert sweep_expired_transfers(manager, None) == 0
    assert len(manager.transfers) == 1


def test_stats_expose_no_secrets(tmp_path) -> None:
    manager = TransferManager(tmp_path / "downloads",
                              HistoryStore(tmp_path / "history.db"))
    transfer = manager.create("sender-node", "receiver-node",
                              [{"name": "f.txt", "size": 1}])
    token = manager.get(transfer["transfer_id"])["token"]
    assert token not in repr(manager.stats())
