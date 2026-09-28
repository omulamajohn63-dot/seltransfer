"""Transfer limits, streaming enforcement, and cleanup.

The important property here is that a hostile or broken sender cannot fill the
disk: the size cap has to bite *during* the stream, and every failure path has to
leave neither a partial file nor inflated byte accounting behind.
"""

import pytest

from seltransfer.storage import HistoryStore
from seltransfer.transfers import TransferManager, safe_relative_path


@pytest.fixture
def manager(tmp_path):
    return TransferManager(tmp_path / "downloads", HistoryStore(tmp_path / "h.db"))


class Stream:
    """Minimal async byte stream standing in for a request body."""

    def __init__(self, *chunks, error=None):
        self.chunks = list(chunks)
        self.error = error

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        for chunk in self.chunks:
            yield chunk
        if self.error is not None:
            raise self.error


def accepted(manager, name="f.bin", size=10, sha256=None, **kwargs):
    metadata = {"name": name, "size": size}
    if sha256 is not None:
        metadata["sha256"] = sha256
    transfer = manager.create("sender", "receiver", [metadata], **kwargs)
    manager.update_state(transfer["transfer_id"], "ACCEPTED")
    return manager.get(transfer["transfer_id"])


# --- declared-size validation ----------------------------------------------

def test_declared_size_over_the_cap_is_rejected_at_creation(tmp_path):
    manager = TransferManager(tmp_path / "downloads", HistoryStore(tmp_path / "h.db"),
                              max_file_bytes=100)
    with pytest.raises(ValueError, match="per-file limit"):
        manager.create("s", "r", [{"name": "big.bin", "size": 101}])


def test_transfer_total_over_the_cap_is_rejected(tmp_path):
    manager = TransferManager(tmp_path / "downloads", HistoryStore(tmp_path / "h.db"),
                              max_file_bytes=100, max_transfer_bytes=150)
    with pytest.raises(ValueError, match="transfer is larger"):
        manager.create("s", "r", [{"name": "a", "size": 100}, {"name": "b", "size": 100}])


def test_too_many_files_is_rejected(tmp_path):
    manager = TransferManager(tmp_path / "downloads", HistoryStore(tmp_path / "h.db"),
                              max_files_per_transfer=2)
    with pytest.raises(ValueError, match="too many files"):
        manager.create("s", "r", [{"name": f"f{i}", "size": 1} for i in range(3)])


def test_negative_size_is_rejected(manager):
    with pytest.raises(ValueError, match="invalid size"):
        manager.create("s", "r", [{"name": "f", "size": -1}])


def test_empty_file_list_is_rejected(manager):
    with pytest.raises(ValueError, match="at least one valid file"):
        manager.create("s", "r", [])


def test_traversal_name_is_rejected_at_creation(manager):
    with pytest.raises(ValueError, match="invalid file path"):
        manager.create("s", "r", [{"name": "../escape.txt", "size": 1}])


# --- mid-stream enforcement -------------------------------------------------

@pytest.mark.asyncio
async def test_stream_longer_than_declared_is_cut_off(tmp_path):
    """A sender that lies about size must be stopped while streaming."""
    manager = TransferManager(tmp_path / "downloads", HistoryStore(tmp_path / "h.db"),
                              max_file_bytes=1_000_000)
    transfer = accepted(manager, size=10)
    stream = Stream(b"x" * 10, b"y" * 5_000)
    with pytest.raises(ValueError, match="exceeds the 10 byte limit"):
        await manager.receive_file(transfer["transfer_id"], 0, stream, transfer["token"])
    assert not list((manager.download_root).rglob("*.part")), "no partial file may survive"


@pytest.mark.asyncio
async def test_stream_over_the_configured_cap_is_cut_off(tmp_path):
    """A cap introduced after the transfer was created must still be enforced."""
    manager = TransferManager(tmp_path / "downloads", HistoryStore(tmp_path / "h.db"))
    transfer = accepted(manager, size=10_000)
    manager.max_file_bytes = 64
    stream = Stream(b"a" * 10_000)
    with pytest.raises(ValueError, match="exceeds the 64 byte limit"):
        await manager.receive_file(transfer["transfer_id"], 0, stream, transfer["token"])
    assert not list(manager.download_root.rglob("*.part"))


@pytest.mark.asyncio
async def test_short_stream_is_rejected_and_cleans_up(manager):
    transfer = accepted(manager, size=100)
    with pytest.raises(ValueError, match="does not match metadata"):
        await manager.receive_file(transfer["transfer_id"], 0, Stream(b"short"), transfer["token"])
    assert not list(manager.download_root.rglob("*.part"))
    assert manager.get(transfer["transfer_id"])["status"] == "FAILED"


@pytest.mark.asyncio
async def test_client_disconnect_leaves_no_partial_file_and_no_lost_bytes(manager):
    transfer = accepted(manager, size=1000)
    before = manager.get(transfer["transfer_id"])["transferred_bytes"]
    stream = Stream(b"a" * 100, b"b" * 100, error=ConnectionResetError("peer went away"))
    with pytest.raises(ConnectionResetError):
        await manager.receive_file(transfer["transfer_id"], 0, stream, transfer["token"])
    assert not list(manager.download_root.rglob("*.part"))
    # The 200 bytes that were written must not stay counted against the transfer.
    assert manager.get(transfer["transfer_id"])["transferred_bytes"] == before


@pytest.mark.asyncio
async def test_failed_stream_restores_the_previous_status(manager):
    transfer = accepted(manager, size=1000)
    with pytest.raises(ValueError):
        await manager.receive_file(
            transfer["transfer_id"], 0, Stream(b"a" * 2000), transfer["token"])
    assert manager.get(transfer["transfer_id"])["status"] == "ACCEPTED"


@pytest.mark.asyncio
async def test_sha_mismatch_cleans_up(manager):
    import hashlib
    payload = b"a" * 50
    transfer = accepted(manager, size=50,
                        sha256=hashlib.sha256(b"different").hexdigest())
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        await manager.receive_file(transfer["transfer_id"], 0, Stream(payload), transfer["token"])
    assert not list(manager.download_root.rglob("*.part"))
    assert manager.get(transfer["transfer_id"])["transferred_bytes"] == 0


@pytest.mark.asyncio
async def test_matching_digest_completes_and_verifies(manager):
    import hashlib
    payload = b"hello world"
    digest = hashlib.sha256(payload).hexdigest()
    transfer = accepted(manager, name="f.txt", size=len(payload), sha256=digest)
    result = await manager.receive_file(transfer["transfer_id"], 0, Stream(payload),
                                        transfer["token"])
    assert result["status"] == "VERIFIED"
    written = manager.get(transfer["transfer_id"])["received_files"]
    assert len(written) == 1
    assert (manager.download_root / written[0]).read_bytes() == payload


@pytest.mark.asyncio
async def test_incoming_direction_lands_at_the_download_root(manager):
    """A receiver-hosted transfer writes straight to the download directory."""
    transfer = accepted(manager, name="report.txt", size=5, direction="incoming")
    await manager.receive_file(transfer["transfer_id"], 0, Stream(b"hello"), transfer["token"])
    assert (manager.download_root / "report.txt").read_bytes() == b"hello"


@pytest.mark.asyncio
async def test_multi_file_transfer_ends_verified_once(manager):
    transfer = manager.create("s", "r", [{"name": "a", "size": 3}, {"name": "b", "size": 3}])
    manager.update_state(transfer["transfer_id"], "ACCEPTED")
    for index, payload in enumerate([b"aaa", b"bbb"]):
        token = manager.get(transfer["transfer_id"])["token"]
        result = await manager.receive_file(transfer["transfer_id"], index, Stream(payload), token)
    assert result["status"] == "VERIFIED"
    assert result["transferred_bytes"] == 6


# --- path handling ----------------------------------------------------------

@pytest.mark.parametrize("value", ["../x", "a/../b", "/abs", "C:/x", "a//b", "", "a/./b"])
def test_safe_relative_path_rejects_unsafe_values(value):
    with pytest.raises(ValueError, match="invalid file path"):
        safe_relative_path(value)


def test_safe_relative_path_keeps_folder_structure():
    assert safe_relative_path("photos/2024/img.jpg").as_posix() == "photos/2024/img.jpg"


def test_safe_relative_path_strips_reserved_characters():
    assert safe_relative_path('a<b>c:d"e|f?g*h.txt').as_posix() == "a_b_c_d_e_f_g_h.txt"


# --- state machine ----------------------------------------------------------

def test_completed_can_only_be_verified(manager):
    transfer = manager.create("s", "r", [{"name": "f", "size": 1}])
    tid = transfer["transfer_id"]
    manager.update_state(tid, "ACCEPTED")
    with pytest.raises(ValueError, match="cannot transition"):
        manager.update_state(tid, "REJECTED")
