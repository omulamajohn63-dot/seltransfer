import hashlib
from pathlib import Path

import pytest

from seltransfer.config import resolve_app_dir
from seltransfer.storage import HistoryStore
from seltransfer.transfers import TransferManager, safe_relative_path


def test_safe_relative_path_rejects_traversal():
    with pytest.raises(ValueError):
        safe_relative_path("../outside.txt")
    with pytest.raises(ValueError):
        safe_relative_path("C:/outside.txt")


def test_android_hint_does_not_change_native_app_directory(monkeypatch):
    monkeypatch.setenv("ANDROID_STORAGE", "/storage/emulated/0")
    assert resolve_app_dir("Android") == Path.home() / ".seltransfer"


@pytest.mark.asyncio
async def test_streamed_file_is_verified_and_recorded(tmp_path):
    content = b"streamed content"
    manager = TransferManager(tmp_path / "downloads",
                              HistoryStore(tmp_path / "history.db"))
    transfer = manager.create("sender", "receiver", [{
        "name": "folder/file.txt", "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest()
    }])
    manager.update_state(transfer["transfer_id"], "ACCEPTED")

    async def stream():
        yield content[:8]
        yield content[8:]

    token = manager.get(transfer["transfer_id"])["token"]
    result = await manager.receive_file(transfer["transfer_id"], 0, stream(), token)
    assert result["status"] == "VERIFIED"
    assert (tmp_path / "downloads" /
            transfer["transfer_id"] / "folder" / "file.txt").read_bytes() == content
    assert HistoryStore(
        tmp_path / "history.db").list_recent()[0]["status"] == "VERIFIED"
