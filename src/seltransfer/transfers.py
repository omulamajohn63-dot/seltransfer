"""Secure transfer metadata and streaming file receiver."""

from __future__ import annotations

import hashlib
import re
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .storage import HistoryStore

STATES = {"PENDING", "ACCEPTED", "CONNECTING", "TRANSFERRING", "PAUSED",
          "COMPLETED", "VERIFIED", "REJECTED", "CANCELLED", "FAILED"}
_FINISHED_STATES = {"VERIFIED", "REJECTED", "CANCELLED", "FAILED"}
ALLOWED_TRANSITIONS = {
    "PENDING": {"ACCEPTED", "REJECTED", "CANCELLED"},
    "ACCEPTED": {"CONNECTING", "TRANSFERRING", "PAUSED", "CANCELLED", "FAILED"},
    "CONNECTING": {"TRANSFERRING", "CANCELLED", "FAILED"},
    "TRANSFERRING": {"COMPLETED", "PAUSED", "CANCELLED", "FAILED"},
    "PAUSED": {"ACCEPTED", "CANCELLED", "FAILED"},
    "REJECTED": set(), "CANCELLED": set(), "FAILED": set(),
    "COMPLETED": {"VERIFIED"}, "VERIFIED": set(),
}


# Windows refuses these names for any extension, and they refer to devices rather
# than files. Opening "CON" or writing to "NUL.txt" does not create a file; it
# addresses hardware or the null device, so an accepted name here is a silent
# data loss rather than a traversal.
_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


def _is_reserved_name(part: str) -> bool:
    """True for a Windows device name, with or without an extension."""
    stem = part.split(".", 1)[0].strip().rstrip(" .").upper()
    return stem in _RESERVED_NAMES


def safe_relative_path(value: str) -> Path:
    """Reject absolute paths and traversal while retaining folder structure.

    Also rejects Windows device names, control characters, and segments that are
    only dots. The returned path is safe to join onto a download root, but callers
    should still verify the resolved result stays inside it.
    """
    original = Path(value)
    if original.is_absolute() or original.drive or value.startswith(("/", "\\")):
        raise ValueError("invalid file path")
    raw_parts = re.split(r"[/\\]", value)
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError("invalid file path")
    parts = [re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", part).strip(" .")
             for part in raw_parts]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("invalid file path")
    # A name made only of substituted characters, or that addresses a Windows
    # device, must not be written.
    if any(not part.strip("_ .") for part in parts):
        raise ValueError("invalid file path")
    if any(_is_reserved_name(part) for part in parts):
        raise ValueError("reserved file name")
    return Path(*parts)


def sweep_expired_transfers(manager: TransferManager,
                            max_age_seconds: float | None = None) -> int:
    """Drop finished transfers older than ``max_age_seconds``. Returns the count.

    ``max_tracked`` bounds the table, but a slow trickle of finished transfers
    would otherwise sit in memory forever and keep their IDs addressable.
    """
    if max_age_seconds is None:
        return 0
    cutoff = time.time() - max_age_seconds
    removed = 0
    with manager._lock:  # noqa: SLF001 - module-level helper for the same class
        for transfer_id, transfer in list(manager.transfers.items()):
            if (transfer["status"] in _FINISHED_STATES
                    and transfer.get("created", 0) < cutoff):
                del manager.transfers[transfer_id]
                removed += 1
    return removed


class TransferManager:
    def __init__(self, download_root: Path, history: HistoryStore, *,
                 max_file_bytes: int | None = None,
                 max_transfer_bytes: int | None = None,
                 max_files_per_transfer: int | None = None,
                 max_tracked: int | None = None) -> None:
        self.download_root = download_root
        self.download_root.mkdir(parents=True, exist_ok=True)
        self.history = history
        self.transfers: dict[str, dict[str, Any]] = {}
        self.max_file_bytes = max_file_bytes
        self.max_transfer_bytes = max_transfer_bytes
        self.max_files_per_transfer = max_files_per_transfer
        self.max_tracked = max_tracked
        self._lock = threading.RLock()

    # -- bounded state --------------------------------------------------------

    def _evict_if_needed(self) -> None:
        """Bound the in-memory transfer table.

        The table only ever grew. Because an unauthenticated peer can create a
        transfer, that was an unbounded memory sink, and it also meant an ID from
        long ago stayed addressable forever. Finished transfers are dropped
        oldest-first; anything still live is kept, because dropping a live
        transfer would strand a download in progress.
        """
        if self.max_tracked is None or len(self.transfers) <= self.max_tracked:
            return
        finished = [
            transfer for transfer in self.transfers.values()
            if transfer["status"] in _FINISHED_STATES
        ]
        finished.sort(key=lambda transfer: transfer["created"])
        excess = len(self.transfers) - self.max_tracked
        for transfer in finished[:excess]:
            self.transfers.pop(transfer["transfer_id"], None)

    def can_track_one_more(self) -> bool:
        """Whether another transfer can be admitted without breaking the bound.

        Eviction alone is not a bound. It only reclaims *finished* transfers, so a
        peer that opens live transfers keeps them alive and the table grows past
        ``max_tracked`` regardless - the cap was advisory exactly when it mattered
        most. The caller checks this and refuses instead.
        """
        if self.max_tracked is None:
            return True
        if len(self.transfers) < self.max_tracked:
            return True
        # At the cap: acceptable only if evicting a finished transfer makes room.
        return any(transfer["status"] in _FINISHED_STATES
                   for transfer in self.transfers.values())

    def stats(self) -> dict[str, int]:
        """Counts for `doctor`. Contains no tokens and no file paths."""
        with self._lock:
            return {
                "tracked_transfers": len(self.transfers),
                "received_files": sum(
                    len(transfer.get("received_files", {})) for transfer in
                    self.transfers.values()),
            }

    def _validate_files(self, files: list[dict[str, Any]]) -> list[int]:
        """Check declared sizes against the configured limits before accepting.

        Returns the per-file sizes so the caller does not re-parse them.
        """
        if not files:
            raise ValueError("at least one valid file is required")
        if self.max_files_per_transfer is not None and len(files) > self.max_files_per_transfer:
            raise ValueError(
                f"too many files: {len(files)} exceeds the limit of {self.max_files_per_transfer}")
        sizes: list[int] = []
        for item in files:
            name = item.get("name")
            if not name:
                raise ValueError("each file requires a name")
            try:
                size = int(item.get("size", 0))
            except (TypeError, ValueError) as error:
                raise ValueError(f"invalid size for {name}") from error
            if size < 0:
                raise ValueError(f"invalid size for {name}")
            if self.max_file_bytes is not None and size > self.max_file_bytes:
                raise ValueError(
                    f"{name} is larger than the per-file limit of {self.max_file_bytes} bytes")
            sizes.append(size)
        total = sum(sizes)
        if self.max_transfer_bytes is not None and total > self.max_transfer_bytes:
            raise ValueError(
                f"transfer is larger than the limit of {self.max_transfer_bytes} bytes")
        # Reject traversal and absolute paths now, while the caller still gets a
        # validation error, instead of at upload time after the transfer exists.
        for item in files:
            safe_relative_path(str(item["name"]))
        return sizes

    def create(self, sender_id: str, receiver_id: str,
               files: list[dict[str, Any]], direction: str = "outgoing",
               transfer_id: str | None = None,
               sender: dict[str, Any] | None = None,
               transport: str = "http",
               token: str | None = None) -> dict[str, Any]:
        sizes = self._validate_files(files)
        transfer: dict[str, Any] = {
            "transfer_id": transfer_id or str(uuid.uuid4()),
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "files": files,
            "total_bytes": sum(sizes),
            "transferred_bytes": 0,
            "status": "PENDING",
            "direction": direction,
            "transport": transport if transport in {"http", "webrtc"} else "http",
            "created": time.time(),
        }
        # A transfer announced by a remote sender carries that sender's own
        # upload token. It has to be honoured rather than regenerated, because the
        # destination will only ever hand a token to its own node, and the sender
        # is the party that actually needs it.
        transfer["token"] = token or secrets.token_urlsafe(32)
        if sender:
            transfer["sender"] = sender
        with self._lock:
            # Checked *before* inserting. Eviction only reclaims finished
            # transfers, so at the cap with everything live the bound cannot be met
            # by evicting; refusing here is what makes max_tracked a real limit.
            if not self.can_track_one_more():
                raise ValueError(
                    "the server is tracking too many transfers; retry once some "
                    "have finished")
            self.transfers[transfer["transfer_id"]] = transfer
            # Evict after inserting, so the bound is the bound rather than the
            # bound plus one.
            self._evict_if_needed()
        self.history.record(transfer)
        return self.public(transfer)

    def get(self, transfer_id: str) -> dict[str, Any]:
        with self._lock:
            if transfer_id not in self.transfers:
                raise KeyError(transfer_id)
            return self.transfers[transfer_id]

    def get_or_none(self, transfer_id: str) -> dict[str, Any] | None:
        """Lookup that returns ``None`` instead of raising.

        Used on the unauthenticated announcement path, where "no such transfer"
        is the normal case rather than an error.
        """
        with self._lock:
            return self.transfers.get(transfer_id)

    def update_state(self, transfer_id: str, state: str) -> dict[str, Any]:
        if state not in STATES:
            raise ValueError("invalid transfer state")
        transfer = self.get(transfer_id)
        if state not in ALLOWED_TRANSITIONS.get(transfer["status"], set()):
            raise ValueError(
                f"cannot transition {transfer['status']} to {state}")
        transfer["status"] = state
        self.history.record(transfer)
        return self.public(transfer)

    async def receive_file(self, transfer_id: str, index: int, stream: Any,
                           token: str) -> dict[str, Any]:
        transfer = self.get(transfer_id)
        if not secrets.compare_digest(token, transfer["token"]):
            raise PermissionError("invalid transfer token")
        if transfer["status"] not in {"ACCEPTED", "TRANSFERRING"}:
            raise ValueError("transfer has not been accepted")
        if index < 0 or index >= len(transfer["files"]):
            raise IndexError("file not found")
        metadata = transfer["files"][index]
        # A replayed upload is a no-op, decided before anything is written.
        #
        # Checking this late meant the streaming loop had already added the bytes
        # to transferred_bytes, so a client retrying an index doubled the
        # transfer's progress, and it left an orphan copy of the file on disk.
        already = (transfer.get("received_files") or {}).get(str(index))
        if already is not None and Path(str(already)).is_file():
            transfer["status"] = (
                "VERIFIED"
                if len(transfer["received_files"]) == len(transfer["files"])
                else "TRANSFERRING"
            )
            self.history.record(transfer)
            return self.public(transfer)
        relative = safe_relative_path(str(metadata["name"]))
        declared = int(metadata["size"])
        # The limit is the smaller of the configuration cap and the size the sender
        # declared, so an oversized body is cut off while streaming rather than
        # after the whole payload has already filled the disk.
        limit = declared
        if self.max_file_bytes is not None:
            limit = min(limit, self.max_file_bytes)
        temporary_root = (self.download_root / ".partial" / transfer_id
                          if transfer.get("direction") == "incoming"
                          else self.download_root / transfer_id)
        target = temporary_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        part = target.with_name(target.name + ".part")
        previous_status = transfer["status"]
        transfer["status"] = "TRANSFERRING"
        digest = hashlib.sha256()
        size = 0
        try:
            with part.open("wb") as output:
                async for chunk in stream:
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > limit:
                        raise ValueError(
                            f"{metadata['name']} exceeds the {limit} byte limit")
                    output.write(chunk)
                    digest.update(chunk)
                    transfer["transferred_bytes"] += len(chunk)
        except BaseException:
            # Never leave a .part file behind, and never keep bytes counted for a
            # transfer that did not land on disk.
            transfer["transferred_bytes"] = max(0, transfer["transferred_bytes"] - size)
            part.unlink(missing_ok=True)
            if transfer["status"] == "TRANSFERRING":
                transfer["status"] = previous_status
            raise
        if size != declared:
            part.unlink(missing_ok=True)
            transfer["transferred_bytes"] = max(0, transfer["transferred_bytes"] - size)
            transfer["status"] = "FAILED"
            self.history.record(transfer)
            transfer["error"] = "received size does not match metadata"
            raise ValueError(transfer["error"])
        if metadata.get("sha256") and digest.hexdigest() != metadata["sha256"]:
            part.unlink(missing_ok=True)
            transfer["transferred_bytes"] = max(0, transfer["transferred_bytes"] - size)
            transfer["error"] = f"SHA-256 mismatch for {metadata['name']}"
            transfer["status"] = "FAILED"
            self.history.record(transfer)
            raise ValueError(transfer["error"])
        final = (self.download_root / relative
                 if transfer.get("direction") == "incoming"
                 else target)
        final.parent.mkdir(parents=True, exist_ok=True)
        if final.exists():
            final = final.with_name(
                f"{final.stem} ({uuid.uuid4().hex[:8]}){final.suffix}")
        part.replace(final)
        # Keyed by declared index rather than appended.
        #
        # An append-ordered list was read positionally by the download route, so
        # a client that uploaded index 1 before index 0 was served index 1's bytes
        # for index 0. It also let a repeated upload append a second entry, which
        # double-counted transferred_bytes and could push the transfer to VERIFIED
        # before every declared file had actually arrived.
        received = transfer.setdefault("received_files", {})
        received[str(index)] = str(final)
        # transferred_bytes was already accumulated chunk-by-chunk while streaming,
        # and every failure path above rolls it back. Adding again here would
        # double-count a successful transfer.
        if len(received) == len(transfer["files"]):
            transfer["status"] = "VERIFIED"
        else:
            transfer["status"] = "TRANSFERRING"
        self.history.record(transfer)
        return self.public(transfer)

    def complete_browser_file(self, transfer_id: str, index: int,
                              size: int, sha256: str) -> dict[str, Any]:
        """Record a verified browser-received file without writing server-side."""
        transfer = self.get(transfer_id)
        if transfer["status"] not in {"ACCEPTED", "CONNECTING", "TRANSFERRING"}:
            raise ValueError("transfer is not active")
        if index < 0 or index >= len(transfer["files"]):
            raise IndexError("file not found")
        metadata = transfer["files"][index]
        if size != int(metadata["size"]):
            raise ValueError("received size does not match metadata")
        expected = metadata.get("sha256")
        if expected and not secrets.compare_digest(sha256, expected):
            raise ValueError(f"SHA-256 mismatch for {metadata['name']}")
        received = transfer.setdefault("browser_received_files", {})
        if str(index) not in received:
            received[str(index)] = {"name": metadata["name"], "size": size,
                                    "sha256": sha256}
            transfer["transferred_bytes"] += size
        transfer["status"] = "TRANSFERRING"
        if len(received) == len(transfer["files"]):
            transfer["status"] = "VERIFIED"
        self.history.record(transfer)
        return self.public(transfer)

    @staticmethod
    def public(transfer: dict[str, Any]) -> dict[str, Any]:
        data = {key: value for key, value in transfer.items() if key !=
                "token"}
        data.setdefault("direction", "outgoing")
        return data
