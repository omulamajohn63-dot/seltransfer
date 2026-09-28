"""Small SQLite store for durable transfer history."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class HistoryStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS transfers (
                transfer_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                sender_id TEXT NOT NULL, receiver_id TEXT NOT NULL,
                direction TEXT NOT NULL, file_count INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL, status TEXT NOT NULL,
                duration REAL, error TEXT)""")
            # Caller-scoped reads are the common path (see routes.list_transfers),
            # so index both participants rather than scanning the whole table.
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_transfers_sender "
                "ON transfers(sender_id)")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_transfers_receiver "
                "ON transfers(receiver_id)")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def record(self, transfer: dict[str, Any]) -> None:
        """Insert a transfer, or refresh its mutable columns if it is known.

        ``created_at`` is deliberately left untouched on update: it records when
        the transfer was first seen, not when it last changed state.
        """
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO transfers VALUES
                    (?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(transfer_id) DO UPDATE SET
                        status=excluded.status,
                        direction=excluded.direction,
                        file_count=excluded.file_count,
                        total_bytes=excluded.total_bytes,
                        duration=excluded.duration,
                        error=excluded.error""",
                (
                    transfer["transfer_id"], transfer["sender_id"],
                    transfer["receiver_id"], transfer.get("direction", "outgoing"),
                    len(transfer["files"]), transfer["total_bytes"],
                    transfer["status"], transfer.get("duration"),
                    transfer.get("error"),
                ),
            )

    def list_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent transfers regardless of participant.

        Named ``list_recent`` rather than ``list`` so the method does not shadow
        the builtin inside the class body, where it breaks type annotations on
        every sibling method.
        """
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM transfers ORDER BY created_at DESC LIMIT ?", (limit,))]

    def list_for(self, device_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Return only the transfers where ``device_id`` is a participant."""
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(
                """SELECT * FROM transfers
                   WHERE sender_id = ? OR receiver_id = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (device_id, device_id, limit))]

    def clear(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM transfers")

    def clear_for(self, device_id: str) -> None:
        """Delete only the rows ``device_id`` participates in."""
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM transfers WHERE sender_id = ? OR receiver_id = ?",
                (device_id, device_id))
