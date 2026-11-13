"""SQLite metadata, durable rollout snapshots, and sqlite-vec similarity storage."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from win_reg_mcp.models import RegistryFinding, RegistryValue

LOGGER = logging.getLogger(__name__)


class SQLiteStore:
    """Own the local SQLite database and load sqlite-vec for every connection."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        """Create an isolated connection so MCP worker threads never share handles."""
        connection = sqlite3.connect(self.database_path, timeout=45.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=45000")
        try:
            import sqlite_vec
        except ImportError as exc:
            raise RuntimeError(
                "sqlite-vec is required; install the project with `pip install -e .`"
            ) from exc
        connection.enable_load_extension(True)
        sqlite_vec.load(connection)
        connection.enable_load_extension(False)
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Close every isolated SQLite handle after its transaction has been committed."""
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create durable metadata and rollout tables before scanning Windows."""
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS registry_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    unique_key TEXT NOT NULL UNIQUE,
                    fingerprint TEXT NOT NULL,
                    hive TEXT NOT NULL,
                    view TEXT NOT NULL,
                    key_path TEXT NOT NULL,
                    value_name TEXT NOT NULL,
                    value_type TEXT NOT NULL,
                    value_data_json TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    searchable_text TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_registry_hive_path
                    ON registry_entries(hive, key_path);
                CREATE INDEX IF NOT EXISTS idx_registry_value_name
                    ON registry_entries(value_name);
                CREATE TABLE IF NOT EXISTS rollouts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    backup_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT
                );
                """)

    @staticmethod
    def _now() -> str:
        """Use timezone-aware ISO timestamps for audit and recovery records."""
        return datetime.now(UTC).isoformat()

    def ensure_embedding_model(self, model_name: str) -> None:
        """Prevent queries from mixing vectors generated in incompatible model spaces."""
        with self._connection() as connection:
            existing = connection.execute(
                "SELECT value FROM metadata WHERE key = 'embedding_model'"
            ).fetchone()
            if existing and str(existing[0]) != model_name:
                raise RuntimeError(
                    "The embedding model differs from the model used for this SQLite index. "
                    "Use the original --embedding-model or a new --database to rebuild it."
                )
            if not existing:
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('embedding_model', ?)",
                    (model_name,),
                )

    def get_vector_dimension(self) -> int | None:
        """Read the embedding width recorded when the first semantic row was indexed."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'vector_dimension'"
            ).fetchone()
        return int(row[0]) if row else None

    def ensure_vector_table(self, dimension: int) -> None:
        """Create the sqlite-vec virtual table and reject incompatible embedding models."""
        if dimension < 1:
            raise ValueError("Embedding dimension must be positive")
        with self._connection() as connection:
            existing = connection.execute(
                "SELECT value FROM metadata WHERE key = 'vector_dimension'"
            ).fetchone()
            if existing and int(existing[0]) != dimension:
                raise RuntimeError(
                    "The configured embedding model changed vector dimensions. "
                    "Use a new database or rebuild the semantic index."
                )
            if not existing:
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('vector_dimension', ?)",
                    (str(dimension),),
                )
            connection.execute(
                f"CREATE VIRTUAL TABLE IF NOT EXISTS registry_vectors "
                f"USING vec0(embedding float[{dimension}] distance_metric=cosine)"
            )

    @staticmethod
    def _unique_key(value: RegistryValue) -> str:
        """Build an unambiguous identity from hive, view, key, and value name."""
        return json.dumps(
            [
                value.hive.upper(),
                value.view,
                value.key_path.casefold(),
                value.value_name.casefold(),
            ],
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def get_existing_fingerprints(self, values: list[RegistryValue]) -> dict[str, dict[str, Any]]:
        """Fetch prior fingerprints and explanations to avoid repeating local LLM work."""
        if not values:
            return {}
        keys = [self._unique_key(value) for value in values]
        result: dict[str, dict[str, Any]] = {}
        with self._connection() as connection:
            for offset in range(0, len(keys), 400):
                batch = keys[offset : offset + 400]
                placeholders = ",".join("?" for _ in batch)
                rows = connection.execute(
                    f"SELECT unique_key, id, fingerprint, explanation FROM registry_entries "
                    f"WHERE unique_key IN ({placeholders})",
                    batch,
                ).fetchall()
                for row in rows:
                    result[row["unique_key"]] = dict(row)
        return result

    def touch_unchanged(self, unique_keys: list[str], scan_id: str) -> None:
        """Mark cached rows as seen during a complete scan without rebuilding vectors."""
        if not unique_keys:
            return
        with self._connection() as connection:
            connection.executemany(
                "UPDATE registry_entries SET last_seen = ? WHERE unique_key = ?",
                [(scan_id, key) for key in unique_keys],
            )

    def upsert_indexed_values(
        self,
        values: list[RegistryValue],
        explanations: list[str],
        embeddings: list[list[float]],
        fingerprints: list[str],
        scan_id: str,
    ) -> None:
        """Persist value metadata and its matching vector as one SQLite transaction."""
        if not (len(values) == len(explanations) == len(embeddings) == len(fingerprints)):
            raise ValueError("Indexed value batches have inconsistent lengths")
        if not values:
            return
        self.ensure_vector_table(len(embeddings[0]))
        now = self._now()
        with self._connection() as connection:
            for value, explanation, embedding, fingerprint in zip(
                values, explanations, embeddings, fingerprints, strict=True
            ):
                unique_key = self._unique_key(value)
                searchable_text = self.searchable_text(value, explanation)
                payload = json.dumps(value.value_data, ensure_ascii=False)
                existing = connection.execute(
                    "SELECT id FROM registry_entries WHERE unique_key = ?", (unique_key,)
                ).fetchone()
                if existing:
                    entry_id = int(existing[0])
                    connection.execute(
                        "UPDATE registry_entries SET fingerprint=?, hive=?, view=?, key_path=?, "
                        "value_name=?, value_type=?, value_data_json=?, explanation=?, "
                        "searchable_text=?, last_seen=?, updated_at=? WHERE id=?",
                        (
                            fingerprint,
                            value.hive,
                            value.view,
                            value.key_path,
                            value.value_name,
                            value.value_type,
                            payload,
                            explanation,
                            searchable_text,
                            scan_id,
                            now,
                            entry_id,
                        ),
                    )
                    connection.execute("DELETE FROM registry_vectors WHERE rowid = ?", (entry_id,))
                else:
                    cursor = connection.execute(
                        "INSERT INTO registry_entries(unique_key, fingerprint, hive, view, key_path, "
                        "value_name, value_type, value_data_json, explanation, searchable_text, "
                        "last_seen, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            unique_key,
                            fingerprint,
                            value.hive,
                            value.view,
                            value.key_path,
                            value.value_name,
                            value.value_type,
                            payload,
                            explanation,
                            searchable_text,
                            scan_id,
                            now,
                        ),
                    )
                    entry_id = int(cursor.lastrowid)
                connection.execute(
                    "INSERT INTO registry_vectors(rowid, embedding) VALUES(?, ?)",
                    (entry_id, json.dumps(embedding)),
                )

    @staticmethod
    def searchable_text(value: RegistryValue, explanation: str) -> str:
        """Build the human and semantic search document stored beside the vector."""
        value_name = value.value_name if value.value_name else "(Default value)"
        value_data = value.value_data
        if isinstance(value_data, dict) and "__bytes_base64__" in value_data:
            value_data = {
                "kind": "binary",
                "base64_length": len(str(value_data["__bytes_base64__"])),
                "base64_prefix": str(value_data["__bytes_base64__"])[:96],
            }
        elif isinstance(value_data, str) and len(value_data) > 1600:
            value_data = value_data[:1600] + f"... [truncated; {len(value_data)} characters total]"
        elif isinstance(value_data, list) and len(value_data) > 100:
            value_data = value_data[:100] + [f"... [{len(value_data)} items total]"]
        return "\n".join(
            (
                f"Hive: {value.hive}",
                f"Registry view: {value.view}-bit",
                f"Key path: {value.key_path}",
                f"Value name: {value_name}",
                f"Registry type: {value.value_type}",
                f"Current data: {value_data}",
                f"Explanation: {explanation}",
            )
        )

    def finish_scan(self, scan_id: str, complete: bool) -> int:
        """Remove stale values only after a scan that completed without access gaps."""
        if not complete:
            LOGGER.warning("Registry scan had access errors; stale index rows are retained")
            return 0
        with self._connection() as connection:
            stale = connection.execute(
                "SELECT id FROM registry_entries WHERE last_seen != ?", (scan_id,)
            ).fetchall()
            stale_ids = [int(row[0]) for row in stale]
            for entry_id in stale_ids:
                connection.execute("DELETE FROM registry_vectors WHERE rowid = ?", (entry_id,))
                connection.execute("DELETE FROM registry_entries WHERE id = ?", (entry_id,))
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('last_full_scan', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (self._now(),),
            )
        return len(stale_ids)

    def search(self, embedding: list[float], limit: int) -> list[RegistryFinding]:
        """Return nearest semantic matches joined with all explainable Registry metadata."""
        if not self.get_vector_dimension():
            return []
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT e.id, e.hive, e.view, e.key_path, e.value_name, e.value_type, "
                "e.value_data_json, e.explanation, v.distance "
                "FROM registry_vectors AS v "
                "JOIN registry_entries AS e ON e.id = v.rowid "
                "WHERE v.embedding MATCH ? AND k = ? ORDER BY v.distance",
                (json.dumps(embedding), limit),
            ).fetchall()
        return [
            RegistryFinding(
                entry_id=int(row["id"]),
                hive=str(row["hive"]),
                view=str(row["view"]),
                key_path=str(row["key_path"]),
                value_name=str(row["value_name"]),
                value_type=str(row["value_type"]),
                value_data=json.loads(row["value_data_json"]),
                explanation=str(row["explanation"]),
                distance=float(row["distance"]),
            )
            for row in rows
        ]

    def delete_registry_value(self, value: RegistryValue) -> None:
        """Remove a deleted Registry value from both metadata and vector storage."""
        unique_key = self._unique_key(value)
        has_vector_table = self.get_vector_dimension() is not None
        with self._connection() as connection:
            row = connection.execute(
                "SELECT id FROM registry_entries WHERE unique_key = ?", (unique_key,)
            ).fetchone()
            if row:
                entry_id = int(row[0])
                if has_vector_table:
                    connection.execute("DELETE FROM registry_vectors WHERE rowid = ?", (entry_id,))
                connection.execute("DELETE FROM registry_entries WHERE id = ?", (entry_id,))

    def create_rollout(
        self,
        prompt: str,
        plan: dict[str, Any],
        backup: list[dict[str, Any]],
    ) -> int:
        """Commit a complete pre-change snapshot before any Registry write is attempted."""
        with self._connection() as connection:
            cursor = connection.execute(
                "INSERT INTO rollouts(created_at, prompt, plan_json, backup_json, status) "
                "VALUES(?,?,?,?, 'prepared')",
                (
                    self._now(),
                    prompt,
                    json.dumps(plan, ensure_ascii=False),
                    json.dumps(backup, ensure_ascii=False),
                ),
            )
            return int(cursor.lastrowid)

    def finish_rollout(self, rollout_id: int, status: str, error: str | None = None) -> None:
        """Record the durable outcome of an attempted Registry rollout."""
        with self._connection() as connection:
            connection.execute(
                "UPDATE rollouts SET status = ?, error = ? WHERE id = ?",
                (status, error, rollout_id),
            )

    def prepared_rollouts(self) -> list[dict[str, Any]]:
        """List mutations interrupted after backup commit but before final status update."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM rollouts WHERE status = 'prepared' ORDER BY id"
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_applied_rollout(self) -> dict[str, Any] | None:
        """Find the newest successful rollout that has not yet been rolled back."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM rollouts WHERE status IN ('applied', 'rollback_failed') ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def rollout_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Expose a concise audit trail for operational diagnostics."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, created_at, prompt, status, error FROM rollouts "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def entry_count(self) -> int:
        """Return the current size of the Registry metadata index."""
        with self._connection() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM registry_entries").fetchone()[0])
