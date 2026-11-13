"""Full Registry scanning, AI explanation caching, and semantic vector indexing."""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections.abc import Iterable
from typing import Any

from win_reg_mcp.config import Settings
from win_reg_mcp.database import SQLiteStore
from win_reg_mcp.models import RegistryValue
from win_reg_mcp.ollama import OllamaClient
from win_reg_mcp.registry import WindowsRegistry

LOGGER = logging.getLogger(__name__)


class RegistryIndexer:
    """Keep the local semantic catalogue synchronized with the complete Registry."""

    def __init__(
        self,
        settings: Settings,
        registry: WindowsRegistry,
        store: SQLiteStore,
        ollama: OllamaClient,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.store = store
        self.ollama = ollama

    @staticmethod
    def fingerprint(value: RegistryValue) -> str:
        """Detect changes to Registry data without depending on Python object identity."""
        serialized = json.dumps(
            value.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def _bounded_data(value_data: Any) -> Any:
        """Keep large Registry payloads out of model prompts while retaining useful context."""
        if isinstance(value_data, dict) and "__bytes_base64__" in value_data:
            encoded = str(value_data["__bytes_base64__"])
            return {
                "kind": "binary",
                "base64_length": len(encoded),
                "base64_prefix": encoded[:96],
            }
        if isinstance(value_data, str) and len(value_data) > 1600:
            return value_data[:1600] + f"... [truncated; {len(value_data)} characters total]"
        if isinstance(value_data, list) and len(value_data) > 100:
            return value_data[:100] + [f"... [{len(value_data)} items total]"]
        return value_data

    @staticmethod
    def explanation_record(index: int, value: RegistryValue) -> dict[str, Any]:
        """Provide the model with enough context to explain a Registry parameter cautiously."""
        return {
            "id": index,
            "hive": value.hive,
            "view": value.view,
            "key_path": value.key_path,
            "value_name": value.value_name or "(Default)",
            "value_type": value.value_type,
            "value_data": RegistryIndexer._bounded_data(value.value_data),
        }

    def _index_batch(self, values: list[RegistryValue], scan_id: str) -> tuple[int, int]:
        """Explain and embed only values that are new or changed since the previous scan."""
        previous = self.store.get_existing_fingerprints(values)
        changed: list[RegistryValue] = []
        changed_fingerprints: list[str] = []
        unchanged_keys: list[str] = []
        for value in values:
            fingerprint = self.fingerprint(value)
            unique_key = self.store._unique_key(value)
            cached = previous.get(unique_key)
            if cached and cached["fingerprint"] == fingerprint:
                unchanged_keys.append(unique_key)
            else:
                changed.append(value)
                changed_fingerprints.append(fingerprint)
        self.store.touch_unchanged(unchanged_keys, scan_id)
        if not changed:
            return 0, len(unchanged_keys)

        records = [
            self.explanation_record(index, value) for index, value in enumerate(changed)
        ]
        explanations = self.ollama.explain_registry_batch(records)
        searchable_texts = [
            self.store.searchable_text(value, explanation)
            for value, explanation in zip(changed, explanations, strict=True)
        ]
        embeddings: list[list[float]] = []
        for offset in range(0, len(searchable_texts), self.settings.embedding_batch_size):
            embeddings.extend(
                self.ollama.embed(
                    searchable_texts[offset : offset + self.settings.embedding_batch_size]
                )
            )
        self.store.upsert_indexed_values(
            changed,
            explanations,
            embeddings,
            changed_fingerprints,
            scan_id,
        )
        return len(changed), len(unchanged_keys)

    def index_values(self, values: Iterable[RegistryValue]) -> dict[str, int]:
        """Synchronize a small set of values changed by Rollout or Rollback."""
        scan_id = f"rollout-{uuid.uuid4()}"
        changed_count = 0
        unchanged_count = 0
        batch: list[RegistryValue] = []
        for value in values:
            batch.append(value)
            if len(batch) >= self.settings.scan_batch_size:
                changed, unchanged = self._index_batch(batch, scan_id)
                changed_count += changed
                unchanged_count += unchanged
                batch = []
        if batch:
            changed, unchanged = self._index_batch(batch, scan_id)
            changed_count += changed
            unchanged_count += unchanged
        return {"indexed": changed_count, "unchanged": unchanged_count}

    def full_scan(self) -> dict[str, int | bool]:
        """Scan all configured hives and both WOW64 views before the MCP server starts."""
        self.ollama.check_available()
        self.store.ensure_embedding_model(self.settings.embedding_model)
        scan_id = str(uuid.uuid4())
        deadline = time.monotonic() + self.settings.startup_timeout
        scanned = 0
        indexed = 0
        unchanged = 0
        batch: list[RegistryValue] = []
        last_reported = 0
        for value in self.registry.iter_values():
            if time.monotonic() > deadline:
                raise TimeoutError(
                    "The full Registry scan exceeded --startup-timeout; increase the timeout "
                    "to complete the all-hives index."
                )
            scanned += 1
            batch.append(value)
            if len(batch) >= self.settings.scan_batch_size:
                new_count, cached_count = self._index_batch(batch, scan_id)
                indexed += new_count
                unchanged += cached_count
                batch = []
                if scanned - last_reported >= 5000:
                    last_reported = scanned
                    LOGGER.info(
                        "Registry scan progress: %s values; %s new/changed; %s cached",
                        scanned,
                        indexed,
                        unchanged,
                    )
        if batch:
            new_count, cached_count = self._index_batch(batch, scan_id)
            indexed += new_count
            unchanged += cached_count
        errors = int(self.registry.scan_errors)
        removed = self.store.finish_scan(scan_id, complete=(errors == 0))
        summary: dict[str, int | bool] = {
            "scanned": scanned,
            "indexed": indexed,
            "unchanged": unchanged,
            "removed": removed,
            "access_errors": errors,
            "complete": errors == 0,
        }
        LOGGER.info("Registry indexing complete: %s", summary)
        return summary
