"""User-facing Search, Rollout, and Rollback workflows for the MCP server."""

from __future__ import annotations

import base64
import json
import logging
import threading
from typing import Any

from win_reg_mcp.config import Settings
from win_reg_mcp.database import SQLiteStore
from win_reg_mcp.indexer import RegistryIndexer
from win_reg_mcp.models import RegistryAction, RegistryFinding, RegistryValue
from win_reg_mcp.ollama import OllamaClient
from win_reg_mcp.planner import RegistryPlanner
from win_reg_mcp.registry import RegistryError, WindowsRegistry, normalize_registry_data

LOGGER = logging.getLogger(__name__)

ALLOWED_TYPES = {
    "REG_SZ",
    "REG_EXPAND_SZ",
    "REG_MULTI_SZ",
    "REG_DWORD",
    "REG_QWORD",
    "REG_BINARY",
    "REG_NONE",
}
PROTECTED_PREFIXES = {
    "HKLM": ("SAM", "SECURITY"),
    "HKU": (".DEFAULT\\SAM", ".DEFAULT\\SECURITY"),
}


class RegistryManager:
    """Coordinate semantic retrieval, verified change plans, backups, and recovery."""

    def __init__(
        self,
        settings: Settings,
        store: SQLiteStore,
        ollama: OllamaClient,
        registry: WindowsRegistry,
        indexer: RegistryIndexer,
        planner: RegistryPlanner,
    ) -> None:
        self.settings = settings
        self.store = store
        self.ollama = ollama
        self.registry = registry
        self.indexer = indexer
        self.planner = planner
        self._mutation_lock = threading.RLock()

    def _embed_query(self, prompt: str) -> list[float]:
        """Keep query vectors in the same model space and dimension as the stored index."""
        vector = self.ollama.embed([prompt])[0]
        dimension = self.store.get_vector_dimension()
        if dimension is not None and len(vector) != dimension:
            raise RuntimeError(
                "The configured embedding model does not match the indexed vector dimension. "
                "Use the original --embedding-model or a new --database."
            )
        return vector

    @staticmethod
    def _format_data(value: Any, max_length: int = 500) -> str:
        """Render Registry data safely for the human-readable Search and Rollout output."""
        rendered = json.dumps(normalize_registry_data(value), ensure_ascii=False)
        if len(rendered) > max_length:
            return rendered[: max_length - 3] + "..."
        return rendered

    @staticmethod
    def _format_finding(index: int, finding: RegistryFinding) -> str:
        """Render one ranked finding with location, current data, and model explanation."""
        value_name = finding.value_name or "(Default)"
        current = RegistryManager._format_data(finding.value_data)
        return "\n".join(
            (
                f"### {index}. `{finding.hive}` · {finding.view}-bit · distance {finding.distance:.4f}",
                f"- **Key:** `{finding.key_path}`",
                f"- **Value:** `{value_name}`",
                f"- **Type:** `{finding.value_type}`",
                f"- **Current data:** `{current}`",
                f"- **Explanation:** {finding.explanation}",
            )
        )

    def search(self, prompt: str, limit: int | None = None) -> str:
        """Search cached Registry explanations semantically and list ranked findings."""
        query = prompt.strip()
        if not query:
            raise ValueError("Search prompt cannot be empty")
        bounded_limit = max(1, min(int(limit or self.settings.top_k), 100))
        vector = self._embed_query(query)
        findings = self.store.search(vector, bounded_limit)
        if not findings:
            return (
                "## Registry Search\n\n"
                "No indexed Registry values matched this prompt. Confirm the startup scan "
                "completed and that the local database contains indexed values."
            )
        sections = [
            "## Registry Search Results",
            f"Query: **{query}** · Showing {len(findings)} result(s), ranked by semantic distance.",
        ]
        sections.extend(
            self._format_finding(index, finding) for index, finding in enumerate(findings, 1)
        )
        return "\n\n".join(sections)

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Reject malformed paths and normalize separators before Registry calls."""
        normalized = path.strip().replace("/", "\\").strip("\\")
        if "\x00" in normalized or any(part == ".." for part in normalized.split("\\")):
            raise ValueError("Registry key path contains an invalid component")
        if not normalized:
            raise ValueError("Mutating a hive root is not supported")
        return normalized

    def _validate_action(self, action: RegistryAction) -> RegistryAction:
        """Check each model proposal against real keys, supported types, and safe scope."""
        if action.hive not in self.settings.scan_hives:
            raise ValueError(f"Hive is not enabled for this server: {action.hive}")
        if action.view not in self.settings.registry_views:
            raise ValueError(f"Registry view is not enabled: {action.view}")
        action.key_path = self._normalize_path(action.key_path)
        for prefix in PROTECTED_PREFIXES.get(action.hive, ()):
            if action.key_path.casefold() == prefix.casefold() or action.key_path.casefold().startswith(
                prefix.casefold() + "\\"
            ):
                raise PermissionError(f"Changes under {action.hive}\\{prefix} are blocked")
        if action.action not in {"set_value", "delete_value"}:
            raise ValueError(f"Unsupported action: {action.action}")
        if not self.registry.key_exists(action.hive, action.view, action.key_path):
            raise ValueError(
                f"Registry key does not exist: {action.hive}\\{action.key_path} ({action.view}-bit)"
            )
        if action.action == "set_value":
            if not action.value_type:
                raise ValueError("set_value requires an explicit Registry data type")
            action.value_type = action.value_type.upper()
            if action.value_type not in ALLOWED_TYPES:
                raise ValueError(f"Unsupported Registry data type: {action.value_type}")
            action.value_data = self._validate_data(action.value_type, action.value_data)
        return action

    @staticmethod
    def _validate_data(value_type: str, value: Any) -> Any:
        """Reject type mismatches before Registry APIs see model-generated payloads."""
        if value_type in {"REG_SZ", "REG_EXPAND_SZ"}:
            if not isinstance(value, str):
                raise TypeError(f"{value_type} requires a string value")
            return value
        if value_type == "REG_MULTI_SZ":
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise TypeError("REG_MULTI_SZ requires a list of strings")
            return value
        if value_type in {"REG_DWORD", "REG_QWORD"}:
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{value_type} requires an integer")
            maximum = 0xFFFFFFFF if value_type == "REG_DWORD" else 0xFFFFFFFFFFFFFFFF
            if value < 0 or value > maximum:
                raise ValueError(f"{value_type} is outside its valid unsigned range")
            return value
        if value_type in {"REG_BINARY", "REG_NONE"}:
            if isinstance(value, str) and value.startswith("base64:"):
                return {"__bytes_base64__": value[7:]}
            if isinstance(value, dict) and set(value) == {"__bytes_base64__"}:
                base64.b64decode(value["__bytes_base64__"], validate=True)
                return value
            raise TypeError(f"{value_type} requires a base64: string or byte payload")
        raise TypeError(f"Unsupported Registry data type: {value_type}")

    @staticmethod
    def _action_identity(action: RegistryAction) -> tuple[str, str, str, str]:
        """Produce a stable identity for duplicate-target detection and backup records."""
        return (
            action.hive,
            action.view,
            action.key_path.casefold(),
            action.value_name.casefold(),
        )

    def _preflight(
        self, actions: list[RegistryAction]
    ) -> list[tuple[RegistryAction, dict[str, Any]]]:
        """Validate all mutations and read every original value before creating a backup."""
        prepared: list[tuple[RegistryAction, dict[str, Any]]] = []
        identities: set[tuple[str, str, str, str]] = set()
        for proposed in actions:
            action = self._validate_action(proposed)
            identity = self._action_identity(action)
            if identity in identities:
                raise ValueError("The plan contains duplicate mutations for the same Registry value")
            identities.add(identity)
            snapshot = self.registry.read_value(
                action.hive, action.view, action.key_path, action.value_name
            )
            if action.action == "delete_value" and not snapshot.get("exists"):
                raise ValueError(
                    f"Cannot delete missing Registry value {action.hive}\\"
                    f"{action.key_path}\\{action.value_name}"
                )
            if action.action == "set_value" and action.value_type is None:
                raise ValueError("set_value requires value_type")
            prepared.append((action, snapshot))
        return prepared

    @staticmethod
    def _backup_record(action: RegistryAction, snapshot: dict[str, Any]) -> dict[str, Any]:
        """Capture exact coordinates and original bytes/types for deterministic recovery."""
        return {
            "hive": action.hive,
            "view": action.view,
            "key_path": action.key_path,
            "value_name": action.value_name,
            "snapshot": snapshot,
        }

    def _restore_records(self, backup: list[dict[str, Any]]) -> list[str]:
        """Restore every saved value in reverse order and collect failures without stopping."""
        failures = []
        for record in reversed(backup):
            try:
                self.registry.restore_value(
                    record["hive"],
                    record["view"],
                    record["key_path"],
                    record["value_name"],
                    record["snapshot"],
                )
            except Exception as exc:  # Recovery must continue even if one key remains inaccessible.
                failures.append(
                    f"{record['hive']}\\{record['key_path']}\\{record['value_name']}: {exc}"
                )
        return failures

    def _refresh_index(self, actions: list[RegistryAction]) -> str:
        """Refresh only touched values so subsequent semantic queries see the applied state."""
        values: list[RegistryValue] = []
        removed = 0
        for action in actions:
            current = self.registry.read_value(
                action.hive, action.view, action.key_path, action.value_name
            )
            placeholder = RegistryValue(
                hive=action.hive,
                view=action.view,
                key_path=action.key_path,
                value_name=action.value_name,
                value_type=str(current.get("value_type", action.value_type or "REG_NONE")),
                value_data=current.get("value_data"),
            )
            if current.get("exists"):
                values.append(placeholder)
            else:
                self.store.delete_registry_value(placeholder)
                removed += 1
        result = self.indexer.index_values(values)
        return f"{result['indexed']} updated; {removed} removed from the search index"

    @staticmethod
    def _format_action(action: RegistryAction) -> str:
        """Render the precise target and intended data for the Rollout audit result."""
        value_name = action.value_name or "(Default)"
        if action.action == "delete_value":
            change = "DELETE value"
        else:
            change = f"SET {action.value_type} = {RegistryManager._format_data(action.value_data)}"
        location = f"{action.hive}\\{action.key_path}\\{value_name} ({action.view}-bit)"
        suffix = f" — {action.reason}" if action.reason else ""
        return f"- **{change}** `{location}`{suffix}"

    def rollout(self, prompt: str) -> str:
        """Plan, back up, and apply a user-requested Registry change with compensation."""
        request = prompt.strip()
        if not request:
            raise ValueError("Rollout prompt cannot be empty")
        with self._mutation_lock:
            query_vector = self._embed_query(request)
            candidates = self.store.search(query_vector, self.settings.top_k)
            plan, actions, tool_log = self.planner.plan(request, candidates)
            if not actions:
                notes = "\n".join(f"- {note}" for note in plan.get("notes", []))
                return (
                    "## Rollout not applied\n\n"
                    f"**Plan:** {plan.get('summary', 'No safe Registry changes were identified.')}\n\n"
                    f"{notes or 'No validated Registry mutations were produced.'}"
                )
            prepared = self._preflight(actions)
            backup = [self._backup_record(action, snapshot) for action, snapshot in prepared]
            rollout_id = self.store.create_rollout(request, plan, backup)
            applied: list[RegistryAction] = []
            try:
                for action, _snapshot in prepared:
                    self.registry.apply_action(action)
                    applied.append(action)
            except Exception as exc:
                LOGGER.exception("Rollout %s failed; restoring its pre-change snapshot", rollout_id)
                restore_failures = self._restore_records(backup)
                if restore_failures:
                    error = f"Apply error: {exc}; restore failures: {'; '.join(restore_failures)}"
                    self.store.finish_rollout(rollout_id, "rollback_failed", error)
                    raise RegistryError(
                        f"Rollout {rollout_id} failed and automatic restore was incomplete: {error}"
                    ) from exc
                self.store.finish_rollout(rollout_id, "failed_rolled_back", str(exc))
                raise RegistryError(
                    f"Rollout {rollout_id} failed; all attempted changes were restored: {exc}"
                ) from exc
            self.store.finish_rollout(rollout_id, "applied")
            try:
                index_status = self._refresh_index(actions)
            except Exception as exc:
                LOGGER.exception("Rollout %s succeeded but semantic index refresh failed", rollout_id)
                index_status = f"pending next startup scan ({exc})"
            lines = [
                f"## Rollout #{rollout_id} applied",
                f"**Plan:** {plan.get('summary', 'Registry changes applied.')}",
                f"**Automatic backup:** committed to `{self.store.database_path}` before the first write.",
                "**Changes:**",
            ]
            lines.extend(self._format_action(action) for action in actions)
            if plan.get("notes"):
                lines.append("**Notes:**\n" + "\n".join(f"- {note}" for note in plan["notes"]))
            lines.append(f"**Semantic index:** {index_status}.")
            if tool_log:
                lines.append(f"**Internal context tools used:** {len(tool_log)}")
            lines.append("Use `Rollback` to restore this rollout's pre-change values.")
            return "\n\n".join(lines)

    def recover_interrupted_rollouts(self) -> list[str]:
        """Restore prepared snapshots before serving MCP after an unclean process exit."""
        recovered: list[str] = []
        with self._mutation_lock:
            for rollout in self.store.prepared_rollouts():
                backup = json.loads(rollout["backup_json"])
                failures = self._restore_records(backup)
                if failures:
                    error = "; ".join(failures)
                    self.store.finish_rollout(int(rollout["id"]), "rollback_failed", error)
                    recovered.append(f"Rollout #{rollout['id']}: restore pending ({error})")
                else:
                    self.store.finish_rollout(int(rollout["id"]), "rolled_back")
                    recovered.append(f"Rollout #{rollout['id']}: interrupted changes restored")
        return recovered

    def rollback(self) -> str:
        """Restore the most recent successful or incompletely restored Registry rollout."""
        with self._mutation_lock:
            rollout = self.store.latest_applied_rollout()
            if not rollout:
                return "## Rollback\n\nThere is no successful Rollout available to restore."
            backup = json.loads(rollout["backup_json"])
            failures = self._restore_records(backup)
            if failures:
                error = "; ".join(failures)
                self.store.finish_rollout(int(rollout["id"]), "rollback_failed", error)
                return (
                    f"## Rollback #{rollout['id']} incomplete\n\n"
                    "Some original values could not be restored. The backup remains available "
                    f"for another attempt.\n\n{error}"
                )
            self.store.finish_rollout(int(rollout["id"]), "rolled_back")
            actions = [
                RegistryAction(
                    action="set_value",
                    hive=record["hive"],
                    view=record["view"],
                    key_path=record["key_path"],
                    value_name=record["value_name"],
                )
                for record in backup
            ]
            try:
                index_status = self._refresh_index(actions)
            except Exception as exc:
                LOGGER.exception("Rollback %s completed but semantic refresh failed", rollout["id"])
                index_status = f"pending next startup scan ({exc})"
            restored = len(backup)
            return (
                f"## Rollback #{rollout['id']} completed\n\n"
                f"Restored **{restored}** Registry value(s) from the automatic pre-Rollout backup.\n\n"
                f"**Semantic index:** {index_status}."
            )
