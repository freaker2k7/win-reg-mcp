"""Behavioral tests for the three public MCP workflows without Windows or Ollama."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from win_reg_mcp.config import Settings
from win_reg_mcp.manager import RegistryManager
from win_reg_mcp.models import RegistryAction, RegistryFinding, RegistryValue


class FakeOllama:
    """Return deterministic vectors so tests focus on public tool orchestration."""

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[0.1, 0.2, 0.3] for _ in texts]


class FakeStore:
    """Capture durable rollout calls and provide stable semantic search results."""

    def __init__(self) -> None:
        self.database_path = Path("C:/Temp/registry.sqlite3")
        self.finished: list[tuple[int, str, str | None]] = []
        self.created: dict[str, Any] | None = None
        self.last_rollout: dict[str, Any] | None = None
        self.deleted: list[RegistryValue] = []
        self.events: list[str] = []

    def get_vector_dimension(self) -> int:
        return 3

    def search(self, embedding: list[float], limit: int) -> list[RegistryFinding]:
        assert embedding == [0.1, 0.2, 0.3]
        return [
            RegistryFinding(
                entry_id=1,
                hive="HKCU",
                view="64",
                key_path="Control Panel\\Desktop",
                value_name="Wallpaper",
                value_type="REG_SZ",
                value_data="C:\\old.jpg",
                explanation="The path of the current user desktop wallpaper image.",
                distance=0.08,
            )
        ][:limit]

    def create_rollout(
        self, prompt: str, plan: dict[str, Any], backup: list[dict[str, Any]]
    ) -> int:
        self.created = {"prompt": prompt, "plan": plan, "backup": backup}
        self.events.append("backup_committed")
        return 17

    def finish_rollout(self, rollout_id: int, status: str, error: str | None = None) -> None:
        self.finished.append((rollout_id, status, error))

    def delete_registry_value(self, value: RegistryValue) -> None:
        self.deleted.append(value)

    def latest_applied_rollout(self) -> dict[str, Any] | None:
        return self.last_rollout


class FakeRegistry:
    """Simulate exact Registry reads, changes, and pre-change recovery."""

    def __init__(self) -> None:
        self.values: dict[tuple[str, str, str, str], dict[str, Any]] = {
            ("HKCU", "64", "Control Panel\\Desktop", "Wallpaper"): {
                "exists": True,
                "value_type": "REG_SZ",
                "value_data": "C:\\old.jpg",
            }
        }
        self.applied: list[RegistryAction] = []
        self.restored: list[tuple[str, str, str, str, dict[str, Any]]] = []
        self.events: list[str] = []

    def key_exists(self, hive: str, view: str, key_path: str) -> bool:
        return True

    def read_value(self, hive: str, view: str, key_path: str, value_name: str) -> dict[str, Any]:
        return self.values.get((hive, view, key_path, value_name), {"exists": False})

    def apply_action(self, action: RegistryAction) -> None:
        self.applied.append(action)
        self.events.append("registry_write")
        key = (action.hive, action.view, action.key_path, action.value_name)
        if action.action == "set_value":
            self.values[key] = {
                "exists": True,
                "value_type": action.value_type,
                "value_data": action.value_data,
            }
        else:
            self.values.pop(key, None)

    def restore_value(
        self,
        hive: str,
        view: str,
        key_path: str,
        value_name: str,
        snapshot: dict[str, Any],
    ) -> None:
        self.restored.append((hive, view, key_path, value_name, snapshot))
        key = (hive, view, key_path, value_name)
        if snapshot.get("exists"):
            self.values[key] = snapshot
        else:
            self.values.pop(key, None)


class FakeIndexer:
    """Record semantic refresh requests without calling the model or SQLite extension."""

    def __init__(self) -> None:
        self.values: list[RegistryValue] = []

    def index_values(self, values: list[RegistryValue]) -> dict[str, int]:
        self.values.extend(values)
        return {"indexed": len(values), "unchanged": 0}


class FakePlanner:
    """Return a fixed plan for a user-approved Rollout request."""

    def __init__(self, actions: list[RegistryAction]) -> None:
        self.actions = actions

    def plan(
        self, prompt: str, candidates: list[RegistryFinding]
    ) -> tuple[dict[str, Any], list[RegistryAction], list[str]]:
        return (
            {"summary": "Change the desktop wallpaper", "actions": [], "notes": []},
            self.actions,
            [],
        )


def build_manager(
    store: FakeStore,
    registry: FakeRegistry,
    indexer: FakeIndexer,
    planner: FakePlanner,
) -> RegistryManager:
    """Construct the manager with deterministic dependencies for isolated tool tests."""
    settings = Settings(top_k=10, registry_views=("64", "32"), scan_hives=("HKLM", "HKCU", "HKCR", "HKU", "HKCC"))
    return RegistryManager(settings, store, FakeOllama(), registry, indexer, planner)


def test_search_returns_ranked_human_readable_findings() -> None:
    """Search should return key coordinates, current value data, and its explanation."""
    store = FakeStore()
    registry = FakeRegistry()
    indexer = FakeIndexer()
    manager = build_manager(store, registry, indexer, FakePlanner([]))

    result = manager.search("where is the Windows desktop wallpaper stored?", limit=5)

    assert "Registry Search Results" in result
    assert "Control Panel\\Desktop" in result
    assert "Wallpaper" in result
    assert "old.jpg" in result
    assert "current user desktop wallpaper image" in result


def test_rollout_persists_backup_before_applying_change() -> None:
    """Rollout should persist the original value before applying the model's mutation."""
    store = FakeStore()
    registry = FakeRegistry()
    indexer = FakeIndexer()
    action = RegistryAction(
        action="set_value",
        hive="HKCU",
        view="64",
        key_path="Control Panel\\Desktop",
        value_name="Wallpaper",
        value_type="REG_SZ",
        value_data="C:\\XYZ\\third.jpg",
        reason="Set the requested wallpaper image.",
    )
    store.events = registry.events
    manager = build_manager(store, registry, indexer, FakePlanner([action]))

    result = manager.rollout("Change desktop wallpaper to the third file in C:\\XYZ")

    assert store.created is not None
    assert store.created["backup"][0]["snapshot"]["value_data"] == "C:\\old.jpg"
    assert registry.applied == [action]
    assert store.events == ["backup_committed", "registry_write"]
    assert registry.values[("HKCU", "64", "Control Panel\\Desktop", "Wallpaper")][
        "value_data"
    ] == "C:\\XYZ\\third.jpg"
    assert store.finished == [(17, "applied", None)]
    assert "Rollout #17 applied" in result
    assert "Automatic backup" in result
    assert len(indexer.values) == 1


def test_rollback_restores_the_last_rollout_snapshot() -> None:
    """Rollback should restore the newest rollout's saved value and update search indexing."""
    store = FakeStore()
    registry = FakeRegistry()
    indexer = FakeIndexer()
    registry.values[("HKCU", "64", "Control Panel\\Desktop", "Wallpaper")][
        "value_data"
    ] = "C:\\XYZ\\third.jpg"
    store.last_rollout = {
        "id": 17,
        "backup_json": json.dumps(
            [
                {
                    "hive": "HKCU",
                    "view": "64",
                    "key_path": "Control Panel\\Desktop",
                    "value_name": "Wallpaper",
                    "snapshot": {
                        "exists": True,
                        "value_type": "REG_SZ",
                        "value_data": "C:\\old.jpg",
                    },
                }
            ]
        ),
    }
    manager = build_manager(store, registry, indexer, FakePlanner([]))

    result = manager.rollback()

    assert registry.restored[0][4]["value_data"] == "C:\\old.jpg"
    assert registry.values[("HKCU", "64", "Control Panel\\Desktop", "Wallpaper")][
        "value_data"
    ] == "C:\\old.jpg"
    assert store.finished == [(17, "rolled_back", None)]
    assert "Rollback #17 completed" in result
    assert len(indexer.values) == 1
