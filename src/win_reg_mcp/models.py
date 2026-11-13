"""Typed records shared by the scanner, semantic index, and rollout engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class RegistryValue:
    """One value read from a specific Windows Registry view."""

    hive: str
    view: str
    key_path: str
    value_name: str
    value_type: str
    value_data: Any

    def to_dict(self) -> dict[str, Any]:
        """Create a JSON-compatible representation for indexing and MCP output."""
        return asdict(self)


@dataclass(slots=True)
class RegistryFinding:
    """A registry value enriched with an AI explanation and search distance."""

    entry_id: int
    hive: str
    view: str
    key_path: str
    value_name: str
    value_type: str
    value_data: Any
    explanation: str
    distance: float

    def to_dict(self) -> dict[str, Any]:
        """Create a stable response object for the Search tool."""
        return asdict(self)


@dataclass(slots=True)
class RegistryAction:
    """A validated value mutation proposed by the local planning model."""

    action: str
    hive: str
    view: str
    key_path: str
    value_name: str
    value_type: str | None = None
    value_data: Any = None
    reason: str = ""

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RegistryAction:
        """Create an action from the planner response after checking its shape."""
        required = ("action", "hive", "view", "key_path", "value_name")
        missing = [field_name for field_name in required if field_name not in payload]
        if missing:
            raise ValueError(f"Planner action is missing fields: {', '.join(missing)}")
        return cls(
            action=str(payload["action"]).lower(),
            hive=str(payload["hive"]).upper(),
            view=str(payload["view"]),
            key_path=str(payload["key_path"]),
            value_name=str(payload["value_name"]),
            value_type=(str(payload["value_type"]).upper() if payload.get("value_type") else None),
            value_data=payload.get("value_data"),
            reason=str(payload.get("reason", "")),
        )
