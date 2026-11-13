"""Grounded natural-language-to-Registry planning with private local agent tools."""

from __future__ import annotations

import json
import logging
from typing import Any

from win_reg_mcp.config import Settings
from win_reg_mcp.internal_tools import INTERNAL_TOOL_SPECS, InternalAgentTools
from win_reg_mcp.models import RegistryAction, RegistryFinding
from win_reg_mcp.ollama import OllamaClient

LOGGER = logging.getLogger(__name__)

PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["set_value", "delete_value"]},
                    "hive": {"type": "string", "enum": ["HKLM", "HKCU", "HKCR", "HKU", "HKCC"]},
                    "view": {"type": "string", "enum": ["32", "64", "default"]},
                    "key_path": {"type": "string"},
                    "value_name": {"type": "string"},
                    "value_type": {
                        "type": "string",
                        "enum": [
                            "REG_SZ",
                            "REG_EXPAND_SZ",
                            "REG_MULTI_SZ",
                            "REG_DWORD",
                            "REG_QWORD",
                            "REG_BINARY",
                            "REG_NONE",
                        ],
                    },
                    "value_data": {},
                    "reason": {"type": "string"},
                },
                "required": [
                    "action",
                    "hive",
                    "view",
                    "key_path",
                    "value_name",
                ],
            },
        },
        "notes": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "actions", "notes"],
}


class RegistryPlanner:
    """Use vector matches and private tools to turn a user request into a small change plan."""

    def __init__(
        self,
        settings: Settings,
        ollama: OllamaClient,
        internal_tools: InternalAgentTools,
    ) -> None:
        self.settings = settings
        self.ollama = ollama
        self.internal_tools = internal_tools

    @staticmethod
    def _candidate_context(candidates: list[RegistryFinding]) -> str:
        """Serialize relevant cached Registry knowledge so planning need not rediscover it."""
        compact = []
        for candidate in candidates:
            compact.append(
                {
                    "hive": candidate.hive,
                    "view": candidate.view,
                    "key_path": candidate.key_path,
                    "value_name": candidate.value_name,
                    "value_type": candidate.value_type,
                    "value_data": candidate.value_data,
                    "explanation": candidate.explanation,
                    "semantic_distance": round(candidate.distance, 5),
                }
            )
        return json.dumps(compact, ensure_ascii=False, indent=2)

    def plan(
        self,
        prompt: str,
        candidates: list[RegistryFinding],
    ) -> tuple[dict[str, Any], list[RegistryAction], list[str]]:
        """Resolve contextual details with private tools and request schema-valid mutations."""
        system = (
            "You are the planning component of a Windows Registry administration agent running "
            "with administrator privileges. The user has explicitly requested a Rollout. "
            "Use the supplied Registry candidates as the primary source of Registry paths and "
            "meaning; do not invent keys or values. If the task references a file, folder, ordinal "
            "file, screen state, or other local context, call the appropriate internal tool first. "
            "For ordinal files, call find_file and use its sorted order; never guess a file path. "
            "Do not call webcam, screenshot, mouse, keyboard, write_file, or delete_file tools "
            "unless the user's task directly requires them. Never delete files unless explicitly "
            "requested. Registry actions may only be set_value or delete_value. Preserve existing "
            "types unless a type change is required. Use the correct hive and Registry view. "
            "Only propose the minimum changes needed. If the available evidence is insufficient, "
            "return an empty actions array and explain the limitation in notes. Do not claim an "
            "action has been applied. Return only the requested plan object."
        )
        user = (
            f"User request:\n{prompt}\n\n"
            "Relevant Registry index findings (nearest semantic matches first):\n"
            f"{self._candidate_context(candidates)}\n\n"
            "For every action, provide the complete hive, view, key path, value name, exact data "
            "type and correctly typed value data."
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        tool_log: list[str] = []
        for _ in range(self.settings.max_tool_rounds):
            response = self.ollama.chat_with_tools(messages, INTERNAL_TOOL_SPECS)
            message = response.get("message", {})
            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                content = str(message.get("content", "")).strip()
                if not content:
                    raise RuntimeError("The planning model returned no plan")
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    parsed = json.loads(self.ollama.chat_json(messages, PLAN_SCHEMA))
                return self._parse_plan(parsed), self._parse_actions(parsed), tool_log
            messages.append(message)
            for tool_call in tool_calls:
                function = tool_call.get("function", {})
                name = str(function.get("name", ""))
                arguments = function.get("arguments", {})
                if isinstance(arguments, str):
                    arguments = json.loads(arguments)
                try:
                    result = self.internal_tools.dispatch(name, arguments)
                    tool_log.append(f"{name}: {result[:1000]}")
                except Exception as exc:  # Tool errors are returned to the planner for correction.
                    result = f"Internal tool error: {type(exc).__name__}: {exc}"
                    tool_log.append(f"{name}: {result}")
                messages.append(
                    {
                        "role": "tool",
                        "tool_name": name,
                        "content": result[:12000],
                    }
                )
        response_text = self.ollama.chat_json(
            messages
            + [
                {
                    "role": "user",
                    "content": "Stop using tools and return the final Registry plan as JSON now.",
                }
            ],
            PLAN_SCHEMA,
        )
        parsed = json.loads(response_text)
        return self._parse_plan(parsed), self._parse_actions(parsed), tool_log

    @staticmethod
    def _parse_plan(parsed: dict[str, Any]) -> dict[str, Any]:
        """Normalize model output to the durable fields shown in Rollout results."""
        if not isinstance(parsed, dict) or not isinstance(parsed.get("actions"), list):
            raise ValueError("The planning model returned an invalid plan object")
        return {
            "summary": str(parsed.get("summary", "")),
            "actions": parsed["actions"],
            "notes": [str(note) for note in parsed.get("notes", [])],
        }

    @staticmethod
    def _parse_actions(parsed: dict[str, Any]) -> list[RegistryAction]:
        """Convert raw model proposals into typed actions for validation and backup."""
        return [RegistryAction.from_dict(item) for item in parsed.get("actions", [])]
