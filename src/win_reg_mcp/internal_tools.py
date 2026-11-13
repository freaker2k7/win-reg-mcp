"""Local-only desktop and file tools available to the rollout planner, not to MCP clients."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from win_reg_mcp.config import Settings
from win_reg_mcp.ollama import OllamaClient

LOGGER = logging.getLogger(__name__)

INTERNAL_TOOL_SPECS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a small UTF-8 text file when its contents are needed.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write UTF-8 text under a configured workspace root only.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_file",
            "description": "Find files recursively under a folder; results are sorted by path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "root": {"type": "string"},
                    "pattern": {"type": "string", "default": "*"},
                    "limit": {"type": "integer", "default": 200},
                },
                "required": ["root"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_file",
            "description": "Delete one file under a configured workspace root only.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_web",
            "description": "Search public web pages for factual information that may affect a plan.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "default": 5},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "take_screenshot",
            "description": "Capture the current Windows desktop and return the local image path.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_objects_and_describe_screenshot",
            "description": "Describe visible objects, text, and UI elements in a prior screenshot path.",
            "parameters": {
                "type": "object",
                "properties": {"image_path": {"type": "string"}},
                "required": ["image_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "take_webcamshot",
            "description": "Capture one frame from the default webcam and return the local image path.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_objects_and_describe_webcamshot",
            "description": "Describe visible objects and scene context in a prior webcam image path.",
            "parameters": {
                "type": "object",
                "properties": {"image_path": {"type": "string"}},
                "required": ["image_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "move_mouse",
            "description": "Move the desktop pointer to screen coordinates.",
            "parameters": {
                "type": "object",
                "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}},
                "required": ["x", "y"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "click_left_mouse",
            "description": "Perform one left mouse click, optionally at screen coordinates.",
            "parameters": {
                "type": "object",
                "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "click_right_mouse",
            "description": "Perform one right mouse click, optionally at screen coordinates.",
            "parameters": {
                "type": "object",
                "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "release_left_mouse",
            "description": "Release the left mouse button.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "release_right_mouse",
            "description": "Release the right mouse button.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "press_key",
            "description": "Press a keyboard key or a pyautogui key name such as enter or ctrl.",
            "parameters": {
                "type": "object",
                "properties": {"key": {"type": "string"}},
                "required": ["key"],
            },
        },
    },
]


class InternalAgentTools:
    """Provide opt-in desktop capabilities to the LLM while keeping them off the MCP surface."""

    def __init__(self, settings: Settings, ollama: OllamaClient) -> None:
        self.settings = settings
        self.ollama = ollama
        self.workspace_roots = settings.workspace_roots or (Path.cwd().resolve(),)

    @staticmethod
    def _path(path: str) -> Path:
        """Normalize a user-supplied path without following a nonexistent target."""
        return Path(os.path.expandvars(os.path.expanduser(path))).resolve()

    def _require_workspace(self, path: Path) -> None:
        """Keep writes and deletes inside configured workspace roots."""
        for root in self.workspace_roots:
            try:
                path.relative_to(root)
                return
            except ValueError:
                continue
        roots = ", ".join(str(root) for root in self.workspace_roots)
        raise PermissionError(f"Path is outside configured workspace roots: {roots}")

    def read_file(self, path: str) -> str:
        """Read text assets needed to complete a user-requested system change."""
        file_path = self._path(path)
        if not file_path.is_file():
            raise FileNotFoundError(file_path)
        if file_path.stat().st_size > self.settings.max_file_read_bytes:
            raise ValueError("File exceeds the configured read size limit")
        return file_path.read_text(encoding="utf-8", errors="replace")

    def write_file(self, path: str, content: str) -> str:
        """Create or replace a workspace file through an atomic temporary-file move."""
        file_path = self._path(path)
        self._require_workspace(file_path)
        encoded = content.encode("utf-8")
        if len(encoded) > self.settings.max_file_write_bytes:
            raise ValueError("Content exceeds the configured write size limit")
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=file_path.parent, prefix=".winreg-mcp-", delete=False
        ) as temporary:
            temporary.write(encoded)
            temporary_path = Path(temporary.name)
        temporary_path.replace(file_path)
        return f"Wrote {len(encoded)} bytes to {file_path}"

    def find_file(self, root: str, pattern: str = "*", limit: int = 200) -> str:
        """Return deterministic file matches so ordinal file requests can be resolved."""
        root_path = self._path(root)
        if not root_path.is_dir():
            raise NotADirectoryError(root_path)
        bounded_limit = max(1, min(int(limit), 1000))
        matches: list[str] = []
        for current_root, directories, files in os.walk(root_path, followlinks=False):
            directories.sort(key=str.casefold)
            for name in files:
                candidate = Path(current_root) / name
                if candidate.match(pattern):
                    matches.append(str(candidate))
        matches.sort(key=str.casefold)
        limited_matches = matches[:bounded_limit]
        return json.dumps(
            {
                "root": str(root_path),
                "pattern": pattern,
                "count": len(limited_matches),
                "total_matches": len(matches),
                "files": limited_matches,
            },
            ensure_ascii=False,
            indent=2,
        )

    def delete_file(self, path: str) -> str:
        """Delete one explicitly requested workspace file and reject directory deletion."""
        file_path = self._path(path)
        self._require_workspace(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(file_path)
        file_path.unlink()
        return f"Deleted {file_path}"

    def search_web(self, query: str, limit: int = 5) -> str:
        """Fetch concise public search results for technical details the local model lacks."""
        try:
            from ddgs import DDGS
        except ImportError as exc:
            raise RuntimeError("Web search dependency is unavailable") from exc
        bounded_limit = max(1, min(int(limit), self.settings.web_search_results))
        with DDGS() as search:
            results = list(search.text(query, max_results=bounded_limit))
        return json.dumps(results, ensure_ascii=False, indent=2)

    @staticmethod
    def _temporary_image(suffix: str) -> Path:
        """Allocate a stable temporary path for image tools that pass a later model call."""
        handle, name = tempfile.mkstemp(prefix="winreg-mcp-", suffix=suffix)
        os.close(handle)
        return Path(name)

    def take_screenshot(self) -> str:
        """Capture the desktop for a user-requested visual inspection task."""
        try:
            import pyautogui
        except ImportError as exc:
            raise RuntimeError("pyautogui is required for desktop capture") from exc
        target = self._temporary_image(".png")
        pyautogui.screenshot().save(target)
        return str(target)

    def detect_objects_and_describe_screenshot(self, image_path: str) -> str:
        """Use a local vision model to describe a previously captured desktop image."""
        return self.ollama.describe_image(
            self._path(image_path),
            "Describe the visible UI, objects, text, and relevant state. Be precise and concise.",
        )

    def take_webcamshot(self) -> str:
        """Capture one frame from the default webcam for a specifically requested inspection."""
        try:
            import cv2
        except ImportError as exc:
            raise RuntimeError("opencv-python-headless is required for webcam capture") from exc
        capture = cv2.VideoCapture(0)
        try:
            success, frame = capture.read()
        finally:
            capture.release()
        if not success:
            raise RuntimeError("The default webcam did not return a frame")
        target = self._temporary_image(".jpg")
        if not cv2.imwrite(str(target), frame):
            raise RuntimeError("Could not save the webcam frame")
        return str(target)

    def detect_objects_and_describe_webcamshot(self, image_path: str) -> str:
        """Use a local vision model to describe a previously captured webcam frame."""
        return self.ollama.describe_image(
            self._path(image_path),
            "Describe visible objects and the scene. Do not identify people; be concise.",
        )

    @staticmethod
    def _pyautogui() -> Any:
        """Load desktop automation only when an internal desktop tool is actually requested."""
        try:
            import pyautogui
        except ImportError as exc:
            raise RuntimeError("pyautogui is required for mouse and keyboard automation") from exc
        pyautogui.FAILSAFE = True
        return pyautogui

    def move_mouse(self, x: int, y: int) -> str:
        """Move the pointer for a user-directed UI workflow."""
        self._pyautogui().moveTo(int(x), int(y))
        return f"Moved pointer to ({x}, {y})"

    def click_left_mouse(self, x: int | None = None, y: int | None = None) -> str:
        """Click the left mouse button at the current pointer position or supplied coordinates."""
        self._pyautogui().click(x=x, y=y, button="left")
        return "Left mouse button clicked"

    def click_right_mouse(self, x: int | None = None, y: int | None = None) -> str:
        """Click the right mouse button at the current pointer position or supplied coordinates."""
        self._pyautogui().click(x=x, y=y, button="right")
        return "Right mouse button clicked"

    def release_left_mouse(self) -> str:
        """Release a held left mouse button during a desktop interaction sequence."""
        self._pyautogui().mouseUp(button="left")
        return "Left mouse button released"

    def release_right_mouse(self) -> str:
        """Release a held right mouse button during a desktop interaction sequence."""
        self._pyautogui().mouseUp(button="right")
        return "Right mouse button released"

    def press_key(self, key: str) -> str:
        """Press a key through pyautogui after rejecting empty or unusually long inputs."""
        if not key or len(key) > 40:
            raise ValueError("Key name must contain between 1 and 40 characters")
        self._pyautogui().press(key)
        return f"Pressed key: {key}"

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        """Resolve only declared internal function names for Ollama tool-call dispatch."""
        handlers = {
            "read_file": self.read_file,
            "write_file": self.write_file,
            "find_file": self.find_file,
            "delete_file": self.delete_file,
            "search_web": self.search_web,
            "take_screenshot": self.take_screenshot,
            "detect_objects_and_describe_screenshot": self.detect_objects_and_describe_screenshot,
            "take_webcamshot": self.take_webcamshot,
            "detect_objects_and_describe_webcamshot": self.detect_objects_and_describe_webcamshot,
            "move_mouse": self.move_mouse,
            "click_left_mouse": self.click_left_mouse,
            "click_right_mouse": self.click_right_mouse,
            "release_left_mouse": self.release_left_mouse,
            "release_right_mouse": self.release_right_mouse,
            "press_key": self.press_key,
        }
        try:
            handler = handlers[name]
        except KeyError as exc:
            raise ValueError(f"Unknown internal tool: {name}") from exc
        result = handler(**arguments)
        return str(result)
