"""Runtime configuration shared by the registry, indexing, and agent layers."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def default_database_path() -> Path:
    """Choose a per-user data directory without requiring a config file."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "WinRegMCP" / "registry.sqlite3"
    return Path.home() / ".local" / "share" / "win-reg-mcp" / "registry.sqlite3"


@dataclass(slots=True)
class Settings:
    """Configuration values that control the local Ollama and Windows runtime."""

    ollama_url: str = "http://127.0.0.1:11434"
    chat_model: str = "qwen2.5:7b"
    embedding_model: str = "nomic-embed-text"
    vision_model: str = "qwen2.5vl:7b"
    database_path: Path = field(default_factory=default_database_path)
    log_level: str = "INFO"
    log_file: Path | None = None
    ollama_timeout: float = 240.0
    tool_timeout: float = 30.0
    startup_timeout: float = 3600.0
    keep_alive: str = "5m"
    scan_batch_size: int = 32
    embedding_batch_size: int = 32
    top_k: int = 30
    max_tool_rounds: int = 6
    web_search_results: int = 5
    workspace_roots: tuple[Path, ...] = ()
    max_file_read_bytes: int = 2_000_000
    max_file_write_bytes: int = 2_000_000
    registry_views: tuple[str, ...] = ("64", "32")
    scan_hives: tuple[str, ...] = ("HKLM", "HKCU", "HKCR", "HKU", "HKCC")

    def normalized(self) -> Settings:
        """Return a validated copy with canonical URLs and paths."""
        self.database_path = Path(self.database_path).expanduser().resolve()
        if self.log_file is not None:
            self.log_file = Path(self.log_file).expanduser().resolve()
        self.workspace_roots = tuple(
            Path(path).expanduser().resolve() for path in self.workspace_roots
        )
        self.ollama_url = self.ollama_url.rstrip("/")
        if self.scan_batch_size < 1 or self.embedding_batch_size < 1:
            raise ValueError("Batch sizes must be positive")
        if self.top_k < 1 or self.max_tool_rounds < 1:
            raise ValueError("top_k and max_tool_rounds must be positive")
        if self.ollama_timeout <= 0 or self.tool_timeout <= 0 or self.startup_timeout <= 0:
            raise ValueError("Timeout values must be positive")
        return self
