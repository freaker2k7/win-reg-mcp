"""Command-line entry point for the elevated Windows Registry MCP server."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from win_reg_mcp.config import Settings, default_database_path
from win_reg_mcp.database import SQLiteStore
from win_reg_mcp.indexer import RegistryIndexer
from win_reg_mcp.internal_tools import InternalAgentTools
from win_reg_mcp.logging_config import configure_logging
from win_reg_mcp.manager import RegistryManager
from win_reg_mcp.mcp_server import create_mcp_server
from win_reg_mcp.ollama import OllamaClient
from win_reg_mcp.planner import RegistryPlanner
from win_reg_mcp.registry import WindowsRegistry, require_windows_admin


def build_parser() -> argparse.ArgumentParser:
    """Declare runtime models, data paths, logging, scan controls, and timeout defaults."""
    parser = argparse.ArgumentParser(
        prog="win-reg-mcp",
        description="Local AI-powered MCP server for searching and managing Windows Registry.",
    )
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--chat-model", default="qwen2.5:7b")
    parser.add_argument("--embedding-model", default="nomic-embed-text")
    parser.add_argument("--vision-model", default="qwen2.5vl:7b")
    parser.add_argument("--database", type=Path, default=default_database_path())
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    parser.add_argument("--log-file", type=Path)
    parser.add_argument("--ollama-timeout", type=float, default=240.0)
    parser.add_argument("--tool-timeout", type=float, default=30.0)
    parser.add_argument("--startup-timeout", type=float, default=3600.0)
    parser.add_argument("--keep-alive", default="5m")
    parser.add_argument("--scan-batch-size", type=int, default=32)
    parser.add_argument("--embedding-batch-size", type=int, default=32)
    parser.add_argument("--top-k", type=int, default=30)
    parser.add_argument("--max-tool-rounds", type=int, default=6)
    parser.add_argument("--web-search-results", type=int, default=5)
    parser.add_argument("--workspace-root", type=Path, action="append", default=[])
    parser.add_argument("--max-file-read-bytes", type=int, default=2_000_000)
    parser.add_argument("--max-file-write-bytes", type=int, default=2_000_000)
    parser.add_argument(
        "--hive",
        action="append",
        choices=("HKLM", "HKCU", "HKCR", "HKU", "HKCC"),
        dest="hives",
        help="Registry hive to scan; repeat to override the default all-hives list.",
    )
    parser.add_argument(
        "--view",
        action="append",
        choices=("64", "32", "default"),
        dest="views",
        help="Registry view to scan; repeat to override the default 64-bit and 32-bit views.",
    )
    return parser


def settings_from_args(args: argparse.Namespace) -> Settings:
    """Transfer parsed arguments into validated configuration used by all subsystems."""
    return Settings(
        ollama_url=args.ollama_url,
        chat_model=args.chat_model,
        embedding_model=args.embedding_model,
        vision_model=args.vision_model,
        database_path=args.database,
        log_level=args.log_level,
        log_file=args.log_file,
        ollama_timeout=args.ollama_timeout,
        tool_timeout=args.tool_timeout,
        startup_timeout=args.startup_timeout,
        keep_alive=args.keep_alive,
        scan_batch_size=args.scan_batch_size,
        embedding_batch_size=args.embedding_batch_size,
        top_k=args.top_k,
        max_tool_rounds=args.max_tool_rounds,
        web_search_results=args.web_search_results,
        workspace_roots=tuple(args.workspace_root),
        max_file_read_bytes=args.max_file_read_bytes,
        max_file_write_bytes=args.max_file_write_bytes,
        registry_views=tuple(args.views or ("64", "32")),
        scan_hives=tuple(args.hives or ("HKLM", "HKCU", "HKCR", "HKU", "HKCC")),
    ).normalized()


def build_manager(settings: Settings) -> RegistryManager:
    """Wire local Ollama, SQLite vectors, Registry access, and the internal agent tools."""
    store = SQLiteStore(settings.database_path)
    ollama = OllamaClient(settings)
    registry = WindowsRegistry(settings.scan_hives, settings.registry_views)
    indexer = RegistryIndexer(settings, registry, store, ollama)
    internal_tools = InternalAgentTools(settings, ollama)
    planner = RegistryPlanner(settings, ollama, internal_tools)
    return RegistryManager(settings, store, ollama, registry, indexer, planner)


def main() -> None:
    """Require elevation, complete the initial full scan, and then serve MCP over stdio."""
    args = build_parser().parse_args()
    settings = settings_from_args(args)
    configure_logging(settings)
    logger = logging.getLogger(__name__)
    try:
        require_windows_admin()
        manager = build_manager(settings)
        recovery = manager.recover_interrupted_rollouts()
        if recovery:
            logger.warning("Recovered interrupted Rollout records: %s", recovery)
        logger.info(
            "Starting full Registry scan across %s and views %s",
            settings.scan_hives,
            settings.registry_views,
        )
        scan_result = manager.indexer.full_scan()
        logger.info("Startup index result: %s", scan_result)
        server = create_mcp_server(manager)
        logger.info("MCP server ready; public tools: Search, Rollout, Rollback")
        server.run(transport="stdio")
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    except Exception:
        logger.exception("win-reg-mcp could not start or stopped unexpectedly")
        sys.exit(1)


if __name__ == "__main__":
    main()
