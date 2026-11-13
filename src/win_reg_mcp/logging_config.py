"""Centralized logging setup for console and optional rotating log output."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from win_reg_mcp.config import Settings


def configure_logging(settings: Settings) -> None:
    """Configure consistent diagnostics without writing logs to MCP stdout."""
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if settings.log_file:
        settings.log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            RotatingFileHandler(
                settings.log_file,
                maxBytes=5_000_000,
                backupCount=3,
                encoding="utf-8",
            )
        )
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
