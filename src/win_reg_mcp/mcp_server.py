"""Expose the three public Registry workflows through the Model Context Protocol."""

from __future__ import annotations

from typing import Any

from win_reg_mcp.manager import RegistryManager


def create_mcp_server(manager: RegistryManager) -> Any:
    """Build an MCP server whose public surface is limited to Search, Rollout, and Rollback."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("The MCP Python SDK is required; install `mcp>=1.28,<2`") from exc
    server = FastMCP("win-reg-mcp")

    @server.tool(name="Search")
    def Search(prompt: str, limit: int = 30) -> str:  # noqa: N802
        """Search all indexed Windows Registry hives using a natural-language description."""
        return manager.search(prompt, limit)

    @server.tool(name="Rollout")
    def Rollout(prompt: str) -> str:  # noqa: N802
        """Plan and apply a natural-language Registry change after an automatic pre-change backup."""
        return manager.rollout(prompt)

    @server.tool(name="Rollback")
    def Rollback() -> str:  # noqa: N802
        """Restore the most recent Rollout from its SQLite pre-change backup."""
        return manager.rollback()

    return server
