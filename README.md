# win-reg-mcp

Local Python MCP server for semantic search and controlled changes across `HKLM`, `HKCU`, `HKCR`, `HKU`, and `HKCC`, in both 64-bit and 32-bit Registry views. The process must run elevated as Administrator.

## Setup

Install Python 3.11+, Ollama, and the project dependencies in an Administrator PowerShell:

```powershell
ollama pull qwen2.5:7b
ollama pull nomic-embed-text
ollama pull qwen2.5vl:7b  # optional; used only for screenshot/webcam descriptions
python -m pip install -e ".[dev]"
```

Start with `python -m win_reg_mcp`. The initial scan runs before MCP becomes available (default startup timeout: one hour; override with `--startup-timeout`). Existing explanations and embeddings are cached in SQLite; unchanged values are not sent to the LLM again. The server exposes exactly three MCP tools: `Search`, `Rollout`, and `Rollback`.

```powershell
python -m win_reg_mcp --database "$env:LOCALAPPDATA\WinRegMCP\registry.sqlite3" --workspace-root "C:\Work"
```

`Rollout` creates and commits a SQLite snapshot of every target value before applying any change. `Rollback` restores the newest successful rollout. File write/delete agent tools are restricted to configured `--workspace-root` paths (or the current directory when none is configured).

## Build and validation

Run `scripts\format.ps1`, `scripts\test.ps1`, and `scripts\build.ps1` from PowerShell. The ZIP contains source and the complete PyInstaller command, not a prebuilt binary: run `scripts\build.ps1` on Windows to create `dist\win-reg-mcp.exe` (PyInstaller builds for its host OS).
