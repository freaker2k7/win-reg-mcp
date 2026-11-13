$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

python -m pytest --cov=win_reg_mcp --cov-report=term-missing --cov-report=xml:coverage.xml --cov-fail-under=30 -q
if ($LASTEXITCODE -ne 0) { throw "Pytest or coverage failed" }
