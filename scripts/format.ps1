$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

python -m ruff check --fix src tests
if ($LASTEXITCODE -ne 0) { throw "Ruff auto-fix failed" }

python -m black src tests
if ($LASTEXITCODE -ne 0) { throw "Black formatting failed" }

python -m ruff check src tests
if ($LASTEXITCODE -ne 0) { throw "Ruff lint failed" }
