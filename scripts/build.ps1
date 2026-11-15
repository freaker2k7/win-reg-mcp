$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

python -m pip install -e ".[dev]"
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed" }

python -m PyInstaller --noconfirm --clean --onefile --name win-reg-mcp --paths src --collect-all sqlite_vec --collect-all mcp --collect-all pyautogui --collect-all PIL --collect-all cv2 --collect-all ddgs --collect-all typer --hidden-import winreg --hidden-import win32api --hidden-import win32con --hidden-import win32gui --hidden-import win32security --copy-metadata mcp --copy-metadata ddgs src/win_reg_mcp/cli.py

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed with exit code $LASTEXITCODE"
}

New-Item -ItemType Directory -Name "build"
Move-Item -Path ".\dist\win-reg-mcp.exe" -Destination ".\build\win-reg-mcp.exe"
Write-Host "Final build: build\win-reg-mcp.exe"

python -m build
if ($LASTEXITCODE -ne 0) {
    throw "Python build failed with exit code $LASTEXITCODE"
}

Write-Host "Build completed successfully"