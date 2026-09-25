# Build UniGuard.exe with PyInstaller.
#
# Usage (from the repo root or launcher/):
#   powershell -ExecutionPolicy Bypass -File launcher/build.ps1
#
# Produces: launcher/dist/UniGuard.exe (single file, no console)

$ErrorActionPreference = "Stop"

# Resolve the launcher directory (this script's location).
$LauncherDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $LauncherDir

Write-Host "==> Regenerating icon" -ForegroundColor Cyan
python make_icon.py

Write-Host "==> Ensuring PyInstaller is installed" -ForegroundColor Cyan
python -m pip install --quiet --upgrade pyinstaller

Write-Host "==> Cleaning previous build" -ForegroundColor Cyan
if (Test-Path build) { Remove-Item -Recurse -Force build }
if (Test-Path dist)  { Remove-Item -Recurse -Force dist }

Write-Host "==> Building executable" -ForegroundColor Cyan
python -m PyInstaller --clean --noconfirm app.spec

$exe = Join-Path $LauncherDir "dist\UniGuard.exe"
if (Test-Path $exe) {
    $size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
    Write-Host ""
    Write-Host "BUILD OK  ->  $exe  ($size MB)" -ForegroundColor Green
    Write-Host "Double-click it, or keep it next to docker-compose.yml." -ForegroundColor Green
} else {
    Write-Error "Build failed: $exe not found"
    exit 1
}
