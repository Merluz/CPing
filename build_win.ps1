# build_win.ps1
param(
    [string]$InstallDir = "dist/win64"
)

Write-Host "== CPING: Windows Release Build (MSVC) ==" -ForegroundColor Cyan

# Ensure clean
if (Test-Path "build") { Remove-Item -Recurse -Force build }
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }

# IMPORTANT:
# This script MUST be run from:
# "Developer PowerShell for Visual Studio"

# Configure (force MSVC generator)
cmake -S . -B build `
    -G "Visual Studio 17 2022" `
    -A x64 `
    -DCMAKE_INSTALL_PREFIX="$InstallDir"

# Build
cmake --build build --config Release

# Install
cmake --install build --config Release

# Archive result
if (Test-Path "$InstallDir.zip") { Remove-Item "$InstallDir.zip" }
Compress-Archive -Path "$InstallDir" -DestinationPath "$InstallDir.zip"

Write-Host "== DONE! Output in: $InstallDir.zip ==" -ForegroundColor Green
