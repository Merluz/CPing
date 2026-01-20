#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="dist/linux"
BUILD_DIR="build"

echo "== CPING: Linux Release Build =="

# Safety check: Linux only
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script must be run on Linux"
  exit 1
fi

# Clean
rm -rf "$BUILD_DIR" "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Configure
cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$(pwd)/$INSTALL_DIR"

# Build
cmake --build "$BUILD_DIR" -- -j"$(nproc)"

# Install
cmake --install "$BUILD_DIR"

# Package
tar -czf "$INSTALL_DIR.tar.gz" "$INSTALL_DIR"

echo "== DONE! Output in: $INSTALL_DIR.tar.gz =="
