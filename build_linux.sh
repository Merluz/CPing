#!/usr/bin/env bash
set -e

INSTALL_DIR="dist/linux"

echo "== CPING: Linux Release Build =="

rm -rf build "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"

cmake --build build -- -j$(nproc)

cmake --install build

tar -czf "$INSTALL_DIR.tar.gz" "$INSTALL_DIR"

echo "== DONE! Output in: $INSTALL_DIR.tar.gz =="
