#!/usr/bin/env bash
# Smoke test: verify the binary builds and starts correctly.
# Run from the project root: bash tests/smoke_test.sh

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$PROJECT_ROOT/target/debug/openvpn3-gui-rs"

echo "==> Building..."
cargo build --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>&1

echo "==> Checking binary exists..."
if [[ ! -f "$BINARY" ]]; then
    echo "FAIL: binary not found at $BINARY"
    exit 1
fi

echo "==> Running --version..."
"$BINARY" --version

echo "==> Smoke test passed."
