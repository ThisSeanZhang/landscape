#!/usr/bin/env bash

set -euo pipefail

echo "构建 Rust 项目..."
cargo build --release --target "$TARGET_ARCH" --features=duckdb-bundled

echo "复制 Rust 构建产物到 $SCRIPT_DIR/output/landscape-webserver-$TARGET"
mkdir -p "$SCRIPT_DIR/output"
cp "$SCRIPT_DIR/target/$TARGET_ARCH/release/landscape-webserver" "$SCRIPT_DIR/output/landscape-webserver-$TARGET"
