#!/usr/bin/env bash

set -euo pipefail

BUILD_PROFILE="${BUILD_PROFILE:-fast}"

echo "构建 Rust 项目 (profile: $BUILD_PROFILE)..."
cargo build --locked --profile "$BUILD_PROFILE" --target "$TARGET_ARCH" --features=metric-persistent,mem-track

echo "复制 Rust 构建产物到 $SCRIPT_DIR/output/landscape-webserver-$TARGET"
mkdir -p "$SCRIPT_DIR/output"
cp "$SCRIPT_DIR/target/$TARGET_ARCH/$BUILD_PROFILE/landscape-webserver" "$SCRIPT_DIR/output/landscape-webserver-$TARGET"
