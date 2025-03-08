#!/usr/bin/env bash
echo "构建 Rust 项目..."

cargo build --release --target "$TARGET_ARCH" || { echo "Rust 项目构建失败"; exit 1; }

# 将 Rust 构建产物复制到对应架构的 release 文件夹
echo "复制 Rust 构建产物到 $SCRIPT_DIR/output/landscape-webserver-$TARGET"
# mkdir -p "$SCRIPT_DIR/output/$TARGET_ARCH"
cp "$SCRIPT_DIR/target/$TARGET_ARCH/release/landscape-webserver" "$SCRIPT_DIR/output/landscape-webserver-$TARGET"

cd "$SCRIPT_DIR"
