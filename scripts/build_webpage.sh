#!/usr/bin/env bash

echo "SCRIPT_DIR: $SCRIPT_DIR"
echo "Target platform set to: $TARGET"
echo "Rust target: $TARGET_ARCH"
echo "Docker architecture: $DOCKER_ARCH"

echo "构建 Vue 项目..."
cd "$SCRIPT_DIR" || { echo "找不到项目根目录"; exit 1; }

pnpm install --frozen-lockfile || { echo "依赖安装失败"; exit 1; }
pnpm --filter landscape-webui build || { echo "Vue 项目构建失败"; exit 1; }

echo "复制 Vue 构建产物到 output/static..."
mkdir -p "$SCRIPT_DIR/output/static"
cp -r "$SCRIPT_DIR/landscape-webui/dist/"* "$SCRIPT_DIR/output/static/"