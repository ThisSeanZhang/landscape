#!/usr/bin/env bash

set -euo pipefail

echo "SCRIPT_DIR: $SCRIPT_DIR"
echo "Target platform set to: $TARGET"
echo "Rust target: $TARGET_ARCH"
echo "Docker architecture: $DOCKER_ARCH"

echo "构建 Vue 项目..."
cd "$SCRIPT_DIR"

pnpm_cmd install --frozen-lockfile

"$SCRIPT_DIR/gen_ts_bindings.sh"

echo "复制 Scalar API Reference 资源到 output/static/scalar..."
SCALAR_OUTPUT_DIR="$SCRIPT_DIR/output/static/scalar"
SCALAR_JS_SRC="$SCRIPT_DIR/landscape-webui/node_modules/@scalar/api-reference/dist/browser/standalone.js"
SCALAR_CSS_SRC="$SCRIPT_DIR/landscape-webui/node_modules/@scalar/api-reference/dist/style.css"

pnpm_cmd --filter landscape-webui build

rm -rf "$SCRIPT_DIR/output/static"
mkdir -p "$SCALAR_OUTPUT_DIR"

echo "复制 Vue 构建产物到 output/static..."
cp -r "$SCRIPT_DIR/landscape-webui/dist/." "$SCRIPT_DIR/output/static/"

cp "$SCALAR_JS_SRC" "$SCALAR_OUTPUT_DIR/standalone.js"
cp "$SCALAR_CSS_SRC" "$SCALAR_OUTPUT_DIR/style.css"
