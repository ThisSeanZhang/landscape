#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TYPES_DIR="$SCRIPT_DIR/landscape-types"
API_DIR="$TYPES_DIR/src/api"

# 1. Generate OpenAPI spec → landscape-types/openapi.json
echo "Exporting OpenAPI spec..."
cargo test -p landscape-webserver export_openapi_json -- --nocapture

# 2. Clean all generated files (keep only mutator.ts)
echo "Cleaning generated API clients and schemas..."
find "$API_DIR" -mindepth 1 -maxdepth 1 ! -name 'mutator.ts' -exec rm -rf {} +

# 3. Regenerate via orval
echo "Running orval..."
cd "$TYPES_DIR" && npm run generate

echo "Done."
