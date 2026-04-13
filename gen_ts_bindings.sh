#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TYPES_DIR="$SCRIPT_DIR/landscape-types"
API_DIR="$TYPES_DIR/src/api"
source "$SCRIPT_DIR/scripts/pnpm_cmd.sh"

(
    cd "$SCRIPT_DIR"

    # 1. Generate OpenAPI spec → landscape-types/openapi.json
    echo "Exporting OpenAPI spec..."
    cargo test -p landscape-webserver export_openapi_json -- --nocapture

    # 2. Full clean generated dir
    echo "Cleaning generated API clients and schemas..."
    rm -rf "$API_DIR"

    # 3. Regenerate via orval
    echo "Running orval..."
    pnpm_cmd --filter @landscape-router/types generate
)

echo "Done."
