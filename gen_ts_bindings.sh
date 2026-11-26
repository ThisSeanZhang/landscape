#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TYPES_DIR="$SCRIPT_DIR/landscape-types"
API_DIR="$TYPES_DIR/src/api"
OPENAPI_JSON="$TYPES_DIR/openapi.json"
SCHEMA_INDEX="$API_DIR/schemas/index.ts"
LOCK_FILE="$TYPES_DIR/.bindings.lock"
source "$SCRIPT_DIR/scripts/pnpm_cmd.sh"

MODE="force"

should_regenerate_bindings() {
    if [[ ! -f "$OPENAPI_JSON" || ! -f "$SCHEMA_INDEX" || ! -f "$LOCK_FILE" ]]; then
        return 0
    fi

    return 1
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --if-stale)
            MODE="if-stale"
            shift
            ;;
        --force)
            MODE="force"
            shift
            ;;
        -h|--help)
            cat <<'EOF'
Usage: ./gen_ts_bindings.sh [--if-stale|--force]

  --if-stale    Skip regeneration when generated bindings and the lock file already exist.
  --force       Always export OpenAPI and regenerate bindings (default).
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [[ "$MODE" == "if-stale" ]] && ! should_regenerate_bindings; then
    echo "Generated API bindings already exist; skipping regeneration."
    exit 0
fi

(
    cd "$SCRIPT_DIR"

    # 1. Generate OpenAPI spec → landscape-types/openapi.json
    echo "Exporting OpenAPI spec..."
    cargo test -p landscape-webserver export_openapi_json -- --ignored --nocapture

    # 2. Full clean generated dir
    echo "Cleaning generated API clients and schemas..."
    rm -rf "$API_DIR"

    # 3. Regenerate via orval
    echo "Running orval..."
    pnpm_cmd --filter @landscape-router/types generate
)

touch "$LOCK_FILE"

echo "Done."
