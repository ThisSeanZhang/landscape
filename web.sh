#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/scripts/pnpm_cmd.sh"

pnpm_cmd --filter landscape-webui dev "$@"
