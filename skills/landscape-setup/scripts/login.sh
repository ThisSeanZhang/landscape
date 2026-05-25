#!/usr/bin/env bash
# Login to Landscape router and cache JWT token.
# Usage: bash login.sh [--host URL] [--user USER] [--pass PASSWORD]
#
# Falls back to env vars: LANDSCAPE_HOST, LANDSCAPE_USER, LANDSCAPE_PASS
set -euo pipefail

HOST=""
USER=""
PASS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --user) USER="$2"; shift 2 ;;
    --pass) PASS="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

HOST="${HOST:-${LANDSCAPE_HOST:-}}"
USER="${USER:-${LANDSCAPE_USER:-}}"
PASS="${PASS:-${LANDSCAPE_PASS:-}}"

if [[ -z "$HOST" || -z "$USER" || -z "$PASS" ]]; then
  echo "ERROR: provide --host, --user, --pass or set LANDSCAPE_HOST/USER/PASS env vars." >&2
  exit 1
fi

# Remove trailing slash
HOST="${HOST%/}"

# Login
RESP=$(curl -sk -X POST "$HOST/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" 2>/dev/null)

TOKEN=$(echo "$RESP" | jq -r '.data.token // empty')
if [[ -z "$TOKEN" ]]; then
  echo "ERROR: login failed. Response: $RESP" >&2
  exit 1
fi

# Decode JWT payload (middle part) without external tools
_payload=$(echo "$TOKEN" | cut -d. -f2)
# Pad base64 for -d
_payload_padded="${_payload}$(printf '=%.0s' $(seq 1 $(( (4 - ${#_payload} % 4) % 4 ))))"
EXP=$(echo "$_payload_padded" | base64 -d 2>/dev/null | jq -r '.exp // 0')
if [[ "$EXP" -eq 0 ]]; then
  echo "WARN: could not decode JWT expiry, defaulting to 1 hour from now." >&2
  EXP=$(($(date +%s) + 3600))
fi

# Write token file
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOKEN_FILE="$SKILL_DIR/.token"
cat > "$TOKEN_FILE" <<EOF
{
  "host": "$HOST",
  "token": "$TOKEN",
  "exp": $EXP
}
EOF
chmod 600 "$TOKEN_FILE"

# Print setup confirmation
EXP_TIME=$(date -d "@$EXP" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "timestamp $EXP")
echo "✓ Token saved to $TOKEN_FILE"
echo "✓ Token expires: $EXP_TIME"
