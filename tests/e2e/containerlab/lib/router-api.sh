#!/usr/bin/env bash
# Arguments: router container, path under /api/v1/, optional curl arguments.
set -eu
router=$1
shift
exec docker exec -i "$router" sh -ec '
    path=$1
    shift
    token=$(cat /var/lib/landscape/landscape_api_token)
    exec curl -kfsS --max-time 5 -H "Authorization: Bearer $token" "$@" "https://127.0.0.1:6443/api/v1/$path"
' sh "$@"
