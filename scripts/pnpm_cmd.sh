#!/usr/bin/env bash

pnpm_cmd() {
    if command -v corepack >/dev/null 2>&1; then
        if corepack pnpm --version >/dev/null 2>&1; then
            corepack pnpm "$@"
            return
        fi
    fi

    if command -v pnpm >/dev/null 2>&1; then
        pnpm "$@"
        return
    fi

    echo "pnpm not found. Install pnpm globally, or use Node.js with Corepack enabled." >&2
    exit 1
}
