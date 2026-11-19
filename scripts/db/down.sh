#!/bin/sh
set -eu
cargo run --locked --manifest-path ./landscape-database/migration/Cargo.toml --features cli -- down "$@"
