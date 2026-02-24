#!/usr/bin/env bash

# Use local DuckDB if it exists, otherwise fall back to download
if [ -d "./libduckdb" ]; then
    export DUCKDB_LIB_DIR="$(pwd)/libduckdb"
    export DUCKDB_INCLUDE_DIR="$DUCKDB_LIB_DIR"
    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$DUCKDB_LIB_DIR"
    unset DUCKDB_DOWNLOAD_LIB
else
    export DUCKDB_DOWNLOAD_LIB=1
fi

# Run cargo with metric-duckdb enabled (dynamic linking) plus any extra arguments
cargo run --features metric-duckdb "$@"
