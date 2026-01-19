#!/bin/bash
set -e

echo "Building Landscape eBPF in Native Mode (NO CO-RE)..."
export LANDSCAPE_NO_CORE=1
cargo build --release

echo "Build complete."
