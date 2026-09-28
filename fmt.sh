#!/bin/bash
set -e

usage() {
    echo "Usage: $0 [--all] [--rust] [--clippy] [--c] [--frontend]"
    echo ""
    echo "Format source code. Run without options to format all languages and run clippy."
    echo ""
    echo "Options:"
    echo "  -a, --all         Format all (Rust + C + Frontend) and run clippy, same as no options"
    echo "  -r, --rust        Format Rust code only (cargo fmt)"
    echo "  -l, --clippy      Run clippy check only (same as CI: cargo clippy -D warnings)"
    echo "  -c, --c           Format C/eBPF code only (clang-format-18)"
    echo "  -f, --frontend    Format Frontend code only (prettier)"
}

FORMAT_ALL=false
FORMAT_RUST=false
FORMAT_CLIPPY=false
FORMAT_C=false
FORMAT_FRONTEND=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -a|--all) FORMAT_ALL=true; shift ;;
        -r|--rust) FORMAT_RUST=true; shift ;;
        -l|--clippy) FORMAT_CLIPPY=true; shift ;;
        -c|--c) FORMAT_C=true; shift ;;
        -f|--frontend) FORMAT_FRONTEND=true; shift ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

# Default: format all if no specific option is given
if ! $FORMAT_RUST && ! $FORMAT_CLIPPY && ! $FORMAT_C && ! $FORMAT_FRONTEND; then
    FORMAT_ALL=true
fi

if $FORMAT_ALL || $FORMAT_RUST; then
    echo "Formatting Rust code..."
    cargo fmt
fi

if $FORMAT_ALL || $FORMAT_CLIPPY; then
    echo "Running clippy check (same as CI)..."
    cargo clippy --workspace --features metric-persistent -- -D warnings
fi

if $FORMAT_ALL || $FORMAT_C; then
    echo "Formatting C/eBPF code..."
    CLANG_FORMAT=""
    if command -v clang-format-18 &>/dev/null; then
        CLANG_FORMAT="clang-format-18"
    elif command -v clang-format &>/dev/null; then
        CF_VERSION=$(clang-format --version | grep -oP '\d+' | head -1)
        if [ "$CF_VERSION" = "18" ]; then
            CLANG_FORMAT="clang-format"
        else
            echo "Error: clang-format version $CF_VERSION found, but version 18 is required." >&2
            echo "CI uses clang-format-18, other versions may produce different results." >&2
            echo "Install: apt install clang-format-18" >&2
            exit 1
        fi
    else
        echo "Error: clang-format not found. Install clang-format-18:" >&2
        echo "  apt install clang-format-18" >&2
        exit 1
    fi
    echo "Using $($CLANG_FORMAT --version)"
    find landscape-ebpf/src/bpf -type f \( -name '*.c' -o -name '*.h' \) \
        ! -name 'vmlinux.h' \
        -print0 | xargs -0 "$CLANG_FORMAT" -i
fi

if $FORMAT_ALL || $FORMAT_FRONTEND; then
    echo "Formatting webui code (landscape-webui/)..."
    if [ -d "landscape-webui" ]; then
        (cd landscape-webui && npx prettier --write .)
    fi
fi

echo "Format complete."
