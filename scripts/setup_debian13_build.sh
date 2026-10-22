#!/usr/bin/env bash
#
# Install the pinned Debian 13 build toolchain used by CI.
#
# The BPF arena code in landscape-ebpf requires Clang 19+. Clang 18 and older
# compile the BPF sources successfully but emit plain scalar accesses for arena
# globals instead of BPF_ADDR_SPACE_CAST, which the kernel verifier rejects with
# EACCES ("Permission denied").
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must run as root (for example inside the CI container)." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates \
    clang-19 \
    curl \
    cmake \
    file \
    g++ \
    gcc \
    jq \
    libclang-19-dev \
    libelf-dev \
    libzstd-dev \
    lld-19 \
    llvm-19 \
    make \
    pkg-config \
    python3-pip \
    wget \
    xz-utils \
    zlib1g-dev

update-alternatives --install /usr/bin/clang clang /usr/bin/clang-19 200
update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-19 200
update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-19 200

clang --version
clang_major="$(clang --version | sed -n 's/.*clang version \([0-9][0-9]*\).*/\1/p' | head -n1)"
if [[ -z "${clang_major}" || "${clang_major}" -lt 19 ]]; then
    echo "FATAL: landscape-ebpf requires Clang 19+, found: ${clang_major:-unknown}" >&2
    exit 1
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "CLANG=/usr/bin/clang-19" >> "${GITHUB_ENV}"
fi
