#!/usr/bin/env bash
#
# Install the build toolchain used by CI on the Ubuntu GitHub runners.
#
# The BPF arena code in landscape-ebpf requires Clang 19+. Ubuntu 24.04 only
# ships Clang 16/17/18, so when no Clang >= 19 is already present this script
# installs clang-19 from the official apt.llvm.org repository.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

SUDO=""
if [[ "${EUID}" -ne 0 ]]; then
    SUDO="sudo"
fi

$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
    ca-certificates \
    cmake \
    file \
    g++ \
    gcc \
    gnupg \
    jq \
    libelf-dev \
    libzstd-dev \
    make \
    pkg-config \
    python3-pip \
    wget \
    xz-utils \
    zlib1g-dev

clang_major() {
    "$1" --version 2>/dev/null | sed -n 's/.*clang version \([0-9][0-9]*\).*/\1/p' | head -n1
}

find_clang() {
    local candidate clang_ver
    for candidate in clang-19 clang clang-22 clang-21 clang-20; do
        if ! command -v "${candidate}" >/dev/null 2>&1; then
            continue
        fi
        clang_ver="$(clang_major "${candidate}")"
        if [[ -n "${clang_ver}" && "${clang_ver}" -ge 19 ]]; then
            command -v "${candidate}"
            return 0
        fi
    done
    return 1
}

install_clang_19() {
    . /etc/os-release
    local codename="${VERSION_CODENAME:-noble}"
    echo "No Clang >= 19 found; installing clang-19 from apt.llvm.org (${codename})"

    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key |
        $SUDO gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/apt.llvm.org.gpg
    echo "deb https://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-19 main" |
        $SUDO tee /etc/apt/sources.list.d/llvm-19.list >/dev/null

    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends clang-19
}

CLANG_BIN="$(find_clang || true)"
if [[ -z "${CLANG_BIN}" ]]; then
    install_clang_19
    CLANG_BIN="$(find_clang || true)"
fi

if [[ -z "${CLANG_BIN}" ]]; then
    echo "FATAL: landscape-ebpf requires Clang 19+, but no suitable clang was found." >&2
    exit 1
fi

"${CLANG_BIN}" --version | head -n1

if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "CLANG=${CLANG_BIN}" >> "${GITHUB_ENV}"
fi
