#!/usr/bin/env bash
#
# 在 x86_64 主机上交叉编译 Flow Edge 镜像所需的用户态二进制
# （cargo-zigbuild 方案）。
# Cross-compile the user-space binaries required by the Flow Edge image on an
# x86_64 host (cargo-zigbuild approach).
#
# 用法:
# Usage:
#   ./scripts/build_edge_bins.sh <target>
#
#   target:
#     riscv64gc-unknown-linux-gnu
#
# 仅编译 landscape-ebpf 的两个 bin（edge 镜像只需要它们）：
#   redirect_pkg_handler / redirect_demo_server
# 产物位于 target/<target>/release/，与原生构建的布局一致。
# Only the two landscape-ebpf binaries needed by the edge image are built;
# artifacts land in target/<target>/release/, matching the native build layout.
#
# 环境变量:
# Environment variables:
#   GLIBC_VERSION        glibc 目标版本（默认 2.38，原因见 scripts/build_gnu.sh）
#                        Target glibc version (default 2.38, see build_gnu.sh)
#   UBUNTU_PORTS_MIRROR  riscv64 sysroot 镜像（默认 https://ports.ubuntu.com/ubuntu-ports）
#                        riscv64 sysroot mirror
#   SYSROOT_BASE         sysroot 目录（默认 ~/sysroots）
#                        Sysroot directory
#
# 依赖：cargo-zigbuild（cargo install --locked cargo-zigbuild）、
#       zig（pip3 install ziglang==0.16.0 或官方包）、clang（eBPF C 编译）、
#       rustup target add <target>（脚本会自动安装）、
#       dpkg-deb（解包 .deb）、
#       pkg-config 与 libelf-dev/zlib1g-dev（宿主侧，libbpf-cargo 会在宿主
#       编译 libbpf-sys）。
# Dependencies: cargo-zigbuild, zig, clang (eBPF C compilation),
#       rustup target add <target> (installed automatically), dpkg-deb,
#       and pkg-config plus libelf-dev/zlib1g-dev (host side; libbpf-cargo
#       builds libbpf-sys on the host).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

TARGET="${1:-}"
GLIBC_VERSION="${GLIBC_VERSION:-2.38}"
UBUNTU_PORTS_MIRROR="${UBUNTU_PORTS_MIRROR:-https://ports.ubuntu.com/ubuntu-ports}"
SYSROOT_BASE="${SYSROOT_BASE:-$HOME/sysroots}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target> (riscv64gc-unknown-linux-gnu)" >&2
    exit 1
fi

case "$TARGET" in
    riscv64gc-unknown-linux-gnu) ARCH=riscv64; DEB_MIRROR_URL="$UBUNTU_PORTS_MIRROR"; DEB_SUITE=noble; DEB_ARCH=riscv64 ;;
    *) echo "Unsupported target: $TARGET (supported: riscv64gc-unknown-linux-gnu)" >&2; exit 1 ;;
esac

SYSROOT_DIR="$SYSROOT_BASE/${DEB_SUITE}-${DEB_ARCH}"

# sysroot 中需要的包：libelf/zlib/zstd 的运行时与开发包（-dev 里的 libelf.so
# 是指向运行时包中真实 .so 的符号链接，二者缺一不可）。注意 Ubuntu noble
# 做了 t64 过渡：运行时包名为 libelf1t64（libelf1 已不存在）
# Packages needed in the sysroot: the runtime and dev packages of
# libelf/zlib/zstd (the libelf.so in -dev is a symlink to the real .so in the
# runtime package; both are required). Note Ubuntu noble went through the t64
# transition: the runtime package is libelf1t64 (libelf1 no longer exists)
DEB_SYSROOT_PACKAGES=(libelf1t64 libelf-dev zlib1g zlib1g-dev libzstd1 libzstd-dev)

# ---------- 前置检查 / Preflight checks ----------

check_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing dependency: $1 ($2)" >&2
        exit 1
    fi
}

check_cmd cargo-zigbuild "cargo install --locked cargo-zigbuild"
check_cmd clang "apt-get install clang (or your distro's equivalent)"
check_cmd pkg-config "apt-get install pkg-config (or your distro's equivalent)"
check_cmd dpkg-deb "apt-get install dpkg (usually preinstalled)"

# landscape-ebpf 的 build.rs 经 libbpf-cargo 把 libbpf-sys 编译在宿主侧，
# 需要宿主提供 libelf 头文件；目标侧头文件由 sysroot 提供
# landscape-ebpf's build.rs compiles libbpf-sys on the host via libbpf-cargo,
# which needs host libelf headers; the target side gets them from the sysroot
if ! pkg-config --exists libelf; then
    echo "Missing host libelf development files (needed by the host-side libbpf-sys build)" >&2
    echo "  Debian/Ubuntu: apt-get install libelf-dev zlib1g-dev" >&2
    exit 1
fi

if ! python3 -m ziglang version >/dev/null 2>&1 && ! command -v zig >/dev/null 2>&1; then
    echo "Missing dependency: zig (pip3 install ziglang or install from ziglang.org)" >&2
    exit 1
fi

if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    echo "Installing rust target: $TARGET"
    rustup target add "$TARGET"
fi

# ---------- 组装 sysroot / Assemble the sysroot ----------

# .deb 解包出的 .pc 文件 prefix=/usr，交叉环境下 pkg-config 会把 /usr 当
# 系统路径剥掉 -I/-L，因此改写成 sysroot 绝对路径
# The .pc files unpacked from .deb have prefix=/usr; when cross-compiling,
# pkg-config treats /usr as a system path and strips -I/-L, so rewrite it to
# the absolute sysroot path
rewrite_pkg_config_prefix() {
    find "$SYSROOT_DIR" -name '*.pc' -type f -exec \
        sed -i "s|^prefix=/usr\$|prefix=$SYSROOT_DIR/usr|" {} +
}

fetch_sysroot() {
    local index_url="$DEB_MIRROR_URL/dists/$DEB_SUITE/main/binary-$DEB_ARCH/Packages.gz"
    local tmp
    tmp="$(mktemp -d)"

    echo "Downloading Packages index: $index_url"
    wget -qO "$tmp/Packages.gz" "$index_url"
    zcat "$tmp/Packages.gz" > "$tmp/Packages"

    for pkg in "${DEB_SYSROOT_PACKAGES[@]}"; do
        local fn
        fn="$(awk -v p="$pkg" '
            /^Package: / { inpkg = ($0 == "Package: " p) }
            inpkg && /^Filename: / { sub(/^Filename: /, ""); print; exit }
            /^$/ { inpkg = 0 }' "$tmp/Packages")"
        if [[ -z "$fn" ]]; then
            echo "Package not found in Packages index: $pkg ($DEB_SUITE/$DEB_ARCH)" >&2
            exit 1
        fi
        local url="$DEB_MIRROR_URL/$fn"
        echo "Downloading $url"
        wget -qO "$tmp/pkg.deb" "$url"
        dpkg-deb -x "$tmp/pkg.deb" "$SYSROOT_DIR"
    done

    rm -rf "$tmp"
    rewrite_pkg_config_prefix
}

# sysroot 就绪判定：以 libelf 的 pkg-config 文件存在为准
# Sysroot readiness check: presence of libelf's pkg-config file
sysroot_libelf_pc() {
    find "$SYSROOT_DIR" -name libelf.pc -type f -print -quit 2>/dev/null
}

if [[ -z "$(sysroot_libelf_pc)" ]]; then
    mkdir -p "$SYSROOT_DIR"
    fetch_sysroot
fi

# 定位 libelf 所在库目录，供 libbpf-sys 的链接搜索路径使用
# Locate the directory holding libelf for libbpf-sys's link search path
SYSROOT_LIBDIR="$(dirname "$(find "$SYSROOT_DIR" \( -name 'libelf.so' -o -name 'libelf.a' \) -print -quit)")"

# 交叉编译时 pkg-config 只允许作用于该 target，避免影响宿主侧探测
# When cross-compiling, allow pkg-config only for this target so host-side
# detection is unaffected
TARGET_US="${TARGET//-/_}"
export "PKG_CONFIG_ALLOW_CROSS_${TARGET_US}=1"
export "PKG_CONFIG_LIBDIR_${TARGET_US}=$(dirname "$(sysroot_libelf_pc)")"

# libbpf-sys 的 build.rs 不走 pkg-config：
#   - vendored libbpf 的 C 编译从 CFLAGS_<target> 取头文件路径
#   - libelf/libz 的链接搜索路径从 LIBBPF_SYS_LIBRARY_PATH_<target> 取
# 带 '-' 的变量名不能用 export，需经 env 传给 cargo
# libbpf-sys's build.rs does not go through pkg-config:
#   - the C compile of vendored libbpf takes header paths from CFLAGS_<target>
#   - the link search path for libelf/libz comes from LIBBPF_SYS_LIBRARY_PATH_<target>
# Variable names containing '-' cannot be set via export; pass them to cargo
# through env instead
SYSROOT_CFLAGS="-I$SYSROOT_DIR/usr/include"
CROSS_ENV=(
    "CFLAGS_$TARGET=$SYSROOT_CFLAGS"
    "LIBBPF_SYS_LIBRARY_PATH_$TARGET=$SYSROOT_LIBDIR"
)
CROSS_ENV+=(
    "CFLAGS_${TARGET_US}=$SYSROOT_CFLAGS"
    "LIBBPF_SYS_LIBRARY_PATH_${TARGET_US}=$SYSROOT_LIBDIR"
)

# ---------- 构建 / Build ----------

# cargo-zigbuild 会把 glibc 版本从 rust 侧 triple 上剥掉，仅在 zig cc 的
# -target 中保留，因此产物目录始终是 target/<triple>/release/
# cargo-zigbuild strips the glibc suffix from the rust-side triple and keeps
# it only in zig cc's -target, so artifacts always land in
# target/<triple>/release/
ZIG_TARGET="$TARGET.$GLIBC_VERSION"

echo "Building edge bins ($ZIG_TARGET, gnu dynamic)..."
env "${CROSS_ENV[@]}" cargo zigbuild --locked --release --target "$ZIG_TARGET" \
    -p landscape-ebpf --bin redirect_pkg_handler --bin redirect_demo_server

file "target/$TARGET/release/redirect_pkg_handler" "target/$TARGET/release/redirect_demo_server"
echo "Done, artifacts are in target/$TARGET/release/"
