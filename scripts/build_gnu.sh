#!/usr/bin/env bash
#
# 在任意 x86_64 主机上交叉编译 gnu（glibc 动态链接）产物（cargo-zigbuild 方案）。
# Cross-compile dynamically linked glibc (gnu) artifacts on any x86_64 host
# (cargo-zigbuild approach).
#
# 用法:
# Usage:
#   ./scripts/build_gnu.sh <target>
#
#   target:
#     riscv64gc-unknown-linux-gnu | s390x-unknown-linux-gnu
#     loongarch64-unknown-linux-gnu
#
#   产物（无后缀，与原生交叉编译产物的发布命名一致，运行时依赖目标机的
#   libc/libelf.so 等动态库）：
#   Artifacts (no suffix, matching the release naming of native cross builds;
#   at runtime they depend on the target's libc/libelf.so etc.):
#     output/landscape-webserver-<arch>
#     output/redirect_pkg_handler-<arch>
#
# 环境变量:
# Environment variables:
#   GATEWAY=1       启用 gateway 功能（默认 1，接受 1/true）
#                  Enable the gateway feature (default 1; accepts 1/true)
#   GLIBC_VERSION   glibc 目标版本（默认 2.38）。sysroot 里的发行版库
#                  （libelf/libz，noble 与 sid 构建均如此）引用
#                  __isoc23_*@GLIBC_2.38 符号，低于 2.38 时 zig 内置的
#                  libc stub 无法解析导致链接失败（cargo-zigbuild 自身的
#                  默认是 2.17，不可用）
#                  Target glibc version (default 2.38). The distro libs in
#                  the sysroot (libelf/libz, as built in both noble and sid)
#                  reference __isoc23_*@GLIBC_2.38 symbols; below 2.38 zig's
#                  bundled libc stubs cannot resolve them and linking fails
#                  (cargo-zigbuild's own default of 2.17 does not work)
#   UBUNTU_PORTS_MIRROR  riscv64/s390x sysroot 镜像（默认 https://ports.ubuntu.com/ubuntu-ports）
#   DEBIAN_MIRROR        loong64 sysroot 镜像（默认 https://deb.debian.org/debian）
#   SYSROOT_BASE         sysroot 目录（默认 ~/sysroots）
#
# sysroot：zig 只内置 libc，不内置 libelf，从发行版解包 .deb 组装——
# riscv64/s390x 取 Ubuntu noble ports；loong64 取 Debian sid（Ubuntu 无 loong64）。
# 注意 Ubuntu noble 与 Debian sid 都做了 t64 过渡：libelf 运行时包名为 libelf1t64。
# Sysroot: zig bundles libc only, not libelf, so one is assembled by unpacking
# .deb packages — riscv64/s390x come from Ubuntu noble ports; loong64 comes
# from Debian sid (Ubuntu does not ship loong64). Note both Ubuntu noble and
# Debian sid went through the t64 transition: the libelf runtime package is
# named libelf1t64.
#
# 依赖：cargo-zigbuild（cargo install --locked cargo-zigbuild）、
#       zig（pip3 install ziglang==0.16.0 或官方包）、clang（eBPF C 编译）、
#       rustup target add <target>（脚本会自动安装）、
#       dpkg-deb（解包 .deb）、
#       pkg-config 与 libelf-dev/zlib1g-dev（宿主侧，libbpf-cargo 会在宿主编译 libbpf-sys）。
# Dependencies: cargo-zigbuild (cargo install --locked cargo-zigbuild),
#       zig (pip3 install ziglang==0.16.0 or the official package), clang
#       (for eBPF C compilation), rustup target add <target> (installed
#       automatically by this script), dpkg-deb (to unpack .deb), and
#       pkg-config and libelf-dev/zlib1g-dev (host side; libbpf-cargo builds
#       libbpf-sys on the host).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

TARGET="${1:-}"
GATEWAY="${GATEWAY:-1}"
UBUNTU_PORTS_MIRROR="${UBUNTU_PORTS_MIRROR:-https://ports.ubuntu.com/ubuntu-ports}"
DEBIAN_MIRROR="${DEBIAN_MIRROR:-https://deb.debian.org/debian}"
SYSROOT_BASE="${SYSROOT_BASE:-$HOME/sysroots}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target> (riscv64gc/s390x/loongarch64-unknown-linux-gnu)" >&2
    exit 1
fi

# riscv64/s390x 取 Ubuntu noble ports；loong64 取 Debian sid（Ubuntu 无 loong64）
# riscv64/s390x come from Ubuntu noble ports; loong64 from Debian sid
# (Ubuntu does not ship loong64)
case "$TARGET" in
    riscv64gc-unknown-linux-gnu)    ARCH=riscv64;     DEB_MIRROR_URL="$UBUNTU_PORTS_MIRROR"; DEB_SUITE=noble; DEB_ARCH=riscv64 ;;
    s390x-unknown-linux-gnu)        ARCH=s390x;       DEB_MIRROR_URL="$UBUNTU_PORTS_MIRROR"; DEB_SUITE=noble; DEB_ARCH=s390x ;;
    loongarch64-unknown-linux-gnu)  ARCH=loongarch64; DEB_MIRROR_URL="$DEBIAN_MIRROR";       DEB_SUITE=sid;   DEB_ARCH=loong64 ;;
    *) echo "Unsupported target: $TARGET (supported: riscv64gc/s390x/loongarch64-unknown-linux-gnu)" >&2; exit 1 ;;
esac

SYSROOT_DIR="$SYSROOT_BASE/${DEB_SUITE}-${DEB_ARCH}"

# sysroot 中需要的包：libelf/zlib/zstd 的运行时与开发包（-dev 里的 libelf.so
# 是指向运行时包中真实 .so 的符号链接，二者缺一不可）。注意 Ubuntu noble
# 与 Debian sid 都做了 t64 过渡：运行时包名为 libelf1t64（libelf1 已不存在）
# Packages needed in the sysroot: the runtime and dev packages of
# libelf/zlib/zstd (the libelf.so in -dev is a symlink to the real .so
# shipped in the runtime package; both are required). Note both Ubuntu noble
# and Debian sid went through the t64 transition: the runtime package is
# libelf1t64 (libelf1 no longer exists)
DEB_SYSROOT_PACKAGES=(libelf1t64 libelf-dev zlib1g zlib1g-dev libzstd1 libzstd-dev)

# ---------- 前置检查 ----------

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

# landscape-ebpf 的 build.rs 经 libbpf-cargo 把 libbpf-sys 编译在宿主侧
# （构建 vendored libbpf），需要宿主提供 libelf 头文件；目标侧头文件由
# sysroot 提供
# landscape-ebpf's build.rs compiles libbpf-sys on the host via libbpf-cargo
# (building vendored libbpf), which needs host libelf headers; the target
# side gets its headers from the sysroot instead
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

# ---------- 组装 sysroot ----------

# .deb 解包出的 .pc 文件 prefix=/usr，交叉环境下 pkg-config 会把 /usr 当
# 系统路径剥掉 -I/-L，因此改写成 sysroot 绝对路径（multiarch 目录如
# usr/lib/<triplet>/pkgconfig 由 find 定位）
# The .pc files unpacked from .deb have prefix=/usr; when cross-compiling,
# pkg-config treats /usr as a system path and strips -I/-L, so rewrite it to
# the absolute sysroot path (multiarch dirs like usr/lib/<triplet>/pkgconfig
# are located via find)
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
        # 逐行解析：先匹配 "Package: <pkg>" 行，再取同一 stanza 内的
        # Filename 行（dpkg 索引中 Package 恒为段首字段）。不依赖段落模式
        # 与字段切分，gawk/mawk 行为一致
        # Parse line by line: match the "Package: <pkg>" line, then take the
        # Filename line within the same stanza (Package is always the first
        # field in dpkg indexes). No paragraph mode or field splitting, so
        # gawk/mawk behave identically
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
# Sysroot readiness check: the presence of libelf's pkg-config file
sysroot_libelf_pc() {
    find "$SYSROOT_DIR" -name libelf.pc -type f -print -quit 2>/dev/null
}

if [[ -z "$(sysroot_libelf_pc)" ]]; then
    mkdir -p "$SYSROOT_DIR"
    fetch_sysroot
fi

# 定位 libelf 所在库目录（Debian/Ubuntu 的 multiarch 布局在
# usr/lib/<triplet>），供 libbpf-sys 的链接搜索路径使用
# Locate the directory holding libelf (the Debian/Ubuntu multiarch layout
# uses usr/lib/<triplet>) for libbpf-sys's link search path
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

# ---------- 构建 ----------

# glibc 版本：默认 2.38（见头部注释）。版本后缀只传给 cargo zigbuild——
# cargo-zigbuild 会把它从 rust 侧 triple 上剥掉，仅在 zig cc 的 -target 中
# 保留（如 riscv64-linux-gnu.2.38），因此内层 cargo 的产物目录始终是
# 不带后缀的 target/<triple>/release/
# glibc version: 2.38 by default (see the header comment). The version
# suffix is only passed to cargo zigbuild — cargo-zigbuild strips it from
# the rust-side triple and keeps it solely in zig cc's -target (e.g.
# riscv64-linux-gnu.2.38), so the inner cargo always places artifacts in
# target/<triple>/release/ without the suffix
GLIBC_VERSION="${GLIBC_VERSION:-2.38}"
ZIG_TARGET="$TARGET.$GLIBC_VERSION"

FEATURES="metric-persistent"
# 接受 1/true（CI matrix 传入的是 true）
# Accept 1/true (the CI matrix passes true)
case "$GATEWAY" in 1|true|TRUE|yes) FEATURES="$FEATURES,gateway" ;; esac

# 注意：libbpf-sys 不是 workspace 成员，cargo 的 <pkg>/<feature> 语法只对
# "当前包的直接依赖"生效。选中 landscape-ebpf 会连带构建其全部 bin
# （含 redirect_pkg_handler）。
# Note: libbpf-sys is not a workspace member, and cargo's <pkg>/<feature>
# syntax only works for "direct dependencies of the current package".
# Selecting landscape-ebpf also builds all of its binaries
# (including redirect_pkg_handler).
echo "Building landscape-webserver ($ZIG_TARGET, gnu dynamic, gateway=$GATEWAY)..."
env "${CROSS_ENV[@]}" cargo zigbuild --release --target "$ZIG_TARGET" --no-default-features \
    --features "$FEATURES" \
    -p landscape-webserver -p landscape-ebpf

# ---------- 收集产物 ----------

# 注意从不带版本后缀的目录取产物（见上方构建节注释）
# Note: artifacts are collected from the suffix-less directory (see the
# comment in the build section above)
mkdir -p output
cp "target/$TARGET/release/landscape-webserver" "output/landscape-webserver-$ARCH"
cp "target/$TARGET/release/redirect_pkg_handler" "output/redirect_pkg_handler-$ARCH"

file "output/landscape-webserver-$ARCH" "output/redirect_pkg_handler-$ARCH"
echo "Done, artifacts are in output/"
