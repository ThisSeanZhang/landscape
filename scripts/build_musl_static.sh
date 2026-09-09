#!/usr/bin/env bash
#
# 在任意主机上交叉编译各架构的 musl 产物（cargo-zigbuild 方案）。
# Cross-compile per-architecture musl artifacts on any host (cargo-zigbuild approach).
#
# 用法:
# Usage:
#   ./scripts/build_musl_static.sh [target]
#
#   target 可选（默认 x86_64-unknown-linux-musl）:
#   target is optional (defaults to x86_64-unknown-linux-musl):
#     x86_64-unknown-linux-musl | aarch64-unknown-linux-musl
#     riscv64gc-unknown-linux-musl | loongarch64-unknown-linux-musl
#
# 默认 STATIC=1 编译全静态二进制（单文件无 so 依赖，加 -static 后缀）：
# By default STATIC=1 builds fully static binaries (single file with no .so
# dependencies, suffixed with -static):
#   output/landscape-webserver-<arch>-static
#   output/redirect_pkg_handler-<arch>-static
# STATIC=0 时为动态链接 musl libc 的二进制（不加后缀，与现有发布命名一致）。
# With STATIC=0 it builds binaries dynamically linked against musl libc
# (no suffix, matching the existing release naming).
#
# 环境变量:
# Environment variables:
#   STATIC=1       静态编译（默认 1）
#                  Static build (default 1)
#   GATEWAY=1      启用 gateway 功能（默认 1）
#                  Enable the gateway feature (default 1)
#   ALPINE_MIRROR  Alpine 镜像（默认 https://dl-cdn.alpinelinux.org/alpine）
#                  Alpine mirror (default: https://dl-cdn.alpinelinux.org/alpine)
#   SYSROOT_BASE   sysroot 目录（默认 ~/sysroots）
#                  sysroot directory (default: ~/sysroots)
#
# 依赖：cargo-zigbuild（cargo install --locked cargo-zigbuild）、
#       zig（pip3 install ziglang==0.16.0 或官方包）、clang（eBPF C 编译）、
#       rustup target add <target>（脚本会自动安装）、
#       pkg-config 与 libelf-dev/zlib1g-dev（宿主侧，libbpf-cargo 会在宿主编译 libbpf-sys）。
# Dependencies: cargo-zigbuild (cargo install --locked cargo-zigbuild),
#       zig (pip3 install ziglang==0.16.0 or the official package), clang
#       (for eBPF C compilation), rustup target add <target> (installed
#       automatically by this script), pkg-config and libelf-dev/zlib1g-dev
#       (host side; libbpf-cargo builds libbpf-sys on the host).
#
# zig 只内置 libc，不内置 libelf，因此本脚本从 Alpine v3.22 仓库解包
# libelf 相关包组装 sysroot（$SYSROOT_BASE/alpine3.22-<alpine_arch>，
# 已存在则复用）。
# zig bundles libc only, not libelf, so this script assembles a sysroot by
# unpacking the libelf-related packages from the Alpine v3.22 repositories
# into $SYSROOT_BASE/alpine3.22-<alpine_arch> (reused if it already exists).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

TARGET="${1:-x86_64-unknown-linux-musl}"
STATIC="${STATIC:-1}"
GATEWAY="${GATEWAY:-1}"
ALPINE_MIRROR="${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}"
ALPINE_VERSION="${ALPINE_VERSION:-v3.22}"
SYSROOT_BASE="${SYSROOT_BASE:-$HOME/sysroots}"

case "$TARGET" in
    x86_64-unknown-linux-musl)      ALPINE_ARCH=x86_64;      ARCH=x86_64 ;;
    aarch64-unknown-linux-musl)     ALPINE_ARCH=aarch64;     ARCH=aarch64 ;;
    riscv64gc-unknown-linux-musl)   ALPINE_ARCH=riscv64;     ARCH=riscv64 ;;
    loongarch64-unknown-linux-musl) ALPINE_ARCH=loongarch64; ARCH=loongarch64 ;;
    *) echo "Unsupported target: $TARGET (supported: x86_64/aarch64/riscv64gc/loongarch64-unknown-linux-musl)" >&2; exit 1 ;;
esac

SYSROOT_DIR="$SYSROOT_BASE/alpine${ALPINE_VERSION#v}-$ALPINE_ARCH"

# sysroot 中需要的包：musl（qemu 冒烟运行用）、libelf 及其开发文件、
# libelf.so 的运行依赖 zlib/libzstd 及其开发文件、
# 静态版需要的 zlib-static/zstd-static（libelf.a 同层级的 .a 依赖）
# Packages needed in the sysroot: musl (for qemu smoke runs), libelf and
# its dev files, zlib/libzstd (runtime deps of libelf.so) and their dev
# files, plus zlib-static/zstd-static needed by the static build (the .a
# deps living alongside libelf.a)
SYSROOT_PACKAGES=(musl libelf elfutils-dev zlib zlib-dev zstd-libs zstd-dev zlib-static zstd-static)

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

fetch_sysroot() {
    local index_url="$ALPINE_MIRROR/$ALPINE_VERSION/main/$ALPINE_ARCH/APKINDEX.tar.gz"
    local tmp
    tmp="$(mktemp -d)"

    echo "Downloading APKINDEX: $index_url"
    wget -qO "$tmp/APKINDEX.tar.gz" "$index_url"
    tar -xzf "$tmp/APKINDEX.tar.gz" -C "$tmp" APKINDEX

    for pkg in "${SYSROOT_PACKAGES[@]}"; do
        local ver
        ver="$(awk -v p="$pkg" -F: '/^P:/{n=substr($0,3)} n==p && /^V:/{print substr($0,3); exit}' "$tmp/APKINDEX")"
        if [[ -z "$ver" ]]; then
            echo "Package not found in APKINDEX: $pkg" >&2
            exit 1
        fi
        local url="$ALPINE_MIRROR/$ALPINE_VERSION/main/$ALPINE_ARCH/${pkg}-${ver}.apk"
        echo "Downloading $url"
        wget -qO "$tmp/$pkg.apk" "$url"
        tar -xzf "$tmp/$pkg.apk" -C "$SYSROOT_DIR" 2>/dev/null || true
    done

    rm -rf "$tmp"

    # apk 解包出的 .pc 文件 prefix=/usr，交叉环境下 pkg-config 会把
    # /usr 当系统路径剥掉 -I/-L，因此改写成 sysroot 绝对路径
    # The .pc files unpacked from apk have prefix=/usr; when cross-compiling,
    # pkg-config treats /usr as a system path and strips -I/-L, so rewrite
    # it to the absolute sysroot path
    sed -i "s|^prefix=/usr\$|prefix=$SYSROOT_DIR/usr|" "$SYSROOT_DIR"/usr/lib/pkgconfig/*.pc
}

if [[ ! -f "$SYSROOT_DIR/usr/lib/pkgconfig/libelf.pc" ]]; then
    mkdir -p "$SYSROOT_DIR"
    fetch_sysroot
fi

# Alpine 的 libelf.a 里 vendor 了一份 zlib 的 crc32.o，与 libz.a 中的重复，
# 静态链接时 ld.lld 报 "duplicate symbol: crc32"，删除 libelf.a 里那份
# （两份同为 zlib crc32.c，符号 ABI 一致，去重安全）
# Alpine's libelf.a vendors a copy of zlib's crc32.o, duplicating the one in
# libz.a; on static linking ld.lld reports "duplicate symbol: crc32". Remove
# that copy from libelf.a (both come from the same zlib crc32.c with an
# identical symbol ABI, so deduping is safe)
if [[ -f "$SYSROOT_DIR/usr/lib/libelf.a" ]] && ar t "$SYSROOT_DIR/usr/lib/libelf.a" | grep -qx 'crc32.o'; then
    echo "Removing duplicate crc32.o from libelf.a"
    ar d "$SYSROOT_DIR/usr/lib/libelf.a" crc32.o
fi

# 交叉编译时 pkg-config 只允许作用于该 target，避免影响宿主侧探测
# When cross-compiling, allow pkg-config only for this target so host-side
# detection is unaffected
TARGET_US="${TARGET//-/_}"
export "PKG_CONFIG_ALLOW_CROSS_${TARGET_US}=1"
export "PKG_CONFIG_LIBDIR_${TARGET_US}=$SYSROOT_DIR/usr/lib/pkgconfig"

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
    "LIBBPF_SYS_LIBRARY_PATH_$TARGET=$SYSROOT_DIR/usr/lib"
)
CROSS_ENV+=(
    "CFLAGS_${TARGET_US}=$SYSROOT_CFLAGS"
    "LIBBPF_SYS_LIBRARY_PATH_${TARGET_US}=$SYSROOT_DIR/usr/lib"
)

# ---------- 静态/动态模式 ----------

# STATIC=1 时编译全静态二进制（不依赖任何 so）：
#   - +crt-static 覆盖 .cargo/config.toml 里的 -crt-static（env 追加在
#     config 之后，rustc 以最后的为准；注意变量名必须全大写）
#   - x86_64-musl 是 PIE 目标，rustc 会给 cc 传 -static-pie，zig cc 对
#     "-static-pie + -Wl,-Bdynamic" 组合会退化为动态链接，因此加
#     relocation-model=static 让 rustc 改传 "-static -no-pie"（其余架构
#     rustc 本来就传 -static -no-pie，无需处理）
#   - 只开 libbpf-sys/static（链接 sysroot 里的 libelf.a/libz.a）。
#     注意不能用 landscape-ebpf/static：它会连带 libbpf-sys/vendored，
#     从源码构建 elfutils，而 elfutils 依赖 musl 没有的 argp（configure
#     报 "failed to find argp_parse"）
#   - libelf.a 引用 zstd 符号，需追加 -lzstd
# With STATIC=1, build fully static binaries (no .so dependencies):
#   - +crt-static overrides the -crt-static in .cargo/config.toml (env vars
#     are appended after the config, and rustc keeps the last one; note the
#     variable name must be all uppercase)
#   - x86_64-musl is a PIE target and rustc passes -static-pie to cc; zig cc
#     degrades the "-static-pie + -Wl,-Bdynamic" combination back to dynamic
#     linking, so add relocation-model=static to make rustc pass
#     "-static -no-pie" instead (on other architectures rustc already passes
#     -static -no-pie, so no handling is needed)
#   - Only enable libbpf-sys/static (linking libelf.a/libz.a from the
#     sysroot). Note landscape-ebpf/static must NOT be used: it pulls in
#     libbpf-sys/vendored, building elfutils from source, and elfutils
#     depends on argp which musl lacks (configure fails with
#     "failed to find argp_parse")
#   - libelf.a references zstd symbols, so append -lzstd
#
# 命名约定：动态版本不带后缀（与现有发布一致），静态版本加 -static 后缀
# Naming convention: the dynamic build has no suffix (consistent with the
# existing releases), the static build gets a -static suffix
STATIC_SUFFIX=""
if [[ "$STATIC" == "1" ]]; then
    TARGET_UPPER="${TARGET^^}"
    RUSTFLAGS_STATIC="-C target-feature=+crt-static"
    if [[ "$TARGET" == "x86_64-unknown-linux-musl" ]]; then
        RUSTFLAGS_STATIC="$RUSTFLAGS_STATIC -C relocation-model=static"
    fi
    RUSTFLAGS_STATIC="$RUSTFLAGS_STATIC -C link-arg=-lzstd"
    export "CARGO_TARGET_${TARGET_UPPER//-/_}_RUSTFLAGS=$RUSTFLAGS_STATIC"
    STATIC_SUFFIX="-static"
fi

FEATURES="metric-persistent"
# 接受 1/true（CI matrix 传入的是 true）
# Accept 1/true (the CI matrix passes true)
case "$GATEWAY" in 1|true|TRUE|yes) FEATURES="$FEATURES,gateway" ;; esac
[[ "$STATIC" == "1" ]] && FEATURES="$FEATURES,libbpf-sys/static"

# ---------- 构建 ----------

# 注意：libbpf-sys 不是 workspace 成员，cargo 的 <pkg>/<feature> 语法只对
# "当前包的直接依赖"生效，静态特性需同时选中 landscape-ebpf 才能解析。
# 选中 landscape-ebpf 会连带构建其全部 bin（含 redirect_pkg_handler）。
# Note: libbpf-sys is not a workspace member, and cargo's <pkg>/<feature>
# syntax only works for "direct dependencies of the current package", so the
# static feature only resolves when landscape-ebpf is selected as well.
# Selecting landscape-ebpf also builds all of its binaries
# (including redirect_pkg_handler).
echo "Building landscape-webserver ($TARGET, static=$STATIC, gateway=$GATEWAY)..."
env "${CROSS_ENV[@]}" cargo zigbuild --release --target "$TARGET" --no-default-features \
    --features "$FEATURES" \
    -p landscape-webserver -p landscape-ebpf

# ---------- 收集产物 ----------

mkdir -p output
cp "target/$TARGET/release/landscape-webserver" "output/landscape-webserver-$ARCH${STATIC_SUFFIX}"
cp "target/$TARGET/release/redirect_pkg_handler" "output/redirect_pkg_handler-$ARCH${STATIC_SUFFIX}"

file "output/landscape-webserver-$ARCH${STATIC_SUFFIX}" "output/redirect_pkg_handler-$ARCH${STATIC_SUFFIX}"
echo "Done, artifacts are in output/"
