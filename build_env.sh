#!/usr/bin/env bash

set -euo pipefail

# 记录脚本所在的绝对路径，避免后续 cd 或 source 导致路径混乱
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 自动获取当前主机架构
DEFAULT_ARCH="$(uname -m)"

# 镜像名称
IMAGE_NAME="landscape"

# 定义支持的架构（Rust目标）
declare -A TARGETS=(
    ["x86_64"]="x86_64-unknown-linux-gnu"
    ["aarch64"]="aarch64-unknown-linux-gnu"
    ["armv7"]="armv7-unknown-linux-gnueabihf"
)

TARGET_ORDER=("x86_64" "aarch64" "armv7")

# 对应 Docker 平台的架构
declare -A DOCKER_ARCHS=(
    ["x86_64"]="amd64"
    ["aarch64"]="arm64"
    ["armv7"]="arm/v7"
)

# 默认目标架构
TARGET=""

# 打印支持的架构供用户选择
function print_supported_archs() {
    echo "Supported architectures:"
    local i=1
    local key

    for key in "${TARGET_ORDER[@]}"; do
        echo "$i) $key"
        i=$((i + 1))
    done

    echo "$i) Use default architecture ($DEFAULT_ARCH)"
}

# 提示用户选择架构
function prompt_user_selection() {
    if [[ ! -t 0 ]]; then
        TARGET="$DEFAULT_ARCH"
        return
    fi

    print_supported_archs
    echo -n "Please select a target architecture by entering the corresponding number [default = $DEFAULT_ARCH]: "

    local choice=""
    if ! read -r choice; then
        TARGET="$DEFAULT_ARCH"
        return
    fi

    # 如果用户直接回车（输入为空），使用默认架构
    if [[ -z "$choice" ]]; then
        TARGET="$DEFAULT_ARCH"
        return
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        echo "Invalid selection. Please enter a number."
        prompt_user_selection
        return
    fi

    local i=1
    local key
    for key in "${TARGET_ORDER[@]}"; do
        if [[ "$choice" -eq "$i" ]]; then
            TARGET="$key"
            return
        fi
        i=$((i + 1))
    done

    # 如果用户选择了最后一个选项（默认架构）
    if [[ "$choice" -eq "$i" ]]; then
        TARGET="$DEFAULT_ARCH"
        return
    fi

    echo "Invalid selection. Please try again."
    prompt_user_selection
}

# 解析命令行参数
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -t|--target)
            if [[ "$#" -lt 2 ]]; then
                echo "Missing value for $1"
                exit 1
            fi
            TARGET="$2"
            shift
            ;;
        --list)
            print_supported_archs
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
    shift
done

# 如果用户没有指定架构，提示用户选择
if [[ -z "$TARGET" ]]; then
    echo "No target specified."
    prompt_user_selection
fi

# 检查用户输入的架构是否受支持
if [[ -z "${TARGETS[$TARGET]:-}" ]]; then
    echo "Unsupported architecture: $TARGET"
    echo "Use --list to see supported architectures."
    exit 1
fi

# 设置 Rust 和 Docker 的目标架构
TARGET_ARCH="${TARGETS[$TARGET]}"
DOCKER_ARCH="${DOCKER_ARCHS[$TARGET]}"

export TARGET TARGET_ARCH DOCKER_ARCH

source "$SCRIPT_DIR/scripts/pnpm_cmd.sh"
