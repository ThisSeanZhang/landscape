#!/usr/bin/env bash

# 记录脚本所在的**绝对路径**，以免后续 cd 导致路径混乱
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 自动获取当前主机架构
DEFAULT_ARCH="$(uname -m)"

# 定义支持的架构（Rust目标）
declare -A TARGETS=(
    ["x86_64"]="x86_64-unknown-linux-gnu"
    ["aarch64"]="aarch64-unknown-linux-gnu"
)

# 对应 Docker 平台的架构
declare -A DOCKER_ARCHS=(
    ["x86_64"]="amd64"
    ["aarch64"]="arm64"
)

# 默认目标架构
TARGET=""

# 打印支持的架构供用户选择
function print_supported_archs() {
    echo "Supported architectures:"
    local i=1
    for key in "${!TARGETS[@]}"; do
        echo "$i) $key"
        i=$((i + 1))
    done
    echo "$i) Use default architecture ($DEFAULT_ARCH)"
}

# 提示用户选择架构
function prompt_user_selection() {
    print_supported_archs
    echo -n "Please select a target architecture by entering the corresponding number [default = $DEFAULT_ARCH]: "
    read -r choice

    # 如果用户直接回车（输入为空），使用默认架构
    if [[ -z "$choice" ]]; then
        TARGET="$DEFAULT_ARCH"
        return
    fi

    local i=1
    for key in "${!TARGETS[@]}"; do
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
if [[ -z "${TARGETS[$TARGET]}" ]]; then
    echo "Unsupported architecture: $TARGET"
    echo "Use --list to see supported architectures."
    exit 1
fi

# 设置 Rust 和 Docker 的目标架构
TARGET_ARCH="${TARGETS[$TARGET]}"
DOCKER_ARCH="${DOCKER_ARCHS[$TARGET]}"

echo "Target platform set to: $TARGET"
echo "Rust target: $TARGET_ARCH"
echo "Docker architecture: $DOCKER_ARCH"

#
# 第一阶段：Rust 编译
#

echo "Building the project for $TARGET_ARCH..."

# 在脚本所在目录下执行 cargo build（假设你的Cargo.toml也在脚本同目录或上层）
# 如果 cargo 项目在别的子目录，需要适当修改 --manifest-path 或 cd
cargo build --release \
    --package landscape-ebpf \
    --bin redirect_demo_server \
    --bin redirect_pkg_handler \
    --target "$TARGET_ARCH"

if [ $? -ne 0 ]; then
    echo "Build failed. Exiting."
    exit 1
fi

#
# 第二阶段：准备 Docker 构建上下文
#

# 注意，这里用绝对路径，避免cd带来的混乱
COPY_DIR="$SCRIPT_DIR/dockerfiles/redirect_prog/apps"
BUILD_DIR="$SCRIPT_DIR/dockerfiles/redirect_prog"

echo "Creating build directory: $COPY_DIR"
rm -rf "$COPY_DIR"  # 清理旧的构建目录
mkdir -p "$COPY_DIR"

# 针对 server 文件夹的逻辑
if [[ -d "$SCRIPT_DIR/redirect_server" ]]; then
    echo "Found 'redirect_server' folder. Using it directly as the source for the server."
    cp -r "$SCRIPT_DIR/redirect_server" "$COPY_DIR/server"

    # 检查 run.sh 文件是否存在，并设置执行权限
    RUN_SH="$COPY_DIR/server/run.sh"
    if [[ -f "$RUN_SH" ]]; then
        echo "Found 'run.sh' in 'redirect_server'. Ensuring it has execute permission."
        chmod +x "$RUN_SH"
    else
        echo "Error: 'run.sh' not found in 'redirect_server'. Exiting."
        exit 1
    fi
else
    echo "'redirect_server' folder not found. Using build artifacts for the server."
    mkdir -p "$COPY_DIR/server"

    # 复制编译产物
    echo "Copying build artifacts..."

    cp "$SCRIPT_DIR/target/$TARGET_ARCH/release/redirect_demo_server" \
       "$COPY_DIR/server/redirect_demo_server"

    cat <<EOF > "$COPY_DIR/server/run.sh"
#!/bin/bash

/app/server/redirect_demo_server

EOF
    chmod +x "$COPY_DIR/server/run.sh"
fi

# 继续复制其他文件（不受影响）
echo "Copying other artifacts..."
cp "$BUILD_DIR/start.sh" "$COPY_DIR/start.sh"
chmod +x "$COPY_DIR/start.sh"

cp "$SCRIPT_DIR/target/$TARGET_ARCH/release/redirect_pkg_handler" \
   "$COPY_DIR/redirect_pkg_handler"
chmod +x "$COPY_DIR/redirect_pkg_handler"


#
# 第三阶段：使用 Buildx 构建 Docker 镜像并输出到 tar 文件
#

echo "Building Docker image for $DOCKER_ARCH..."

BUILDER_NAME="temp_builder_$(date +%s)"
# 启用 Docker Buildx (确保已启用多平台支持)
docker buildx create --use --name "$BUILDER_NAME" --driver docker-container

# 定义输出文件路径（在脚本所在目录下）
OUTPUT_DIR="$SCRIPT_DIR/output"
mkdir -p "$OUTPUT_DIR"

OUTPUT_PATH="$OUTPUT_DIR/docker_${TARGET}.tar"

# 使用 docker buildx 来构建镜像，并输出到一个 Docker-compatible .tar 文件
docker buildx build \
    --platform "linux/$DOCKER_ARCH" \
    -t "ld_redirect_image:$TARGET" \
    --output "type=docker,dest=$OUTPUT_PATH" \
    --build-arg CONTEXT=/mnt \
    --build-context output="$OUTPUT_DIR" \
    -f "$BUILD_DIR/Dockerfile" \
    "$BUILD_DIR"

if [ $? -ne 0 ]; then
    echo "Docker build failed. Exiting."
    exit 1
fi


docker buildx rm "$BUILDER_NAME"


echo "Docker image built successfully for $DOCKER_ARCH: ld_redirect_image:$TARGET"
echo "The tar file is at: $OUTPUT_PATH"

#
# 第四阶段：如果本机架构与目标架构一致，则自动 load
#

LOCAL_ARCH="$(uname -m)"
if [[ "$LOCAL_ARCH" == "$TARGET" ]]; then
    echo "Local architecture matches target. Loading image into Docker..."
    docker load -i "$OUTPUT_PATH"

    if [ $? -ne 0 ]; then
        echo "Docker load failed. Exiting."
        exit 1
    fi

    echo "Docker image loaded successfully into local Docker."
else
    echo "Local architecture does not match target."
    echo "The image tar has been saved to: $OUTPUT_PATH"
fi

echo "Done."
