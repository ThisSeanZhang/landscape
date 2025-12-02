#!/bin/bash

# 设置GitHub仓库URL
REPO_URL="https://github.com/ThisSeanZhang/landscape/releases"
API_URL="https://api.github.com/repos/ThisSeanZhang/landscape/releases/latest"

# 获取最新版本信息
echo "正在获取最新版本信息..."
LATEST_RELEASE=$(curl -s $API_URL)
VERSION=$(echo "$LATEST_RELEASE" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$VERSION" ]; then
    echo "错误: 无法获取版本信息"
    exit 1
fi

echo "最新版本: $VERSION"

# 创建下载目录
DOWNLOAD_DIR="downloads"
BACKUP_DIR="backup"
mkdir -p $DOWNLOAD_DIR
mkdir -p $BACKUP_DIR

# 下载static.zip
STATIC_URL="$REPO_URL/download/$VERSION/static.zip"
STATIC_FILENAME="static.$VERSION.zip"
echo "正在下载 static.zip..."
wget -O "$DOWNLOAD_DIR/$STATIC_FILENAME" "$STATIC_URL"

if [ $? -eq 0 ]; then
    echo "✓ 成功下载: $STATIC_FILENAME"
else
    echo "✗ 下载失败: static.zip"
    exit 1
fi

# 下载landscape-webserver-x86_64
SERVER_URL="$REPO_URL/download/$VERSION/landscape-webserver-x86_64"
SERVER_FILENAME="landscape-webserver.$VERSION"
echo "正在下载 landscape-webserver-x86_64..."
wget -O "$DOWNLOAD_DIR/$SERVER_FILENAME" "$SERVER_URL"

if [ $? -eq 0 ]; then
    echo "✓ 成功下载: $SERVER_FILENAME"
else
    echo "✗ 下载失败: landscape-webserver-x86_64"
    exit 1
fi

# 备份当前的landscape-webserver（如果存在）
CURRENT_SERVER="landscape-webserver"
if [ -f "$CURRENT_SERVER" ]; then
    BACKUP_NAME="landscape-webserver_backup_$(date +%Y%m%d_%H%M%S)"
    mv "$CURRENT_SERVER" "$BACKUP_DIR/$BACKUP_NAME"
    echo "✓ 已备份当前版本到: $BACKUP_DIR/$BACKUP_NAME"
fi

# 复制新版本并设置权限
cp "$DOWNLOAD_DIR/$SERVER_FILENAME" "$CURRENT_SERVER"
chmod +x "$CURRENT_SERVER"

echo "✓ 已更新 landscape-webserver 为最新版本 $VERSION"
echo "✓ 已设置可执行权限"

# 显示下载文件信息
echo ""
echo "下载完成:"
echo "  - $DOWNLOAD_DIR/$STATIC_FILENAME"
echo "  - $DOWNLOAD_DIR/$SERVER_FILENAME"
echo ""
echo "当前版本: $VERSION"

rm -r .landscape-router/static_bak
mv .landscape-router/static .landscape-router/static_bak
unzip "$DOWNLOAD_DIR/$STATIC_FILENAME" -d .landscape-router
