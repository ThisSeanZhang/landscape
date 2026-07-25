# 使用 Debian 作为基础镜像
FROM debian:latest

# 设置工作目录
WORKDIR /app

# 安装必要的工具
RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    # tcpdump  \
    # curl  \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY apps/ ./

RUN chmod +x /app/start.sh \
    && chmod +x /app/redirect_pkg_handler \
    && chmod +x /app/server/run.sh \
    && chmod +x /app/server/redirect_demo_server

# 使用启动脚本作为容器启动命令
CMD ["/app/start.sh"]
