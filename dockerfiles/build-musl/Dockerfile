FROM rust:alpine3.22
RUN rustup component add rustfmt

# RUN printf "https://mirrors.tuna.tsinghua.edu.cn/alpine/latest-stable/main\nhttps://mirrors.tuna.tsinghua.edu.cn/alpine/latest-stable/community\n" \
#     | tee /etc/apk/repositories

RUN apk update && apk add --no-cache \
    # 基础构建工具
    clang \
    gcc \
    build-base \
    make \
    pkgconf \
    elfutils-dev \
    linux-headers