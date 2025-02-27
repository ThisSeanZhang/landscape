FROM rust:slim-bookworm

RUN rustup component add rustfmt && rustup target add aarch64-unknown-linux-gnu

RUN dpkg --add-architecture arm64 && apt-get update && \
    apt-get install -y \
    # arm
    gcc-aarch64-linux-gnu libelf-dev:arm64 zlib1g-dev:arm64 \
    clang libelf1 libelf-dev zlib1g-dev make pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /landscape
