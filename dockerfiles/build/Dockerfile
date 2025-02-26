FROM rust:slim-bookworm

RUN rustup component add rustfmt

RUN apt-get update && \
    apt-get install -y \
    clang libelf1 libelf-dev zlib1g-dev make pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /landscape
