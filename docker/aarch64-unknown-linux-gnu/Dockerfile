FROM ghcr.io/cross-rs/aarch64-unknown-linux-gnu:latest

ENV PKG_CONFIG_ALLOW_CROSS="true"

RUN dpkg --add-architecture arm64 && \
    apt-get update && \
    apt-get install --assume-yes \
        git \
        cmake \
        curl \
        ca-certificates \
        libssl-dev:arm64 \
        libyajl-dev:arm64
