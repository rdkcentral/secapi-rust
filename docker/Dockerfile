# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Install required packages and Rust from rustup
RUN apt-get update && \
    apt-get upgrade && \
    apt-get install -y \
        git \
        cmake \
        build-essential \
        libssl-dev \
        libyajl-dev \
        curl \
        ca-certificates \
        vim && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    rm -rf /var/lib/apt/lists/*

# Add Rust to PATH
ENV PATH="/root/.cargo/bin:${PATH}"

# Setup user
RUN useradd -m -d /home/workuser -s /bin/bash workuser
USER workuser
WORKDIR /home/workuser
