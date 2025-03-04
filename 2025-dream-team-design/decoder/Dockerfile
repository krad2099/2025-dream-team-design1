# Dockerfile for the 2025 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.04

LABEL version="0.3"
LABEL description="Updated Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
# Do this first because it takes the longest
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3.10 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    wget \
    libtool \
    texinfo \
    unzip \
    ninja-build \
    cmake \
    pkg-config \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --upgrade pip && \
    pip3 install cryptography loguru

# Install MSDK
RUN wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02

# Install WolfSSL for cryptographic functions
RUN git clone --depth 1 --branch v5.6.0-stable https://github.com/wolfSSL/wolfssl.git && \
    cd wolfssl && \
    ./autogen.sh && \
    ./configure --enable-aesgcm --enable-hmac --enable-pkcs7 --enable-keygen && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf wolfssl

# Set environment variables for WolfSSL
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /decoder

ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder
