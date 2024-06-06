# Use an official Ubuntu base image with specified platform
FROM --platform=linux/amd64 ubuntu:24.04 AS base

# Switch to non-root user
USER builder

# Healthcheck instruction
HEALTHCHECK --interval=30s --timeout=30s --start-period=30s --retries=3 CMD gcc --version || exit 1

# Install necessary packages including the latest GCC
RUN apt-get update && apt-get install -y \
    gawk \
    bison \
    wget \
    python3 \
    build-essential \
    gcc \
    g++\
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Download and extract glibc 2.29
RUN wget -c https://ftp.gnu.org/gnu/glibc/glibc-2.29.tar.gz && \
    tar -zxvf glibc-2.29.tar.gz

# Create the final stage
FROM base

# Set the working directory
WORKDIR /glibc-2.29

# Copy the source files from the base stage
COPY --from=base /glibc-2.29 /glibc-2.29

# Command to install glibc 2.29 and copy libc.so to the host directory
CMD gcc --version && g++ --version &&\
    mkdir glibc-build && cd glibc-build && \
    ../configure --prefix=/opt/glibc-2.29 CFLAGS="-O3 -fcf-protection=none" && \
    make -j$(nproc) &&\
    make install && \
    cp /opt/glibc-2.29/lib/libc.so /host/libc.so && \
    echo "Build complete. libc.so has been copied to /host/libc.so" && \
    exec /bin/bash