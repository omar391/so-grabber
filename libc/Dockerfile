# Define default values for the Ubuntu and glibc versions
ARG UBUNTU_VERSION=20.04
ARG GLIBC_VERSION=2.29

# Use the variables in the FROM instruction
FROM --platform=linux/amd64 ubuntu:${UBUNTU_VERSION}

# Redefine the ARGs to use them within the build stage
ARG UBUNTU_VERSION
ARG GLIBC_VERSION

# Install necessary packages, download and extract glibc, and create the host directory in one layer
RUN apt-get update && apt-get install -y \
    gawk \
    bison \
    wget \
    python3 \
    build-essential \
    gcc \
    g++ \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* && \
    wget -c https://ftp.gnu.org/gnu/glibc/glibc-${GLIBC_VERSION}.tar.gz && \
    tar -zxvf glibc-${GLIBC_VERSION}.tar.gz && \
    rm glibc-${GLIBC_VERSION}.tar.gz

# Set the working directory
WORKDIR /glibc-${GLIBC_VERSION}

# Healthcheck instruction to ensure gcc is installed correctly
HEALTHCHECK --interval=30s --timeout=30s --start-period=30s --retries=3 CMD gcc --version || exit 1

# Command to install glibc
RUN gcc --version && g++ --version && \
    mkdir glibc-build && cd glibc-build && \
    ../configure --prefix=/opt/glibc-${GLIBC_VERSION} --enable-add-ons CFLAGS="-g -O3 -fcf-protection=none -Wno-error -Wno-maybe-uninitialized -Wno-array-bounds -Wno-array-parameter -Wno-stringop-overflow -Wno-zero-length-bounds -Wno-use-after-free -Wno-builtin-declaration-mismatch" && \
    make -j$(nproc) && \
    make install && \
    echo "Build complete. libc.so has been installed to /opt/glibc-${GLIBC_VERSION}/lib/libc.so"

CMD ["bash"]