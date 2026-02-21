# Stage 1: Build Linux kernel with LLVM/Clang (cached unless KERNEL_VERSION changes)
FROM ubuntu:24.04@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9 AS kernel-build

ARG KERNEL_VERSION=6.12.14
ARG KERNEL_CONFIG=defconfig
ARG LLVM_VERSION=18

ENV DEBIAN_FRONTEND=noninteractive

# Install LLVM toolchain and kernel build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bc \
    bison \
    ca-certificates \
    cpio \
    flex \
    kmod \
    libelf-dev \
    libssl-dev \
    make \
    lsb-release \
    software-properties-common \
    wget \
    xz-utils \
    && wget -qO- https://apt.llvm.org/llvm.sh | bash -s -- ${LLVM_VERSION} \
    && apt-get install -y --no-install-recommends \
    clang-${LLVM_VERSION} \
    lld-${LLVM_VERSION} \
    llvm-${LLVM_VERSION} \
    && rm -rf /var/lib/apt/lists/*

# Symlink versioned LLVM tools to unversioned names
RUN for tool in /usr/bin/*-${LLVM_VERSION}; do \
    ln -sf "$tool" "${tool%-${LLVM_VERSION}}"; \
    done

WORKDIR /kernel

# Download and extract kernel source
RUN wget -qO- "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz" \
    | tar xJ --strip-components=1

# Build kernel with LLVM
RUN make LLVM=1 ${KERNEL_CONFIG} \
    && ./scripts/config --set-val CONFIG_GCC_PLUGINS n \
    && make LLVM=1 -j"$(nproc)"

# Generate compile_commands.json from the build's .cmd files
RUN python3 ./scripts/clang-tools/gen_compile_commands.py


# Stage 2: Run kbitcode against the kernel build tree
FROM kernel-build AS kbitcode

# Install Python 3.12 and uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3.12-venv \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files
WORKDIR /app
COPY pyproject.toml uv.lock kbitcode.py ./

# Create output directory
RUN mkdir -p /output

CMD ["uv", "run", "python", "kbitcode.py", \
    "--build-dir", "/kernel", \
    "--output-dir", "/output", \
    "-v"]
