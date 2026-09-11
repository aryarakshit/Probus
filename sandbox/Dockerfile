# Multi-toolchain sandbox for secure C & Rust compilation and execution
# Enforces --network none and non-root execution inside isolated container
FROM rust:1.80-slim-bookworm

# Install GCC and build-essential for C compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    make \
    valgrind \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged sandbox user
RUN useradd -m -s /bin/bash sandboxuser

# Create workspace directory with strict permissions
WORKDIR /work
RUN chown sandboxuser:sandboxuser /work

USER sandboxuser

# Default command
CMD ["bash"]
