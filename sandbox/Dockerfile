# Multi-toolchain sandbox for secure C & Rust compilation and execution
# Enforces --network none and non-root execution inside isolated container
FROM rust:1.80-slim-bookworm

# Install GCC and sanitizers for C compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libasan8 \
    libubsan1 \
    make \
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
