FROM rust:1.88 as builder

WORKDIR /usr/src

# Install build dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        pkg-config \
        libssl-dev \
        clang \
        git \
    && rm -rf /var/lib/apt/lists/*

# Copy the whole repository (workspace)
COPY . .

# Build the `aether` release binary using the crate manifest in aether/Cargo.toml
# Set CARGO_TARGET_DIR to place the target in the workspace root for predictable COPY path
RUN CARGO_TARGET_DIR=/usr/src/aether/target cargo build --release --manifest-path aether/Cargo.toml

# Final runtime image
FROM debian:bookworm-slim

# Install runtime deps (certs)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary produced in the builder stage
COPY --from=builder /usr/src/aether/target/release/aether /usr/local/bin/aether

# Default listening port (matches default in code)
EXPOSE 1819

ENTRYPOINT ["/usr/local/bin/aether"]
