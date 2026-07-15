FROM rust:1.88 as builder

WORKDIR /usr/src/aether

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

# Copy the whole repository (workspace) and build the `aether` release binary
COPY . .

# Build the workspace release for the aether binary
RUN cargo build --release -p aether

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
