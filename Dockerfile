FROM rust:1.88 AS builder

RUN apt-get update && \
    apt-get install -y \
    clang \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY aether ./aether
COPY quiche ./quiche

WORKDIR /usr/src/app/aether
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12

WORKDIR /app

COPY --from=builder /usr/src/app/aether/target/release/aether /usr/local/bin/aether

ENV AETHER_SOCKS=0.0.0.0:1819

ENTRYPOINT ["aether"]
