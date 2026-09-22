FROM rust:1.98-bookworm AS builder

ARG GO_VERSION=1.22.12

RUN apt-get update && \
    apt-get install -y \
    clang \
    cmake \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /usr/src/app

COPY pt-build.sh ./pt-build.sh
COPY psiphon-build.sh ./psiphon-build.sh
COPY aether ./aether
COPY quiche ./quiche

WORKDIR /usr/src/app/aether

RUN bash ../pt-build.sh linux "$(dpkg --print-architecture)" /usr/src/app/aether/pt
RUN bash ../psiphon-build.sh linux "$(dpkg --print-architecture)" /usr/src/app/aether/pt

RUN cargo build --release --locked --features tor

FROM gcr.io/distroless/cc-debian12

WORKDIR /app

COPY --from=builder /usr/src/app/aether/target/release/aether /usr/local/bin/aether
COPY --from=builder /usr/src/app/aether/pt /usr/local/bin/pt

ENV AETHER_SOCKS=0.0.0.0:1819
ENV AETHER_CONFIG=/data/aether.toml

VOLUME ["/data"]

EXPOSE 1819

ENTRYPOINT ["aether"]
