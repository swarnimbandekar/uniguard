FROM rust:1.85-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    pkg-config \
    cmake \
    build-essential \
    libssl-dev \
    libsasl2-dev \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libssl3 \
    libsasl2-2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/threat-ingest /usr/local/bin/threat-ingest

ENTRYPOINT ["threat-ingest"]
