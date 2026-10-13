# GritScan backend — multi-stage build
# Stage 1: Build the Rust binary
FROM rust:1.82-slim-bookworm AS builder

WORKDIR /build

# Copy manifests first for better caching
COPY Cargo.toml ./
COPY src ./src

# Build release binary
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/gritscan-backend /usr/local/bin/gritscan-backend

# Data volume for SQLite
VOLUME ["/data"]

EXPOSE 8050

CMD ["gritscan-backend"]
