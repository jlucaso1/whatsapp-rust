# whatsapp-rust Docker build
#
# Produces a fully static musl binary running on a scratch (empty) container.
# musl is preferred over glibc for long-running processes: predictable memory
# usage with no fragmentation from glibc's per-thread arena allocator.
#
# Build:  docker build -t whatsapp-rust .
# Run:    docker run -v whatsapp-data:/data whatsapp-rust
#
# The /data volume persists the SQLite database across restarts.
# Pass --phone <number> for pair code auth:
#   docker run -v whatsapp-data:/data whatsapp-rust --phone 15551234567

# --- Planner: extract dependency recipe ---
FROM rust:alpine AS chef
RUN apk add --no-cache musl-dev
COPY rust-toolchain.toml .
RUN rustup show && cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- Builder: cook deps (cached layer), then compile source ---
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# --- Runtime: static binary on empty image ---
FROM scratch
COPY --from=builder /app/target/release/whatsapp-rust /whatsapp-rust
WORKDIR /data
ENTRYPOINT ["/whatsapp-rust"]
