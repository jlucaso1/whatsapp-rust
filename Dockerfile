# --- Build stage ---
FROM rust:slim AS builder

# Install musl toolchain for fully static binary
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*

# Install the exact nightly from rust-toolchain.toml + musl target
COPY rust-toolchain.toml .
RUN rustup show && rustup target add x86_64-unknown-linux-musl

WORKDIR /app

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY wacore/Cargo.toml wacore/Cargo.toml
COPY wacore/appstate/Cargo.toml wacore/appstate/Cargo.toml
COPY wacore/binary/Cargo.toml wacore/binary/Cargo.toml
COPY wacore/derive/Cargo.toml wacore/derive/Cargo.toml
COPY wacore/libsignal/Cargo.toml wacore/libsignal/Cargo.toml
COPY wacore/noise/Cargo.toml wacore/noise/Cargo.toml
COPY waproto/Cargo.toml waproto/Cargo.toml
COPY storages/sqlite-storage/Cargo.toml storages/sqlite-storage/Cargo.toml
COPY transports/tokio-transport/Cargo.toml transports/tokio-transport/Cargo.toml
COPY http_clients/ureq-client/Cargo.toml http_clients/ureq-client/Cargo.toml
COPY tests/e2e/Cargo.toml tests/e2e/Cargo.toml

# Create dummy source files so cargo can resolve the workspace and cache deps
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && mkdir -p wacore/src && echo '' > wacore/src/lib.rs \
    && mkdir -p wacore/appstate/src && echo '' > wacore/appstate/src/lib.rs \
    && mkdir -p wacore/binary/src && echo '' > wacore/binary/src/lib.rs \
    && mkdir -p wacore/derive/src && echo '' > wacore/derive/src/lib.rs \
    && mkdir -p wacore/libsignal/src && echo '' > wacore/libsignal/src/lib.rs \
    && mkdir -p wacore/noise/src && echo '' > wacore/noise/src/lib.rs \
    && mkdir -p waproto/src && echo '' > waproto/src/lib.rs \
    && mkdir -p storages/sqlite-storage/src && echo '' > storages/sqlite-storage/src/lib.rs \
    && mkdir -p transports/tokio-transport/src && echo '' > transports/tokio-transport/src/lib.rs \
    && mkdir -p http_clients/ureq-client/src && echo '' > http_clients/ureq-client/src/lib.rs \
    && mkdir -p tests/e2e/src && echo '' > tests/e2e/src/lib.rs

# Pre-build dependencies (cached unless Cargo.toml/lock change)
# build.rs scripts may fail with dummy sources — that's fine for dep caching
RUN cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || true

# Copy real source code
COPY . .

# Touch source files to invalidate the dummy builds
RUN find . -name "*.rs" -path "*/src/*" -exec touch {} +

RUN cargo build --release --target x86_64-unknown-linux-musl

# --- Runtime stage ---
FROM scratch

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/whatsapp-rust /whatsapp-rust

WORKDIR /data

ENTRYPOINT ["/whatsapp-rust"]
