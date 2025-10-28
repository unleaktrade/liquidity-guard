# -------- Builder stage (official Rust toolchain) --------
FROM rust:1.90-slim-bookworm AS builder

# Enable faster incremental linking and cache-friendly builds
ENV CARGO_TERM_COLOR=always \
    RUSTFLAGS="-C target-cpu=native" \
    SQLX_OFFLINE=true

WORKDIR /app

# System packages required by Solana crates
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates build-essential curl \
 && rm -rf /var/lib/apt/lists/*

# Pre-cache deps: copy manifests first
COPY Cargo.toml Cargo.lock ./

# Create a minimal dummy main.rs to build deps and populate target cache
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --locked && rm -rf src

# Now add the real source and build optimized release
COPY src ./src
# touch to avoid cache misses if timestamps confuse cargo
RUN touch src/main.rs
RUN cargo build --release --locked

# -------- Runtime stage (minimal Debian) --------
FROM debian:bookworm-slim AS runtime

# Minimal runtime libs for TLS and certs
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 curl \
 && rm -rf /var/lib/apt/lists/*

# Non-root runtime user
RUN useradd -m -u 10001 -s /usr/sbin/nologin appuser

WORKDIR /app

# Copy the built binary
COPY --from=builder /app/target/release/liquidity-guard /usr/local/bin/liquidity-guard

# Drop privileges
USER appuser

EXPOSE 8080

# Healthcheck against the service
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://localhost:8080/health || exit 1

# Entrypoint
CMD ["/usr/local/bin/liquidity-guard"]
