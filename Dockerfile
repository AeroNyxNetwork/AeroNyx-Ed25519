FROM rust:1.73-bullseye as builder

# Create a new empty shell project
WORKDIR /usr/src/solana-vpn
COPY Cargo.toml .

# Build dependencies to cache them
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy the actual source code
COPY src src

# Build the application
RUN cargo build --release

# Create a minimal runtime image
FROM debian:bullseye-slim

# Install necessary runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl1.1 \
        iproute2 \
        iptables \
        procps \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /usr/src/solana-vpn/target/release/solana-vpn /usr/local/bin/solana-vpn

# Add a startup script
WORKDIR /app
COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Default command
CMD ["solana-vpn"]
