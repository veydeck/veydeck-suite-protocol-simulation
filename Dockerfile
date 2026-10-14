FROM rust:1.95.0-trixie AS rust-builder

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p protocol-simulation

FROM debian:trixie-slim

LABEL veydeck.owner="suite"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=rust-builder /src/target/release/protocol-simulation /usr/local/bin/protocol-simulation
COPY frontend/dist /app/public

ENV PORT=8080
ENV VEYDECK_FRONTEND_DIR=/app/public
ENV VEYDECK_SUITE_DATA_DIR=/data

EXPOSE 8080

CMD ["protocol-simulation"]
