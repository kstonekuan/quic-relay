FROM rust:1.83-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/quic-relay /usr/local/bin/quic-relay
EXPOSE 4433/udp
ENTRYPOINT ["quic-relay"]
CMD ["--port", "4433"]
