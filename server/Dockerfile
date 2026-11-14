# Build-Kontext ist das Repo-Root: docker build -f server/Dockerfile .
FROM rust:1.95-slim-trixie AS build
# Das mitgebaute OpenSSL (webauthn-rs) braucht Compiler, make und ein vollständiges perl.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential perl pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY agent agent
COPY server server
RUN cargo build --release --locked -p patchwatch-server

FROM debian:trixie-slim
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin patchwatch
COPY --from=build /src/target/release/patchwatch-server /usr/local/bin/patchwatch-server
USER 10001
ENV PATCHWATCH_LISTEN=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["patchwatch-server", "healthcheck"]
ENTRYPOINT ["patchwatch-server"]
CMD ["serve"]
