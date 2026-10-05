# Pinned by digest-free tag: the build is reproducible enough for a test fixture, and floating
# on the current stable image keeps security updates coming without a manual bump.
FROM rust:1-trixie AS builder

WORKDIR /build

# Dependencies are built against the manifests alone, so editing source does not rebuild them.
# The dummy sources exist only to give cargo something to compile.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
# cargo decides what to rebuild from mtimes, and the copy above may land with an older one than
# the placeholder it replaced, which would leave the dummy binary in place.
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked \
    && strip target/release/entra-sim

# Slim rather than scratch: rustls needs no OpenSSL, so a static image would work, but keeping a
# shell means a failing container can still be inspected, which matters for something whose job
# is to be debugged against.
FROM debian:trixie-slim

# curl is the HEALTHCHECK's only dependency, and the simulator serves TLS with a certificate it
# generates, so the CA bundle is needed for nothing else.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes curl \
    && rm -rf /var/lib/apt/lists/*

# An unprivileged user, with /certs and /seed owned by it so a mounted volume can be written.
RUN useradd --system --create-home --uid 10001 entrasim \
    && mkdir -p /certs /seed \
    && chown entrasim:entrasim /certs /seed

COPY --from=builder /build/target/release/entra-sim /usr/local/bin/entra-sim

USER entrasim
WORKDIR /home/entrasim

# Defaults chosen so `docker run -p 8080:8080 -p 8443:8443 entra-sim` is immediately usable:
# the certificate covers the container name and localhost, and the CA lands where a volume can
# pick it up.
ENV ENTRA_SIM_BIND=0.0.0.0 \
    ENTRA_SIM_HTTP_PORT=8080 \
    ENTRA_SIM_HTTPS_PORT=8443 \
    ENTRA_SIM_TLS_SAN=localhost,127.0.0.1,entra-sim \
    ENTRA_SIM_CA_OUT=/certs/ca.pem \
    ENTRA_SIM_PUBLIC_HOST=localhost:8443

EXPOSE 8080 8443

# Startup generates an RSA signing key and a certificate, which can take a few seconds on a
# slow or contended machine, hence the start period.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD curl --fail --silent --output /dev/null http://127.0.0.1:${ENTRA_SIM_HTTP_PORT}/__sim__/health

ENTRYPOINT ["/usr/local/bin/entra-sim"]
