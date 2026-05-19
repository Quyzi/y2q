# syntax=docker/dockerfile:1
#
# y2q -- post-quantum secure storage
#
# Build variants:
#   Standard (filesystem backend):
#     podman build -t y2q:latest .
#
#   With io_uring (Linux kernel >= 5.6 required at runtime):
#     podman build --build-arg URING=1 -t y2q:latest-uring .
#
# Runtime configuration (figment env-override convention: Y2QD_SECTION__KEY):
#   Y2QD_SERVER__HOST         bind address (default: 0.0.0.0, set in image)
#   Y2QD_SERVER__PORT         TCP port (default: 8080)
#   Y2QD_STORAGE__BASE_PATH   object data directory (default: /var/lib/y2q/data)
#   Y2QD_CRYPTO__KEYSTORE_DIR key material directory (default: /var/lib/y2q/keys)
#
# Typical run:
#   podman run -p 8080:8080 \
#     -v /host/data:/var/lib/y2q/data \
#     -v /host/keys:/var/lib/y2q/keys \
#     y2q:latest
#
# Override config file:
#   podman run ... -v /host/config.toml:/etc/y2q/config.toml:ro y2q:latest

ARG URING=0

# ---------------------------------------------------------------------------
# Download Swagger UI zip
# utoipa-swagger-ui's build.rs fetches this at compile time. Pre-fetching in
# a separate stage keeps the download cached independently of the Rust build,
# and avoids needing curl in the build image (build.rs handles file:// natively).
#
# cgr.dev/chainguard/curl is distroless (no shell); use exec-form RUN.
# v5.17.14 is the version bundled by utoipa-swagger-ui 9.0.2 -- update if
# the crate is upgraded.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/curl:latest AS swagger-dl
RUN ["/usr/bin/curl", "-fsSL", \
     "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v5.17.14.zip", \
     "-o", "/tmp/swagger-ui.zip"]

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/rust:latest AS builder

WORKDIR /work

# Point utoipa-swagger-ui's build.rs at the pre-fetched zip; build.rs handles
# file:// URLs natively without invoking curl.
COPY --from=swagger-dl /tmp/swagger-ui.zip /tmp/swagger-ui.zip
ENV SWAGGER_UI_DOWNLOAD_URL=file:///tmp/swagger-ui.zip

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY config.default.toml ./

ARG URING

RUN if [ "$URING" = "1" ]; then \
        cargo build --release -p y2qd --features uring && \
        cargo build --release -p y2q-cli && \
        cargo build --release -p y2q-warp; \
    else \
        cargo build --release -p y2qd -p y2q-cli -p y2q-warp; \
    fi

# Assemble the runtime filesystem layout so the runtime stage is a single
# layer of COPY instructions with no shell required.
RUN mkdir -p \
        rootfs/usr/local/bin \
        rootfs/var/lib/y2q/data \
        rootfs/var/lib/y2q/keys \
        rootfs/etc/y2q && \
    cp target/release/y2qd     rootfs/usr/local/bin/y2qd     && \
    cp target/release/y2q      rootfs/usr/local/bin/y2q      && \
    cp target/release/y2q-warp rootfs/usr/local/bin/y2q-warp && \
    cp config.default.toml     rootfs/etc/y2q/config.toml

# ---------------------------------------------------------------------------
# Runtime stage -- minimal Chainguard glibc-dynamic, non-root (UID 65532)
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/glibc-dynamic:latest

COPY --from=builder --chown=65532:65532 /work/rootfs/usr/local/bin /usr/local/bin
COPY --from=builder --chown=65532:65532 /work/rootfs/var/lib/y2q   /var/lib/y2q
COPY --from=builder --chown=65532:65532 /work/rootfs/etc/y2q       /etc/y2q

LABEL org.opencontainers.image.title="y2q" \
      org.opencontainers.image.description="Post-quantum secure storage daemon"

# config.default.toml binds to 127.0.0.1; override so the daemon is
# reachable outside the container.
ENV Y2QD_SERVER__HOST=0.0.0.0

EXPOSE 8080

VOLUME ["/var/lib/y2q/data", "/var/lib/y2q/keys"]

ENTRYPOINT ["/usr/local/bin/y2qd"]
CMD ["--config", "/etc/y2q/config.toml"]
