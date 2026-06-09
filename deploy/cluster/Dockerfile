# syntax=docker/dockerfile:1
#
# y2q cluster image: the y2qd binary on a shell-bearing Wolfi base (same glibc
# lineage as the production glibc-dynamic runtime), plus an entrypoint that
# bootstraps the shared keystore and brings up a node. Used by
# deploy/cluster/docker-compose.yml for a self-contained multi-node cluster.
#
# Build context is the repository root:
#   docker build -f deploy/cluster/Dockerfile -t y2q-cluster:latest .
#
# The plain production image (distroless, no shell) lives in ./Dockerfile; this
# one trades that minimalism for a shell so one image can both generate the
# keystore and run a node.

# ---------------------------------------------------------------------------
# Pre-fetch Swagger UI (utoipa-swagger-ui's build.rs needs it at compile time).
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/curl:latest AS swagger-dl
RUN ["/usr/bin/curl", "-fsSL", \
     "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v5.17.14.zip", \
     "-o", "/tmp/swagger-ui.zip"]

# ---------------------------------------------------------------------------
# Build stage (release y2qd only).
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/rust:latest AS builder
WORKDIR /work
COPY --from=swagger-dl /tmp/swagger-ui.zip /tmp/swagger-ui.zip
ENV SWAGGER_UI_DOWNLOAD_URL=file:///tmp/swagger-ui.zip
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY config.default.toml ./
# gxhash needs AES + SSE2 intrinsics; the repo's .cargo/config.toml
# (target-cpu=native) is not copied into the image. Require only AES-NI + SSE2
# so the binary stays portable across x86-64 server CPUs.
ENV RUSTFLAGS="-C target-feature=+aes,+sse2"
RUN cargo build --release -p y2qd

# ---------------------------------------------------------------------------
# Runtime stage: Wolfi base (glibc + busybox shell), non-root.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest

COPY --from=builder /work/target/release/y2qd /usr/local/bin/y2qd
# The daemon's config requires the server/storage/crypto/auth sections (no serde
# defaults); ship the reference config as the base every node/init layers onto.
COPY config.default.toml /etc/y2q/config.toml
COPY --chmod=0755 deploy/cluster/entrypoint.sh /usr/local/bin/cluster-entrypoint.sh

# Reachable outside the container.
ENV Y2QD_SERVER__HOST=0.0.0.0

EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/usr/local/bin/cluster-entrypoint.sh"]
