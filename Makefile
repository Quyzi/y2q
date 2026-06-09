CARGO   ?= cargo
PODMAN  ?= podman
# Prefer the native `podman-compose` (talks to podman directly) over
# `podman compose`, which delegates to docker-compose and needs the Podman API
# socket running. Override with `make cluster-up COMPOSE="docker compose"`.
COMPOSE ?= $(shell command -v podman-compose >/dev/null 2>&1 && echo podman-compose || echo "$(PODMAN) compose")

IMAGE         ?= y2q:latest
IMAGE_DEV     ?= y2q:dev
IMAGE_CLUSTER ?= y2q-cluster:latest

.PHONY: all \
        build build-y2qd build-y2q build-y2q-warp \
        release release-y2qd release-y2q release-y2q-warp \
        test \
        bench \
        clippy \
        fmt fmt-check \
        check \
        image image-dev image-cluster \
        cluster-up cluster-down \
		install-local \
        clean help

# Default
all: build

# ---------------------------------------------------------------------------
# Build -- debug
# ---------------------------------------------------------------------------

build: ## Debug build, all workspace crates
	$(CARGO) build

build-y2qd: ## Debug build -- y2qd only
	$(CARGO) build -p y2qd

build-y2q: ## Debug build -- y2q CLI only
	$(CARGO) build -p y2q-cli

build-y2q-warp: ## Debug build -- y2q-warp only
	$(CARGO) build -p y2q-warp

# ---------------------------------------------------------------------------
# Build -- release
# ---------------------------------------------------------------------------

release: ## Release build, all binaries (filesystem backend)
	$(CARGO) build --release -p y2qd -p y2q-cli -p y2q-warp

release-y2qd: ## Release build -- y2qd only
	$(CARGO) build --release -p y2qd

release-y2q: ## Release build -- y2q CLI only
	$(CARGO) build --release -p y2q-cli

release-y2q-warp: ## Release build -- y2q-warp only
	$(CARGO) build --release -p y2q-warp

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

test: ## Run all tests
	$(CARGO) test

# ---------------------------------------------------------------------------
# Bench
# ---------------------------------------------------------------------------

bench: ## Run criterion benchmarks
	$(CARGO) bench

# ---------------------------------------------------------------------------
# Lint and format
# ---------------------------------------------------------------------------

clippy: ## Clippy, all crates, warnings as errors
	$(CARGO) clippy -- -D warnings

fmt: ## Format all source files
	$(CARGO) fmt

fmt-check: ## Check formatting without modifying files (CI)
	$(CARGO) fmt -- --check

check: fmt-check clippy test ## Full CI gate: fmt-check + clippy + test

# ---------------------------------------------------------------------------
# Container images
# ---------------------------------------------------------------------------

image: ## Build container image -- y2q:latest
	$(PODMAN) build -t $(IMAGE) .

image-dev: ## Build dev image -- y2q:dev (Pyroscope enabled)
	$(PODMAN) build --build-arg PYROSCOPE=1 -t $(IMAGE_DEV) .

image-cluster: ## Build cluster image -- y2q-cluster:latest (shell + y2qd)
	$(PODMAN) build -f deploy/cluster/Dockerfile -t $(IMAGE_CLUSTER) .

cluster-up: ## Build + start the 5-node demo cluster (deploy/cluster)
	cd deploy/cluster && $(COMPOSE) up --build

cluster-down: ## Stop the demo cluster and remove its volumes
	cd deploy/cluster && $(COMPOSE) down -v

# ---------------------------------------------------------------------------
# Install local binaries
# ---------------------------------------------------------------------------

install-local: ## Build release binaries and install to ~/.cargo/bin
	$(CARGO) install --force --path crates/y2q-cli
	$(CARGO) install --force --path crates/y2qd
	$(CARGO) install --force --path crates/y2q-warp

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------

clean: ## Remove build artifacts
	$(CARGO) clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
