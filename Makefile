CARGO  ?= cargo
PODMAN ?= podman

IMAGE           ?= y2q:latest
IMAGE_URING     ?= y2q:latest-uring
IMAGE_DEV       ?= y2q:dev
IMAGE_DEV_URING ?= y2q:dev-uring

.PHONY: all \
        build build-y2qd build-y2q build-y2q-warp \
        release release-y2qd release-y2q release-y2q-warp release-uring \
        test test-uring \
        bench \
        clippy clippy-uring \
        fmt fmt-check \
        check \
        image image-uring images \
        image-dev image-dev-uring images-dev \
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

release-uring: ## Release build -- y2qd with io_uring backend (Linux, kernel >= 5.6)
	$(CARGO) build --release -p y2qd --features uring

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

test: ## Run all tests (filesystem backend)
	$(CARGO) test

test-uring: ## Run all tests with io_uring feature enabled
	$(CARGO) test --features y2qd/uring

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

clippy-uring: ## Clippy with io_uring feature, warnings as errors
	$(CARGO) clippy --features y2qd/uring -- -D warnings

fmt: ## Format all source files
	$(CARGO) fmt

fmt-check: ## Check formatting without modifying files (CI)
	$(CARGO) fmt -- --check

check: fmt-check clippy test ## Full CI gate: fmt-check + clippy + test

# ---------------------------------------------------------------------------
# Container images
# ---------------------------------------------------------------------------

image: ## Build container image -- y2q:latest (filesystem backend)
	$(PODMAN) build -t $(IMAGE) .

image-uring: ## Build container image -- y2q:latest-uring (io_uring backend)
	$(PODMAN) build --build-arg URING=1 -t $(IMAGE_URING) .

images: image image-uring ## Build both container image variants

image-dev: ## Build dev image -- y2q:dev (filesystem + Pyroscope)
	$(PODMAN) build --build-arg PYROSCOPE=1 -t $(IMAGE_DEV) .

image-dev-uring: ## Build dev image -- y2q:dev-uring (io_uring + Pyroscope)
	$(PODMAN) build --build-arg URING=1 --build-arg PYROSCOPE=1 -t $(IMAGE_DEV_URING) .

images-dev: image-dev image-dev-uring ## Build both dev image variants (Pyroscope enabled)

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
