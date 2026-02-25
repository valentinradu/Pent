# Halt Linux e2e test image
#
# Single-stage: builds halt from source and runs the e2e integration tests in
# the same environment.  The Rust toolchain is kept because
# `cargo test --test e2e_linux` compiles and links the test binary at run time.
#
# Build:
#   docker build -t halt-test -f e2e/Dockerfile .
#
# Run e2e tests:
#   docker run --rm --cap-add NET_ADMIN halt-test
#
# NET_ADMIN is required for halt's Linux network-namespace isolation
# (ProxyOnly / LocalhostOnly modes call unshare(CLONE_NEWNET) + ip-link).

FROM rust:1.85-slim-bookworm

# iproute2       — ip rule / ip netns / ip link commands used by halt
# curl           — network tests (proxy-aware HTTP client)
# bash           — filesystem tests (sandboxed shell for write/read probes)
# ca-certificates — TLS roots for HTTPS in curl tests
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    curl \
    bash \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /halt
COPY . .

# Pre-build so the CMD step goes straight to test execution.
RUN cargo build --workspace

# Default: run the Linux e2e integration tests.
CMD ["cargo", "test", "--test", "e2e_linux", "--", "--nocapture"]
