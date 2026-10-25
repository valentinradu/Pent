# Pent Linux e2e test image
#
# Single-stage: builds pent from source and runs the e2e integration tests in
# the same environment.  The Rust toolchain is kept because
# `cargo test --test e2e_linux` compiles and links the test binary at run time.
#
# Build:
#   docker build -t pent-test -f e2e/Dockerfile .
#
# Run e2e tests:
#   docker run --rm --security-opt seccomp=unconfined \
#     --security-opt apparmor=unconfined pent-test
#
# Pent needs no capability. It needs unprivileged user namespaces, and the
# default seccomp and AppArmor profiles of Docker block unshare(2).

FROM rust:1.87-slim-bookworm

# curl           — network tests (proxy-aware HTTP client)
# bash           — filesystem tests (sandboxed shell for write/read probes)
# ca-certificates — TLS roots for HTTPS in curl tests
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    bash \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /pent
COPY . .

# Pre-build so the CMD step goes straight to test execution.
RUN cargo build --workspace

# Default: run the Linux e2e integration tests.
CMD ["cargo", "test", "--test", "e2e_linux", "--", "--nocapture"]
