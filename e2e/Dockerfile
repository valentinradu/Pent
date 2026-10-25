# Pent Linux e2e test image
#
# Single-stage: builds pent from source and runs the integration and e2e
# tests in the same environment. The Rust toolchain stays in the image,
# because `cargo test` compiles and links the test binaries at run time.
#
# Build:
#   docker build -t pent-test -f e2e/Dockerfile .
#
# Run the tests:
#   docker run --rm --security-opt seccomp=unconfined \
#     --security-opt apparmor=unconfined \
#     --tmpfs /tmp:exec,mode=1777 pent-test
#
# Pent needs no capability. It needs unprivileged user namespaces, and the
# default seccomp and AppArmor profiles of Docker block unshare(2). Pent
# puts the upper layers of its overlays in /tmp. The kernel does not accept
# an upper layer on overlayfs (the root filesystem of the container), thus
# /tmp must be a tmpfs.
#
# The tests run as a normal user, not as root: root can write to files that
# the tests expect to be protected, and `sudo` does nothing for root.

# Cargo 1.91 or later: .cargo/config.toml sets build.build-dir.
FROM rust:1.91-slim-bookworm

# curl            the network tests (a proxy-aware HTTP client)
# ca-certificates the TLS roots for HTTPS in the curl tests
# sudo            the watch guard test (sudo must not get privileges)
# The base image has sh, getent (libc-bin) and the coreutils.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    sudo \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home tester
USER tester
ENV CARGO_HOME=/home/tester/.cargo

WORKDIR /home/tester/pent
COPY --chown=tester:tester . .

# Build before the CMD step, so that the CMD step only runs the tests.
RUN cargo build --workspace --tests

# The integration and e2e tests of the pent binary, also the tests that
# need the internet (they skip when the internet is not available). The
# tests run in parallel with the default number of threads.
CMD ["cargo", "test", "-p", "pent", "--no-fail-fast", \
     "--test", "e2e_linux", "--test", "integration_test", "--test", "profile_test", \
     "--", "--include-ignored"]
