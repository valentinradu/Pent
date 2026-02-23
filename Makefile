SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

DEFAULT_GOAL := help

HALT_BIN ?= ./target/release/halt
DOCKER_IMAGE ?= halt-test
REMOTE ?= origin
BRANCH ?= main

.PHONY: help build build-release install test clippy fmt fmt-check check \
	e2e-macos e2e-linux release-check release-tag release-publish-all

help:
	@echo "Halt developer tasks"
	@echo ""
	@echo "Build/Test:"
	@echo "  make build               Build workspace (debug)"
	@echo "  make build-release       Build workspace (release)"
	@echo "  make install             Install local halt to ~/.cargo/bin"
	@echo "  make test                Run workspace tests"
	@echo "  make clippy              Run clippy with -D warnings"
	@echo "  make fmt                Format all Rust code"
	@echo "  make fmt-check           Verify Rust formatting"
	@echo "  make check               fmt-check + clippy + test"
	@echo ""
	@echo "E2E:"
	@echo "  make e2e-macos           Run macOS e2e agent tests"
	@echo "  make e2e-linux           Run Linux e2e agent tests in Docker"
	@echo ""
	@echo "Release:"
	@echo "  make release-check VERSION=X.Y.Z"
	@echo "  make release-tag VERSION=X.Y.Z"
	@echo "  make release-publish-all VERSION=X.Y.Z"
	@echo ""
	@echo "Notes:"
	@echo "  - release-tag pushes tag vX.Y.Z to $(REMOTE), triggering release workflow."
	@echo "  - release workflow fans out binaries, AUR/APT publish, and Homebrew tap dispatch."

build:
	cargo build --workspace

build-release:
	cargo build --workspace --release

install:
	cargo install --path crates/halt --force

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

check: fmt-check clippy test

e2e-macos: build-release
	HALT="$(HALT_BIN)" bash e2e/test-macos-agents.sh

e2e-linux:
	docker build --file e2e/Dockerfile --tag "$(DOCKER_IMAGE)" .
	docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN "$(DOCKER_IMAGE)" /halt/e2e/test-linux-agents.sh

release-check:
	@if [[ -z "$${VERSION:-}" ]]; then \
		echo "error: VERSION is required (example: make release-tag VERSION=0.1.0)" >&2; \
		exit 1; \
	fi
	@if ! [[ "$${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$$ ]]; then \
		echo "error: VERSION must match X.Y.Z (got '$${VERSION}')" >&2; \
		exit 1; \
	fi
	@if [[ "$$(git rev-parse --abbrev-ref HEAD)" != "$(BRANCH)" ]]; then \
		echo "error: must be on branch '$(BRANCH)' to release" >&2; \
		exit 1; \
	fi
	@if [[ -n "$$(git status --porcelain)" ]]; then \
		echo "error: working tree is not clean" >&2; \
		git status --short; \
		exit 1; \
	fi
	@if git rev-parse --verify --quiet "refs/tags/v$${VERSION}" >/dev/null; then \
		echo "error: local tag v$${VERSION} already exists" >&2; \
		exit 1; \
	fi
	@if git ls-remote --exit-code --tags "$(REMOTE)" "refs/tags/v$${VERSION}" >/dev/null 2>&1; then \
		echo "error: remote tag v$${VERSION} already exists on $(REMOTE)" >&2; \
		exit 1; \
	fi
	@echo "release-check passed for v$${VERSION}"

release-tag: release-check
	git fetch "$(REMOTE)"
	git tag "v$${VERSION}"
	git push "$(REMOTE)" "v$${VERSION}"
	@echo "pushed tag v$${VERSION} to $(REMOTE)"

release-publish-all: release-tag

