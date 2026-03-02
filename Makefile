SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

DEFAULT_GOAL := help

PENT_BIN ?= ./target/release/pent
DOCKER_IMAGE ?= pent-test
REMOTE ?= origin
BRANCH ?= main

.PHONY: help build build-release install test clippy fmt fmt-check check \
	e2e-macos e2e-linux release-check release-tag release-publish-all

help:
	@echo "Pent developer tasks"
	@echo ""
	@echo "Build/Test:"
	@echo "  make build               Build workspace (debug)"
	@echo "  make build-release       Build workspace (release)"
	@echo "  make install             Install local pent to ~/.cargo/bin"
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
	cargo install --path crates/pent --force
	@# Install man pages (generated into man/ by build.rs during cargo build).
	@if [ -d man ]; then \
		if [ -n "$${MANPREFIX:-}" ]; then \
			MAN_DIR="$$MANPREFIX/man1"; \
		elif [ "$$(uname)" = "Darwin" ]; then \
			MAN_DIR="$$(brew --prefix 2>/dev/null)/share/man/man1"; \
			MAN_DIR=$${MAN_DIR:-/usr/local/share/man/man1}; \
		elif [ "$$(id -u)" = "0" ]; then \
			MAN_DIR="/usr/local/share/man/man1"; \
		else \
			MAN_DIR="$$HOME/.local/share/man/man1"; \
		fi; \
		mkdir -p "$$MAN_DIR"; \
		for page in man/*.1; do \
			gzip -c "$$page" > "$$page.gz"; \
			cp "$$page.gz" "$$MAN_DIR/$$(basename $$page.gz)"; \
			rm "$$page.gz"; \
		done; \
		echo "Man pages installed to $$MAN_DIR"; \
	fi
	@PENT_BIN=$$(which pent); \
	echo ""; \
	echo "pent uses veth pairs for network proxying, which requires CAP_NET_ADMIN."; \
	echo "This capability must be set once on the pent binary."; \
	echo "Your password will be used to run setcap on $$PENT_BIN."; \
	echo "Skip this if you only need filesystem sandboxing (proxy mode won't work)."; \
	read -r -p "Enable network proxying? [Y/n] " REPLY; \
	case "$$REPLY" in \
		[nN]*) \
			echo "Skipped. To enable later: sudo setcap cap_net_admin=eip $$PENT_BIN" ;; \
		*) \
			sudo setcap cap_net_admin=eip "$$PENT_BIN" && \
			echo "Successfully set CAP_NET_ADMIN on $$PENT_BIN" ;; \
	esac

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

check: fmt-check clippy test

e2e-macos:
	cargo test --test e2e_macos -- --nocapture

e2e-linux:
	docker build --file e2e/Dockerfile --tag "$(DOCKER_IMAGE)" .
	docker run --rm --cap-add NET_ADMIN "$(DOCKER_IMAGE)"

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

