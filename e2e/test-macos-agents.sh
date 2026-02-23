#!/usr/bin/env bash
# test-macos-agents.sh - e2e smoke-tests halt with each macOS agent config.
#
# For each agent config we validate:
#   1. Filesystem (Seatbelt/SBPL):
#      - workspace write succeeds (true positive)
#      - workspace read succeeds (true positive)
#      - write outside allowed paths is denied (true negative)
#
# Network containment is NOT tested on macOS: transparent proxy enforcement
# is not supported (no per-process network namespaces; DYLD_INSERT_LIBRARIES
# is unreliable across Go binaries and hardened-runtime binaries). See README
# for the full explanation. Use the Linux e2e suite for network tests.
#
# Requirements:
#   - macOS (sandbox-exec available)
#   - halt binary (HALT env var, default: ./target/release/halt)
#   - curl
#
# Usage:
#   e2e/test-macos-agents.sh
#   HALT=/usr/local/bin/halt e2e/test-macos-agents.sh
#
# Exit codes: 0 = all tests passed, 1 = at least one test failed.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)

resolve_halt() {
    if [ -n "${HALT:-}" ]; then
        echo "$HALT"
        return 0
    fi
    if [ -x "${ROOT_DIR}/target/release/halt" ]; then
        echo "${ROOT_DIR}/target/release/halt"
        return 0
    fi
    if [ -x "${ROOT_DIR}/target/debug/halt" ]; then
        echo "${ROOT_DIR}/target/debug/halt"
        return 0
    fi
    if command -v halt >/dev/null 2>&1; then
        command -v halt
        return 0
    fi
    return 1
}

HALT=$(resolve_halt) || {
    echo "error: could not find halt binary. Set HALT=/path/to/halt or build target/release/halt." >&2
    exit 1
}
PASS=0
FAIL=0
LAST_EXIT=0
WORKSPACE=$(mktemp -d)
CONFIGS_TMPDIR=$(mktemp -d)
trap 'rm -rf "$WORKSPACE" "$CONFIGS_TMPDIR"' EXIT

# Generate per-agent config files using the profile system.
# On macOS, dirs::config_dir() resolves to ~/Library/Application Support,
# so the config lands at $HOME/Library/Application Support/halt/halt.toml.
config_file_for() {
    echo "${CONFIGS_TMPDIR}/${1}_home/Library/Application Support/halt/halt.toml"
}

for _agent in claude codex gemini; do
    _agent_home="${CONFIGS_TMPDIR}/${_agent}_home"
    mkdir -p "${_agent_home}"
    HOME="${_agent_home}" "$HALT" config add --global "@${_agent}"
done

green() { printf '\033[0;32m✓ %s\033[0m\n' "$*"; }
red()   { printf '\033[0;31m✗ %s\033[0m\n' "$*" >&2; }

pass() { green "$1"; PASS=$((PASS + 1)); }
fail() { red "$1"; FAIL=$((FAIL + 1)); }

echo "Using HALT: ${HALT}"

run_halt() {
    local stderr_file="$1"
    shift
    set +e
    "$HALT" run --no-config "$@" 2>"$stderr_file"
    LAST_EXIT=$?
    set -e
    return 0
}

assert_exit() {
    local expected="$1"
    local actual="$2"
    local label="$3"
    local stderr_file="$4"
    if [ "$actual" -eq "$expected" ]; then
        pass "$label"
    else
        fail "$label (expected exit $expected, got $actual)"
        cat "$stderr_file" >&2 || true
    fi
}

assert_one_of_exits() {
    local actual="$1"
    local label="$2"
    local stderr_file="$3"
    shift 3
    local expected
    for expected in "$@"; do
        if [ "$actual" -eq "$expected" ]; then
            pass "$label (curl exit $actual)"
            return 0
        fi
    done
    fail "$label (got exit $actual, expected one of: $*)"
    cat "$stderr_file" >&2 || true
    return 1
}

for AGENT in claude codex gemini; do
    CONFIG=$(config_file_for "$AGENT")
    STDERR="/tmp/halt_stderr_${AGENT}_$$"
    SENTINEL="${WORKSPACE}/sentinel-${AGENT}.txt"
    BLOCKED_FILE="${HOME}/halt-test-blocked-${AGENT}.$$"
    echo ""
    echo "── ${AGENT} ─────────────────────────────────────────────────────────"

    run_halt "$STDERR" --config "$CONFIG" -- /bin/sh -c "echo ok > '${SENTINEL}'"
    code=$LAST_EXIT
    if [ "$code" -eq 0 ] && [ -f "$SENTINEL" ]; then
        pass "${AGENT}: workspace write succeeds"
    else
        fail "${AGENT}: workspace write failed (exit $code)"
        cat "$STDERR" >&2 || true
    fi

    run_halt "$STDERR" --config "$CONFIG" -- /bin/cat "$SENTINEL"
    assert_exit 0 "$LAST_EXIT" "${AGENT}: workspace read succeeds" "$STDERR"

    run_halt "$STDERR" --config "$CONFIG" \
        -- /bin/sh -c "echo x > '${BLOCKED_FILE}' 2>/dev/null; exit 0"
    if [ ! -f "$BLOCKED_FILE" ]; then
        pass "${AGENT}: write to \$HOME blocked by sandbox"
    else
        fail "${AGENT}: write to \$HOME was NOT blocked (SBPL not enforced)"
        rm -f "$BLOCKED_FILE"
    fi

    rm -f "$STDERR"
done

echo ""
echo "══════════════════════════════════════════════════════"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ]
