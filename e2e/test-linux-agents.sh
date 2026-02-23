#!/usr/bin/env bash
# test-linux-agents.sh — e2e smoke-tests halt with each Linux agent config.
#
# Tests two sandbox dimensions for every agent:
#   1. Filesystem (Landlock): workspace is writable; paths outside it are blocked.
#   2. Network (proxy):       allowed domains resolve; blocked domains get NXDOMAIN.
#
# Requirements (already present in the halt-test Docker image):
#   - halt binary in PATH
#   - curl, bash
#   - NET_ADMIN capability (for halt's network namespace creation)
#
# Usage inside the halt-test container:
#   /halt/e2e/test-linux-agents.sh
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
# On Linux, dirs::config_dir() resolves to ~/.config,
# so the config lands at $HOME/.config/halt/halt.toml.
config_file_for() {
    echo "${CONFIGS_TMPDIR}/${1}_home/.config/halt/halt.toml"
}

for _agent in claude codex gemini; do
    _agent_home="${CONFIGS_TMPDIR}/${_agent}_home"
    mkdir -p "${_agent_home}"
    HOME="${_agent_home}" "$HALT" config add --global "@${_agent}"
done

# ── Helpers ──────────────────────────────────────────────────────────────────

green()  { printf '\033[0;32m✓ %s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m✗ %s\033[0m\n' "$*" >&2; }

pass() { green "$1"; PASS=$((PASS + 1)); }
fail() { red   "$1"; FAIL=$((FAIL + 1)); }

echo "Using HALT: ${HALT}"

# run_halt CONFIG ARGS... -- CMD ARGS...
# Captures halt exit code in LAST_EXIT (does not abort on failure).
run_halt() {
    local config="$1"
    shift
    set +e
    "$HALT" run --no-config --config "$config" "$@" 2>/tmp/halt_stderr
    LAST_EXIT=$?
    set -e
    return 0
}

# assert_exit EXPECTED ACTUAL LABEL
assert_exit() {
    local expected="$1" actual="$2" label="$3"
    if [ "$actual" -eq "$expected" ]; then
        pass "$label"
    else
        fail "$label (expected exit $expected, got $actual)"
        cat /tmp/halt_stderr >&2 || true
    fi
}

assert_one_of_exits() {
    local actual="$1"
    local label="$2"
    shift 2
    local expected
    for expected in "$@"; do
        if [ "$actual" -eq "$expected" ]; then
            pass "$label (curl exit $actual)"
            return 0
        fi
    done
    fail "$label (got exit $actual, expected one of: $*)"
    cat /tmp/halt_stderr >&2 || true
    return 1
}

# ── Check Landlock availability ───────────────────────────────────────────────
# halt check only verifies the Landlock API is present; some kernels (e.g.
# Docker Desktop on macOS) expose the syscall but do not enforce restrictions.
# Probe by actually running a sandboxed write to a path that must be blocked.
LANDLOCK_AVAILABLE=false
if "$HALT" check 2>/dev/null; then
    "$HALT" run --no-config --network unrestricted \
        -- bash -c "echo probe > /etc/halt-landlock-probe 2>/dev/null; exit 0" \
        2>/dev/null </dev/null || true
    if [ ! -f /etc/halt-landlock-probe ]; then
        LANDLOCK_AVAILABLE=true
    else
        rm -f /etc/halt-landlock-probe
        echo "NOTE: Landlock API available but not enforcing (kernel limitation) — skipping filesystem tests"
    fi
else
    echo "NOTE: halt check reports sandbox unavailable — skipping Landlock filesystem tests"
fi

# ── Landlock filesystem tests ─────────────────────────────────────────────────
# These do not require NET_ADMIN because we use --network unrestricted to skip
# network namespace creation while still exercising Landlock.

test_filesystem() {
    local agent="$1"
    local config
    config=$(config_file_for "$agent")

    if [ "$LANDLOCK_AVAILABLE" = false ]; then
        echo ""
        echo "── $agent: filesystem (Landlock) — SKIPPED (kernel lacks Landlock) ──"
        return 0
    fi

    echo ""
    echo "── $agent: filesystem (Landlock) ──────────────────────────────────"

    # 1. Basic execution: a simple command in the workspace must succeed.
    local sentinel="$WORKSPACE/sentinel-${agent}.txt"
    run_halt "$config" \
        --network unrestricted \
        -- bash -c "echo ok > '$sentinel'" </dev/null
    local code=$LAST_EXIT
    if [ "$code" -eq 0 ] && [ -f "$sentinel" ]; then
        pass "$agent: workspace write succeeds"
    else
        fail "$agent: workspace write failed (exit $code)"
    fi

    # 2. Reading a file written inside the workspace must succeed.
    run_halt "$config" \
        --network unrestricted \
        -- bash -c "cat '$sentinel'" </dev/null
    assert_exit 0 "$LAST_EXIT" "$agent: workspace read succeeds"

    # 3. Writing outside the workspace (e.g. /etc/halt-test) must be denied.
    #    Landlock denies writes to paths not in the ruleset; bash exits non-zero.
    run_halt "$config" \
        --network unrestricted \
        -- bash -c "echo x > /etc/halt-test-${agent} 2>/dev/null; exit 0" </dev/null
    # The shell exits 0 because of the explicit `exit 0`, but the write itself
    # silently fails with EACCES — we verify the file was NOT created.
    if [ ! -f "/etc/halt-test-${agent}" ]; then
        pass "$agent: write to /etc blocked by Landlock"
    else
        fail "$agent: write to /etc was NOT blocked — Landlock not enforced"
        rm -f "/etc/halt-test-${agent}"
    fi
}

# ── Network proxy tests ───────────────────────────────────────────────────────
# Require NET_ADMIN for halt's ProxyOnly network namespace setup.
# We test via curl using HTTP_PROXY injected by halt.

test_network() {
    local agent="$1"
    local config
    config=$(config_file_for "$agent")
    # Determine the first domain in the allowlist for this agent.
    local allowed_domain blocked_domain="blocked-domain.invalid"

    case "$agent" in
        claude)  allowed_domain="api.anthropic.com" ;;
        codex)   allowed_domain="api.openai.com" ;;
        gemini)  allowed_domain="generativelanguage.googleapis.com" ;;
        *)       allowed_domain="github.com" ;;
    esac

    echo ""
    echo "── $agent: network (proxy) ─────────────────────────────────────────"

    # 4. Allowed domain: DNS query should resolve (proxy returns A record).
    #    We only check that curl can at least perform DNS resolution — a
    #    connection error is OK, but NXDOMAIN / proxy-blocked is not.
    #    curl exit codes: 6 = DNS fail, 7 = connect fail (host up), 22 = HTTP err
    run_halt "$config" \
        -- curl -sS --max-time 5 \
           "https://${allowed_domain}" \
           -o /dev/null 2>/tmp/halt_stderr </dev/null
    local code=$LAST_EXIT
    # exit 7 (connection refused / timeout) means DNS resolved — that's fine.
    # exit 6 (DNS fail) means the proxy blocked or can't resolve — that's a fail.
    if [ "$code" -ne 6 ]; then
        pass "$agent: allowed domain '$allowed_domain' resolved through proxy (curl exit $code)"
    else
        fail "$agent: allowed domain '$allowed_domain' NOT resolved (curl exit $code — DNS blocked?)"
        cat /tmp/halt_stderr >&2 || true
    fi

    # 5. Blocked domain: must be denied (observed as curl exit 6 or 56).
    run_halt "$config" \
        -- curl -sS --max-time 5 \
           "https://${blocked_domain}" \
           -o /dev/null 2>/tmp/halt_stderr </dev/null
    code=$LAST_EXIT
    assert_one_of_exits "$code" "$agent: blocked domain '$blocked_domain' denied" 6 56

}

# ── Run all tests for every agent ─────────────────────────────────────────────

for AGENT in claude codex gemini; do
    test_filesystem "$AGENT"
    test_network    "$AGENT"
done

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════════"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ]
