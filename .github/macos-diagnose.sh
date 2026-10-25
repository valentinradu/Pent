#!/bin/bash
# TEMPORARY diagnostic for the macOS backend of pent.
#
# The macOS backend never ran on a Mac. This script reads the real answers
# of the machine to the four open questions:
#
# A. Why does `sandbox-exec -p '(version 1) (allow default)' /bin/true`
#    fail? (MAC-5)
# B. Does a `(with report)` allow rule put a line in the unified log, and
#    what is the exact text of that line? (MAC-6)
# C. Does `(deny process-exec)` after `(allow default)` stop a program?
#    (MAC-4)
# D. How long can a path in a profile be? (MAC-7)
#
# Remove this script and its step in ci.yml when the findings are closed.

set -u
D=/tmp/pent-diag
rm -rf "$D"
mkdir -p "$D/tools"
echo KNOWN >"$D/known.txt"
echo SECRET >"$D/secret.txt"
printf '#!/bin/sh\necho HELLO_FROM_TOOL\n' >"$D/tools/hello"
chmod 755 "$D/tools/hello"

say() { printf '\n========== %s ==========\n' "$1"; }

say "A1 the files of the probe"
ls -l /bin/true /usr/bin/true /bin/false /usr/bin/true 2>&1
say "A2 sandbox-exec -p with /bin/true"
/usr/bin/sandbox-exec -p '(version 1) (allow default)' /bin/true
echo "exit=$?"
say "A3 sandbox-exec -p with /usr/bin/true"
/usr/bin/sandbox-exec -p '(version 1) (allow default)' /usr/bin/true
echo "exit=$?"
say "A4 sandbox-exec -p with /bin/sh -c true"
/usr/bin/sandbox-exec -p '(version 1) (allow default)' /bin/sh -c true
echo "exit=$?"

# ── B. the shape of a report ──────────────────────────────────────────────
cat >"$D/report.sb" <<'EOF'
(version 1)
(allow default)
(allow file-read-data (with report))
(allow file-write* (with report))
(allow process-exec (with report))
EOF
cat >"$D/deny.sb" <<'EOF'
(version 1)
(allow default)
(deny file-read-data (literal "/tmp/pent-diag/secret.txt"))
EOF

say "B1 a read under an allow-with-report profile"
/usr/bin/sandbox-exec -f "$D/report.sb" /bin/cat "$D/known.txt"
echo "exit=$?"
say "B2 a shell that lives one second, with a child that reads"
/usr/bin/sandbox-exec -f "$D/report.sb" /bin/sh -c \
  "sleep 1; cat $D/known.txt; sleep 1; echo MORE >> $D/known.txt; sleep 1"
echo "exit=$?"
say "B3 a denied read"
/usr/bin/sandbox-exec -f "$D/deny.sb" /bin/cat "$D/secret.txt"
echo "exit=$?"
# The reports need a moment to reach the store.
sleep 3

PRED='processImagePath == "/kernel" AND (sender == "Sandbox" OR eventMessage BEGINSWITH "Sandbox: ")'
say "B4 log show with the predicate of pent"
/usr/bin/log show --last 60s --style syslog --predicate "$PRED" 2>&1 | head -60
say "B5 log show with the predicate of pent and --info --debug"
/usr/bin/log show --last 60s --info --debug --style syslog --predicate "$PRED" 2>&1 | head -40
say "B6 log show, every message of the kernel that names Sandbox"
/usr/bin/log show --last 60s --info --debug --style syslog \
  --predicate 'eventMessage CONTAINS "Sandbox"' 2>&1 | head -60
say "B7 the same lines, with the style that log stream uses"
/usr/bin/log show --last 60s --style syslog --predicate \
  'processImagePath == "/kernel"' 2>&1 | grep -c .
say "B8 ps -A -o pid=,ppid=,stat=,comm= (the source of the name check)"
/bin/ps -A -o pid=,ppid=,stat=,comm= | head -5

# ── C. process-exec ───────────────────────────────────────────────────────
cat >"$D/exec.sb" <<EOF
(version 1)
(allow default)
(deny process-exec)
(allow process-exec (subpath "/bin"))
(allow process-exec (subpath "/usr/bin"))
(allow process-exec (subpath "/usr/lib"))
(allow process-exec (subpath "/System"))
EOF
say "C1 deny process-exec, allow /bin: a program in /bin"
/usr/bin/sandbox-exec -f "$D/exec.sb" /bin/sh -c 'echo SHELL_RAN; /bin/echo ECHO_RAN'
echo "exit=$?"
say "C2 the same profile: a program outside the allowed paths"
/usr/bin/sandbox-exec -f "$D/exec.sb" /bin/sh -c "$D/tools/hello || echo TOOL_DENIED"
echo "exit=$?"
say "C3 deny process-exec without any allow: nothing may run"
/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny process-exec)' /bin/sh -c 'echo SHELL_RAN'
echo "exit=$?"
say "C4 deny process-exec* instead of process-exec"
/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny process-exec*)' /bin/sh -c 'echo SHELL_RAN'
echo "exit=$?"

# ── D. the longest path in a profile ──────────────────────────────────────
say "D1 the longest string that a literal accepts"
for n in 64 128 255 256 511 512 1023 1024 2047 2048 4096; do
  p="/$(/usr/bin/printf 'x%.0s' $(seq 1 "$n"))"
  printf '(version 1)\n(allow default)\n(allow file-read-data (literal "%s"))\n' "$p" >"$D/len.sb"
  if /usr/bin/sandbox-exec -f "$D/len.sb" /usr/bin/true 2>"$D/len.err"; then
    echo "length $n: ok"
  else
    echo "length $n: refused: $(head -2 "$D/len.err" | tr '\n' ' ')"
  fi
done
say "D2 (literal \"/\") alone"
/usr/bin/sandbox-exec -p '(version 1)(allow default)(allow file-read-data (literal "/"))' /usr/bin/true
echo "exit=$?"

say "the diagnostic ends"
exit 0
