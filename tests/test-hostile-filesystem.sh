#!/bin/sh
# Readiness test 4 of 6: survive a real client filesystem.
#
# THE QUESTION THIS ANSWERS
# "What happens when it meets something unusual on our server?" Client estates
# are not tidy. Application directories carry filenames with spaces and
# apostrophes, vendors leave broken symlinks, backup processes create symlink
# loops, and permissions are inconsistent. A tool that crashes, hangs, or -
# worst of all - silently skips a tree when it meets one of these is not fit to
# run unattended on a production host.
#
# The failure mode that matters most here is not a crash. A crash is visible and
# someone investigates. The dangerous outcome is the one this project has hit
# before: the scan silently covers nothing, the report prints the path under
# "Paths scanned" with no findings beneath it, and that reads as a clean result
# for a directory that was never examined.
#
# WHAT IS PLANTED
# Everything below is created inside a temporary directory and removed on exit;
# nothing outside it is touched. The hostile cases are:
#
#   - spaces, apostrophes and double quotes in names
#   - a leading dash, which many commands parse as an option
#   - shell glob metacharacters in a name
#   - non-ASCII (UTF-8) names
#   - a symlink loop, which makes a naive recursive walk run forever
#   - a broken symlink pointing nowhere
#   - a directory with no read permission
#   - deep nesting
#   - a world-writable file and a world-writable directory with no sticky bit,
#     both of which the scan must actually find
#   - a SetUID file, which the scan must actually find
#
# The test asserts both that the collection completes and that it genuinely
# examined the tree - by requiring it to FIND the planted world-writable and
# SetUID files. A run that completed but found nothing would pass a
# "did not crash" test while proving the opposite of what is wanted.
#
# Usage: sudo sh tests/test-hostile-filesystem.sh
# Exit:  0 = survived and examined everything, 1 = otherwise

set -u

REPO_ROOT=`CDPATH= cd -- "\`dirname -- "$0"\`/.." && pwd`
COLLECTOR="$REPO_ROOT/linux-unix-evidence-gathering-script.sh"

if [ ! -f "$COLLECTOR" ]; then
    printf 'FAIL: collector not found at %s\n' "$COLLECTOR" >&2
    exit 1
fi
if [ "`id -u`" != "0" ]; then
    printf 'FAIL: must run as root (use: sudo sh %s)\n' "$0" >&2
    exit 1
fi

WORK=`mktemp -d`
cleanup() {
    # The unreadable directory must be made readable again or rm cannot descend.
    chmod -R u+rwX "$WORK" 2>/dev/null || :
    rm -rf "$WORK" 2>/dev/null || :
}
trap cleanup EXIT INT TERM

failures=0
checks=0
pass() { printf 'ok        %s\n' "$1"; }
fail() { printf 'NOT OK    %s\n' "$1"; failures=`expr $failures + 1`; }

APP="$WORK/Finance App"      # deliberately contains a space
mkdir -p "$APP"

printf '== planting a hostile application tree ==\n'

mkdir -p "$APP/sub dir with spaces"
printf 'x\n' > "$APP/sub dir with spaces/config file.conf"

printf 'x\n' > "$APP/o'brien's report.txt"
printf 'x\n' > "$APP/say \"hello\".txt"
printf 'x\n' > "$APP/-leading-dash.txt"
printf 'x\n' > "$APP/glob[chars]*.txt"
printf 'x\n' > "$APP/rapport-financiér-café.txt"
printf 'x\n' > "$APP/tab	inside.txt"

# Symlink loop: a naive recursive walk never terminates on this.
mkdir -p "$APP/loopdir"
ln -s "$APP/loopdir" "$APP/loopdir/self" 2>/dev/null || :
ln -s ../loopdir "$APP/loopdir/relative_self" 2>/dev/null || :

ln -s /nonexistent/target "$APP/broken_symlink" 2>/dev/null || :

# Unreadable directory: traversal must degrade, not abort.
mkdir -p "$APP/forbidden"
printf 'secret\n' > "$APP/forbidden/inside.txt"
chmod 000 "$APP/forbidden"

# Deep nesting.
deep="$APP/deep"; mkdir -p "$deep"
i=0; while [ "$i" -lt 25 ]; do deep="$deep/level$i"; i=`expr $i + 1`; done
mkdir -p "$deep"; printf 'bottom\n' > "$deep/bottom.txt"

# The findings the scan MUST report, to prove it really walked the tree.
printf 'world writable\n' > "$APP/world writable file.sh"
chmod 0666 "$APP/world writable file.sh"
mkdir -p "$APP/wwdir no sticky"
chmod 0777 "$APP/wwdir no sticky"
printf '#!/bin/sh\n' > "$APP/setuid binary"
chmod 4755 "$APP/setuid binary"

printf '   planted %s entries under: %s\n\n' \
    "`find "$APP" -mindepth 1 2>/dev/null | wc -l | tr -d ' '`" "$APP"

printf '== running the collection against it ==\n'
OUT="$WORK/out"
mkdir -p "$OUT"

# A hang is a failure. The collection must not run away on the symlink loop.
start=`date +%s`
timeout 600 sh "$COLLECTOR" --output-dir "$OUT" --app-dir "$APP" </dev/null >"$WORK/run.log" 2>&1
rc=$?
elapsed=`expr \`date +%s\` - $start`
printf '   exit=%s elapsed=%ss\n\n' "$rc" "$elapsed"

checks=`expr $checks + 1`
if [ "$rc" -eq 124 ]; then
    fail "the collection HUNG (timed out after 600s) - likely the symlink loop"
    exit 1
elif [ "$rc" -eq 0 ]; then
    pass "completed without hanging or crashing (${elapsed}s)"
else
    fail "exited non-zero ($rc)"
    tail -15 "$WORK/run.log" | sed 's/^/            /'
fi

E="$OUT/SOX-ITGC-AUDIT-LINUX-UNIX"
REPORT="$E/report/SOX-ITGC-AUDIT-REPORT.txt"

checks=`expr $checks + 1`
if [ -s "$REPORT" ] && grep -q 'Execution Summary' "$REPORT" 2>/dev/null; then
    pass "produced a complete report"
else
    fail "the report is missing or truncated"
fi

printf '\n== the tree was genuinely examined, not merely survived ==\n'

# This is the assertion that matters. A path containing a space was once
# word-split into two nonexistent paths, so the scan examined nothing while the
# report still listed the intact path under "Paths scanned" - a clean result for
# a directory never looked at.
checks=`expr $checks + 1`
if grep -Fq 'world writable file.sh' "$REPORT" 2>/dev/null; then
    pass "found the world-writable file inside a path containing spaces"
else
    fail "did NOT find the planted world-writable file - the tree with spaces in"
    printf '            its name was not actually scanned\n'
fi

checks=`expr $checks + 1`
if grep -Fq 'wwdir no sticky' "$REPORT" 2>/dev/null; then
    pass "found the world-writable directory with no sticky bit"
else
    fail "did NOT find the planted world-writable directory"
fi

checks=`expr $checks + 1`
if grep -Fq 'setuid binary' "$REPORT" 2>/dev/null; then
    pass "found the SetUID file"
else
    fail "did NOT find the planted SetUID file"
fi

checks=`expr $checks + 1`
if grep -Fq "o'brien" "$REPORT" 2>/dev/null && grep -Fq 'rapport-financi' "$REPORT" 2>/dev/null; then
    pass "listed filenames containing apostrophes and non-ASCII characters"
else
    fail "the directory listing lost files with apostrophes or non-ASCII names"
fi

checks=`expr $checks + 1`
if grep -Fq 'leading-dash' "$REPORT" 2>/dev/null; then
    pass "listed a filename beginning with a dash"
else
    fail "a filename beginning with a dash was lost from the listing"
fi

checks=`expr $checks + 1`
if grep -Fq 'bottom.txt' "$REPORT" 2>/dev/null; then
    pass "descended the full depth of a deeply nested tree"
else
    fail "did not reach the bottom of the deeply nested tree"
fi

printf '\n== the mode-000 directory was traversed, because root can ==\n'
# Worth being precise about rather than asserting something vaguer that would
# pass either way. The planted directory is mode 000, but this collection runs
# as root, and root holds CAP_DAC_OVERRIDE - it can read a directory whose
# permissions forbid everyone. So on this run there is NO evidence gap, and the
# correct assertion is that the contents WERE reached.
#
# This matters for the audit: it means a restrictive permission on the client's
# server does not silently shrink the population that Section 10 and 11 examine.
# The complementary case - a path that even root cannot read, such as one on an
# unresponsive mount - is a genuine gap and is covered by the collection log's
# "exists but could not be read" WARN, exercised in test-degraded-environment.
checks=`expr $checks + 1`
LOG="$E/metadata/COLLECTION-LOG.txt"
if grep -Fq 'inside.txt' "$REPORT" 2>/dev/null; then
    pass "listed the contents of a mode-000 directory (root traversal works, so"
    printf '          restrictive client permissions do not silently shrink the scan)\n'
else
    fail "did not reach inside a mode-000 directory even as root; the scanned"
    printf '            population would be silently smaller than the report implies\n'
fi

checks=`expr $checks + 1`
if [ -s "$LOG" ]; then
    pass "collection log produced (verdict: `sed -n 's/^FINAL_RESULT: //p' "$LOG" | tail -1`)"
else
    fail "no collection log was produced"
fi

printf '\n== nothing planted was modified by the collection ==\n'
checks=`expr $checks + 1`
if [ "`stat -c '%a' "$APP/world writable file.sh" 2>/dev/null`" = "666" ] &&
   [ "`stat -c '%a' "$APP/setuid binary" 2>/dev/null`" = "4755" ] &&
   [ "`stat -c '%a' "$APP/forbidden" 2>/dev/null`" = "0" ]; then
    pass "planted permissions are unchanged - the scan observed without altering"
else
    fail "the collection altered permissions on the planted tree"
    printf '            ww=%s setuid=%s forbidden=%s\n' \
        "`stat -c '%a' "$APP/world writable file.sh" 2>/dev/null`" \
        "`stat -c '%a' "$APP/setuid binary" 2>/dev/null`" \
        "`stat -c '%a' "$APP/forbidden" 2>/dev/null`"
fi

printf '\n-----------------------------------------------\n'
printf 'checks: %s   failures: %s\n' "$checks" "$failures"
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS - survived a hostile filesystem and examined all of it\n'
exit 0
