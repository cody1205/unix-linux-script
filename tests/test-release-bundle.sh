#!/bin/sh
# Test the release builder.
#
# WHY THIS EXISTS
# tools/make-release.sh produces the artifact that is actually sent to a client.
# Everything else in this repository is tested; the thing on the critical path to
# the engagement was not. If the builder silently produces a bundle whose script
# is not executable, or whose printed checksum does not match the file, nobody
# finds out until a client is on the phone.
#
# The properties asserted here are the ones the delivery model depends on:
#
#   1. the bundle contains exactly the two files a client should receive
#   2. the collector extracts EXECUTABLE - the entire reason for bundling
#   3. the instructions extract non-executable, because they are not a program
#   4. the extracted collector still parses
#   5. the printed checksums match the actual files, so the value emailed to the
#      client is the value they can verify
#   6. modes do not depend on the operator's umask
#   7. the guards refuse to build, AND name the right cause
#
# Point 7 matters more than it looks. The CRLF guard originally sat after the
# parse check, and because carriage returns also break "sh -n" a CRLF-damaged
# file was reported as "does not parse" - true, but it sends the operator hunting
# for a syntax error when the repair is one tr command. A guard that fires with
# the wrong diagnosis is only half a guard, so the message is asserted too.
#
# No root required: the builder only reads the repository and writes a tarball.
#
# Usage: sh tests/test-release-bundle.sh

set -u

REPO_ROOT=`CDPATH= cd -- "\`dirname -- "$0"\`/.." && pwd`
BUILDER="$REPO_ROOT/tools/make-release.sh"
COLLECTOR="linux-unix-evidence-gathering-script.sh"
INSTRUCTIONS="CLIENT-INSTRUCTIONS.md"

if [ ! -f "$BUILDER" ]; then
    printf 'FAIL: builder not found at %s\n' "$BUILDER" >&2
    exit 1
fi

WORK=`mktemp -d`
trap 'rm -rf "$WORK"' EXIT INT TERM

failures=0
checks=0
pass() { printf 'ok        %s\n' "$1"; }
fail() { printf 'NOT OK    %s\n' "$1"; failures=`expr $failures + 1`; }

printf '== building a release from the current tree ==\n'
OUT="$WORK/dist"
if ! sh "$BUILDER" vTEST "$OUT" > "$WORK/build.log" 2>&1; then
    printf 'FAIL: the builder exited non-zero on a clean tree\n' >&2
    sed 's/^/  /' "$WORK/build.log" >&2
    exit 1
fi
BUNDLE="$OUT/sox-itgc-collector-vTEST.tar.gz"
if [ ! -f "$BUNDLE" ]; then
    printf 'FAIL: no bundle at %s\n' "$BUNDLE" >&2
    exit 1
fi
printf '   %s\n\n' "$BUNDLE"

printf '== 1. the bundle contains exactly the two client-facing files ==\n'
checks=`expr $checks + 1`
tar tzf "$BUNDLE" 2>/dev/null | sed 's|^\./||' | grep -v '^$' | sort > "$WORK/contents.txt"
printf '%s\n%s\n' "$COLLECTOR" "$INSTRUCTIONS" | sort > "$WORK/expected.txt"
if diff "$WORK/contents.txt" "$WORK/expected.txt" >/dev/null 2>&1; then
    pass "contains $COLLECTOR and $INSTRUCTIONS, and nothing else"
else
    fail "bundle contents are not what a client should receive:"
    diff "$WORK/expected.txt" "$WORK/contents.txt" | sed 's/^/            /'
fi

printf '\n== 2. the collector extracts EXECUTABLE ==\n'
# The entire justification for shipping a tarball. If this regresses, the client
# is told to run ./script and gets "permission denied" as their first experience
# of the engagement.
checks=`expr $checks + 1`
EX="$WORK/extract"
mkdir -p "$EX"
( cd "$EX" && tar xzf "$BUNDLE" ) 2>/dev/null
if [ -x "$EX/$COLLECTOR" ]; then
    pass "extracted as executable (mode `stat -c '%a' "$EX/$COLLECTOR" 2>/dev/null`), so ./$COLLECTOR works with no chmod"
else
    fail "the collector is NOT executable after extraction - bundling achieved nothing"
fi

printf '\n== 3. the instructions extract NOT executable ==\n'
checks=`expr $checks + 1`
if [ -f "$EX/$INSTRUCTIONS" ] && [ ! -x "$EX/$INSTRUCTIONS" ]; then
    pass "instructions are `stat -c '%a' "$EX/$INSTRUCTIONS" 2>/dev/null`, correct for a document"
else
    fail "the instructions file is missing or wrongly marked executable"
fi

printf '\n== 4. the extracted collector still parses ==\n'
checks=`expr $checks + 1`
if sh -n "$EX/$COLLECTOR" 2>/dev/null; then
    pass "the delivered script parses under sh"
else
    fail "the DELIVERED script does not parse - the bundle would fail on the client host"
fi

printf '\n== 5. the printed checksums match the actual files ==\n'
# The client verifies the bundle against a value we email them. If the builder
# prints something other than the real checksum, that check fails on their host
# and the engagement stalls on a false alarm.
checks=`expr $checks + 1`
_printed_bundle=`grep -A1 'SHA-256 of the bundle' "$WORK/build.log" | tail -1 | tr -d ' '`
_actual_bundle=`sha256sum "$BUNDLE" 2>/dev/null | awk '{print $1}'`
if [ -n "$_actual_bundle" ] && [ "$_printed_bundle" = "$_actual_bundle" ]; then
    pass "printed bundle checksum matches the bundle"
else
    fail "bundle checksum mismatch: printed=$_printed_bundle actual=$_actual_bundle"
fi

checks=`expr $checks + 1`
_printed_script=`grep -A1 'SHA-256 of the collector inside it' "$WORK/build.log" | tail -1 | tr -d ' '`
_actual_script=`sha256sum "$REPO_ROOT/$COLLECTOR" 2>/dev/null | awk '{print $1}'`
if [ -n "$_actual_script" ] && [ "$_printed_script" = "$_actual_script" ]; then
    pass "printed collector checksum matches the collector"
    printf '          (the report records this same value as "Collector Script\n'
    printf '          Checksum", which is what ties a returned package to a release;\n'
    printf '          that tie-back is asserted in test-evidence-chain.sh)\n'
else
    fail "collector checksum mismatch: printed=$_printed_script actual=$_actual_script"
fi

printf '\n== 6. modes do not depend on the operator umask ==\n'
# The builder chmods explicitly rather than inheriting. Without that, whoever
# happens to run the release step decides what the client receives.
checks=`expr $checks + 1`
OUT2="$WORK/dist-umask"
( umask 077; sh "$BUILDER" vUMASK "$OUT2" >/dev/null 2>&1 )
EX2="$WORK/extract-umask"
mkdir -p "$EX2"
( cd "$EX2" && tar xzf "$OUT2/sox-itgc-collector-vUMASK.tar.gz" ) 2>/dev/null
if [ -x "$EX2/$COLLECTOR" ]; then
    pass "built under umask 077 and the collector is still executable"
else
    fail "a restrictive umask changed what the client would receive"
fi

printf '\n== 7. the guards refuse to build, and name the right cause ==\n'
# Run against a COPY of the tree so the real repository is never modified.
FAKE="$WORK/tree"
mkdir -p "$FAKE/tools"
cp "$BUILDER" "$FAKE/tools/"
cp "$REPO_ROOT/$INSTRUCTIONS" "$FAKE/"

checks=`expr $checks + 1`
sed 's/$/\r/' "$REPO_ROOT/$COLLECTOR" > "$FAKE/$COLLECTOR"
sh "$FAKE/tools/make-release.sh" vCRLF "$WORK/nope" > "$WORK/crlf.log" 2>&1
_rc=$?
if [ "$_rc" -ne 0 ] && grep -q 'carriage returns' "$WORK/crlf.log" 2>/dev/null; then
    pass "refuses a CRLF-damaged script AND says so, rather than blaming syntax"
else
    fail "CRLF guard did not fire correctly (exit $_rc):"
    head -3 "$WORK/crlf.log" | sed 's/^/            /'
fi

checks=`expr $checks + 1`
cp "$REPO_ROOT/$COLLECTOR" "$FAKE/$COLLECTOR"
printf '\nif then fi\n' >> "$FAKE/$COLLECTOR"
sh "$FAKE/tools/make-release.sh" vBROKEN "$WORK/nope" > "$WORK/parse.log" 2>&1
_rc=$?
if [ "$_rc" -ne 0 ] && grep -q 'does not parse' "$WORK/parse.log" 2>/dev/null; then
    pass "refuses a script that does not parse"
else
    fail "parse guard did not fire (exit $_rc)"
fi

checks=`expr $checks + 1`
cp "$REPO_ROOT/$COLLECTOR" "$FAKE/$COLLECTOR"
rm -f "$FAKE/$INSTRUCTIONS"
sh "$FAKE/tools/make-release.sh" vMISSING "$WORK/nope" > "$WORK/missing.log" 2>&1
_rc=$?
if [ "$_rc" -ne 0 ]; then
    pass "refuses to build when a required file is absent"
else
    fail "built a bundle with $INSTRUCTIONS missing - the client would get a script and no guidance"
fi

printf '\n-----------------------------------------------\n'
printf 'checks: %s   failures: %s\n' "$checks" "$failures"
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS - the client bundle is built correctly\n'
exit 0
