#!/bin/sh
# Test the receipt verifier against a healthy package and against deliberately
# degraded ones.
#
# The verifier is what an auditor runs before trusting a delivery, so the thing
# that actually matters is that it FAILS when it should. A checker that only
# passes on good input provides false assurance, so every degradation below was
# produced by damaging a real package in a way that has occurred or plausibly
# could: a report cut short mid-write, a log without its verdict, a manifest
# claiming files that never arrived, an archive truncated in transfer.
#
# Exit codes under test:
#   0 clean, 1 warnings, 2 incomplete or errors, 3 unexaminable
#
# Requires root only because producing the fixture package requires a real
# collection run.
#
# Usage: sudo sh tests/test-verify-package.sh

set -u

REPO_ROOT=`CDPATH= cd -- "\`dirname -- "$0"\`/.." && pwd`
COLLECTOR="$REPO_ROOT/linux-unix-evidence-gathering-script.sh"
VERIFIER="$REPO_ROOT/tools/verify-package.sh"

for required in "$COLLECTOR" "$VERIFIER"; do
    if [ ! -f "$required" ]; then
        printf 'FAIL: not found: %s\n' "$required" >&2
        exit 1
    fi
done
if [ "`id -u`" != "0" ]; then
    printf 'FAIL: must run as root (use: sudo sh %s)\n' "$0" >&2
    exit 1
fi

WORK=`mktemp -d`
trap 'rm -rf "$WORK"' EXIT INT TERM

failures=0
checks=0

expect_exit() {
    _label=$1
    _want=$2
    _target=$3
    checks=`expr "$checks" + 1`
    sh "$VERIFIER" "$_target" >"$WORK/out.txt" 2>&1
    _got=$?
    if [ "$_got" = "$_want" ]; then
        printf 'ok        %s (exit %s)\n' "$_label" "$_got"
    else
        printf 'NOT OK    %s: expected exit %s, got %s\n' "$_label" "$_want" "$_got"
        sed 's/^/            /' "$WORK/out.txt" | tail -12 >&2
        failures=`expr "$failures" + 1`
    fi
}

# A fresh copy of the reference package, to damage without affecting the others.
fresh_copy() {
    _dest="$WORK/$1"
    rm -rf "$_dest"
    mkdir -p "$_dest"
    ( cd "$_dest" && tar -xzf "$ARCHIVE" ) 2>/dev/null
    printf '%s/SOX-ITGC-AUDIT-LINUX-UNIX' "$_dest"
}

printf '== producing a reference package ==\n'
OUT="$WORK/collect"
mkdir -p "$OUT"
sh "$COLLECTOR" --output-dir "$OUT" </dev/null >"$WORK/collect.log" 2>&1
ARCHIVE=`ls "$OUT"/*.tar.gz 2>/dev/null | head -1`
if [ -z "$ARCHIVE" ]; then
    printf 'FAIL: the collector produced no archive; cannot test the verifier\n' >&2
    tail -20 "$WORK/collect.log" >&2
    exit 1
fi
printf '  %s\n\n' "$ARCHIVE"

printf '== an intact package verifies, and the verdict agrees with the log ==\n'
# The exit code is derived from the package's own verdict rather than assumed to
# be 0. A collection is only CLEAN if nothing on the host limited it, and that is
# a property of the host, not of the verifier: a CI runner, or any real client
# system with a file that exists but cannot be read, legitimately produces
# warnings. Hard-coding 0 here tested the environment instead of the tool, and
# failed the moment it ran somewhere other than a developer's container.
REFERENCE_LOG="`fresh_copy reference`/metadata/COLLECTION-LOG.txt"
reference_verdict=`sed -n 's/^FINAL_RESULT: //p' "$REFERENCE_LOG" 2>/dev/null | tail -1`
[ -n "$reference_verdict" ] || reference_verdict=`sed -n 's/^RESULT: //p' "$REFERENCE_LOG" 2>/dev/null | head -1`
case "$reference_verdict" in
    COMPLETED_CLEAN)          reference_exit=0 ;;
    COMPLETED_WITH_WARNINGS)  reference_exit=1 ;;
    *)                        reference_exit=2 ;;
esac
printf '  (this host collected as %s, so the verifier must return %s)\n' \
    "$reference_verdict" "$reference_exit"
expect_exit "intact archive" "$reference_exit" "$ARCHIVE"
expect_exit "intact extracted directory" "$reference_exit" "`fresh_copy intact`"

# The clean path still needs pinning deterministically, which no real host can be
# relied on to provide. Construct one: strip the WARN lines and set the verdict to
# match, so the package is internally consistent and genuinely clean.
target=`fresh_copy clean`
grep -v ' | WARN  | ' "$target/metadata/COLLECTION-LOG.txt" \
    | sed -e 's/^RESULT: .*/RESULT: COMPLETED_CLEAN/' \
          -e 's/^FINAL_RESULT: .*/FINAL_RESULT: COMPLETED_CLEAN/' \
          -e 's/^WARNINGS: .*/WARNINGS: 0/' \
          -e 's/^FINAL_WARNINGS: .*/FINAL_WARNINGS: 0/' > "$WORK/t" \
    && mv "$WORK/t" "$target/metadata/COLLECTION-LOG.txt"
expect_exit "package whose collection was clean" 0 "$target"

printf '\n== degraded packages are rejected ==\n'

# The truncated-archive bug this project actually shipped: the report was cut
# off before its execution summary because the archive was built too early.
target=`fresh_copy truncated_report`
head -40 "$target/report/SOX-ITGC-AUDIT-REPORT.txt" > "$WORK/t" && mv "$WORK/t" "$target/report/SOX-ITGC-AUDIT-REPORT.txt"
expect_exit "report truncated before its execution summary" 2 "$target"

# The same failure reaching the log: no verdict was ever written.
target=`fresh_copy truncated_log`
grep -v '^RESULT: ' "$target/metadata/COLLECTION-LOG.txt" > "$WORK/t" && mv "$WORK/t" "$target/metadata/COLLECTION-LOG.txt"
expect_exit "collection log has no verdict" 2 "$target"

# Chain of custody broken: the manifest names a file that is not in the package.
target=`fresh_copy missing_file`
first_copied=`sed -n 's/^COPIED|//p' "$target/metadata/MANIFEST.txt" 2>/dev/null | cut -d'|' -f1 | head -1`
if [ -n "$first_copied" ] && [ -f "$target/raw_files$first_copied" ]; then
    rm -f "$target/raw_files$first_copied"
    expect_exit "manifest names a file the package does not contain" 2 "$target"
else
    printf 'ok        (skipped manifest test: no copied files in fixture)\n'
fi

# Nothing usable at all.
target=`fresh_copy no_log`
rm -f "$target/metadata/COLLECTION-LOG.txt"
expect_exit "collection log absent entirely" 2 "$target"

printf '\n== a package that lost all its collected files is rejected ==\n'
# Removing raw_files/ entirely, rather than one file from it. The original guard
# only ran the manifest check when raw_files/ existed, so a package that had lost
# every collected file skipped the check and passed - a false PACKAGE VERIFIED,
# which for this tool is the defining failure.
target=`fresh_copy no_raw_files`
rm -rf "$target/raw_files"
expect_exit "raw_files absent while the manifest claims copies" 2 "$target"

printf '\n== a relative path is accepted, as the documented usage requires ==\n'
# Extraction happens inside a temporary directory, so a relative archive path was
# being resolved against that directory and a valid package came back as exit 3,
# "may be corrupt or truncated in transfer". The documented invocation - run from
# the directory holding the archive - is precisely this case. Every earlier test
# used mktemp -d paths, which are absolute, so none of them exercised it.
RELDIR=`dirname "$ARCHIVE"`
RELNAME=`basename "$ARCHIVE"`
checks=`expr "$checks" + 1`
( cd "$RELDIR" && sh "$VERIFIER" "$RELNAME" ) >"$WORK/rel.txt" 2>&1
rel_exit=$?
if [ "$rel_exit" = "$reference_exit" ]; then
    printf 'ok        archive by relative path (exit %s)\n' "$rel_exit"
else
    printf 'NOT OK    archive by relative path: expected exit %s, got %s\n' "$reference_exit" "$rel_exit"
    sed 's/^/            /' "$WORK/rel.txt" | tail -6 >&2
    failures=`expr "$failures" + 1`
fi

printf '\n== unexaminable inputs are distinguished from bad ones ==\n'
head -c 400 "$ARCHIVE" > "$WORK/corrupt.tar.gz"
expect_exit "archive truncated in transfer" 3 "$WORK/corrupt.tar.gz"
expect_exit "target does not exist" 3 "$WORK/absent.tar.gz"

printf '\n== a package with collection warnings is usable, not rejected ==\n'
# A warning means evidence was limited, which the auditor must read - but the
# package is still valid. Conflating that with a broken delivery would train
# people to ignore the checker.
WOUT="$WORK/warn"
mkdir -p "$WOUT"
sh "$COLLECTOR" --output-dir "$WOUT" --app-dir /nonexistent-application-root </dev/null >/dev/null 2>&1
WARCHIVE=`ls "$WOUT"/*.tar.gz 2>/dev/null | head -1`
if [ -n "$WARCHIVE" ]; then
    expect_exit "collection reported warnings" 1 "$WARCHIVE"
else
    printf 'NOT OK    could not produce a warning-state package\n'
    failures=`expr "$failures" + 1`
fi

printf '\n-----------------------------------------------\n'
printf 'checks: %s   failures: %s\n' "$checks" "$failures"
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS\n'
exit 0
