#!/bin/sh
# Readiness test 6 of 6: two collections of an unchanged host must agree.
#
# THE QUESTION THIS ANSWERS
# "If we run it again, do we get the same answer?" A reviewer, a second auditor,
# or the client may re-run the collection. If the two packages disagree about
# the host's configuration, neither can be relied on, and no one can tell which
# is right. Reproducibility is what makes a collection evidence rather than an
# observation.
#
# WHAT MUST DIFFER, AND WHAT MUST NOT
# Some variation is correct and expected: timestamps, elapsed scan times, the
# archive filename, and anything sampled from a live log. Those describe WHEN
# the collection ran, not what the host is configured to do.
#
# Everything else must be identical. The account inventory, group membership,
# sudo rules, SSH settings, cron jobs, the world-writable and SetUID
# populations, the set of files collected, and the permissions recorded for
# them must all match, because none of them changed between the two runs.
#
# The comparison therefore normalises the known-variable fields and requires
# exact equality of the rest. That is a stronger assertion than "roughly the
# same", and it is the one worth making: a collection that quietly varies its
# findings run to run cannot support an audit conclusion.
#
# Usage: sudo sh tests/test-determinism.sh
# Exit:  0 = the two runs agree, 1 = they disagree

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
trap 'rm -rf "$WORK"' EXIT INT TERM

failures=0
checks=0
pass() { printf 'ok        %s\n' "$1"; }
fail() { printf 'NOT OK    %s\n' "$1"; failures=`expr $failures + 1`; }

printf '== running two collections of the same unchanged host ==\n'
for n in 1 2; do
    mkdir -p "$WORK/run$n"
    sh "$COLLECTOR" --output-dir "$WORK/run$n" </dev/null >"$WORK/run$n.log" 2>&1
    printf '   run %s: exit %s\n' "$n" "$?"
done
R1="$WORK/run1/SOX-ITGC-AUDIT-LINUX-UNIX"
R2="$WORK/run2/SOX-ITGC-AUDIT-LINUX-UNIX"
printf '\n'

# Strip the fields that legitimately differ between two runs. Each pattern is
# listed explicitly rather than filtered loosely, so that a genuine difference
# cannot be masked by an over-broad rule.
normalise() {
    sed \
        -e 's/^Generated: .*/Generated: <TIME>/' \
        -e 's/^STARTED: .*/STARTED: <TIME>/' \
        -e 's/^FINISHED: .*/FINISHED: <TIME>/' \
        -e 's/^Started:   .*/Started:   <TIME>/' \
        -e 's/^Completed: .*/Completed: <TIME>/' \
        -e 's/^Elapsed:   .*/Elapsed:   <DURATION>/' \
        -e 's/SOX-ITGC-AUDIT-LINUX-UNIX-[A-Za-z0-9._-]*-[0-9]\{8\}-[0-9]\{6\}/<ARCHIVE>/g' \
        -e 's#/run[12]#/run<N>#g' \
        -e 's/^  Section .*/  Section <TIMING>/' \
        -e 's/^TIMING|.*/TIMING|<TIMING>/' \
        -e 's/^[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9:]\{8\} /<TS> /' \
        -e '/^[^ ][^ ]*  *[0-9][0-9]*  *[0-9][0-9]*  *[0-9][0-9]*  *[0-9][0-9]*% /s/.*/<DF-CAPACITY>/' \
        -e 's/^\([dlbcps-][rwxsStT-]\{9\}[.+]*\)  *[0-9][0-9]*  */\1 <LINKS> /' \
        -e 's/^\([dlbcps-][rwxsStT-]\{9\}[.+]* <LINKS> \)\(.*\) \(\/tmp\|\/var\/tmp\|\/dev\/shm\|\/var\/lock\)$/\1<META> \3/' \
        -e 's/^\([[:space:]]*\(Local time\|Universal time\|RTC time\|System clock synchronized\|NTP service\)\):.*/\1: <CLOCK>/' \
        "$1"
}
# The last three rules normalise things that are genuinely point-in-time on a
# live host, and each was added only after CI demonstrated it - a developer
# container did not reproduce any of them:
#
#   df capacity   Free space changes between the two runs because the FIRST run
#                 wrote an evidence package to the same filesystem. Requiring it
#                 to be identical would assert something false about filesystems.
#
#   link count    Normalised on EVERY long-format listing line, not just the
#                 shared temporary directories where it first showed up.
#
#                 A directory's link count is its number of subdirectories, and
#                 that changes whenever anything on the system creates or removes
#                 one. Two separate cases have now hit this: /tmp, whose count
#                 rose because this test's own mktemp ran between the two
#                 collections; and /var/cache/man - the "man" account's home
#                 directory on Debian, listed by the home-directory permission
#                 review - which fell from 36 to 2 when man-db cleaned its cache
#                 mid-test. Both were the host changing underneath the
#                 collection, reported accurately both times.
#
#                 The MODE, OWNER, GROUP and SIZE are deliberately still
#                 compared. Those are the evidence - who can write to this
#                 directory, who owns it - and normalising them away would gut
#                 the check. Only the count of subdirectories is discarded.
#
#   /tmp size and date
#                 Additionally normalised for the shared temporary directories
#                 only, whose mtime and size change as files come and go in them.
#
#   clock lines   timedatectl reports the current time, which necessarily differs
#                 between two runs. The synchronisation STATE is what the section
#                 is evidencing, and the surrounding lines carrying it are still
#                 compared.
# The last rule normalises df output. Free space genuinely changes between the
# two runs - the first run wrote an evidence package to the same filesystem, so
# the second run correctly observes less space available. Capacity is
# point-in-time operational evidence, not configuration, and requiring it to be
# identical would assert something false about how a filesystem behaves.

printf '== 1. the report describes the same host both times ==\n'
checks=`expr $checks + 1`
# Section 9 (login history) and Section 25 (auth log samples) read live logs
# that legitimately gain entries between two runs - including the entries
# created by the first run's own sudo. Those two sections are compared
# separately below rather than being allowed to mask differences elsewhere.
extract_stable() {
    awk '
        /^9\. Recent Login Activity/       { skip = 1 }
        /^10\. World-Writable/             { skip = 0 }
        /^25\. Authentication Log Samples/ { skip = 1 }
        /^Execution Summary/               { skip = 0 }
        !skip { print }
    ' "$1"
}
extract_stable "$R1/report/SOX-ITGC-AUDIT-REPORT.txt" > "$WORK/r1.raw"
extract_stable "$R2/report/SOX-ITGC-AUDIT-REPORT.txt" > "$WORK/r2.raw"
normalise "$WORK/r1.raw" > "$WORK/r1.txt"
normalise "$WORK/r2.raw" > "$WORK/r2.txt"

if diff "$WORK/r1.txt" "$WORK/r2.txt" > "$WORK/report.diff" 2>&1; then
    pass "the two reports are byte-identical once timestamps are normalised"
else
    _d=`grep -c '^[<>]' "$WORK/report.diff" 2>/dev/null`
    fail "the two reports disagree on $_d line(s) about an unchanged host:"
    head -30 "$WORK/report.diff" | sed 's/^/            /'
fi

printf '\n== 2. the same set of files was collected ==\n'
checks=`expr $checks + 1`
grep '^COPIED' "$R1/metadata/MANIFEST.txt" | sort > "$WORK/m1.txt"
grep '^COPIED' "$R2/metadata/MANIFEST.txt" | sort > "$WORK/m2.txt"
if diff "$WORK/m1.txt" "$WORK/m2.txt" > "$WORK/man.diff" 2>&1; then
    pass "identical file set, with identical source permissions and ownership"
else
    fail "the two runs collected different files, or recorded different modes:"
    head -20 "$WORK/man.diff" | sed 's/^/            /'
fi

printf '\n== 3. the same files were withheld ==\n'
checks=`expr $checks + 1`
# Plain temporary files rather than process substitution: <(...) is a bash
# extension, and this suite is run with sh, which is dash on many systems.
sort "$R1/metadata/SENSITIVE_FILES_SKIPPED.txt" > "$WORK/s1.txt" 2>/dev/null
sort "$R2/metadata/SENSITIVE_FILES_SKIPPED.txt" > "$WORK/s2.txt" 2>/dev/null
if diff "$WORK/s1.txt" "$WORK/s2.txt" >"$WORK/skip.diff" 2>&1; then
    pass "the credential safeguards withheld exactly the same files"
else
    fail "the two runs withheld different files:"
    head -10 "$WORK/skip.diff" | sed 's/^/            /'
fi

printf '\n== 4. the collected file CONTENTS are identical ==\n'
checks=`expr $checks + 1`
# Compares the bytes of every collected file, not merely the file list. A
# collection that copied the right paths but truncated one of them would pass
# the manifest check above and fail here.
( cd "$R1/raw_files" 2>/dev/null && find . -type f -exec sha256sum {} \; 2>/dev/null | sort -k2 ) > "$WORK/h1.txt"
( cd "$R2/raw_files" 2>/dev/null && find . -type f -exec sha256sum {} \; 2>/dev/null | sort -k2 ) > "$WORK/h2.txt"
if diff "$WORK/h1.txt" "$WORK/h2.txt" > "$WORK/hash.diff" 2>&1; then
    _n=`grep -c . "$WORK/h1.txt" 2>/dev/null`
    pass "all $_n collected files are byte-identical between the two runs"
else
    fail "collected file contents differ between runs:"
    head -20 "$WORK/hash.diff" | sed 's/^/            /'
fi

printf '\n== 5. the same verdict was reached ==\n'
checks=`expr $checks + 1`
_v1=`sed -n 's/^FINAL_RESULT: //p' "$R1/metadata/COLLECTION-LOG.txt" 2>/dev/null | tail -1`
_v2=`sed -n 's/^FINAL_RESULT: //p' "$R2/metadata/COLLECTION-LOG.txt" 2>/dev/null | tail -1`
if [ "$_v1" = "$_v2" ] && [ -n "$_v1" ]; then
    pass "both runs reached the same verdict ($_v1)"
else
    fail "verdicts differ: run1=$_v1 run2=$_v2"
fi

printf '\n== 6. the volatile sections differ only as expected ==\n'
checks=`expr $checks + 1`
# Positive confirmation that the exclusions in check 1 were narrow and honest:
# the live-log sections SHOULD be able to differ, and the test states plainly
# which parts of the evidence are point-in-time rather than reproducible.
_s1=`grep -c 'Log file:\|Command: last' "$R1/report/SOX-ITGC-AUDIT-REPORT.txt" 2>/dev/null`
_s2=`grep -c 'Log file:\|Command: last' "$R2/report/SOX-ITGC-AUDIT-REPORT.txt" 2>/dev/null`
if [ "$_s1" = "$_s2" ]; then
    pass "both runs sampled the same live-log sources ($_s1 of them)"
    printf '          Their CONTENT is point-in-time by nature and is excluded from\n'
    printf '          the equality check above; the sources themselves must match.\n'
else
    fail "the runs sampled different log sources ($_s1 vs $_s2)"
fi

printf '\n-----------------------------------------------\n'
printf 'checks: %s   failures: %s\n' "$checks" "$failures"
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS - the collection is reproducible\n'
exit 0
