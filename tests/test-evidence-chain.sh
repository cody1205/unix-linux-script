#!/bin/sh
# Readiness test 3 of 6: the evidence chain must be complete and honest.
#
# THE QUESTION THIS ANSWERS
# "Can you account for every file this evidence came from?" Chain of custody is
# the property that makes a collection admissible as workpaper support. If the
# report cites a file that appears nowhere in the manifest, a reviewer cannot
# establish where the evidence came from. If the manifest claims a file the
# package does not contain, the manifest is overstating the delivery. Both are
# failures of the same control, in opposite directions.
#
# WHAT IS ASSERTED
#   1. Every file the manifest says was COPIED is actually present.
#   2. Every file present in raw_files/ is accounted for in the manifest -
#      nothing arrives in the package unexplained.
#   3. Every source file the report names as a File Path is either copied,
#      recorded as withheld, or recorded as absent. No file may be silently
#      referenced and then unaccounted for.
#   4. Every withheld credential file appears in BOTH records of that decision
#      (the manifest and SENSITIVE_FILES_SKIPPED.txt), which is what the client
#      is told to check.
#   5. Nothing in raw_files/ is a file the sensitive-path rules should have
#      stopped - the classification is enforced against the delivered package,
#      not just against the function in isolation.
#   6. The report, log, and manifest agree on the file count.
#
# Usage: sudo sh tests/test-evidence-chain.sh
# Exit:  0 = the chain is complete, 1 = otherwise

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

printf '== producing a collection ==\n'
OUT="$WORK/out"
mkdir -p "$OUT"
sh "$COLLECTOR" --output-dir "$OUT" --app-dir /usr/local </dev/null >"$WORK/run.log" 2>&1
E="$OUT/SOX-ITGC-AUDIT-LINUX-UNIX"
REPORT="$E/report/SOX-ITGC-AUDIT-REPORT.txt"
MANIFEST="$E/metadata/MANIFEST.txt"
SKIPPED="$E/metadata/SENSITIVE_FILES_SKIPPED.txt"
RAW="$E/raw_files"

for f in "$REPORT" "$MANIFEST" "$SKIPPED"; do
    if [ ! -s "$f" ]; then
        printf 'FAIL: collection did not produce %s\n' "$f" >&2
        tail -20 "$WORK/run.log" >&2
        exit 1
    fi
done
printf '   report %s lines, manifest %s lines\n\n' \
    "`wc -l < "$REPORT" | tr -d ' '`" "`wc -l < "$MANIFEST" | tr -d ' '`"

printf '== 1. every COPIED entry is present in the package ==\n'
checks=`expr $checks + 1`
: > "$WORK/missing.txt"
sed -n 's/^COPIED|//p' "$MANIFEST" | cut -d'|' -f1 | sort -u > "$WORK/claimed.txt"
while IFS= read -r p; do
    [ -n "$p" ] || continue
    [ -f "$RAW$p" ] || printf '%s\n' "$p" >> "$WORK/missing.txt"
done < "$WORK/claimed.txt"
_n=`grep -c . "$WORK/missing.txt" 2>/dev/null`; [ -n "$_n" ] || _n=0
if [ "$_n" -eq 0 ]; then
    pass "all `grep -c . "$WORK/claimed.txt"` COPIED files are present"
else
    fail "$_n manifest COPIED entries are not in the package:"
    sed 's/^/            /' "$WORK/missing.txt" | head -10
fi

printf '\n== 2. every delivered file is explained by the manifest ==\n'
checks=`expr $checks + 1`
: > "$WORK/unexplained.txt"
if [ -d "$RAW" ]; then
    ( cd "$RAW" && find . -type f -print 2>/dev/null ) | sed 's/^\.//' | sort -u > "$WORK/delivered.txt"
    # COPIED_REDACTED is the second verb that puts a file in the package: the
    # /etc/passwd of a host that stores password hashes inline, delivered with
    # the password field removed. It is recorded under a distinct verb precisely
    # because it is NOT a verbatim copy, and a reviewer must be able to tell the
    # difference - so this check has to know about it rather than assuming
    # everything in the package arrived as COPIED.
    sed -n -e 's/^COPIED|//p' -e 's/^COPIED_REDACTED|//p' "$MANIFEST" | cut -d'|' -f1 | sort -u > "$WORK/accounted.txt"
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        grep -Fxq "$p" "$WORK/accounted.txt" || printf '%s\n' "$p" >> "$WORK/unexplained.txt"
    done < "$WORK/delivered.txt"
fi
_n=`grep -c . "$WORK/unexplained.txt" 2>/dev/null`; [ -n "$_n" ] || _n=0
if [ "$_n" -eq 0 ]; then
    pass "every file in raw_files/ is named in the manifest"
else
    fail "$_n delivered file(s) appear nowhere in the manifest:"
    sed 's/^/            /' "$WORK/unexplained.txt" | head -10
fi

printf '\n== 3. every source path the report names is accounted for ==\n'
# The requirement this enforces: if a file is named in the report, its contents
# are in the package - or it is a credential file whose withholding is recorded.
#
# EVERY form in which the report names a source path is collected, not just the
# section headers. That matters: an earlier version of this test looked only for
# "File Path:", which meant Section 21 - a dozen or more files reported with
# permissions and a checksum but never delivered - was invisible to it. When the
# header format later changed, that same narrow pattern would have matched
# nothing at all and the check would have passed while examining zero paths.
#
# The non-empty assertion below exists for exactly that reason. A test that
# silently checks nothing is worse than no test, because it reports success.
extract_referenced_paths() {
    {
        sed -n 's/^Directory: //p'              "$REPORT"
        sed -n 's/^File: //p'                   "$REPORT"
        sed -n 's/^Path: //p'                   "$REPORT"
        sed -n 's/^Full File Content: //p'      "$REPORT"
        sed -n 's/^Sensitive file review: //p'  "$REPORT"
    } 2>/dev/null | grep '^/' | sort -u
}
extract_referenced_paths > "$WORK/referenced.txt"

checks=`expr $checks + 1`
_ref_total=`grep -c . "$WORK/referenced.txt" 2>/dev/null`
[ -n "$_ref_total" ] || _ref_total=0
if [ "$_ref_total" -ge 20 ]; then
    pass "the report names $_ref_total distinct source paths (enough to be a real check)"
else
    fail "only $_ref_total source paths were found in the report. The extraction"
    printf '            patterns above no longer match its format, so every\n'
    printf '            assertion in this section would pass without examining\n'
    printf '            anything. Fix the patterns, not this threshold.\n'
fi

checks=`expr $checks + 1`
: > "$WORK/unaccounted.txt"
while IFS= read -r p; do
    [ -n "$p" ] || continue
    # Accounted for if copied, redacted, withheld as sensitive, or - for a path
    # that does not exist on this host - legitimately absent. A directory
    # reference is accounted for if anything beneath it was collected.
    if grep -Fq "|$p|" "$MANIFEST" || grep -Fq "|$p" "$MANIFEST" || grep -Fxq "$p" "$SKIPPED"; then
        continue
    fi
    if [ ! -e "$p" ]; then
        continue   # absent on this platform; the report says "not available"
    fi
    if [ -d "$p" ] && [ -d "$RAW$p" ]; then
        continue   # directory whose contents were collected
    fi
    printf '%s\n' "$p" >> "$WORK/unaccounted.txt"
done < "$WORK/referenced.txt"
_n=`grep -c . "$WORK/unaccounted.txt" 2>/dev/null`; [ -n "$_n" ] || _n=0
if [ "$_n" -eq 0 ]; then
    pass "all `grep -c . "$WORK/referenced.txt"` referenced source paths are accounted for"
else
    fail "$_n path(s) are referenced by the report but recorded nowhere:"
    sed 's/^/            /' "$WORK/unaccounted.txt" | head -10
fi

printf '\n== 3b. every referenced file is DELIVERED, not merely recorded ==\n'
# Stronger than check 3, and the assertion that matches the operating rule: a
# file named in the report must have its CONTENTS in raw_files. Being mentioned
# in the manifest is not enough - an auditor reading the report needs to be able
# to open the file and see what it said.
#
# The one permitted exception is a credential-bearing file, which is withheld on
# purpose and must be listed in SENSITIVE_FILES_SKIPPED.txt. That is the whole
# reason the skip list exists: it converts "missing" into "deliberately
# withheld, and here is the record of it".
#
# This is the check that would have caught Section 21 delivering a dozen files'
# checksums with none of their contents.
checks=`expr $checks + 1`
: > "$WORK/undelivered.txt"
_delivered=0
_withheld=0
_sampled=0
while IFS= read -r p; do
    [ -n "$p" ] || continue
    [ -f "$p" ] || continue          # only regular files that exist on this host
    if [ -f "$RAW$p" ]; then
        _delivered=`expr $_delivered + 1`
        continue
    fi
    if grep -Fq "$p" "$SKIPPED" 2>/dev/null; then
        _withheld=`expr $_withheld + 1`
        continue
    fi
    # Second permitted exception: an authentication log that was SAMPLED.
    #
    # These are deliberately not copied, in full or in part. On a production
    # server an auth log routinely runs to hundreds of megabytes or gigabytes,
    # and records authentication activity for EVERY user of the system - the
    # overwhelming majority of it outside the scope of the audit and none of the
    # auditors' business to be carrying off the client's server.
    #
    # What the report relies on is that authentication logging was OPERATING at
    # the time of collection, and the sampled lines quoted in the report
    # evidence exactly that. The full file stays where it belongs, on the
    # client's system, and can be requested if a sample ever raises a question.
    #
    # The exception is narrow: it requires an explicit LOG_SAMPLED record naming
    # this path in the manifest. A file that is simply missing does not qualify.
    if grep -Fq "LOG_SAMPLED|$p|" "$MANIFEST" 2>/dev/null; then
        _sampled=`expr ${_sampled:-0} + 1`
        continue
    fi
    printf '%s\n' "$p" >> "$WORK/undelivered.txt"
done < "$WORK/referenced.txt"
_n=`grep -c . "$WORK/undelivered.txt" 2>/dev/null`; [ -n "$_n" ] || _n=0
if [ "$_n" -eq 0 ]; then
    pass "$_delivered delivered, $_sampled sampled-not-copied by design, $_withheld withheld by design, 0 unexplained"
else
    fail "$_n file(s) are named in the report but their contents were not delivered:"
    sed 's/^/            /' "$WORK/undelivered.txt" | head -15
    printf '            A reader of the report cannot see what these contained.\n'
fi

printf '\n== 4. withheld files appear in BOTH records of that decision ==\n'
checks=`expr $checks + 1`
: > "$WORK/onesided.txt"
sed -n 's/^SENSITIVE_METADATA_ONLY|//p' "$MANIFEST" | sort -u > "$WORK/sens_manifest.txt"
while IFS= read -r p; do
    [ -n "$p" ] || continue
    grep -Fq "$p" "$SKIPPED" || printf 'in manifest but not in SENSITIVE_FILES_SKIPPED.txt: %s\n' "$p" >> "$WORK/onesided.txt"
done < "$WORK/sens_manifest.txt"
_n=`grep -c . "$WORK/onesided.txt" 2>/dev/null`; [ -n "$_n" ] || _n=0
if [ "$_n" -eq 0 ]; then
    pass "the manifest and the skip list agree on what was withheld"
else
    fail "$_n withheld file(s) are recorded in only one of the two places:"
    sed 's/^/            /' "$WORK/onesided.txt" | head -10
fi

printf '\n== 5. the sensitive-path rules held against the delivered package ==\n'
checks=`expr $checks + 1`
# Enforced against what actually arrived, not against the classifier in
# isolation. A regression that bypassed the guard on the way to raw_files/
# would pass a unit test of the function and fail here.
: > "$WORK/leaked.txt"
sed -n '/^is_sensitive_path()/,/^}/p' "$COLLECTOR" > "$WORK/fn.sh"
# shellcheck source=/dev/null
. "$WORK/fn.sh"
if [ -d "$RAW" ]; then
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        if is_sensitive_path "$p"; then
            printf '%s\n' "$p" >> "$WORK/leaked.txt"
        fi
    done < "$WORK/delivered.txt"
fi
_n=`grep -c . "$WORK/leaked.txt" 2>/dev/null`; [ -n "$_n" ] || _n=0
if [ "$_n" -eq 0 ]; then
    pass "no file classified as sensitive was delivered in raw_files/"
else
    fail "$_n sensitive file(s) reached the package:"
    sed 's/^/            /' "$WORK/leaked.txt" | head -10
fi

printf '\n== 6. the log and the manifest agree on the file count ==\n'
checks=`expr $checks + 1`
_log_count=`sed -n 's/^FILES_COLLECTED: //p' "$E/metadata/COLLECTION-LOG.txt" 2>/dev/null | head -1`
_man_count=`grep -c '^COPIED|' "$MANIFEST" 2>/dev/null`
[ -n "$_man_count" ] || _man_count=0
if [ "$_log_count" = "$_man_count" ]; then
    pass "log reports $_log_count collected files, manifest holds $_man_count"
else
    fail "log says $_log_count collected files, manifest holds $_man_count"
fi

printf '\n== 7. the collector identifies itself in the evidence ==\n'
checks=`expr $checks + 1`
_recorded=`sed -n 's/^COLLECTOR_SELF|.*checksum=//p' "$MANIFEST" 2>/dev/null | head -1`
_actual=`sha256sum "$COLLECTOR" 2>/dev/null | awk '{print $1}'`
if [ -n "$_recorded" ] && [ "$_recorded" = "$_actual" ]; then
    pass "the package records the exact checksum of the script that produced it"
else
    fail "collector self-checksum missing or wrong (recorded=${_recorded:-none} actual=$_actual)"
fi

printf '\n-----------------------------------------------\n'
printf 'checks: %s   failures: %s\n' "$checks" "$failures"
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS - the evidence chain is complete\n'
exit 0
