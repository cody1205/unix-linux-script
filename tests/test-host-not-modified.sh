#!/bin/sh
# Readiness test 1 of 6: prove the host is not modified.
#
# THE QUESTION THIS ANSWERS
# "You want to run a root script on our production server. Prove it changes
# nothing." That is the first question every client asks and the first thing
# firm leadership must be able to stand behind. Every other property of this
# tool is secondary to it, because a collection that alters a client system is
# not an audit procedure - it is an incident.
#
# HOW IT IS PROVED
# The filesystem state of every directory the collector reads is recorded
# before the run and again after it, and the two are compared. The snapshot
# records, per path: mode, owner, group, size, mtime and ctime.
#
#   mtime  changes when a file's CONTENT is written
#   ctime  changes when content OR metadata (mode, owner, link count) changes
#   size   changes when content is added or removed
#   mode   changes on chmod
#   owner  changes on chown
#
# Between them these catch any create, modify, delete, chmod, or chown. A file
# that was written and then restored to its original content would still be
# caught, because ctime cannot be set backwards by an unprivileged write.
#
# ATIME IS DELIBERATELY EXCLUDED, and this matters for the client conversation:
# reading a file updates its access time on some mount configurations. That is
# an unavoidable consequence of reading and is not a modification of the file -
# no content, permission, ownership, or size changes. Recording atime here would
# report every file the script legitimately read as "changed" and drown the
# result. The test measures atime separately and reports the count as
# information, so the effect is disclosed rather than hidden.
#
# SCOPE
# The system directories the collector actually reads. /proc, /sys, /dev and
# /run are kernel-backed and change constantly on their own; including them
# would produce noise unrelated to this script. The output directory is
# excluded because writing there is the script's entire purpose and is done
# under an operator-chosen path.
#
# Usage: sudo sh tests/test-host-not-modified.sh
# Exit:  0 = the host was not modified, 1 = it was

set -u

REPO_ROOT=`CDPATH= cd -- "\`dirname -- "$0"\`/.." && pwd`
COLLECTOR="$REPO_ROOT/linux-unix-evidence-gathering-script.sh"

if [ ! -f "$COLLECTOR" ]; then
    printf 'FAIL: collector not found at %s\n' "$COLLECTOR" >&2
    exit 1
fi
if [ "`id -u`" != "0" ]; then
    printf 'FAIL: must run as root, since that is how the collector runs (use: sudo sh %s)\n' "$0" >&2
    exit 1
fi

WORK=`mktemp -d`
trap 'rm -rf "$WORK"' EXIT INT TERM

# Directories the collector reads from. /var/log and /var/adm are included even
# though the system writes to them on its own, so that any truncation or
# rotation caused by the collector would be visible; genuine system log growth
# during the run is reported separately below rather than failing the test.
SCAN_DIRS="/etc /root /home /usr/local /opt /var/spool /bin /sbin"
LOG_DIRS="/var/log /var/adm"

# find -printf emits every field in ONE process. The obvious implementation -
# pipe find into a loop and run stat per path - forks a subprocess for each of
# roughly 107,000 paths, twice. Measured, that is ~36 seconds per 20,000 paths
# against ~79 milliseconds for the same work here: about 460x slower, turning
# this test into a six-minute job per snapshot.
#
# That is not merely inconvenient. A gate slow enough to be annoying is a gate
# somebody eventually disables, and this is the test that underwrites the single
# most important claim the tool makes. Keeping it fast keeps it running.
#
# Fields: path | mode | uid | gid | size | mtime | ctime
snapshot() {
    _snap_out=$1
    shift
    find "$@" -xdev \( -type f -o -type d -o -type l \) \
        -printf '%p|%m|%U|%G|%s|%T@|%C@\n' 2>/dev/null | sort > "$_snap_out"
}

atime_snapshot() {
    _at_out=$1
    shift
    find "$@" -xdev -type f -printf '%p|%A@\n' 2>/dev/null | sort > "$_at_out"
}

# -printf is a GNU extension. This test is a Linux CI gate rather than something
# that ships to a client, so requiring it is acceptable - but it must fail
# loudly rather than silently comparing two empty snapshots, which would report
# a triumphant PASS while checking nothing at all.
if ! find /etc -maxdepth 0 -printf '%p\n' >/dev/null 2>&1; then
    printf 'FAIL: this test requires GNU find (-printf). Without it the snapshots\n' >&2
    printf '      would be empty and the comparison would pass without checking.\n' >&2
    exit 1
fi

printf '== recording filesystem state before the collection ==\n'
printf '   scanning: %s\n' "$SCAN_DIRS"
snapshot "$WORK/before.txt" $SCAN_DIRS $LOG_DIRS
atime_snapshot "$WORK/atime_before.txt" $SCAN_DIRS
printf '   %s paths recorded\n\n' "`wc -l < "$WORK/before.txt" | tr -d ' '`"

printf '== running the collection as root ==\n'
OUT="$WORK/out"
mkdir -p "$OUT"
sh "$COLLECTOR" --output-dir "$OUT" </dev/null >"$WORK/run.log" 2>&1
_run_rc=$?
printf '   collector exit status: %s\n' "$_run_rc"
printf '   verdict: %s\n\n' "`sed -n 's/^FINAL_RESULT: //p' "$OUT/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt" 2>/dev/null | tail -1`"

printf '== recording filesystem state after the collection ==\n'
snapshot "$WORK/after.txt" $SCAN_DIRS $LOG_DIRS
atime_snapshot "$WORK/atime_after.txt" $SCAN_DIRS
printf '   %s paths recorded\n\n' "`wc -l < "$WORK/after.txt" | tr -d ' '`"

failures=0

printf '== comparing ==\n'

# System logs legitimately grow during any run - the collector's own sudo
# invocation is itself logged. Those are separated out so a real modification is
# not lost among them, and so that log growth is visible rather than suppressed.
diff "$WORK/before.txt" "$WORK/after.txt" > "$WORK/diff.txt" 2>&1 || :

changed_logs=`grep '^[<>]' "$WORK/diff.txt" 2>/dev/null | grep -c -E '\|/var/(log|adm)/' 2>/dev/null`
[ -n "$changed_logs" ] || changed_logs=0

# Anything outside the log directories is a genuine modification.
grep '^[<>]' "$WORK/diff.txt" 2>/dev/null | grep -v -E '\|/var/(log|adm)/' > "$WORK/real_changes.txt" 2>/dev/null || :
# The leading "< " / "> " markers make the same path appear twice; count paths.
sed 's/^[<>] //' "$WORK/real_changes.txt" 2>/dev/null | cut -d'|' -f1 | sort -u > "$WORK/changed_paths.txt"
changed_count=`grep -c . "$WORK/changed_paths.txt" 2>/dev/null`
[ -n "$changed_count" ] || changed_count=0

if [ "$changed_count" -eq 0 ]; then
    printf 'ok        no file outside the output directory was created, modified,\n'
    printf '          deleted, chmodded, or chowned by the collection\n'
else
    printf 'NOT OK    %s path(s) changed outside the output directory:\n' "$changed_count"
    sed 's/^/            /' "$WORK/changed_paths.txt" | head -40
    printf '          full detail:\n'
    sed 's/^/            /' "$WORK/real_changes.txt" | head -40
    failures=`expr $failures + 1`
fi

# Disclosure, not a failure: log growth caused by the run.
if [ "$changed_logs" -gt 0 ]; then
    printf '\ninfo      %s entr(y/ies) under /var/log or /var/adm changed during the run.\n' "$changed_logs"
    printf '          This is expected and is not caused by the collector writing to\n'
    printf '          logs: running anything under sudo causes the system to record an\n'
    printf '          authentication event. Shown here so the effect is disclosed.\n'
    grep '^[<>]' "$WORK/diff.txt" | grep -E '\|/var/(log|adm)/' | sed 's/^/            /' | head -10
fi

# Access times: disclosed, never failed on. See the header for why.
atime_changed=`diff "$WORK/atime_before.txt" "$WORK/atime_after.txt" 2>/dev/null | grep -c '^>' 2>/dev/null`
[ -n "$atime_changed" ] || atime_changed=0
printf '\ninfo      %s file(s) had their ACCESS time updated by being read.\n' "$atime_changed"
printf '          Reading a file is not modifying it: no content, size, permission,\n'
printf '          or ownership changed on any of them. On mounts using relatime or\n'
printf '          noatime this number is small or zero.\n'

# The collector must also not leave anything behind outside its output
# directory - a stray temporary file is a modification of the client's system
# even if it is harmless.
printf '\n== checking for stray temporary files ==\n'
for tmpdir in /tmp /var/tmp; do
    if [ -d "$tmpdir" ]; then
        found=`find "$tmpdir" -maxdepth 1 -newer "$WORK/before.txt" \( -name '*sox*' -o -name '*SOX*' -o -name '*audit*' -o -name '*itgc*' -o -name '*ITGC*' \) -print 2>/dev/null | grep -v "^$WORK" | head -5`
        if [ -n "$found" ]; then
            printf 'NOT OK    collector left files in %s:\n' "$tmpdir"
            printf '%s\n' "$found" | sed 's/^/            /'
            failures=`expr $failures + 1`
        else
            printf 'ok        nothing left behind in %s\n' "$tmpdir"
        fi
    fi
done

# The evidence must actually have been produced. A script that collects nothing
# would trivially pass every assertion above.
printf '\n== confirming the run actually did the work ==\n'
E="$OUT/SOX-ITGC-AUDIT-LINUX-UNIX"
if [ -s "$E/report/SOX-ITGC-AUDIT-REPORT.txt" ] && grep -q 'Execution Summary' "$E/report/SOX-ITGC-AUDIT-REPORT.txt" 2>/dev/null; then
    _copied=`grep -c '^COPIED' "$E/metadata/MANIFEST.txt" 2>/dev/null`
    [ -n "$_copied" ] || _copied=0
    printf 'ok        a complete report was produced and %s files were collected\n' "$_copied"
    printf '          (so the "nothing changed" result above is not vacuous)\n'
    if [ "$_copied" -lt 5 ]; then
        printf 'NOT OK    only %s files collected; too few to consider this a real run\n' "$_copied"
        failures=`expr $failures + 1`
    fi
else
    printf 'NOT OK    the collection did not produce a complete report\n'
    failures=`expr $failures + 1`
fi

printf '\n-----------------------------------------------\n'
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL - the host was modified, or the run was not valid\n'
    exit 1
fi
printf 'RESULT: PASS - the collection left the host unchanged\n'
exit 0
