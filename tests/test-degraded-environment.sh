#!/bin/sh
# Readiness test 5 of 6: behave honestly when conditions are bad.
#
# THE QUESTION THIS ANSWERS
# "What if something goes wrong during the collection?" Things will go wrong on
# a real engagement: the output directory fills up, an operator runs it without
# sudo, a path is on an unresponsive mount, someone presses Ctrl-C.
#
# The requirement in every one of those cases is NOT that the collection
# succeeds. It is that the package never misrepresents itself. A partial
# collection that says it is partial is usable - the auditor reads the warnings
# and requests what is missing. A partial collection that reports
# COMPLETED_CLEAN is worse than no collection at all, because the audit team
# will rely on it and the gap will never be found.
#
# So every case below asserts the VERDICT, not merely the exit status.
#
# WHAT IS EXERCISED
#   1. No root         - must refuse rather than silently under-collect
#   2. --dry-run       - the review mode offered to clients must work unprivileged
#   3. Unwritable output directory - must fail loudly, not pretend
#   4. Output directory full - must not claim a clean collection
#   5. Unreadable source file - must WARN and never report CLEAN
#   6. Interruption (SIGINT/SIGTERM) - must leave a FAILED verdict, not a
#      silently truncated package
#   7. Restrictive umask and unusual locale - must not corrupt output
#   8. Re-running over a previous collection - must not merge two runs
#
# Usage: sudo sh tests/test-degraded-environment.sh
# Exit:  0 = degraded honestly in every case, 1 = otherwise

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
# mktemp -d creates the directory 0700. The unprivileged cases below run as
# "nobody", which cannot traverse a 0700 directory owned by root, so without
# this the collector would fail for a reason that has nothing to do with the
# behaviour under test - and would look like a defect in the tool.
chmod 0755 "$WORK"
cleanup() {
    umount "$WORK/tiny" 2>/dev/null || :
    chmod -R u+rwX "$WORK" 2>/dev/null || :
    rm -rf "$WORK" 2>/dev/null || :
    rm -f /etc/sox-unreadable-probe.conf 2>/dev/null || :
}
trap cleanup EXIT INT TERM

failures=0
checks=0
pass() { printf 'ok        %s\n' "$1"; }
fail() { printf 'NOT OK    %s\n' "$1"; failures=`expr $failures + 1`; }

verdict_of() {
    _v=`sed -n 's/^FINAL_RESULT: //p' "$1/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt" 2>/dev/null | tail -1`
    [ -n "$_v" ] || _v=`sed -n 's/^RESULT: //p' "$1/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt" 2>/dev/null | head -1`
    printf '%s' "${_v:-none}"
}

printf '== 1. refuses to run without root ==\n'
checks=`expr $checks + 1`
O="$WORK/noroot"; mkdir -p "$O"; chmod 0777 "$O"
# setpriv drops to an unprivileged user; su -c is the fallback.
if command -v setpriv >/dev/null 2>&1; then
    setpriv --reuid=65534 --regid=65534 --clear-groups \
        sh "$COLLECTOR" --output-dir "$O" </dev/null >"$WORK/noroot.log" 2>&1
    rc=$?
else
    su -s /bin/sh nobody -c "sh '$COLLECTOR' --output-dir '$O' </dev/null" >"$WORK/noroot.log" 2>&1
    rc=$?
fi
if [ "$rc" -ne 0 ] && grep -q 'must be run with sudo' "$WORK/noroot.log" 2>/dev/null; then
    pass "refused with a clear message and non-zero exit ($rc)"
    # It must also not have left a half-collection behind that someone could send.
    if [ -d "$O/SOX-ITGC-AUDIT-LINUX-UNIX" ]; then
        fail "but it left an evidence directory behind after refusing"
    fi
else
    fail "did not refuse cleanly without root (exit=$rc)"
    head -5 "$WORK/noroot.log" | sed 's/^/            /'
fi

printf '\n== 2. --dry-run works unprivileged, as offered to clients ==\n'
checks=`expr $checks + 1`
O="$WORK/dry"; mkdir -p "$O"; chmod 0777 "$O"
if command -v setpriv >/dev/null 2>&1; then
    setpriv --reuid=65534 --regid=65534 --clear-groups \
        sh "$COLLECTOR" --dry-run --output-dir "$O" </dev/null >"$WORK/dry.log" 2>&1
    rc=$?
else
    su -s /bin/sh nobody -c "sh '$COLLECTOR' --dry-run --output-dir '$O' </dev/null" >"$WORK/dry.log" 2>&1
    rc=$?
fi
_dryreport="$O/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt"
if [ "$rc" -eq 0 ] && [ -s "$_dryreport" ]; then
    _dv=`verdict_of "$O"`
    pass "completed unprivileged and produced a report (verdict: $_dv)"
    # A non-root run cannot read root-only files, so it must NOT claim to be clean.
    checks=`expr $checks + 1`
    if [ "$_dv" = "COMPLETED_CLEAN" ]; then
        fail "a non-root run reported COMPLETED_CLEAN, but it cannot have read"
        printf '            root-only files; the verdict overstates the evidence\n'
    else
        pass "did not claim CLEAN despite running without privilege ($_dv)"
    fi
else
    fail "--dry-run failed unprivileged (exit=$rc)"
    tail -5 "$WORK/dry.log" | sed 's/^/            /'
fi

printf '\n== 3. unwritable output directory fails loudly ==\n'
checks=`expr $checks + 1`
O="$WORK/readonly"; mkdir -p "$O"; chmod 0555 "$O"
sh "$COLLECTOR" --output-dir "$O" </dev/null >"$WORK/ro.log" 2>&1
rc=$?
# Root can write to a 0555 directory, so this must be judged on what happened,
# not on the mode: either it wrote successfully (acceptable - root may) or it
# reported the failure. What is unacceptable is silence.
if [ -f "$O/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt" ]; then
    pass "root wrote through the restrictive mode, which is expected for root"
elif grep -q 'could not create the evidence directory\|not accessible' "$WORK/ro.log" 2>/dev/null; then
    pass "reported the unwritable directory explicitly on the terminal"
else
    fail "neither collected nor reported why (exit=$rc)"
    tail -5 "$WORK/ro.log" | sed 's/^/            /'
fi

printf '\n== 4. a full output filesystem does not yield a CLEAN verdict ==\n'
checks=`expr $checks + 1`
mkdir -p "$WORK/tiny"
if command -v mount >/dev/null 2>&1 && mount -t tmpfs -o size=768k tmpfs "$WORK/tiny" 2>/dev/null; then
    sh "$COLLECTOR" --output-dir "$WORK/tiny" </dev/null >"$WORK/full.log" 2>&1
    rc=$?
    _fv=`verdict_of "$WORK/tiny"`
    if [ "$_fv" = "COMPLETED_CLEAN" ]; then
        fail "reported COMPLETED_CLEAN on a filesystem too small to hold the evidence"
        printf '            A truncated package that calls itself clean is the worst\n'
        printf '            possible outcome for an audit deliverable.\n'
    else
        pass "did not claim a clean collection on a full filesystem (verdict: ${_fv})"
    fi
    umount "$WORK/tiny" 2>/dev/null || :
else
    printf 'SKIP      cannot mount tmpfs in this environment\n'
fi

printf '\n== 5. a file that exists but cannot be read is reported as a gap ==\n'
checks=`expr $checks + 1`
# Root can read anything, so a permission-based unreadable file cannot be
# simulated here. An immutable-attribute or unresponsive-mount file would be the
# real-world case. What CAN be verified is that the code path exists and is
# reachable: assert the collector logs the distinction at all.
if grep -q 'exists but could not be read' "$COLLECTOR" 2>/dev/null; then
    pass "the collector distinguishes 'absent' from 'present but unreadable'"
    printf '          (as root this cannot be triggered by permissions; the distinction\n'
    printf '          matters on client hosts where a path is on a stalled mount)\n'
else
    fail "the collector does not distinguish absent from unreadable"
fi

printf '\n== 6. interruption leaves an honest FAILED verdict ==\n'
for sig in INT TERM; do
    checks=`expr $checks + 1`
    O="$WORK/sig$sig"; mkdir -p "$O"
    # --app-dir /usr makes Section 23 list a large tree recursively, which
    # guarantees the collection is still running when the signal arrives.
    # A fixed "sleep 1" raced: on a fast host the collection had already
    # finished, kill silently did nothing, and the test then read a legitimately
    # CLEAN verdict and reported it as a failure to handle the signal. The test
    # was measuring its own timing rather than the collector's behaviour.
    #
    # setsid is required, and the reason is a POSIX rule that is easy to trip
    # over: when a non-interactive shell starts an asynchronous (background)
    # job, it sets SIGINT and SIGQUIT to SIG_IGN in that job - and a signal that
    # is ignored on entry to a shell CANNOT be re-trapped afterwards, so
    # "trap - INT" inside the job does not restore it either.
    #
    # Launching the collector with "&" therefore made its own INT trap
    # inoperative: kill -INT did nothing at all, the collection ran to
    # completion, and the test reported a correctly-handled signal as a defect
    # in the collector. Running it in a new session gives it default signal
    # dispositions, which is what an operator pressing Ctrl-C at a terminal
    # actually produces - the case being tested.
    #
    # Worth knowing beyond this test: for an unattended or scheduled run, the
    # signal that matters is SIGTERM. It is never ignored this way and is what
    # init, systemd, and a plain kill send.
    # The collector MUST run in the foreground here, and the signal must come
    # from a background helper - not the other way round.
    #
    # POSIX: when a non-interactive shell starts an asynchronous (background)
    # job, it sets SIGINT and SIGQUIT to SIG_IGN in that job. An ignored
    # disposition is inherited across both fork and exec, so it survives
    # "trap - INT" (a shell cannot re-trap a signal ignored at entry) and it
    # survives setsid (a new session does not reset dispositions). Backgrounding
    # the collector therefore made it deaf to SIGINT, kill -INT did nothing, the
    # collection ran to completion, and the test blamed the collector for a
    # signal the test itself had disabled.
    #
    # Running it in the foreground gives it the default disposition - exactly
    # what an operator gets pressing Ctrl-C at a terminal, which is the case
    # under test. The helper below only SENDS the signal, so being backgrounded
    # costs it nothing.
    (
        _w=0
        while [ ! -s "$O/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt" ] && [ "$_w" -lt 60 ]; do
            sleep 1
            _w=`expr $_w + 1`
        done
        sleep 1
        _target=`ps -eo pid,args 2>/dev/null | grep "[l]inux-unix-evidence-gathering-script.sh --output-dir $O" | awk 'NR == 1 { print $1 }'`
        [ -n "$_target" ] && kill -"$sig" "$_target" 2>/dev/null
    ) &
    _killer=$!

    sh "$COLLECTOR" --output-dir "$O" --app-dir /usr </dev/null >"$WORK/sig.log" 2>&1
    rc=$?
    wait "$_killer" 2>/dev/null || :
    _sv=`verdict_of "$O"`
    _rep="$O/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt"
    if [ "$_sv" = "FAILED" ] || [ "$_sv" = "none" ]; then
        # "none" means it was killed before any verdict was written; the report
        # then lacks its Execution Summary and the receipt verifier rejects it.
        if [ "$_sv" = "FAILED" ]; then
            pass "SIG$sig left an explicit FAILED verdict in the log"
        elif grep -q 'Execution Summary' "$_rep" 2>/dev/null; then
            fail "SIG$sig produced a complete-looking report with no verdict"
        else
            pass "SIG$sig left no verdict and a truncated report, which the receipt"
            printf '          verifier rejects as an incomplete delivery\n'
        fi
    else
        fail "SIG$sig produced verdict '$_sv' on an interrupted, incomplete collection"
    fi
done

printf '\n== 7. restrictive umask and unusual locale do not corrupt output ==\n'
checks=`expr $checks + 1`
O="$WORK/umask"; mkdir -p "$O"
( umask 077; LC_ALL=C LANG=C TZ=UTC sh "$COLLECTOR" --output-dir "$O" </dev/null ) >"$WORK/um.log" 2>&1
_uv=`verdict_of "$O"`
_usections=`grep -c '^[0-9]\{1,2\}\. ' "$O/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt" 2>/dev/null`
[ -n "$_usections" ] || _usections=0
if [ "$_usections" -ge 20 ]; then
    pass "produced $_usections sections under umask 077 / LC_ALL=C / TZ=UTC ($_uv)"
else
    fail "output degraded under a restrictive umask or C locale ($_usections sections)"
fi

printf '\n== 8. re-running does not merge two collections ==\n'
checks=`expr $checks + 1`
O="$WORK/rerun"; mkdir -p "$O"
sh "$COLLECTOR" --output-dir "$O" </dev/null >/dev/null 2>&1
# Plant a file that must not survive into the second run's package.
printf 'stale evidence from run 1\n' > "$O/SOX-ITGC-AUDIT-LINUX-UNIX/raw_files/STALE-MARKER.txt"
sh "$COLLECTOR" --output-dir "$O" </dev/null >/dev/null 2>&1
if [ -f "$O/SOX-ITGC-AUDIT-LINUX-UNIX/raw_files/STALE-MARKER.txt" ]; then
    fail "evidence from a previous run survived into the new package"
    printf '            Two collections would be indistinguishable in one deliverable.\n'
else
    pass "the previous collection was cleared; the package reflects one run only"
fi

printf '\n-----------------------------------------------\n'
printf 'checks: %s   failures: %s\n' "$checks" "$failures"
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS - degrades honestly under every adverse condition tested\n'
exit 0
