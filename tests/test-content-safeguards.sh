#!/bin/sh
# Readiness test 7: planted content cannot leak, hang, or bloat the package.
#
# THE QUESTION THIS ANSWERS
# "What happens when a configuration directory contains something that is not
# an ordinary configuration file?" On a real host it will: a symbolic link
# someone left behind, a named pipe from a monitoring agent, a core dump or a
# log that landed in the wrong place. The collector walks /etc/cron.d,
# /etc/sudoers.d, /etc/pam.d and /etc/profile.d and reads what it finds there,
# so whatever is there ends up in the evidence unless something stops it.
#
# Each case below was a real defect found by planting exactly this and running
# the collector, not by reading it:
#
#   1. A symbolic link in /etc/cron.d pointing at /etc/shadow was followed.
#      The shadow file was copied into raw_files/ under the link's name and
#      printed in the report, with a CLEAN verdict. The sensitive-path check
#      screened the link's own path, which is not sensitive, and never looked
#      at where it led. A second route - the "active entries" summary of
#      /etc/sudoers.d - leaked the same way after the first was closed, and a
#      third - grep across /etc/profile.d/*.sh - would have searched the target.
#   2. A named pipe in the same directories hung the collection for good.
#      [ -r ] is true for a FIFO, and the cat that followed blocked waiting for
#      a writer. On a client host there is no timeout to end it.
#   3. A 200 MB file in /etc/cron.d was printed in full into the report and
#      copied into raw_files/, producing a 200 MB report and a package too
#      large to transfer, with a CLEAN verdict. 100 KB of random bytes went
#      into the report alongside it.
#   4. --output-dir naming a path that could not be used fell back to the
#      current directory and exited 0, contradicting the client instructions'
#      promise about where the script writes.
#   5. With awk, sed, grep, sort or expr present but broken, the collection ran
#      to the end, lost two hundred lines of evidence silently, and reported
#      COMPLETED_CLEAN - because with expr or grep broken, the error counters
#      cannot count.
#
# Every case asserts what reached the package and what the manifest says, not
# merely that the run completed.
#
# Usage: sudo sh tests/test-content-safeguards.sh
# Exit:  0 = every safeguard held, 1 = otherwise

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

SENTINEL="SENTINEL-CONTENT-SAFEGUARD-7c3e9a1d"
SECRET=/root/.content-safeguard-secret
PLANTED=""
# A planted name containing a newline cannot live in the whitespace-separated
# PLANTED list - the cleanup loop would split it in two and remove neither,
# leaving junk in /etc/cron.d on whatever machine ran this test. It is held
# on its own and removed explicitly. The same for a name containing spaces
# and log-column text.
NL_PLANT=""
COL_PLANT=""

WORK=`mktemp -d`
cleanup() {
    for p in $PLANTED; do rm -f "$p" 2>/dev/null; done
    [ -n "$NL_PLANT" ] && rm -f "$NL_PLANT" 2>/dev/null
    [ -n "$COL_PLANT" ] && rm -f "$COL_PLANT" 2>/dev/null
    rm -f "$SECRET" 2>/dev/null
    chmod -R u+rwX "$WORK" 2>/dev/null || :
    rm -rf "$WORK" 2>/dev/null || :
}
trap cleanup EXIT INT TERM

failures=0
checks=0
pass() { printf 'ok        %s\n' "$1"; }
fail() { printf 'NOT OK    %s\n' "$1"; failures=`expr $failures + 1`; }
skip() { printf 'SKIP      %s\n' "$1"; }

plant() {
    PLANTED="$PLANTED $1"
}

verdict_of() {
    grep -E '^(FINAL_)?RESULT:' "$1/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt" 2>/dev/null | tail -1 | awk '{ print $2 }'
}

# Only directories the collector actually examines are used, and only where
# they exist on this host. Each case plants into every one of them.
COPIED_DIRS=""
for d in /etc/cron.d /etc/sudoers.d /etc/pam.d /etc/profile.d; do
    [ -d "$d" ] && COPIED_DIRS="$COPIED_DIRS $d"
done
if [ -z "$COPIED_DIRS" ]; then
    printf 'FAIL: none of the examined directories exist on this host\n' >&2
    exit 1
fi

run_collector() {
    _rc_out=$1
    shift
    timeout 600 sh "$COLLECTOR" --output-dir "$_rc_out" "$@" </dev/null >"$_rc_out.stdout" 2>"$_rc_out.stderr"
}

#############################################################################
printf '\n== 1. a symbolic link to a credential file is withheld, wherever it is ==\n'
printf '%s\n' "$SENTINEL" > "$SECRET"
chmod 600 "$SECRET"
for d in $COPIED_DIRS; do
    ln -s "$SECRET" "$d/zz-safeguard-link" && plant "$d/zz-safeguard-link"
done
# The TMOUT check greps /etc/profile.d/*.sh directly, so a .sh name is needed
# to reach that route.
if [ -d /etc/profile.d ]; then
    ln -s "$SECRET" /etc/profile.d/zz-safeguard-link.sh && plant /etc/profile.d/zz-safeguard-link.sh
fi
if [ -d /etc/cron.d ]; then
    ln -s /etc/shadow /etc/cron.d/zz-safeguard-shadow && plant /etc/cron.d/zz-safeguard-shadow
    # A legitimate link must still be collected, or the fix has thrown away
    # /etc/os-release and /etc/resolv.conf on every systemd host.
    ln -s /etc/hostname /etc/cron.d/zz-safeguard-benign && plant /etc/cron.d/zz-safeguard-benign
fi

OUT1="$WORK/links"
run_collector "$OUT1"
rc=$?
P1="$OUT1/SOX-ITGC-AUDIT-LINUX-UNIX"

checks=`expr $checks + 1`
if [ -d "$P1/raw_files" ] && grep -rl "$SENTINEL" "$P1/raw_files" >/dev/null 2>&1; then
    fail "the linked secret's contents reached raw_files/ through:"
    grep -rl "$SENTINEL" "$P1/raw_files" | sed 's/^/            /'
else
    pass "no copy in raw_files/ contains the linked secret"
fi

checks=`expr $checks + 1`
if grep -q "$SENTINEL" "$P1/report/SOX-ITGC-AUDIT-REPORT.txt" 2>/dev/null; then
    fail "the linked secret was printed in the report"
    grep -n -B3 "$SENTINEL" "$P1/report/SOX-ITGC-AUDIT-REPORT.txt" | head -8 | sed 's/^/            /'
else
    pass "the report does not contain the linked secret"
fi

checks=`expr $checks + 1`
if [ -f "$P1/raw_files/etc/cron.d/zz-safeguard-shadow" ]; then
    fail "/etc/shadow was copied into raw_files/ through a link in /etc/cron.d"
else
    pass "/etc/shadow was not copied through the link"
fi

checks=`expr $checks + 1`
_withheld=`grep -c 'zz-safeguard-link\|zz-safeguard-shadow' "$P1/metadata/SENSITIVE_FILES_SKIPPED.txt" 2>/dev/null`
_planted=`printf '%s\n' $PLANTED | grep -c 'zz-safeguard-link\|zz-safeguard-shadow'`
if [ "${_withheld:-0}" -ge "$_planted" ]; then
    pass "every withheld link is listed in SENSITIVE_FILES_SKIPPED.txt ($_withheld)"
else
    fail "skip list names $_withheld of $_planted withheld links"
fi

checks=`expr $checks + 1`
if grep -q 'zz-safeguard-shadow|note=symbolic link to /etc/shadow' "$P1/metadata/MANIFEST.txt" 2>/dev/null; then
    pass "the manifest records the link and names its target"
else
    fail "the manifest does not say where the withheld link led"
fi

checks=`expr $checks + 1`
if [ -f "$P1/raw_files/etc/cron.d/zz-safeguard-benign" ] && grep -q 'zz-safeguard-benign|.*symlink_target=/etc/hostname' "$P1/metadata/MANIFEST.txt"; then
    pass "a benign link is still collected, with its target recorded"
else
    fail "a benign link was not collected, or its target was not recorded"
fi

for p in $PLANTED; do rm -f "$p"; done
PLANTED=""

#############################################################################
printf '\n== 2. a named pipe does not hang the collection, and is recorded ==\n'
for d in $COPIED_DIRS; do
    mkfifo "$d/zz-safeguard-fifo" && plant "$d/zz-safeguard-fifo"
done
if [ -d /etc/profile.d ]; then
    mkfifo /etc/profile.d/zz-safeguard-fifo.sh && plant /etc/profile.d/zz-safeguard-fifo.sh
fi

OUT2="$WORK/fifo"
_t0=`date +%s`
run_collector "$OUT2"
rc=$?
_t1=`date +%s`
P2="$OUT2/SOX-ITGC-AUDIT-LINUX-UNIX"

checks=`expr $checks + 1`
if [ "$rc" = "124" ]; then
    fail "the collection hung on a named pipe (killed by timeout after `expr $_t1 - $_t0`s)"
else
    pass "the collection completed with named pipes present (`expr $_t1 - $_t0`s, exit $rc)"
fi

checks=`expr $checks + 1`
_special=`grep -c '^EXAMINED_SPECIAL|.*zz-safeguard-fifo' "$P2/metadata/MANIFEST.txt" 2>/dev/null`
if [ "${_special:-0}" -ge 1 ]; then
    pass "the manifest records the pipes as examined but not read ($_special entries)"
else
    fail "the pipes left no trace in the manifest"
fi

checks=`expr $checks + 1`
if grep -q 'named pipe, socket, or device' "$P2/metadata/COLLECTION-LOG.txt" 2>/dev/null; then
    pass "the collection log warns about the pipes"
else
    fail "the collection log is silent about the pipes"
fi

for p in $PLANTED; do rm -f "$p"; done
PLANTED=""

#############################################################################
printf '\n== 3. oversized and binary files are capped and disclosed ==\n'
if [ -d /etc/cron.d ]; then
    dd if=/dev/zero of=/etc/cron.d/zz-safeguard-huge bs=1048576 count=70 2>/dev/null && plant /etc/cron.d/zz-safeguard-huge
    dd if=/dev/urandom of=/etc/cron.d/zz-safeguard-binary bs=1024 count=100 2>/dev/null && plant /etc/cron.d/zz-safeguard-binary
    # Text, larger than the print limit but under the copy limit: the report
    # must be cut and say so; the copy must be whole.
    awk 'BEGIN { for (i = 0; i < 120000; i++) print "# line", i, "of a very long configuration file" }' > /etc/cron.d/zz-safeguard-longtext
    plant /etc/cron.d/zz-safeguard-longtext

    OUT3="$WORK/big"
    run_collector "$OUT3"
    P3="$OUT3/SOX-ITGC-AUDIT-LINUX-UNIX"
    R3="$P3/report/SOX-ITGC-AUDIT-REPORT.txt"

    checks=`expr $checks + 1`
    _rsize=`wc -c < "$R3" 2>/dev/null | tr -d ' '`
    if [ "${_rsize:-0}" -lt 20000000 ]; then
        pass "the report stayed readable ($_rsize bytes) with a 70 MB file in /etc/cron.d"
    else
        fail "the report is $_rsize bytes; the oversized file was printed into it"
    fi

    checks=`expr $checks + 1`
    if [ -f "$P3/raw_files/etc/cron.d/zz-safeguard-huge" ]; then
        fail "the 70 MB file was copied into raw_files/"
    elif grep -q '^NOT_COPIED_TOO_LARGE|/etc/cron.d/zz-safeguard-huge|size=73400320|.*checksum=[0-9a-f]' "$P3/metadata/MANIFEST.txt"; then
        pass "the oversized file was recorded with its size and checksum instead of copied"
    else
        fail "the oversized file is neither copied nor properly recorded"
        grep 'zz-safeguard-huge' "$P3/metadata/MANIFEST.txt" | sed 's/^/            /'
    fi

    checks=`expr $checks + 1`
    if LC_ALL=C grep -q '[^[:print:][:space:]]' "$R3" 2>/dev/null; then
        fail "the report contains non-printable bytes"
    else
        pass "no binary content reached the report"
    fi

    checks=`expr $checks + 1`
    if [ -f "$P3/raw_files/etc/cron.d/zz-safeguard-binary" ] && grep -q '^PRINTED_BINARY_OMITTED|/etc/cron.d/zz-safeguard-binary|' "$P3/metadata/MANIFEST.txt"; then
        pass "the binary file was copied for the reviewer and its omission from the report recorded"
    else
        fail "the binary file's copy or its PRINTED_BINARY_OMITTED record is missing"
    fi

    checks=`expr $checks + 1`
    _src_sum=`sha256sum /etc/cron.d/zz-safeguard-longtext | awk '{ print $1 }'`
    _cp_sum=`sha256sum "$P3/raw_files/etc/cron.d/zz-safeguard-longtext" 2>/dev/null | awk '{ print $1 }'`
    if [ "$_src_sum" = "$_cp_sum" ] && grep -q '^PRINTED_TRUNCATED|/etc/cron.d/zz-safeguard-longtext|' "$P3/metadata/MANIFEST.txt" && grep -q 'truncated in this report after' "$R3"; then
        pass "a long text file is cut in the report, disclosed, and copied whole"
    else
        fail "long text handling: copy identical=`[ "$_src_sum" = "$_cp_sum" ] && echo yes || echo no`, truncation recorded=`grep -c '^PRINTED_TRUNCATED|/etc/cron.d/zz-safeguard-longtext|' "$P3/metadata/MANIFEST.txt"`"
    fi

    for p in $PLANTED; do rm -f "$p"; done
    PLANTED=""
else
    skip "/etc/cron.d absent; size cases not exercised"
fi

#############################################################################
printf '\n== 4. an explicit --output-dir that cannot be used is an error, not a fallback ==\n'
checks=`expr $checks + 1`
mkdir -p "$WORK/cwd"
: > "$WORK/cwd/not-a-directory"
( cd "$WORK/cwd" && sh "$COLLECTOR" --output-dir "$WORK/cwd/not-a-directory" </dev/null >"$WORK/cwd/out.txt" 2>"$WORK/cwd/err.txt" )
rc=$?
if [ "$rc" = "1" ] && ! [ -d "$WORK/cwd/SOX-ITGC-AUDIT-LINUX-UNIX" ] && grep -q 'cannot be used' "$WORK/cwd/err.txt"; then
    pass "refused with exit 1 and wrote nothing to the working directory"
else
    fail "exit=$rc; wrote to cwd=`[ -d "$WORK/cwd/SOX-ITGC-AUDIT-LINUX-UNIX" ] && echo yes || echo no`"
    head -3 "$WORK/cwd/err.txt" | sed 's/^/            /'
fi
# A path argument containing a newline was split in two: an --app-dir became
# two directories that did not exist, and the one the operator asked about was
# never listed, with only a "does not exist" warning to say so.
checks=`expr $checks + 1`
sh "$COLLECTOR" --output-dir "$WORK/cwd/nl" --app-dir "$WORK/one
two" </dev/null >/dev/null 2>"$WORK/cwd/nl.err"
_nlrc=$?
if [ "$_nlrc" = "1" ] && grep -q 'newline character' "$WORK/cwd/nl.err" && ! [ -d "$WORK/cwd/nl" ]; then
    pass "an --app-dir containing a newline is refused up front, with nothing written"
else
    fail "newline in --app-dir: exit=$_nlrc, output created=`[ -d "$WORK/cwd/nl" ] && echo yes || echo no`"
fi

#############################################################################
printf '\n== 5. a broken core tool stops the run before anything is collected ==\n'
# The collector pins its own PATH, so a tool can only be "broken" by making
# the real binary unusable. A private mount namespace does that for this
# process alone, leaving the host untouched.
checks=`expr $checks + 1`
if command -v unshare >/dev/null 2>&1 && unshare -m true 2>/dev/null; then
    _awk=`command -v awk`
    : > "$WORK/empty"
    mkdir -p "$WORK/preflight"
    unshare -m sh -c "mount --bind '$WORK/empty' '$_awk' && sh '$COLLECTOR' --output-dir '$WORK/preflight/out' </dev/null >'$WORK/preflight/stdout' 2>'$WORK/preflight/stderr'; echo \$? > '$WORK/preflight/rc'" 2>/dev/null
    _prc=`cat "$WORK/preflight/rc" 2>/dev/null`
    if [ "$_prc" = "1" ] && ! [ -d "$WORK/preflight/out" ] && grep -q 'depends on:.*awk' "$WORK/preflight/stderr"; then
        pass "with awk unusable: exit 1, nothing written, and the message names awk"
    else
        fail "with awk unusable: exit=${_prc:-none}, output dir created=`[ -d "$WORK/preflight/out" ] && echo yes || echo no`"
        head -3 "$WORK/preflight/stderr" 2>/dev/null | sed 's/^/            /'
    fi
else
    skip "cannot create a mount namespace here; preflight not exercised at runtime"
    if grep -q '^preflight_required_tools$' "$COLLECTOR"; then
        pass "the preflight is present and invoked"
    else
        fail "the preflight is not invoked"
    fi
fi

#############################################################################
printf '\n== 6. portability guards that a Linux-only CI cannot exercise at runtime ==\n'
# test -k is not in POSIX test; on a shell without it the sticky-bit check
# reported /tmp as unprotected. grep's \| alternation is GNU-only; on Solaris,
# AIX and HP-UX it silently matches nothing, which turned LDAP/SSSD detection
# off on exactly the platforms it matters on.
checks=`expr $checks + 1`
if grep -q '\[ -k ' "$COLLECTOR"; then
    fail "the collector uses test -k, which is not POSIX"
else
    pass "no test -k in the collector"
fi
checks=`expr $checks + 1`
if grep -E "grep [^']*'[^']*\\\\\|" "$COLLECTOR" | grep -v '^\s*#' | grep -q .; then
    fail "the collector uses GNU-only \\| alternation in a grep pattern:"
    grep -nE "grep [^']*'[^']*\\\\\|" "$COLLECTOR" | grep -v '^\s*#' | sed 's/^/            /'
else
    pass "no GNU-only regex alternation in grep patterns"
fi

#############################################################################
printf '\n== 7. relative and linked paths are recorded absolute and physical ==\n'
# "OUTPUT_DIRECTORY: rel/SOX-ITGC-AUDIT-LINUX-UNIX" in a log read on another
# machine answers nothing. The output directory and every --app-dir are
# anchored at the invocation directory and recorded with links resolved.
checks=`expr $checks + 1`
mkdir -p "$WORK/rel/base/app" "$WORK/rel/real-out"
: > "$WORK/rel/base/app/x.conf"
ln -s "$WORK/rel/real-out" "$WORK/rel/base/out-link"
( cd "$WORK/rel/base" && sh "$COLLECTOR" --output-dir out-link --app-dir app </dev/null >/dev/null 2>&1 )
_rl="$WORK/rel/real-out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt"
_rm="$WORK/rel/real-out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/MANIFEST.txt"
_rw=`cd "$WORK/rel/real-out" && pwd -P`
if grep -q "^OUTPUT_DIRECTORY: $_rw/SOX-ITGC-AUDIT-LINUX-UNIX\$" "$_rl" 2>/dev/null && grep -q "^APP_DIR_LISTED|`cd "$WORK/rel/base/app" && pwd -P`|" "$_rm" 2>/dev/null; then
    pass "output directory and application directory recorded absolute, links resolved"
else
    fail "paths were not recorded absolute and physical:"
    grep -h '^OUTPUT_DIRECTORY:' "$_rl" 2>/dev/null | sed 's/^/            /'
    grep -h '^APP_DIR' "$_rm" 2>/dev/null | sed 's/^/            /'
fi

#############################################################################
printf '\n== 8. the package is not scanned as if it were part of the host ==\n'
# Copies in raw_files/ keep the source mode until the end of the run, so an
# output directory under a scanned root turned a world-writable source into
# a second finding at the copy's path - a path that does not exist on the host.
checks=`expr $checks + 1`
if [ -d /etc/cron.d ] && [ -d /opt ]; then
    printf '# planted\n' > /etc/cron.d/zz-safeguard-ww
    chmod 666 /etc/cron.d/zz-safeguard-ww
    plant /etc/cron.d/zz-safeguard-ww
    mkdir -p /opt/zz-safeguard-audit
    sh "$COLLECTOR" --output-dir /opt/zz-safeguard-audit </dev/null >/dev/null 2>&1
    _sr=/opt/zz-safeguard-audit/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt
    _real=`grep -c '^-rw-rw-rw-.* /etc/cron.d/zz-safeguard-ww$' "$_sr" 2>/dev/null`
    _copy=`grep -c '/opt/zz-safeguard-audit/.*zz-safeguard-ww' "$_sr" 2>/dev/null`
    if [ "${_real:-0}" -ge 1 ] && [ "${_copy:-0}" -eq 0 ]; then
        pass "the world-writable source is found at its real path only, not at the copy's"
    else
        fail "real-path finding=${_real:-0} copy-path finding=${_copy:-0} (want >=1 / 0)"
    fi
    rm -rf /opt/zz-safeguard-audit
    for p in $PLANTED; do rm -f "$p"; done
    PLANTED=""
else
    skip "/etc/cron.d or /opt absent; self-scan case not exercised"
fi

#############################################################################
printf '\n== 9. credential material is recognised by content: hard links and stray copies ==\n'
# A hard link is the same inode under another name. It resolves to itself, its
# path is in no table, and it was copied byte-for-byte into raw_files/. A copy
# of the shadow file left in a configuration directory leaked the same way.
if [ -d /etc/cron.d ] && [ -f /etc/shadow ]; then
    if ln /etc/shadow /etc/cron.d/zz-safeguard-hardlink 2>/dev/null; then
        plant /etc/cron.d/zz-safeguard-hardlink
    fi
    cp /etc/shadow /etc/cron.d/zz-safeguard-copy && plant /etc/cron.d/zz-safeguard-copy
    # A genuine credential table with real hashes, since this host's accounts
    # may all be locked (field 2 = "*") and the shape rule alone would carry it.
    printf 'svc:$6$saltsalt$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ:20000:0:99999:7:::\n' > /etc/cron.d/zz-safeguard-hashline
    plant /etc/cron.d/zz-safeguard-hashline

    OUT9="$WORK/content"
    run_collector "$OUT9"
    P9="$OUT9/SOX-ITGC-AUDIT-LINUX-UNIX"

    checks=`expr $checks + 1`
    _leaked=""
    for f in zz-safeguard-hardlink zz-safeguard-copy zz-safeguard-hashline; do
        [ -f "$P9/raw_files/etc/cron.d/$f" ] && _leaked="$_leaked $f"
    done
    if [ -z "$_leaked" ]; then
        pass "no hard link, copy, or hash-bearing file reached raw_files/"
    else
        fail "credential material reached raw_files/ through:$_leaked"
    fi

    checks=`expr $checks + 1`
    if grep -q "zz-safeguard-copy.*credential material" "$P9/metadata/SENSITIVE_FILES_SKIPPED.txt" 2>/dev/null; then
        pass "the skip list names the copy and says it was withheld for its contents"
    else
        fail "the skip list does not record the withheld copy with a content reason"
        grep 'zz-safeguard' "$P9/metadata/SENSITIVE_FILES_SKIPPED.txt" 2>/dev/null | sed 's/^/            /'
    fi

    checks=`expr $checks + 1`
    if grep -q '\$6\$saltsalt\$' "$P9/report/SOX-ITGC-AUDIT-REPORT.txt" 2>/dev/null; then
        fail "a password hash was printed in the report"
    else
        pass "no password hash reached the report"
    fi

    # The rule must not over-block: the real account and group files, which
    # share the colon-separated shape, must still be collected.
    checks=`expr $checks + 1`
    if [ -f "$P9/raw_files/etc/passwd" ] && [ -f "$P9/raw_files/etc/group" ]; then
        pass "/etc/passwd and /etc/group are still collected"
    else
        fail "the content rule over-blocked /etc/passwd or /etc/group"
    fi

    for p in $PLANTED; do rm -f "$p"; done
    PLANTED=""
else
    skip "/etc/cron.d or /etc/shadow absent; content cases not exercised"
fi

#############################################################################
printf '\n== 10. every scanned root is a real directory, each listed once ==\n'
# POSIX find does not follow a symbolic link given as a starting point. A root
# that is a link - /bin on a merged-/usr host, /opt relocated to a data volume
# - was listed under "Paths scanned" while examining nothing. The manifest
# must name the physical directory that was walked, once.
checks=`expr $checks + 1`
_rm10="$OUT1/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/MANIFEST.txt"
_roots=`grep '^WORLD_WRITABLE_SCAN|files|root=' "$_rm10" 2>/dev/null | cut -d'|' -f3 | sed 's/^root=//'`
_linked=0
_missing=0
printf '%s\n' "$_roots" | while IFS= read -r _r; do
    [ -n "$_r" ] || continue
    if [ -L "$_r" ]; then printf 'LINK %s\n' "$_r"; fi
    if [ ! -d "$_r" ]; then printf 'MISSING %s\n' "$_r"; fi
done > "$WORK/roots.txt"
_dupes=`printf '%s\n' "$_roots" | sort | uniq -d | wc -l | tr -d ' '`
if [ -n "$_roots" ] && [ ! -s "$WORK/roots.txt" ] && [ "$_dupes" = "0" ]; then
    pass "all `printf '%s\n' "$_roots" | grep -c .` recorded scan roots are real directories, none a link, none repeated"
else
    fail "scan roots are not clean: duplicates=$_dupes"
    sed 's/^/            /' "$WORK/roots.txt"
fi

#############################################################################
printf '\n== 11. a filename containing |, %% or a newline cannot corrupt the manifest ==\n'
# The manifest is one record per line with "|" between fields. A file named
# "zz<newline>probe" split its own COPIED record across two lines, and the
# receipt verifier then reported two files missing from a complete package.
if [ -d /etc/cron.d ]; then
    NL_PLANT='/etc/cron.d/zz-safeguard-nl
probe'
    printf '# h\n' > "$NL_PLANT"
    printf '# h\n' > '/etc/cron.d/zz-safeguard-pipe|probe' && plant '/etc/cron.d/zz-safeguard-pipe|probe'
    printf '# h\n' > '/etc/cron.d/zz-safeguard-pct%probe' && plant '/etc/cron.d/zz-safeguard-pct%probe'
    OUT11="$WORK/names"
    run_collector "$OUT11"
    P11="$OUT11/SOX-ITGC-AUDIT-LINUX-UNIX"
    checks=`expr $checks + 1`
    if grep -q '^COPIED|/etc/cron.d/zz-safeguard-nl%0Aprobe|' "$P11/metadata/MANIFEST.txt" && grep -q '^COPIED|/etc/cron.d/zz-safeguard-pipe%7Cprobe|' "$P11/metadata/MANIFEST.txt" && grep -q '^COPIED|/etc/cron.d/zz-safeguard-pct%25probe|' "$P11/metadata/MANIFEST.txt"; then
        pass "each hostile name is one encoded record in the manifest"
    else
        fail "hostile names were not encoded as single records:"
        grep -n -A1 'zz-safeguard-nl\|zz-safeguard-pipe\|zz-safeguard-pct' "$P11/metadata/MANIFEST.txt" | sed 's/^/            /'
    fi
    checks=`expr $checks + 1`
    _arc11=`ls "$OUT11"/*.tar.gz 2>/dev/null | head -1`
    sh "$REPO_ROOT/tools/verify-package.sh" "$_arc11" >"$WORK/verify11.txt" 2>&1
    _vrc=$?
    if [ "$_vrc" -le 1 ] && ! grep -q 'missing from the package' "$WORK/verify11.txt"; then
        pass "the receipt verifier decodes them and finds every copy (exit $_vrc)"
    else
        fail "the verifier rejected a complete package (exit $_vrc):"
        grep -i 'PROBLEM' "$WORK/verify11.txt" | sed 's/^/            /'
    fi
    for p in $PLANTED; do rm -f "$p"; done
    PLANTED=""
    rm -f "$NL_PLANT"
    NL_PLANT=""
else
    skip "/etc/cron.d absent; hostile-name case not exercised"
fi

#############################################################################
printf '\n== 12. a filename that looks like a log column cannot forge the verdict ==\n'
# The verdict is recounted from the collection log by matching the level
# column. Log messages embed host paths verbatim, so a WARN about a file named
# "zz | ERROR | x" once matched the ERROR pattern: a run with no errors was
# COMPLETED_WITH_ERRORS, exit 1, and the verifier rejected the package.
if [ -d /etc/cron.d ]; then
    COL_PLANT='/etc/cron.d/zz-safeguard | ERROR | x'
    mkfifo "$COL_PLANT"
    OUT12="$WORK/logcol"
    run_collector "$OUT12"
    _rc12=$?
    L12="$OUT12/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt"
    _err12=`sed -n 's/^FINAL_ERRORS: //p' "$L12" 2>/dev/null | tail -1`
    _v12=`verdict_of "$OUT12"`
    checks=`expr $checks + 1`
    if [ "$_rc12" = "0" ] && [ "${_err12:-x}" = "0" ] && [ "$_v12" != "COMPLETED_WITH_ERRORS" ] && [ "$_v12" != "FAILED" ]; then
        pass "a WARN about that file is counted as a warning, not an error (verdict $_v12)"
    else
        fail "the filename forged the verdict: exit=$_rc12 errors=${_err12:-none} verdict=$_v12"
    fi
    checks=`expr $checks + 1`
    _arc12=`ls "$OUT12"/*.tar.gz 2>/dev/null | head -1`
    sh "$REPO_ROOT/tools/verify-package.sh" "$_arc12" >/dev/null 2>&1
    _vrc12=$?
    if [ "$_vrc12" -le 1 ]; then
        pass "the receipt verifier counts it the same way (exit $_vrc12)"
    else
        fail "the verifier rejected the package (exit $_vrc12)"
    fi
    rm -f "$COL_PLANT"
    COL_PLANT=""
else
    skip "/etc/cron.d absent; log-column case not exercised"
fi

#############################################################################
printf '\n== 13. terminal escape sequences cannot reach the report, log, or manifest ==\n'
# A cron file containing ESC[2J ESC[H and a forged COLLECTION RESULT line
# reached the report verbatim and was replayed to the operator's terminal,
# which cleared the screen and printed the forgery; an auditor running cat on
# the report gets the same. A filename carrying ESC did the same to the
# manifest. The raw copy must stay byte-exact; everything a person reads
# must not.
if [ -d /etc/cron.d ]; then
    _esc=`printf '\033'`
    COL_PLANT="/etc/cron.d/zz-safeguard-esc${_esc}[31mname"
    printf '# h\n' > "$COL_PLANT"
    printf '# harmless\n%s[2J%s[H%s]0;pwned%s\\\nCOLLECTION RESULT: COMPLETED_CLEAN (forged)\n' "$_esc" "$_esc" "$_esc" "$_esc" > /etc/cron.d/zz-safeguard-esc-content
    plant /etc/cron.d/zz-safeguard-esc-content
    OUT13="$WORK/esc"
    run_collector "$OUT13"
    P13="$OUT13/SOX-ITGC-AUDIT-LINUX-UNIX"
    checks=`expr $checks + 1`
    _escbytes=0
    for f in report/SOX-ITGC-AUDIT-REPORT.txt metadata/COLLECTION-LOG.txt metadata/MANIFEST.txt metadata/SENSITIVE_FILES_SKIPPED.txt; do
        _n=`tr -cd '\033' < "$P13/$f" 2>/dev/null | wc -c | tr -d ' '`
        _escbytes=`expr $_escbytes + ${_n:-0}`
    done
    _term=`tr -cd '\033' < "$OUT13.stdout" 2>/dev/null | wc -c | tr -d ' '`
    if [ "$_escbytes" = "0" ] && [ "${_term:-0}" = "0" ]; then
        pass "no escape byte in the report, log, manifest, skip list, or terminal output"
    else
        fail "escape bytes survived: files=$_escbytes terminal=${_term:-?}"
    fi
    checks=`expr $checks + 1`
    if cmp -s /etc/cron.d/zz-safeguard-esc-content "$P13/raw_files/etc/cron.d/zz-safeguard-esc-content" 2>/dev/null; then
        pass "the raw copy is still byte-exact"
    else
        fail "the raw copy was altered or is missing"
    fi
    checks=`expr $checks + 1`
    _arc13=`ls "$OUT13"/*.tar.gz 2>/dev/null | head -1`
    sh "$REPO_ROOT/tools/verify-package.sh" "$_arc13" >"$WORK/verify13.txt" 2>&1
    _vrc13=$?
    if [ "$_vrc13" -le 1 ] && ! grep -q 'missing from the package' "$WORK/verify13.txt" && grep -q '^COPIED|/etc/cron.d/zz-safeguard-esc%1B\[31mname|' "$P13/metadata/MANIFEST.txt"; then
        pass "the escape in the filename is encoded as %1B and the verifier still finds the copy (exit $_vrc13)"
    else
        fail "encoded-name round trip failed (verifier exit $_vrc13)"
        grep -i 'PROBLEM' "$WORK/verify13.txt" | sed 's/^/            /'
    fi
    rm -f "$COL_PLANT"
    COL_PLANT=""
    for p in $PLANTED; do rm -f "$p"; done
    PLANTED=""
else
    skip "/etc/cron.d absent; escape-sequence case not exercised"
fi

#############################################################################
printf '\n== 14. the run lock refuses a live second launch and ignores a stale one ==\n'
# A second collection launched into the same directory used to delete the
# first run's package mid-collection; both then failed with several hundred
# errors. A lock left by a process that has since died - or whose PID now
# belongs to something unrelated - must not wedge the directory.
checks=`expr $checks + 1`
mkdir -p "$WORK/lock"
sh "$COLLECTOR" --output-dir "$WORK/lock" --app-dir /usr </dev/null >/dev/null 2>&1 &
_first=$!
_w=0
while [ ! -f "$WORK/lock/.sox-itgc-collector.lock" ] && [ "$_w" -lt 30 ]; do sleep 1; _w=`expr $_w + 1`; done
sh "$COLLECTOR" --output-dir "$WORK/lock" </dev/null >"$WORK/lock-second.txt" 2>&1
_second=$?
wait "$_first"
_firstrc=$?
if [ "$_second" = "1" ] && grep -q 'already running' "$WORK/lock-second.txt" && [ "$_firstrc" = "0" ] && [ ! -f "$WORK/lock/.sox-itgc-collector.lock" ]; then
    pass "second launch refused in one line; first run completed (exit $_firstrc); lock removed after"
else
    fail "second=$_second first=$_firstrc lock-left=`[ -f "$WORK/lock/.sox-itgc-collector.lock" ] && echo yes || echo no`"
    head -2 "$WORK/lock-second.txt" | sed 's/^/            /'
fi
checks=`expr $checks + 1`
mkdir -p "$WORK/stale"
printf '1\n' > "$WORK/stale/.sox-itgc-collector.lock"     # PID 1 is alive and is not this script
sh "$COLLECTOR" --output-dir "$WORK/stale" </dev/null >"$WORK/stale-run.txt" 2>&1
_stale=$?
if [ "$_stale" = "0" ]; then
    pass "a lock naming a live, unrelated process is ignored and the run proceeds"
else
    fail "a stale lock naming PID 1 blocked the run (exit $_stale)"
    head -2 "$WORK/stale-run.txt" | sed 's/^/            /'
fi

#############################################################################
printf '\n-----------------------------------------------\n'
printf 'checks: %s   failures: %s\n' "$checks" "$failures"
if [ "$failures" -eq 0 ]; then
    printf 'RESULT: PASS - planted links, pipes and oversized files cannot leak, hang, or bloat the package\n'
    exit 0
fi
printf 'RESULT: FAIL - a content safeguard did not hold\n'
exit 1
