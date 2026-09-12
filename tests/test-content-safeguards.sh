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
printf '\n== 15. a terminal that goes away mid-run does not kill the collection ==\n'
# "sudo ./script | head", "| less" quit early, "| tee" killed: the collector
# writes a progress line to the terminal during the run, and with SIGPIPE at
# its default the first write after the reader exits killed the shell itself
# - mid-collection, exit 141, no verdict, no archive, lock left behind.
checks=`expr $checks + 1`
mkdir -p "$WORK/pipe"
( sh "$COLLECTOR" --output-dir "$WORK/pipe" </dev/null 2>"$WORK/pipe-stderr.txt"; printf '%s\n' "$?" > "$WORK/pipe-rc.txt" ) | head -n 3 >/dev/null
_prc=`cat "$WORK/pipe-rc.txt" 2>/dev/null`
_pv=`verdict_of "$WORK/pipe"`
_parc=`ls "$WORK/pipe"/*.tar.gz 2>/dev/null | wc -l | tr -d ' '`
# What stderr must not carry is the symptom itself - a broken-pipe complaint.
# Other stderr noise is the host's tools (a CI runner's systemctl with no bus,
# say) and is not what this case is about.
if [ "${_prc:-141}" -le 1 ] && [ -n "$_pv" ] && [ "$_parc" = "1" ] && [ ! -f "$WORK/pipe/.sox-itgc-collector.lock" ] && ! grep -qi 'broken pipe' "$WORK/pipe-stderr.txt" 2>/dev/null; then
    pass "piped into head: exit $_prc, verdict $_pv, archive built, no lock left, no broken-pipe error"
else
    fail "piped into head: exit=${_prc:-none} verdict=${_pv:-none} archive=$_parc lock=`[ -f "$WORK/pipe/.sox-itgc-collector.lock" ] && echo left || echo removed` stderr=`wc -l < "$WORK/pipe-stderr.txt" 2>/dev/null` lines"
    head -5 "$WORK/pipe-stderr.txt" 2>/dev/null | sed 's/^/            /'
fi

#############################################################################
printf '\n== 16. a name service that never answers cannot hang the collection ==\n'
# getent resolves through the host's resolver, and a directory server that is
# down blocks it for the resolver's retry cycle - or forever. A getent that
# never answered hung the collection until it was killed. Each query is now
# bounded; the first timeout marks the name service unusable and the account
# sections read the local files instead. Exercised with a getent that sleeps,
# bind-mounted over the real one in a private mount namespace.
checks=`expr $checks + 1`
if command -v unshare >/dev/null 2>&1 && unshare -m true 2>/dev/null && command -v getent >/dev/null 2>&1; then
    mkdir -p "$WORK/ns"
    printf '#!/bin/sh\nsleep 600\n' > "$WORK/ns/fake-getent"
    chmod 755 "$WORK/ns/fake-getent"
    _getent=`command -v getent`
    _t0=`date +%s`
    unshare -m sh -c "mount --bind '$WORK/ns/fake-getent' '$_getent' && timeout 300 sh '$COLLECTOR' --output-dir '$WORK/ns/out' </dev/null >/dev/null 2>&1; echo \$? > '$WORK/ns/rc'" 2>/dev/null
    _t1=`date +%s`
    _nrc=`cat "$WORK/ns/rc" 2>/dev/null`
    _nl="$WORK/ns/out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt"
    _nm="$WORK/ns/out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/MANIFEST.txt"
    _nr="$WORK/ns/out/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt"
    _elapsed=`expr $_t1 - $_t0`
    if [ "$_nrc" = "0" ] && [ "$_elapsed" -lt 200 ] && grep -q '^NAME_SERVICE_TIMEOUT|' "$_nm" 2>/dev/null && grep -q 'did not answer' "$_nl" 2>/dev/null && grep -q '^root:0:' "$_nr" 2>/dev/null; then
        pass "completed in ${_elapsed}s with one bounded timeout, a WARN, and local accounts listed from /etc/passwd"
    else
        fail "hanging name service: exit=${_nrc:-none} elapsed=${_elapsed}s timeout-recorded=`grep -c '^NAME_SERVICE_TIMEOUT|' "$_nm" 2>/dev/null` local-users=`grep -c '^root:0:' "$_nr" 2>/dev/null`"
    fi
    # The fake getent's own sleep is an orphan of the fixture, not the collector:
    # the collector killed the getent wrapper, and the sleep it had started was
    # re-parented to init. Both are ended here so the test leaves nothing behind.
    for _sp in `ps -eo pid,args 2>/dev/null | awk '($2 == "sleep" && $3 == "600") || $0 ~ /fake-getent/ { print $1 }'`; do kill "$_sp" 2>/dev/null; done
    sleep 1
else
    skip "cannot create a mount namespace here; name-service timeout not exercised"
    if grep -q '^name_service_query()' "$COLLECTOR"; then
        pass "the bounded name-service query is present"
    else
        fail "the bounded name-service query is missing"
    fi
fi

#############################################################################
printf '\n== 17. a host command that never returns cannot hang the collection ==\n'
# df blocks on a stale NFS mount; rpm waits for a package-manager lock;
# systemctl on a wedged bus; ntpq resolving peer names. A df that never
# answered hung the collection until it was killed. Each such command runs
# under a bound; a timeout is noted in the section, logged, and recorded.
checks=`expr $checks + 1`
if command -v unshare >/dev/null 2>&1 && unshare -m true 2>/dev/null && command -v df >/dev/null 2>&1; then
    mkdir -p "$WORK/df"
    printf '#!/bin/sh\nsleep 600\n' > "$WORK/df/fake-df"
    chmod 755 "$WORK/df/fake-df"
    _df=`command -v df`
    _t0=`date +%s`
    unshare -m sh -c "mount --bind '$WORK/df/fake-df' '$_df' && timeout 300 sh '$COLLECTOR' --output-dir '$WORK/df/out' </dev/null >/dev/null 2>&1; echo \$? > '$WORK/df/rc'" 2>/dev/null
    _t1=`date +%s`
    _drc=`cat "$WORK/df/rc" 2>/dev/null`
    _dm="$WORK/df/out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/MANIFEST.txt"
    _dr="$WORK/df/out/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt"
    _delapsed=`expr $_t1 - $_t0`
    if [ "$_drc" = "0" ] && [ "$_delapsed" -lt 200 ] && grep -q '^COMMAND_TIMEOUT|df' "$_dm" 2>/dev/null && grep -q 'did not finish within' "$_dr" 2>/dev/null; then
        pass "completed in ${_delapsed}s; the stopped df is recorded and the section says so"
    else
        fail "hanging df: exit=${_drc:-none} elapsed=${_delapsed}s timeout-recorded=`grep -c '^COMMAND_TIMEOUT|df' "$_dm" 2>/dev/null`"
    fi
    for _sp in `ps -eo pid,args 2>/dev/null | awk '($2 == "sleep" && $3 == "600") || $0 ~ /fake-df/ { print $1 }'`; do kill "$_sp" 2>/dev/null; done
    sleep 1
else
    skip "cannot create a mount namespace here; host-command timeout not exercised"
    if grep -q '^bounded_host_command()' "$COLLECTOR"; then
        pass "the bounded host-command runner is present"
    else
        fail "the bounded host-command runner is missing"
    fi
fi

#############################################################################
printf '\n== 18. a filesystem walk that never returns cannot hang the collection ==\n'
# find -xdev keeps a scan from crossing INTO a network mount, but a scan root
# that is itself on a dead mount hangs find before it walks anything, and so
# did the recursive --app-dir listing. Exercised with a find that hangs only
# when asked to walk the --app-dir root and behaves normally for every other
# root, so the assertion is that ONE root costs one bound while the rest of
# the evidence is still collected. Also asserts what the first version of the
# fix got wrong: the timeout note went into the captured list as if it were
# a path, the hung process tree was left running on the host, and the shell
# announced "Terminated" on the console every time the watchdog fired.
checks=`expr $checks + 1`
if command -v unshare >/dev/null 2>&1 && unshare -m true 2>/dev/null && command -v find >/dev/null 2>&1; then
    mkdir -p "$WORK/fs/dead-root/sub" "$WORK/fs/out"
    printf 'x\n' > "$WORK/fs/dead-root/sub/app.conf"
    _find=`command -v find`
    cp "$_find" "$WORK/fs/find.real"
    printf '#!/bin/sh\ncase "$1" in\n    %s*) exec sleep 600 ;;\nesac\nexec %s "$@"\n' "$WORK/fs/dead-root" "$WORK/fs/find.real" > "$WORK/fs/fake-find"
    chmod 755 "$WORK/fs/fake-find" "$WORK/fs/find.real"
    _t0=`date +%s`
    unshare -m sh -c "mount --bind '$WORK/fs/fake-find' '$_find' && timeout 900 sh '$COLLECTOR' --output-dir '$WORK/fs/out' --app-dir '$WORK/fs/dead-root' </dev/null >/dev/null 2>'$WORK/fs/stderr'; echo \$? > '$WORK/fs/rc'" 2>/dev/null
    _t1=`date +%s`
    _frc=`cat "$WORK/fs/rc" 2>/dev/null`
    _fm="$WORK/fs/out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/MANIFEST.txt"
    _fr="$WORK/fs/out/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt"
    _felapsed=`expr $_t1 - $_t0`
    _orphans=`ps -eo pid,args 2>/dev/null | awk '($2 == "sleep" && $3 == "600") { n++ } END { print n + 0 }'`
    _timeouts=`grep -c '^SCAN_TIMEOUT|' "$_fm" 2>/dev/null`
    _other_roots=`grep -c '^WORLD_WRITABLE_SCAN|files|root=' "$_fm" 2>/dev/null`
    if [ "$_frc" = "0" ] && [ "$_felapsed" -lt 600 ] && [ "$_timeouts" = "1" ] && grep -q "^SCAN_TIMEOUT|root=$WORK/fs/dead-root|" "$_fm" 2>/dev/null \
        && [ "${_other_roots:-0}" -ge 2 ] && grep -q 'NOTE: the scan of .*did not finish within' "$_fr" 2>/dev/null; then
        pass "completed in ${_felapsed}s: one bound for the dead root, the other $_other_roots roots still scanned, the report says so"
    else
        fail "hanging find: exit=${_frc:-none} elapsed=${_felapsed}s scan-timeouts=$_timeouts other-roots=$_other_roots"
    fi
    checks=`expr $checks + 1`
    if [ "$_orphans" = "0" ]; then
        pass "the stopped walk's process tree is gone from the host"
    else
        fail "$_orphans process(es) from the stopped walk were left running on the host"
    fi
    checks=`expr $checks + 1`
    if grep -q 'Terminated' "$WORK/fs/stderr" 2>/dev/null; then
        fail "the shell announced 'Terminated' on the console when the watchdog fired"
    elif grep -q 'Under .*NOTE:\|^NOTE: the scan of.*(metadata not available)' "$_fr" 2>/dev/null; then
        fail "the timeout note was captured into a finding list as if it were a path"
    else
        pass "nothing on the console, and the note stands on its own in the report"
    fi
    for _sp in `ps -eo pid,args 2>/dev/null | awk '($2 == "sleep" && $3 == "600") || $0 ~ /fake-find/ { print $1 }'`; do kill "$_sp" 2>/dev/null; done
    sleep 1
else
    skip "cannot create a mount namespace here; scan timeout not exercised"
    if grep -q '^bounded_scan()' "$COLLECTOR"; then
        pass "the bounded scan runner is present"
    else
        fail "the bounded scan runner is missing"
    fi
fi

#############################################################################
printf '\n== 19. an interrupted collection stops at once and leaves nothing running ==\n'
# A shell blocked reading a command substitution does not run its traps until
# the substitution finishes, so a kill sent to a collector stuck in a scan
# was ignored for the length of the scan's bound - 240 seconds - and the
# handler, when it finally ran, left the scan's process tree and the
# watchdog's sleep running on the host. Bounded work now runs where the
# shell sits in "wait", which every shell interrupts at once, and the
# handler's first act is to stop every process the collector started.
# SIGTERM is used because a job started from a non-interactive shell has
# SIGINT ignored; the handler is the same for both.
checks=`expr $checks + 1`
if command -v unshare >/dev/null 2>&1 && unshare -m true 2>/dev/null && [ -x "$WORK/fs/fake-find" ]; then
    mkdir -p "$WORK/fs/int"
    _t0=`date +%s`
    unshare -m sh -c "mount --bind '$WORK/fs/fake-find' '$_find' && sh '$COLLECTOR' --output-dir '$WORK/fs/int' --app-dir '$WORK/fs/dead-root' </dev/null >/dev/null 2>'$WORK/fs/int.stderr' & p=\$!; sleep 20; kill -TERM \$p; wait \$p; echo \$? > '$WORK/fs/int.rc'" 2>/dev/null
    _t1=`date +%s`
    _irc=`cat "$WORK/fs/int.rc" 2>/dev/null`
    _il="$WORK/fs/int/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt"
    _ir="$WORK/fs/int/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt"
    _ielapsed=`expr $_t1 - $_t0`
    _iorphans=`ps -eo pid,args 2>/dev/null | awk '($2 == "sleep" && ($3 == "600" || $3 == "240")) { n++ } END { print n + 0 }'`
    if [ "$_ielapsed" -lt 40 ] && grep -q '^RESULT: FAILED' "$_il" 2>/dev/null && grep -q '^INTERRUPTED_BY: SIGTERM' "$_il" 2>/dev/null && grep -q 'COLLECTION INTERRUPTED' "$_ir" 2>/dev/null; then
        pass "the handler ran within `expr $_ielapsed - 20`s of the signal (exit $_irc), and the package says it is incomplete"
    else
        fail "interrupt during a scan: exit=${_irc:-none} elapsed=${_ielapsed}s (signal at 20s) verdict=`sed -n 's/^RESULT: //p' "$_il" 2>/dev/null | head -1`"
    fi
    checks=`expr $checks + 1`
    if [ "$_iorphans" = "0" ] && [ ! -f "$WORK/fs/int/.sox-itgc-collector.lock" ] && [ "`ls -a "$WORK/fs/int" 2>/dev/null | grep -c '^\.sox-itgc-'`" = "0" ]; then
        pass "no scan, watchdog, lock or scratch file left behind"
    else
        fail "left behind: orphans=$_iorphans lock=`ls "$WORK/fs/int/.sox-itgc-collector.lock" 2>/dev/null | wc -l` scratch=`ls -a "$WORK/fs/int" 2>/dev/null | grep -c '^\.sox-itgc-'`"
    fi
    for _sp in `ps -eo pid,args 2>/dev/null | awk '($2 == "sleep" && ($3 == "600" || $3 == "240")) || $0 ~ /fake-find/ { print $1 }'`; do kill "$_sp" 2>/dev/null; done
    sleep 1
else
    skip "cannot create a mount namespace here; interruption during a scan not exercised"
    if grep -q '^kill_descendants()' "$COLLECTOR"; then
        pass "the interruption handler's process cleanup is present"
    else
        fail "the interruption handler's process cleanup is missing"
    fi
fi

#############################################################################
printf '\n== 20. twenty thousand local accounts do not take nine minutes ==\n'
# passwd -S and chage -l were run once per account, and each reads the whole
# shadow file: 20,000 accounts took 531 seconds in two subsections, against
# 5 seconds for everything else. The same fields are now derived in one pass
# over the two files. The assertion is the time, the row count, and that the
# hash column became a status word rather than reaching the report.
checks=`expr $checks + 1`
if command -v unshare >/dev/null 2>&1 && unshare -m true 2>/dev/null; then
    mkdir -p "$WORK/acct/out"
    cp /etc/passwd "$WORK/acct/passwd"; cp /etc/shadow "$WORK/acct/shadow"; cp /etc/group "$WORK/acct/group"
    awk 'BEGIN { for (i = 1; i <= 20000; i++) printf "bulk%05d:x:%d:%d:Bulk account %d:/home/bulk%05d:/bin/sh\n", i, 30000 + i, 30000 + i, i, i }' >> "$WORK/acct/passwd"
    awk 'BEGIN { for (i = 1; i <= 20000; i++) printf "bulk%05d:$6$saltsalt$QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ:19000:0:90:7:14::\n", i }' >> "$WORK/acct/shadow"
    awk 'BEGIN { for (i = 1; i <= 20000; i++) printf "bulk%05d:x:%d:\n", i, 30000 + i }' >> "$WORK/acct/group"
    _t0=`date +%s`
    unshare -m sh -c "mount --bind '$WORK/acct/passwd' /etc/passwd && mount --bind '$WORK/acct/shadow' /etc/shadow && mount --bind '$WORK/acct/group' /etc/group && timeout 600 sh '$COLLECTOR' --output-dir '$WORK/acct/out' </dev/null >/dev/null 2>&1; echo \$? > '$WORK/acct/rc'" 2>/dev/null
    _t1=`date +%s`
    _arc=`cat "$WORK/acct/rc" 2>/dev/null`
    _ar="$WORK/acct/out/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt"
    _aelapsed=`expr $_t1 - $_t0`
    _arows=`grep -c '^bulk[0-9]* *P *2022-01-08 ' "$_ar" 2>/dev/null`
    _aexp=`grep -c '^bulk20000 *2022-01-08 *2022-04-08 *2022-04-22 *never ' "$_ar" 2>/dev/null`
    if [ "$_arc" = "0" ] && [ "$_aelapsed" -lt 180 ] && [ "$_arows" = "20000" ] && [ "$_aexp" = "1" ]; then
        pass "completed in ${_aelapsed}s with all 20,000 accounts in the status table and the expiry dates computed"
    else
        fail "20,000 accounts: exit=${_arc:-none} elapsed=${_aelapsed}s status-rows=$_arows expiry-row-for-bulk20000=$_aexp"
    fi
    checks=`expr $checks + 1`
    if grep -q 'saltsalt' "$_ar" 2>/dev/null || grep -rq 'saltsalt' "$WORK/acct/out/SOX-ITGC-AUDIT-LINUX-UNIX/raw_files" 2>/dev/null; then
        fail "a password hash from the shadow file reached the package"
    else
        pass "no password hash reached the report or the copied files"
    fi
else
    skip "cannot create a mount namespace here; account-count scaling not exercised"
    if grep -q '^print_account_status_from_shadow()' "$COLLECTOR"; then
        pass "the one-pass account status table is present"
    else
        fail "the one-pass account status table is missing"
    fi
fi

#############################################################################
printf '\n== 21. a root or a home directory that never answers costs one bound ==\n'
# Before any walk, each scan root is stat-ed and resolved physically, and
# the home-directory review stats every local account's home: on a hard NFS
# mount whose server is gone, each of those blocks in the kernel. Neither
# can be produced on demand without a dead NFS server, so the bounded
# functions are exercised with their probes replaced by ones that hang for
# a chosen path, under a short bound, and the assertions are about what the
# collector does around the hang: the dead root is skipped and recorded, the
# live roots still come back, a second look does not pay the bound again,
# and a review stopped mid-way keeps what it had.
checks=`expr $checks + 1`
mkdir -p "$WORK/probe"
sed -n '/^process_table()/,/^}/p; /^process_tree_pids()/,/^}/p; /^kill_process_tree()/,/^}/p; /^bounded_run_to_file()/,/^}/p; /^bounded_run()/,/^}/p; /^scan_output_file()/,/^}/p; /^scan_skip_file()/,/^}/p; /^scan_root_skipped()/,/^}/p; /^scan_root_timed_out()/,/^}/p; /^probe_scan_root()/,/^}/p; /^physical_unique_roots()/,/^}/p; /^print_scan_skip_notes()/,/^}/p; /^absolute_directory()/,/^}/p; /^print_home_review_bounded()/,/^}/p' "$COLLECTOR" > "$WORK/probe/functions.sh"
cat > "$WORK/probe/check.sh" <<'PROBE'
. "$1"
WORKING_DIRECTORY=$2; INVOCATION_DIRECTORY=/; SCAN_TIMEOUT_SECONDS=240; ROOT_PROBE_TIMEOUT_SECONDS=3; HOME_REVIEW_TIMEOUT_SECONDS=3
log_event() { printf 'LOG %s %s: %s\n' "$1" "$2" "$3" >> "$WORKING_DIRECTORY/log"; }
record_manifest_line() { printf '%s\n' "$1" >> "$WORKING_DIRECTORY/manifest"; }
manifest_path() { printf '%s' "$1"; }
no_entries_found() { echo "no entries found"; }
probe_scan_root() { case "$1" in /dead*) sleep 600 ;; esac; [ -d "$1" ] || return 1; absolute_directory "$1"; }
t0=`date +%s`
roots=`printf '/etc\n/dead/mount\n/nonexistent-zz\n/usr/bin\n/etc\n' | physical_unique_roots | tr '\n' ' '`
t1=`expr \`date +%s\` - $t0`
again=`printf '/dead/mount\n/etc\n' | physical_unique_roots | tr '\n' ' '`
t2=`expr \`date +%s\` - $t0`
slow_review() { echo "User: a"; echo "User: b"; sleep 600; echo "User: never"; }
review=`print_home_review_bounded home_directory_review slow_review | tr '\n' '|'`
printf 'roots=[%s] first=%ss again=[%s] total=%ss\n' "$roots" "$t1" "$again" "$t2"
printf 'skip=[%s] manifest=[%s]\n' "`tr '\n' ' ' < \"\`scan_skip_file\`\"`" "`tr '\n' ' ' < $WORKING_DIRECTORY/manifest`"
printf 'review=[%s]\n' "$review"
printf 'orphans=%s\n' "`ps -e -o args= | grep -c '^sleep 600'`"
PROBE
sh "$WORK/probe/check.sh" "$WORK/probe/functions.sh" "$WORK/probe" > "$WORK/probe/out" 2>&1
if grep -q '^roots=\[/etc /usr/bin \] first=[0-9]s again=\[/etc \] total=[0-9]s$' "$WORK/probe/out" \
    && grep -q '^skip=\[/dead/mount \] manifest=\[SCAN_TIMEOUT|root=/dead/mount|seconds=3 SECTION_TIMEOUT|home_directory_review|seconds=3|partial=yes \]$' "$WORK/probe/out" \
    && grep -q '^review=\[User: a|User: b|NOTE: this review did not finish within 3 seconds' "$WORK/probe/out" \
    && grep -q '^orphans=0$' "$WORK/probe/out"; then
    pass "dead root skipped once and recorded, live roots returned, partial home review kept, nothing left running"
else
    fail "bounded probes: `tr '\n' ' ' < "$WORK/probe/out" | cut -c1-300`"
fi
for _sp in `ps -eo pid,args 2>/dev/null | awk '($2 == "sleep" && $3 == "600") { print $1 }'`; do kill "$_sp" 2>/dev/null; done

#############################################################################
printf '\n== 22. argument edge cases are refused or normalised, never half-applied ==\n'
# An empty --app-dir value was reported as "contains a newline"; the same
# directory named twice ("/opt" and "/opt/") was listed twice in full; and a
# package written inside its own --app-dir appeared in the listing with no
# explanation.
mkdir -p "$WORK/args/out" "$WORK/args/app/sub"
checks=`expr $checks + 1`
_e1=`sh "$COLLECTOR" --output-dir "$WORK/args/out" --app-dir '' </dev/null 2>&1 >/dev/null; echo "rc=$?"`
_e2=`sh "$COLLECTOR" --output-dir "$WORK/args/out" --app-dir= </dev/null 2>&1 >/dev/null; echo "rc=$?"`
if printf '%s' "$_e1" | grep -q 'empty value' && printf '%s' "$_e1" | grep -q 'rc=1' && printf '%s' "$_e2" | grep -q 'empty value' && printf '%s' "$_e2" | grep -q 'rc=1'; then
    pass "an empty --app-dir value is refused up front, in both spellings, and says why"
else
    fail "empty --app-dir: [`printf '%s' "$_e1" | tr '\n' ' '`] [`printf '%s' "$_e2" | tr '\n' ' '`]"
fi
checks=`expr $checks + 1`
rm -rf "$WORK/args/out"; mkdir -p "$WORK/args/out"
sh "$COLLECTOR" --output-dir "$WORK/args/out" --app-dir "$WORK/args/app" --app-dir "$WORK/args/app/" </dev/null >/dev/null 2>&1
_am="$WORK/args/out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/MANIFEST.txt"
if [ "`grep -c '^APP_DIR_LISTED|' "$_am" 2>/dev/null`" = "1" ]; then
    pass "the same directory named twice is listed once"
else
    fail "duplicate --app-dir produced `grep -c '^APP_DIR_LISTED|' "$_am" 2>/dev/null` listings"
fi
checks=`expr $checks + 1`
rm -rf "$WORK/args/out"; mkdir -p "$WORK/args/app/out"
sh "$COLLECTOR" --output-dir "$WORK/args/app/out" --app-dir "$WORK/args/app" </dev/null >/dev/null 2>&1
_am="$WORK/args/app/out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/MANIFEST.txt"
_arp="$WORK/args/app/out/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt"
if grep -q '^APP_DIR_CONTAINS_PACKAGE|' "$_am" 2>/dev/null && grep -q 'evidence package itself' "$_arp" 2>/dev/null; then
    pass "a package written inside its own --app-dir is pointed out in the listing and recorded"
else
    fail "package inside app-dir: record=`grep -c '^APP_DIR_CONTAINS_PACKAGE|' "$_am" 2>/dev/null` note=`grep -c 'evidence package itself' "$_arp" 2>/dev/null`"
fi
rm -rf "$WORK/args"

#############################################################################
printf '\n== 23. a root with hundreds of SetUID files is capped and disclosed, like Section 9 ==\n'
# 600 SetUID files planted under an --app-dir were listed in full, with no
# sign that the population was abnormal. Section 9 has always capped its
# findings per root and said so; Section 10 now does the same.
checks=`expr $checks + 1`
mkdir -p "$WORK/suid/app" "$WORK/suid/out"
_i=1
while [ "$_i" -le 600 ]; do : > "$WORK/suid/app/s$_i"; _i=`expr $_i + 1`; done
chmod 4755 "$WORK/suid/app"/s*
sh "$COLLECTOR" --output-dir "$WORK/suid/out" --app-dir "$WORK/suid/app" </dev/null >/dev/null 2>&1
_sm="$WORK/suid/out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/MANIFEST.txt"
_sr="$WORK/suid/out/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt"
_sl="$WORK/suid/out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt"
_listed=`sed -n '/^SetUID Files:/,/^SetGID Files:/p' "$_sr" 2>/dev/null | grep -c "^$WORK/suid/app/s"`
if [ "$_listed" = "500" ] && grep -q "^PRIVILEGED_BIT_SCAN|setuid|root=$WORK/suid/app|entries=more than 500|listed=500|truncated=yes" "$_sm" 2>/dev/null \
    && grep -q 'more than 500 SetUID files exist under this root' "$_sr" 2>/dev/null && grep -q ' | WARN  | .*SetUID files exist under' "$_sl" 2>/dev/null; then
    pass "500 of 600 listed under that root, with the note, the WARN and the manifest's truncated=yes"
else
    fail "SetUID cap: listed=$_listed record=`grep -c "^PRIVILEGED_BIT_SCAN|setuid|root=$WORK/suid/app|" "$_sm" 2>/dev/null` note=`grep -c 'more than 500 SetUID' "$_sr" 2>/dev/null`"
fi
rm -rf "$WORK/suid"

#############################################################################
printf '\n== 24. a sudo operator the directory cannot resolve does not hang the handover ==\n'
# The operator on a directory-joined host is usually a directory account.
# "id" looked it up and "chown" took its name, both through the resolver:
# with the directory server down, a collection that had survived every
# other lookup hung at the very end, after the archive was written. The
# lookup is now bounded and numeric, and paid once - the first version
# cached it in a subshell and paid the bound twice.
checks=`expr $checks + 1`
if command -v unshare >/dev/null 2>&1 && unshare -m true 2>/dev/null && command -v id >/dev/null 2>&1; then
    mkdir -p "$WORK/hand/out"
    _id=`command -v id`
    cp "$_id" "$WORK/hand/id.real"
    printf '#!/bin/sh\ncase "$*" in *ldapoperator*) exec sleep 600 ;; esac\nexec %s "$@"\n' "$WORK/hand/id.real" > "$WORK/hand/fake-id"
    chmod 755 "$WORK/hand/fake-id" "$WORK/hand/id.real"
    _t0=`date +%s`
    unshare -m sh -c "mount --bind '$WORK/hand/fake-id' '$_id' && SUDO_USER=ldapoperator timeout 300 sh '$COLLECTOR' --output-dir '$WORK/hand/out' </dev/null >/dev/null 2>&1; echo \$? > '$WORK/hand/rc'" 2>/dev/null
    _t1=`date +%s`
    _hrc=`cat "$WORK/hand/rc" 2>/dev/null`
    _hl="$WORK/hand/out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt"
    _helapsed=`expr $_t1 - $_t0`
    _hwarns=`grep -c ' | WARN  | handover    | .*could not be resolved' "$_hl" 2>/dev/null`
    if [ "$_hrc" = "0" ] && [ "$_helapsed" -lt 150 ] && [ "$_hwarns" = "1" ] && [ "`ls "$WORK/hand/out"/*.tar.gz 2>/dev/null | wc -l`" = "1" ] \
        && [ "`ls -ld "$WORK/hand/out/SOX-ITGC-AUDIT-LINUX-UNIX" | awk '{ print $3 }'`" = "root" ]; then
        pass "completed in ${_helapsed}s with one bound paid, one WARN, the archive written and the package left to root"
    else
        fail "unresolvable SUDO_USER: exit=${_hrc:-none} elapsed=${_helapsed}s warns=$_hwarns archive=`ls "$WORK/hand/out"/*.tar.gz 2>/dev/null | wc -l`"
    fi
    for _sp in `ps -eo pid,args 2>/dev/null | awk '($2 == "sleep" && $3 == "600") || $0 ~ /fake-id/ { print $1 }'`; do kill "$_sp" 2>/dev/null; done
    sleep 1
else
    skip "cannot create a mount namespace here; handover resolution not exercised"
    if grep -q '^resolve_handover_owner()' "$COLLECTOR"; then
        pass "the bounded, numeric handover resolution is present"
    else
        fail "the bounded, numeric handover resolution is missing"
    fi
fi

#############################################################################
printf '\n== 25. the preflight knows what the time bounds themselves depend on ==\n'
# Every bound is a sleep in a watchdog, and every tree kill starts from ps.
# A sleep that cannot run made each bound a silent no-op; a ps that cannot
# list processes leaves a stopped command's children running. The first is
# refused up front like the other required tools; the second is a warning
# on the console and in the log, because the collection is still sound.
checks=`expr $checks + 1`
if command -v unshare >/dev/null 2>&1 && unshare -m true 2>/dev/null; then
    mkdir -p "$WORK/pf/out"
    printf '#!/bin/sh\nexit 1\n' > "$WORK/pf/broken"; chmod 755 "$WORK/pf/broken"
    _sleep=`command -v sleep`; _ps=`command -v ps`
    unshare -m sh -c "mount --bind '$WORK/pf/broken' '$_sleep' && sh '$COLLECTOR' --output-dir '$WORK/pf/out' </dev/null >/dev/null 2>'$WORK/pf/sleep.err'; echo \$? > '$WORK/pf/sleep.rc'" 2>/dev/null
    if [ "`cat "$WORK/pf/sleep.rc" 2>/dev/null`" = "1" ] && grep -q 'depends on:.*sleep' "$WORK/pf/sleep.err" 2>/dev/null && [ "`ls "$WORK/pf/out" | wc -l`" = "0" ]; then
        pass "a sleep that cannot run is refused before anything is collected"
    else
        fail "broken sleep: rc=`cat "$WORK/pf/sleep.rc" 2>/dev/null` stderr=`head -c 100 "$WORK/pf/sleep.err" 2>/dev/null | tr '\n' ' '`"
    fi
    checks=`expr $checks + 1`
    rm -rf "$WORK/pf/out"; mkdir -p "$WORK/pf/out"
    unshare -m sh -c "mount --bind '$WORK/pf/broken' '$_ps' && sh '$COLLECTOR' --output-dir '$WORK/pf/out' </dev/null >/dev/null 2>'$WORK/pf/ps.err'; echo \$? > '$WORK/pf/ps.rc'" 2>/dev/null
    _pl="$WORK/pf/out/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt"
    if [ "`cat "$WORK/pf/ps.rc" 2>/dev/null`" = "0" ] && grep -q '^WARNING: ps cannot list' "$WORK/pf/ps.err" 2>/dev/null && grep -q ' | WARN  | startup     | ps cannot list' "$_pl" 2>/dev/null \
        && [ "`ls "$WORK/pf/out"/*.tar.gz 2>/dev/null | wc -l`" = "1" ]; then
        pass "a ps that cannot list processes is a warning on the console and in the log, and the collection completes"
    else
        fail "broken ps: rc=`cat "$WORK/pf/ps.rc" 2>/dev/null` console=`grep -c 'ps cannot list' "$WORK/pf/ps.err" 2>/dev/null` logged=`grep -c 'ps cannot list' "$_pl" 2>/dev/null`"
    fi
    rm -rf "$WORK/pf"
else
    skip "cannot create a mount namespace here; preflight of sleep and ps not exercised"
    if grep -q 'PREFLIGHT_PS_USABLE=no' "$COLLECTOR" && grep -q '_pf_missing sleep' "$COLLECTOR"; then
        pass "the sleep requirement and the ps warning are present"
    else
        fail "the sleep requirement or the ps warning is missing"
    fi
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
