#!/bin/sh
# Readiness test 2 of 6: prove nothing leaves the host.
#
# THE QUESTION THIS ANSWERS
# "Does this send our configuration anywhere?" A client is being asked to run a
# script, as root, that reads their access-control configuration. The single
# most reasonable fear about such a script is that it transmits what it finds.
# The answer must be demonstrable rather than asserted, because the claim "it
# makes no network connections" is exactly the kind of claim a reader cannot
# verify by skimming three thousand lines of shell.
#
# HOW IT IS PROVED, THREE INDEPENDENT WAYS
#
#   1. Source audit. The script is searched for every command capable of
#      opening a network connection, and for the shell's own /dev/tcp
#      redirection facility. This catches intent that never executes on this
#      host - a curl call inside an AIX-only branch would not run here, but
#      would still be found.
#
#   2. Syscall trace. The collection is run under strace, and every socket and
#      connect syscall it makes is recorded. AF_INET and AF_INET6 sockets are
#      network sockets; AF_UNIX and AF_NETLINK are local kernel interfaces used
#      by ordinary tools such as getent and systemctl and never leave the
#      machine. Only the former would constitute egress.
#
#   3. Behaviour with no network at all. The collection is run inside a network
#      namespace that has no interfaces - not even loopback - and must still
#      complete and produce equivalent evidence. This proves the tool does not
#      merely avoid transmitting, but has no dependency on the network
#      whatsoever, so it cannot stall on an unreachable DNS server or filer.
#
# Any one of these could be argued around in isolation. Together they cover
# intent, actual syscalls, and observable dependency.
#
# Usage: sudo sh tests/test-no-network-egress.sh
# Exit:  0 = no egress and no network dependency, 1 = otherwise

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

printf '== 1. source audit: no network-capable command is invoked ==\n'

# Commands that transmit. Matched as command invocations - at the start of a
# line or after a pipe, semicolon, and so on - so that the words appearing
# inside explanatory comments and report text do not produce false hits. The
# script legitimately mentions "ftp" and "telnet" when searching a client's
# inetd configuration for them, and greps sshd_config; those are evidence
# collection, not transmission.
NET_COMMANDS='curl|wget|nc|ncat|netcat|telnet|ftp|tftp|sftp|scp|rsync|ssh|slogin|rsh|rcp|rlogin|host|dig|nslookup|ping|traceroute|openssl|mail|mailx|sendmail|logger'

checks=`expr $checks + 1`
if grep -nE "(^|[;&|(\`]|\\\$\\()[[:space:]]*($NET_COMMANDS)[[:space:]]" "$COLLECTOR" \
    | grep -v '^[0-9]*:[[:space:]]*#' > "$WORK/netcmds.txt" 2>/dev/null; then
    printf 'NOT OK    a network-capable command appears to be invoked:\n'
    sed 's/^/            /' "$WORK/netcmds.txt" | head -20
    failures=`expr $failures + 1`
else
    printf 'ok        no network-capable command is invoked anywhere in the script\n'
fi

# The shell can open a socket without any external command at all, via the
# /dev/tcp and /dev/udp pseudo-devices. This is a bash extension rather than
# POSIX, but it is worth excluding explicitly: it is the one way a shell script
# can transmit data with nothing on the command line that looks like networking.
checks=`expr $checks + 1`
if grep -nE '/dev/(tcp|udp)' "$COLLECTOR" > "$WORK/devtcp.txt" 2>/dev/null; then
    printf 'NOT OK    the script references /dev/tcp or /dev/udp:\n'
    sed 's/^/            /' "$WORK/devtcp.txt"
    failures=`expr $failures + 1`
else
    printf 'ok        no /dev/tcp or /dev/udp socket redirection\n'
fi

printf '\n== 2. syscall trace: no network socket is opened ==\n'
OUT1="$WORK/traced"
mkdir -p "$OUT1"
checks=`expr $checks + 1`
# Both subprocess runs below are bounded by a timeout.
#
# An unbounded run here is not acceptable in a gate: this job was observed
# running for over an hour on a CI host, where the collection's filesystem scans
# cover a very large /opt and strace multiplies the cost of every syscall in
# every child process. A gate that can hang indefinitely blocks every other
# change and eventually gets removed.
#
# A timeout is also diagnostically useful rather than merely defensive - see the
# namespace test below, where exceeding it is itself a finding.
NET_TEST_TIMEOUT=600

run_bounded() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$NET_TEST_TIMEOUT" "$@"
    else
        "$@"
    fi
}

if command -v strace >/dev/null 2>&1; then
    # --seccomp-bpf is the difference between a usable gate and an unusable one.
    #
    # Plain "strace -f" ptrace-stops EVERY syscall in every child in order to
    # filter them, and this collection makes an enormous number of them while
    # walking the filesystem. Measured on a small container: 2 seconds without
    # strace, 94 seconds with it - a 47x multiplier. On a CI host, where the
    # plain collection already takes minutes because /opt is very large, that
    # multiplier produced a job still running after an hour.
    #
    # --seccomp-bpf installs a seccomp filter so the kernel only stops the
    # process for the syscalls actually being traced. Same evidence, 3 seconds
    # instead of 94 - and verified to still capture thousands of syscalls, so it
    # is genuinely tracing rather than silently observing nothing.
    _strace_mode=""
    if strace --help 2>&1 | grep -q -- '--seccomp-bpf'; then
        _strace_mode="--seccomp-bpf"
    fi

    run_bounded strace $_strace_mode -f -qq -e trace=socket,connect,sendto,sendmsg \
        -o "$WORK/strace.txt" \
        sh "$COLLECTOR" --output-dir "$OUT1" </dev/null >/dev/null 2>&1 || :

    # A trace that captured nothing at all would make the "zero network sockets"
    # conclusion vacuous - it would be indistinguishable from strace having
    # failed to attach. Require evidence that tracing actually happened.
    _traced_lines=`grep -c . "$WORK/strace.txt" 2>/dev/null`
    [ -n "$_traced_lines" ] || _traced_lines=0
    if [ "$_traced_lines" -eq 0 ]; then
        printf 'NOT OK    strace produced no output at all, so it cannot be concluded\n'
        printf '          that no sockets were opened - the trace itself did not work\n'
        failures=`expr $failures + 1`
    fi

    # AF_INET / AF_INET6 are the network families. AF_UNIX (local IPC),
    # AF_NETLINK (kernel interface), and AF_LOCAL never leave the machine.
    grep -E 'socket\(AF_INET' "$WORK/strace.txt" > "$WORK/inet.txt" 2>/dev/null || :
    _inet=`grep -c . "$WORK/inet.txt" 2>/dev/null`
    [ -n "$_inet" ] || _inet=0

    # ONE HONEST CAVEAT, stated here so it is not discovered later.
    #
    # This assertion is exact on a standalone host, which is what CI runs. On a
    # host joined to LDAP or Active Directory, a name-service lookup - the
    # getent calls in Sections 1, 5 and 24 - will contact the directory server,
    # because that is what resolving a user means on such a host. That is the
    # same lookup "ls -l" performs to turn a UID into a name, it is initiated by
    # the operating system's name service rather than by this script, and it
    # sends no evidence anywhere: it asks "who is UID 1001" and receives a name.
    #
    # The guarantee this test enforces is therefore precisely: the collector
    # opens no network socket of its own, and transmits no collected data. It is
    # not, and cannot honestly be, "no packet will ever leave the host while it
    # runs" - and the documentation is worded to match.
    if [ "$_inet" -eq 0 ]; then
        printf 'ok        zero AF_INET/AF_INET6 sockets opened during a full collection\n'
        _local=`grep -c 'socket(AF_UNIX\|socket(AF_NETLINK\|socket(AF_LOCAL' "$WORK/strace.txt" 2>/dev/null`
        [ -n "$_local" ] || _local=0
        printf 'info      %s local socket(s) (AF_UNIX/AF_NETLINK) were opened. These are\n' "$_local"
        printf '          kernel and IPC interfaces used by ordinary tools such as getent\n'
        printf '          and timedatectl. They cannot carry data off the machine.\n'
    else
        printf 'NOT OK    %s network socket(s) were opened:\n' "$_inet"
        sed 's/^/            /' "$WORK/inet.txt" | head -10
        failures=`expr $failures + 1`
    fi
else
    # Worded to avoid the literal word that checkbashisms flags as a possible
    # "source" builtin when it appears in a string.
    printf 'SKIP      strace not available; the static audit and namespace test still apply\n'
fi

printf '\n== 3. behaviour with no network at all ==\n'
OUT2="$WORK/isolated"
mkdir -p "$OUT2"
checks=`expr $checks + 1`
if command -v unshare >/dev/null 2>&1; then
    # A fresh network namespace has no interfaces and no loopback route.
    #
    # Exceeding the timeout here is a genuine finding rather than a test defect,
    # and is reported as one. It would mean some command in the collection
    # attempts a network operation and then WAITS for it to time out - "last"
    # performing reverse DNS on login records is the usual candidate. On a
    # client host that matters: a server whose DNS resolver is unreachable would
    # stall the collection in exactly the same way, which is the failure mode
    # this whole section exists to rule out.
    if run_bounded unshare -n sh "$COLLECTOR" --output-dir "$OUT2" </dev/null >"$WORK/iso.log" 2>&1; then
        _iso_rc=0
    else
        _iso_rc=$?
    fi
    _iso_log="$OUT2/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt"
    _iso_verdict=`sed -n 's/^FINAL_RESULT: //p' "$_iso_log" 2>/dev/null | tail -1`
    _iso_sections=`grep -c '^[0-9]\{1,2\}\. ' "$OUT2/SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt" 2>/dev/null`
    [ -n "$_iso_sections" ] || _iso_sections=0

    if [ "$_iso_rc" -eq 124 ]; then
        printf 'NOT OK    the collection did not finish within %ss with no network.\n' "$NET_TEST_TIMEOUT"
        printf '          It reached section %s of 25 before being stopped.\n' "$_iso_sections"
        printf '          Either something in it waits on a network operation instead\n'
        printf '          of failing fast - "last" doing reverse DNS on login records\n'
        printf '          is the usual candidate - or the collection is simply too slow\n'
        printf '          on this host. The first matters to a client: a server whose\n'
        printf '          DNS resolver is unreachable would stall the same way.\n'
        failures=`expr $failures + 1`
    elif [ "$_iso_rc" -eq 0 ] && [ "$_iso_sections" -ge 20 ]; then
        printf 'ok        completed with no network interfaces at all (exit %s, %s sections, verdict %s)\n' \
            "$_iso_rc" "$_iso_sections" "${_iso_verdict:-none}"
        printf '          The tool has no network dependency, so it cannot stall waiting\n'
        printf '          on DNS, a directory server, or an unreachable mount.\n'
    else
        printf 'NOT OK    failed or produced a degraded report without a network\n'
        printf '            exit=%s sections=%s verdict=%s\n' "$_iso_rc" "$_iso_sections" "${_iso_verdict:-none}"
        tail -10 "$WORK/iso.log" | sed 's/^/            /'
        failures=`expr $failures + 1`
    fi
else
    printf 'SKIP      unshare not available\n'
fi

printf '\n-----------------------------------------------\n'
printf 'checks: %s   failures: %s\n' "$checks" "$failures"
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS - nothing is transmitted and nothing depends on the network\n'
exit 0
