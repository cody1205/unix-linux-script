#!/bin/sh
# End-to-end test: run the real collector and prove the evidence package
# contains no credential material, and that the manifest is honest.
#
# Plants sentinel "credentials" into paths the collector reads on this platform,
# runs a full collection into a temporary output directory, then asserts:
#   1. no sentinel value appears anywhere under raw_files/
#   2. no generic credential pattern (hash / private key) appears under raw_files/
#   3. each planted credential file is recorded in SENSITIVE_FILES_SKIPPED.txt
#   4. every COPIED| manifest entry actually exists under raw_files/
#      (the chain-of-custody promise: nothing is claimed that was not delivered)
#
# Requires root, because the collector requires root for a full collection and
# the sentinels must be planted under /etc. Planted files are removed and any
# pre-existing versions restored on exit. Intended for ephemeral CI runners.
#
# Usage: sudo sh tests/test-no-credential-leak.sh

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

SENTINEL='SENTINEL_CREDENTIAL_MUST_NOT_LEAK_9f3a2b7c'
WORK=`mktemp -d`
OUT="$WORK/out"
PLANTED="$WORK/planted.list"
: > "$PLANTED"

# Plant a file, remembering whether it already existed so it can be restored.
plant() {
    _p=$1
    _content=$2
    mkdir -p "`dirname "$_p"`" 2>/dev/null || return 0
    if [ -e "$_p" ]; then
        cp -p "$_p" "$WORK/backup`echo "$_p" | tr / _`" 2>/dev/null
        printf 'restore %s\n' "$_p" >> "$PLANTED"
    else
        printf 'remove %s\n' "$_p" >> "$PLANTED"
    fi
    printf '%s\n' "$_content" > "$_p" 2>/dev/null || return 0
    chmod 600 "$_p" 2>/dev/null
    printf '  planted %s\n' "$_p"
}

cleanup() {
    while read -r _action _path; do
        case "$_action" in
            remove)  rm -f "$_path" 2>/dev/null ;;
            restore) cp -p "$WORK/backup`echo "$_path" | tr / _`" "$_path" 2>/dev/null ;;
        esac
    done < "$PLANTED"
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

printf '== planting sentinel credentials ==\n'
# Directory secret with an embedded bind password (read on Linux, section 3).
plant /etc/sssd/sssd.conf "[sssd]
domains = test.example
[domain/test.example]
id_provider = ldap
ldap_default_authtok = $SENTINEL"
# SSH key material in a home directory listed in /etc/passwd (section 14).
plant /root/.ssh/authorized_keys \
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA${SENTINEL} test@fixture"
# AIX-convention hash store. Not read by the Linux code path, but planting it
# proves it is never swept up incidentally by a directory-expanding reference.
plant /etc/security/passwd "root:
	password = {ssha512}06\$$SENTINEL
	lastupdate = 1717243200"

# Small application tree so the app-dir section has something to list.
APPFIX="$WORK/appfixture"
mkdir -p "$APPFIX/bin" "$APPFIX/conf"
printf '#!/bin/sh\nexit 0\n' > "$APPFIX/bin/run.sh"
printf 'tier=TEST\n' > "$APPFIX/conf/app.conf"

printf '\n== running collector ==\n'
sh "$COLLECTOR" --output-dir "$OUT" --app-dir "$APPFIX" </dev/null >"$WORK/console.txt" 2>&1
collector_rc=$?
printf 'collector exit: %s\n' "$collector_rc"

E="$OUT/SOX-ITGC-AUDIT-LINUX-UNIX"
REPORT="$E/report/SOX-ITGC-AUDIT-REPORT.txt"
MANIFEST="$E/metadata/MANIFEST.txt"
SKIPPED="$E/metadata/SENSITIVE_FILES_SKIPPED.txt"

failures=0
fail() {
    printf 'NOT OK    %s\n' "$1"
    failures=`expr $failures + 1`
}
pass() {
    printf 'ok        %s\n' "$1"
}

if [ "$collector_rc" -ne 0 ]; then
    fail "collector exited non-zero ($collector_rc)"
    tail -20 "$WORK/console.txt" >&2
fi
for required in "$REPORT" "$MANIFEST" "$SKIPPED"; do
    if [ -s "$required" ]; then
        pass "produced `basename "$required"`"
    else
        fail "missing or empty: $required"
    fi
done

if [ ! -d "$E/raw_files" ]; then
    fail "no raw_files/ directory produced"
    printf '\nRESULT: FAIL\n'
    exit 1
fi

printf '\n== 1. sentinel must not appear in raw_files/ ==\n'
if grep -rl "$SENTINEL" "$E/raw_files" >"$WORK/hits" 2>/dev/null && [ -s "$WORK/hits" ]; then
    fail "sentinel credential leaked into the evidence package:"
    sed 's/^/            /' "$WORK/hits" >&2
else
    pass "no sentinel value in any collected file"
fi

printf '\n== 2. no credential patterns in raw_files/ ==\n'
# shadow-family hashes, AIX hashes, and PEM private keys
if grep -rlE '\$[0-9y]\$[./A-Za-z0-9]|\{ssha[0-9]+\}|BEGIN [A-Z ]*PRIVATE KEY' \
        "$E/raw_files" >"$WORK/pat" 2>/dev/null && [ -s "$WORK/pat" ]; then
    fail "credential-shaped content found in collected files:"
    sed 's/^/            /' "$WORK/pat" >&2
else
    pass "no hash or private-key patterns in collected files"
fi

printf '\n== 3. planted credentials recorded as skipped ==\n'
for p in /etc/sssd/sssd.conf /root/.ssh/authorized_keys; do
    if [ ! -f "$p" ]; then
        continue
    fi
    if grep -qF "$p" "$SKIPPED" 2>/dev/null || grep -qF "SENSITIVE_METADATA_ONLY|$p" "$MANIFEST" 2>/dev/null; then
        pass "tracked as sensitive: $p"
    else
        fail "read but not recorded as sensitive: $p"
    fi
done

printf '\n== 4. every COPIED manifest entry exists in raw_files/ ==\n'
missing=0
copied=0
while IFS= read -r line; do
    case "$line" in
        COPIED\|*) ;;
        *) continue ;;
    esac
    src=`printf '%s' "$line" | sed 's/^COPIED|//' | cut -d'|' -f1`
    copied=`expr $copied + 1`
    if [ ! -f "$E/raw_files$src" ]; then
        printf '            claimed but absent: %s\n' "$src" >&2
        missing=`expr $missing + 1`
    fi
done < "$MANIFEST"
if [ "$missing" -ne 0 ]; then
    fail "$missing of $copied COPIED entries are not present in raw_files/"
else
    pass "all $copied COPIED entries present in raw_files/"
fi

printf '\n-----------------------------------------------\n'
printf 'failures: %s\n' "$failures"
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS\n'
exit 0
