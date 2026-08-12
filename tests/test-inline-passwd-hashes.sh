#!/bin/sh
# Unit test: detection of password hashes stored inline in /etc/passwd.
#
# Why this exists:
# /etc/passwd must stay collectable - the account inventory is core evidence
# referenced by a dozen sections - so it is deliberately NOT in the
# is_sensitive_path() table. On most hosts that is safe, because field 2 holds a
# placeholder and the hash lives in /etc/shadow, which IS withheld.
#
# It is not safe everywhere. HP-UX in its historical non-shadow, non-trusted
# configuration keeps the crypt hash directly in field 2 of /etc/passwd, and
# shadowing there is opt-in rather than default. On such a host the credential
# material this collector exists to withhold would be copied into raw_files/
# through the front door.
#
# The guard is therefore a CONTENT test rather than a path test, and this file
# asserts it against fixtures representing each convention. A credential guard
# that has never been demonstrated to fire is not a guard, so the positive cases
# below - the ones that must be detected as hash-bearing - are the point.
#
# Hermetic: uses fixture files, so HP-UX and AIX conventions are checked on a
# Linux runner.
#
# Usage: sh tests/test-inline-passwd-hashes.sh
# Exit:  0 = all assertions passed, 1 = at least one failed

set -u

REPO_ROOT=`CDPATH= cd -- "\`dirname -- "$0"\`/.." && pwd`
COLLECTOR="$REPO_ROOT/linux-unix-evidence-gathering-script.sh"

if [ ! -f "$COLLECTOR" ]; then
    printf 'FAIL: collector not found at %s\n' "$COLLECTOR" >&2
    exit 1
fi

WORK=`mktemp -d`
trap 'rm -rf "$WORK"' EXIT INT TERM

# Extract only the pure content check, so sourcing it cannot run the collector.
sed -n '/^file_has_inline_password_hashes()/,/^}/p' "$COLLECTOR" > "$WORK/fn.sh"
if [ ! -s "$WORK/fn.sh" ]; then
    printf 'FAIL: could not extract file_has_inline_password_hashes() from the collector\n' >&2
    exit 1
fi
# shellcheck source=/dev/null
. "$WORK/fn.sh"

failures=0
checked=0

# Must be detected as carrying credential material.
assert_hashes() {
    _label=$1
    _content=$2
    checked=`expr $checked + 1`
    printf '%s\n' "$_content" > "$WORK/passwd"
    if file_has_inline_password_hashes "$WORK/passwd"; then
        printf 'ok        detected hashes: %s\n' "$_label"
    else
        printf 'NOT OK    LEAK RISK - hashes not detected: %s\n' "$_label"
        failures=`expr $failures + 1`
    fi
}

# Must NOT be flagged: no credential material present. A false positive here
# redacts the account inventory on a host that never needed it, which silently
# degrades evidence, so over-detection matters too.
assert_no_hashes() {
    _label=$1
    _content=$2
    checked=`expr $checked + 1`
    printf '%s\n' "$_content" > "$WORK/passwd"
    if file_has_inline_password_hashes "$WORK/passwd"; then
        printf 'NOT OK    FALSE POSITIVE - evidence needlessly redacted: %s\n' "$_label"
        failures=`expr $failures + 1`
    else
        printf 'ok        no hashes present: %s\n' "$_label"
    fi
}

printf '== hosts that store hashes inline must be detected ==\n'

# HP-UX non-shadow: the case this guard exists for. Traditional DES crypt.
assert_hashes 'HP-UX non-shadow, DES crypt in field 2' \
'root:Ax9kQ1mZbCdEf:0:3::/:/sbin/sh
oracle:zZ8pLmNqRsTuV:101:20::/home/oracle:/usr/bin/sh
daemon:*:1:5::/:/sbin/sh'

# Modern crypt formats, in case a host was migrated but never shadowed.
assert_hashes 'MD5 crypt ($1$) in field 2' \
'root:$1$abcdefgh$ZyXwVuTsRqPoNmLkJiHgF0:0:0::/root:/bin/sh'

assert_hashes 'SHA-512 crypt ($6$) in field 2' \
'jdoe:$6$saltsalt$LongHashValueGoesHere123456789:1001:1001::/home/jdoe:/bin/sh'

assert_hashes 'yescrypt ($y$) in field 2' \
'jdoe:$y$j9T$abcdefghijklmnop$qrstuvwxyz0123456789:1001:1001::/home/jdoe:/bin/sh'

# A single compromised account among many placeholders must still be caught.
assert_hashes 'one hashed account among many shadowed accounts' \
'root:x:0:0::/root:/bin/bash
bin:x:1:1::/bin:/sbin/nologin
legacy:Ax9kQ1mZbCdEf:500:500::/home/legacy:/bin/sh
nobody:x:99:99::/:/sbin/nologin'

printf '\n== placeholder conventions must NOT be flagged ==\n'

assert_no_hashes 'Linux / Solaris shadow indirection (x)' \
'root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
jdoe:x:1000:1000::/home/jdoe:/bin/bash'

assert_no_hashes 'locked and no-login accounts (*, !, !!)' \
'root:*:0:0::/root:/bin/sh
svc:!:101:101::/var/empty:/sbin/nologin
old:!!:102:102::/var/empty:/sbin/nologin'

assert_no_hashes 'AIX shadow indirection (##username)' \
'root:##root:0:0::/:/usr/bin/ksh
esaadmin:##esaadmin:8:8::/var/esa:/usr/bin/ksh'

assert_no_hashes 'Solaris no-password / locked markers (NP, *NP*, *LK*)' \
'listen:*LK*:37:4:Network Admin:/usr/net/nls:
noaccess:NP:60002:60002:No Access User:/:
nobody4:*NP*:65534:65534:SunOS 4.x Nobody:/:'

assert_no_hashes 'empty field 2 (no password set)' \
'guest::1002:1002::/home/guest:/bin/sh'

assert_no_hashes 'NIS netgroup directives are not accounts' \
'root:x:0:0::/root:/bin/sh
+@sysadmins:::::
+::::::
-baduser:::::'

assert_no_hashes 'comments and blank lines' \
'# local accounts only

root:x:0:0::/root:/bin/sh
'

printf '\n== degenerate input must not crash or false-positive ==\n'
assert_no_hashes 'empty file' ''
assert_no_hashes 'malformed line with no field 2' 'garbagewithnocolons'

# An unreadable or absent file must return "no hashes" rather than erroring:
# the caller uses this to decide whether to redact, and a hard failure there
# would break collection of a file that is usually perfectly safe.
checked=`expr $checked + 1`
if file_has_inline_password_hashes "$WORK/does-not-exist"; then
    printf 'NOT OK    absent file reported as hash-bearing\n'
    failures=`expr $failures + 1`
else
    printf 'ok        absent file handled without error\n'
fi

printf '\n-----------------------------------------------\n'
printf 'assertions: %s   failures: %s\n' "$checked" "$failures"
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS\n'
exit 0
