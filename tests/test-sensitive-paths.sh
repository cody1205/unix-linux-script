#!/bin/sh
# Unit test: is_sensitive_path() classification table.
#
# The collector must never copy credential-bearing files into the evidence
# package, and must still collect policy files that merely describe controls.
# This test extracts is_sensitive_path() from the collector and asserts the
# classification of a fixed table of paths across Linux, AIX, Solaris, and
# HP-UX conventions.
#
# This is the primary guard for the class of defect where a platform's
# password-hash store is not recognized as sensitive: it is hermetic and does
# not depend on the OS the test runs under, so an AIX-only or HP-UX-only path
# is still checked on a Linux CI runner.
#
# Usage: sh tests/test-sensitive-paths.sh
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

# Extract just the classification function so sourcing it cannot run the
# collector's main flow.
sed -n '/^is_sensitive_path()/,/^}/p' "$COLLECTOR" > "$WORK/is_sensitive_path.sh"
if [ ! -s "$WORK/is_sensitive_path.sh" ]; then
    printf 'FAIL: could not extract is_sensitive_path() from the collector\n' >&2
    exit 1
fi
# shellcheck source=/dev/null
. "$WORK/is_sensitive_path.sh"

failures=0
checked=0

# Must be treated as sensitive: contents are never printed or copied.
assert_sensitive() {
    checked=`expr $checked + 1`
    if is_sensitive_path "$1"; then
        printf 'ok        protected: %s\n' "$1"
    else
        printf 'NOT OK    LEAK RISK - must be protected but is not: %s\n' "$1"
        failures=`expr $failures + 1`
    fi
}

# Must NOT be treated as sensitive: these are control-evidence files the
# auditor needs in raw_files/. Over-blocking silently guts the evidence.
assert_collectable() {
    checked=`expr $checked + 1`
    if is_sensitive_path "$1"; then
        printf 'NOT OK    OVER-BLOCKED - evidence file withheld: %s\n' "$1"
        failures=`expr $failures + 1`
    else
        printf 'ok        collectable: %s\n' "$1"
    fi
}

printf '== credential stores must be protected ==\n'
# Linux / Solaris
assert_sensitive /etc/shadow
assert_sensitive /etc/gshadow
# AIX: password hashes and password-history hashes live here, not /etc/shadow
assert_sensitive /etc/security/passwd
assert_sensitive /etc/security/opasswd
assert_sensitive /etc/opasswd
assert_sensitive /etc/security/passwd.conf
# AIX LDAP client config embeds the directory bind password
assert_sensitive /etc/security/ldap/ldap.cfg
# Directory / Kerberos secrets
assert_sensitive /etc/sssd/sssd.conf
assert_sensitive /etc/krb5.keytab
assert_sensitive /etc/krb5/krb5.keytab
assert_sensitive /etc/ldap.secret

printf '\n== key material and trust files must be protected ==\n'
assert_sensitive /root/.ssh/id_rsa
assert_sensitive /root/.ssh/authorized_keys
assert_sensitive /home/jdoe/.ssh/authorized_keys
assert_sensitive /home/jdoe/.ssh/id_ed25519
assert_sensitive /home/oracle/.rhosts
assert_sensitive /home/oracle/.shosts
assert_sensitive /etc/ssl/private/server.key
assert_sensitive /etc/pki/tls/certs/client.pem

printf '\n== control-evidence files must remain collectable ==\n'
assert_collectable /etc/passwd
assert_collectable /etc/group
assert_collectable /etc/sudoers
assert_collectable /etc/sudoers.d/10_break_glass
assert_collectable /etc/ssh/sshd_config
assert_collectable /etc/login.defs
assert_collectable /etc/security/pwquality.conf
# AIX password/login POLICY stanzas - no hashes, required for the report
assert_collectable /etc/security/user
assert_collectable /etc/security/login.cfg
assert_collectable /etc/security/audit/config
# HP-UX password policy - no hashes
assert_collectable /etc/default/passwd
assert_collectable /etc/default/login
assert_collectable /etc/pam.conf
assert_collectable /etc/pam.d/system-auth
assert_collectable /etc/nsswitch.conf
assert_collectable /etc/syslog.conf
assert_collectable /etc/inittab

printf '\n== classify_source_file: one outcome per file, and the right one ==\n'
# Three routes used to decide independently what happened to a source file, and
# they disagreed three times - most subtly by recording a file as BOTH
# "could not be read" and "deliberately withheld". They now share
# classify_source_file, so a contradiction is impossible by construction; what
# still needs asserting is that the single answer it gives is the CORRECT one.
#
# The ordering property is the one that matters: for a credential file the
# contents were never going to be delivered, so being unable to read them
# changes nothing about the package. It must classify as withheld, not as an
# evidence gap.
sed -n '/^path_exists()/,/^}/p'          "$COLLECTOR" >  "$WORK/cls.sh"
sed -n '/^classify_source_file()/,/^}/p' "$COLLECTOR" >> "$WORK/cls.sh"
# shellcheck source=/dev/null
. "$WORK/cls.sh"

assert_class() {
    checked=`expr $checked + 1`
    _got=`classify_source_file "$2"`
    if [ "$_got" = "$3" ]; then
        printf 'ok        %s -> %s\n' "$1" "$_got"
    else
        printf 'NOT OK    %s: expected %s, got %s\n' "$1" "$3" "$_got"
        failures=`expr $failures + 1`
    fi
}

printf 'plain\n' > "$WORK/normal.conf"
printf 'key\n'   > "$WORK/server.key"      # matches the *.key sensitive rule

assert_class "absent path"                    "$WORK/nothing-here"  absent
assert_class "ordinary readable file"         "$WORK/normal.conf"   collectable
assert_class "credential file, readable"      "$WORK/server.key"    withheld

# Root can read anything, so the unreadable cases only mean something when the
# test is not running as root. Skipped loudly rather than silently passing.
if [ "`id -u`" = "0" ]; then
    printf 'SKIP      unreadable cases need a non-root run (root bypasses mode bits)\n'
else
    chmod 000 "$WORK/normal.conf" "$WORK/server.key"
    assert_class "ordinary file, unreadable"      "$WORK/normal.conf"   unreadable
    assert_class "credential file, UNREADABLE"    "$WORK/server.key"    withheld
    printf '          ^ the ordering property: withheld outranks unreadable, so a\n'
    printf '            credential file is never reported as an evidence gap\n'
    chmod 644 "$WORK/normal.conf" "$WORK/server.key"
fi

printf '\n-----------------------------------------------\n'
printf 'assertions: %s   failures: %s\n' "$checked" "$failures"
if [ "$failures" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS\n'
exit 0
