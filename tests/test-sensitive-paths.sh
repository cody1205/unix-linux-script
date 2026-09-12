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
# The backup copies passwd, useradd and pwconv leave beside the live file. They
# hold the same hashes and exist on every Linux host.
assert_sensitive /etc/shadow-
assert_sensitive /etc/gshadow-
assert_sensitive /etc/shadow.bak
assert_sensitive /etc/security/passwd.bak

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
sed -n '/^canonical_path()/,/^}/p'       "$COLLECTOR" >> "$WORK/cls.sh"
sed -n '/^directory_is_physical()/,/^}/p' "$COLLECTOR" >> "$WORK/cls.sh"
sed -n '/^symlink_target_off_limits()/,/^}/p' "$COLLECTOR" >> "$WORK/cls.sh"
sed -n '/^file_contains_credential_material()/,/^}/p' "$COLLECTOR" >> "$WORK/cls.sh"
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

# What a path DENOTES is classified, not how it is spelled. A link at an
# innocent name that leads to a credential file was followed and copied before
# this was true - /etc/shadow arrived in raw_files/ as /etc/cron.d/x.
ln -s "$WORK/server.key"  "$WORK/innocent-name.conf"
ln -s "$WORK/normal.conf" "$WORK/benign-link.conf"
mkdir -p "$WORK/linked-dir-target" "$WORK/home/.ssh"
printf 'k\n' > "$WORK/home/.ssh/id_rsa"              # sensitive by the */.ssh/id_* rule
ln -s "$WORK/home/.ssh/id_rsa" "$WORK/plain-name"    # an innocent name leading to key material
assert_class "link to a credential file, innocent name"   "$WORK/innocent-name.conf" withheld
assert_class "link to an ordinary file"                   "$WORK/benign-link.conf"   collectable
assert_class "innocent name leading to key material"      "$WORK/plain-name"         withheld
assert_class "dangling link"                              "$WORK/dangling"           absent
ln -s "$WORK/dangling-target-missing" "$WORK/dangling"
assert_class "dangling link (present, target absent)"     "$WORK/dangling"           absent
ln -s "$WORK/loop-b" "$WORK/loop-a"; ln -s "$WORK/loop-a" "$WORK/loop-b"
assert_class "symbolic link loop"                         "$WORK/loop-a"             absent

# Something that exists but is not a file. Its contents are never read: a
# pipe with no writer blocks forever, and the collection with it.
if mkfifo "$WORK/pipe.conf" 2>/dev/null; then
    assert_class "named pipe where a file is expected"    "$WORK/pipe.conf"          special
fi
assert_class "a directory"                                "$WORK/linked-dir-target"  special

# Credential material recognised by CONTENT. A hard link to /etc/shadow is the
# same inode under an innocent name: it resolves to itself and no path rule
# can see it, yet it was copied byte-for-byte. The bytes are what is judged.
printf 'root:$6$saltsalt$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ:20000:0:99999:7:::\n' > "$WORK/one-hash.txt"
printf 'root:*:20501:0:99999:7:::\ndaemon:*:20501:0:99999:7:::\nbin:!:20501:0:99999:7:::\n' > "$WORK/locked-shadow.txt"
printf 'root:*::\ndaemon:!::\nsudo:!::\n' > "$WORK/gshadow-shape.txt"
printf 'root:x:0:\ndaemon:x:1:\nsudo:x:27:alice\n' > "$WORK/group-like.txt"
printf '0 5 * * * root /usr/bin/backup >/dev/null 2>&1\n# comment: with colons 1:2:3:4:5:6:7:8\n' > "$WORK/crontab-like.txt"
printf 'alice:100000:65536\nbob:165536:65536\n' > "$WORK/subuid-like.txt"
printf 'web:$apr1$abcdefgh$ijklmnopqrstuvwxyz012\n' > "$WORK/htpasswd-like.txt"
assert_class "one line with a crypt hash in field 2"      "$WORK/one-hash.txt"       withheld
assert_class "shadow-shaped table, all accounts locked"   "$WORK/locked-shadow.txt"  withheld
assert_class "gshadow-shaped table"                       "$WORK/gshadow-shape.txt"  withheld
assert_class "htpasswd-style hash line"                   "$WORK/htpasswd-like.txt"  withheld
assert_class "/etc/group-shaped file (no hashes)"         "$WORK/group-like.txt"     collectable
assert_class "crontab with colons in a comment"           "$WORK/crontab-like.txt"   collectable
assert_class "subuid-shaped numeric table"                "$WORK/subuid-like.txt"    collectable

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
