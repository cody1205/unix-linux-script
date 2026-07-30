# common.sh - shared harness for the multi-OS simulation tests.
#
# Sourced by the os_*.sh builders. Each builder describes one long-lived company
# server: a themed root filesystem plus command shims that make the collector
# believe it is running on that operating system. The harness then runs the
# UNMODIFIED collector inside a chroot and asserts properties of the evidence
# package it produces.
#
# Why simulate instead of booting VMs: AIX runs only on IBM POWER and HP-UX only
# on PA-RISC/Itanium, so neither can boot on x86 at all. These fixtures drive the
# collector's real per-OS code paths (uname dispatch, platform-specific files and
# commands) against realistic data. See README.md for the fidelity caveats.
#
# Environment overrides:
#   SIM_WORK   base working directory        (default ${TMPDIR:-/tmp}/sox-itgc-sim)
#   COLLECTOR  path to the script under test (default the repo's collector)
#   KEEP_ROOT  set to any value to leave the chroot mounted for inspection
#
# Requires root: chroot and bind mounts. Everything it creates lives under
# SIM_WORK; it makes no change to the host outside that directory.

set -u

SIM_DIR=`CDPATH= cd -- "\`dirname -- "$0"\`" && pwd`
REPO_ROOT=`CDPATH= cd -- "$SIM_DIR/../.." && pwd`
COLLECTOR=${COLLECTOR:-$REPO_ROOT/linux-unix-evidence-gathering-script.sh}
SIM_WORK=${SIM_WORK:-${TMPDIR:-/tmp}/sox-itgc-sim}
KEEP_ROOT=${KEEP_ROOT:-}

# ---- values each os_*.sh sets before calling sim_main ----------------------
OS_KEY=""      # short name, e.g. rhel
OS_LABEL=""    # human label for output, e.g. "Red Hat Enterprise Linux 8"
UNAME_S=""     # Linux | AIX | HP-UX  (drives the collector's OS dispatch)
UNAME_R=""
UNAME_V=""
UNAME_M=""
NODENAME=""
APPDIR=""      # application directory passed via --app-dir
BLOCKERS=""    # commands that must appear ABSENT on this OS

# Each os_*.sh must define:
#   write_os_shims   - OS-specific shim executables into $RSHIMS
#   write_os_files   - themed files under $R
#   verify_os        - OS-specific assertions against "$REPORT"

_failures=0
_checks=0

sim_fail() {
    printf '  NOT OK  %s\n' "$1"
    _failures=`expr $_failures + 1`
}

sim_pass() {
    printf '  ok      %s\n' "$1"
}

sim_check() {
    _checks=`expr $_checks + 1`
}

# Assert a regex is present in the generated report.
assert_report_matches() {
    sim_check
    if grep -qE "$1" "$REPORT" 2>/dev/null; then
        sim_pass "$2"
    else
        sim_fail "$2 (no match for: $1)"
    fi
}

# ---------------------------------------------------------------------------
# Teardown. This runs as root and the fixture has the host's /usr bind-mounted
# inside it, so a stray rm -rf here could destroy the host. Guarded three ways:
# refuse paths outside SIM_WORK, unmount everything first, then refuse to delete
# if any mount is still present underneath.
sim_teardown() {
    _r=${1:-}
    [ -n "$_r" ] || return 0

    case "$_r" in
        "$SIM_WORK"/*) ;;
        *)
            printf 'REFUSING teardown of %s: outside %s\n' "$_r" "$SIM_WORK" >&2
            return 1
            ;;
    esac
    [ -d "$_r" ] || return 0

    umount -R "$_r" 2>/dev/null || true
    # Deepest-first second pass for anything umount -R could not detach.
    awk -v r="$_r/" 'index($2, r) == 1 { print $2 }' /proc/mounts 2>/dev/null \
        | sort -r \
        | while read -r _m; do
            umount -l "$_m" 2>/dev/null || true
        done

    if awk -v r="$_r/" 'index($2, r) == 1 { f = 1 } END { exit !f }' /proc/mounts 2>/dev/null; then
        printf 'REFUSING to remove %s - mounts still present:\n' "$_r" >&2
        awk -v r="$_r/" 'index($2, r) == 1 { print "    " $2 }' /proc/mounts >&2
        return 1
    fi

    rm -rf "$_r"
}

sim_new_root() {
    R="$SIM_WORK/roots/$OS_KEY"
    RSHIMS="$SIM_WORK/shims/$OS_KEY"
    OUT="$SIM_WORK/out/$OS_KEY"

    sim_teardown "$R" || exit 1
    rm -rf "$RSHIMS" "$OUT"
    mkdir -p "$RSHIMS" "$OUT"

    mkdir -p "$R"/etc "$R"/var/log "$R"/var/spool/cron/crontabs "$R"/var/adm \
             "$R"/home "$R"/opt "$R"/root/.ssh "$R"/tmp "$R"/dev "$R"/out \
             "$R"/usr "$R"/usr/local/bin "$R"/usr/local/sbin \
             "$R"/etc/pam.d "$R"/etc/sudoers.d "$R"/etc/ssh "$R"/etc/cron.d \
             "$R"/etc/security "$R"/etc/profile.d "$R"/etc/rsyslog.d \
             "$R"/etc/default "$R"/etc/sssd "$R"/etc/audit "$R"/etc/systemd \
             "$R"/etc/syslog-ng/conf.d "$R"/etc/alternatives
    chmod 700 "$R/root/.ssh"

    # usr-merged layout, matching a modern distro
    ln -s usr/bin "$R/bin"
    ln -s usr/lib "$R/lib"
    ln -s usr/lib64 "$R/lib64"
    ln -s usr/sbin "$R/sbin"

    cp "$COLLECTOR" "$R/collect.sh"
}

# Shims driven purely by the per-OS variables and fixture data files.
sim_write_universal_shims() {
    cat > "$RSHIMS/uname" <<EOF
#!/bin/sh
s='$UNAME_S'; r='$UNAME_R'; v='$UNAME_V'; m='$UNAME_M'; n='$NODENAME'
if [ \$# -eq 0 ]; then echo "\$s"; exit 0; fi
out=''
for a in "\$@"; do
  case "\$a" in
    -s) out="\$out \$s";; -r) out="\$out \$r";; -v) out="\$out \$v";;
    -m|-p|-i) out="\$out \$m";; -n) out="\$out \$n";;
    -a) echo "\$s \$n \$r \$v \$m"; exit 0;;
  esac
done
echo \${out# }
EOF

    cat > "$RSHIMS/hostname" <<EOF
#!/bin/sh
echo '$NODENAME'
EOF

    cat > "$RSHIMS/last" <<'EOF'
#!/bin/sh
if [ -f /etc/.sim_last ]; then cat /etc/.sim_last; else echo 'wtmp begins'; fi
EOF

    cat > "$RSHIMS/df" <<'EOF'
#!/bin/sh
if [ -f /etc/.sim_df ]; then cat /etc/.sim_df; else echo 'Filesystem 1K-blocks Used Available Use% Mounted on'; fi
EOF

    # Themed setuid/setgid answers; anything else falls through to real find.
    cat > "$RSHIMS/find" <<'EOF'
#!/bin/sh
case "$*" in
  *4000*) [ -f /etc/.sim_setuid ] && cat /etc/.sim_setuid; exit 0;;
  *2000*) [ -f /etc/.sim_setgid ] && cat /etc/.sim_setgid; exit 0;;
  *) exec /usr/bin/find "$@";;
esac
EOF

    chmod 0755 "$RSHIMS/uname" "$RSHIMS/hostname" "$RSHIMS/last" \
               "$RSHIMS/df" "$RSHIMS/find"
}

sim_mount_all() {
    mount --bind /usr "$R/usr"
    mount -o remount,bind,ro "$R/usr" 2>/dev/null || true
    # Shims shadow /usr/sbin, which the collector's fixed PATH searches first.
    mount --bind "$RSHIMS" "$R/usr/sbin"
    mount --bind /dev "$R/dev"
    # The host reaches awk and friends through /etc/alternatives symlinks. The
    # themed /etc replaces the host's, so without this bind those symlinks
    # dangle and every awk-based section silently reports "no entries found".
    mount --bind /etc/alternatives "$R/etc/alternatives"
    mount -o remount,bind,ro "$R/etc/alternatives" 2>/dev/null || true

    # Make commands that this OS does not ship appear absent.
    for _c in $BLOCKERS; do
        if [ -e "$R/usr/bin/$_c" ]; then
            : > "$RSHIMS/.blocked"
            chmod 000 "$RSHIMS/.blocked"
            mount --bind "$RSHIMS/.blocked" "$R/usr/bin/$_c"
        fi
    done
}

sim_run_collector() {
    chroot "$R" /usr/bin/env -i \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root TERM=dumb \
        /usr/bin/sh /collect.sh --output-dir /out --app-dir "$APPDIR" \
        </dev/null >"$OUT/console.txt" 2>&1
    COLLECTOR_RC=$?
}

sim_extract() {
    rm -rf "$OUT/evidence"
    mkdir -p "$OUT/evidence"
    cp -a "$R/out/." "$OUT/evidence/" 2>/dev/null || true
    E="$OUT/evidence/SOX-ITGC-AUDIT-LINUX-UNIX"
    REPORT="$E/report/SOX-ITGC-AUDIT-REPORT.txt"
    MANIFEST="$E/metadata/MANIFEST.txt"
    SKIPPED="$E/metadata/SENSITIVE_FILES_SKIPPED.txt"
}

# Assertions that must hold on every platform.
sim_verify_common() {
    sim_check
    if [ "$COLLECTOR_RC" -eq 0 ]; then
        sim_pass "collector exited 0"
    else
        sim_fail "collector exited $COLLECTOR_RC"
        tail -15 "$OUT/console.txt" >&2
    fi

    sim_check
    if [ -s "$REPORT" ]; then
        sim_pass "report produced (`wc -l < "$REPORT" | tr -d ' '` lines)"
    else
        sim_fail "no report produced at $REPORT"
        return
    fi

    sim_check
    if [ -s "$MANIFEST" ]; then
        sim_pass "manifest produced"
    else
        sim_fail "manifest missing or empty"
    fi

    # The OS dispatch is the whole point of these fixtures: if uname is not
    # honoured, every platform-specific assertion below is meaningless.
    assert_report_matches "^Platform: $UNAME_S\$" "platform detected as $UNAME_S"

    # The regression that motivated this harness: an AIX password-hash store
    # was copied into raw_files/ because it was not recognized as sensitive.
    sim_check
    if [ -d "$E/raw_files" ]; then
        if grep -rlE '\$[0-9y]\$[./A-Za-z0-9]|\{ssha[0-9]+\}|BEGIN [A-Z ]*PRIVATE KEY' \
                "$E/raw_files" >"$OUT/leaks.txt" 2>/dev/null && [ -s "$OUT/leaks.txt" ]; then
            sim_fail "CREDENTIAL LEAK - hash or key material in raw_files/:"
            sed 's/^/            /' "$OUT/leaks.txt" >&2
        else
            sim_pass "no hash or private-key material in raw_files/"
        fi
    else
        sim_fail "no raw_files/ directory produced"
    fi

    sim_check
    if find "$E/raw_files" -name authorized_keys 2>/dev/null | grep -q .; then
        sim_fail "authorized_keys copied into raw_files/"
    else
        sim_pass "no authorized_keys copied"
    fi

    # Chain of custody: never claim a file that was not delivered.
    sim_check
    _missing=0
    _copied=0
    while IFS= read -r _line; do
        case "$_line" in COPIED\|*) ;; *) continue ;; esac
        _src=`printf '%s' "$_line" | sed 's/^COPIED|//'`
        _copied=`expr $_copied + 1`
        if [ ! -f "$E/raw_files$_src" ]; then
            printf '            claimed but absent: %s\n' "$_src" >&2
            _missing=`expr $_missing + 1`
        fi
    done < "$MANIFEST"
    if [ "$_missing" -eq 0 ] && [ "$_copied" -gt 0 ]; then
        sim_pass "all $_copied COPIED entries present in raw_files/"
    else
        sim_fail "$_missing of $_copied COPIED entries absent from raw_files/"
    fi

    # Double slashes made manifest paths ambiguous for downstream tooling.
    sim_check
    if grep -q '//' "$MANIFEST" 2>/dev/null; then
        sim_fail "manifest contains double-slash paths"
        grep -m3 '//' "$MANIFEST" | sed 's/^/            /' >&2
    else
        sim_pass "manifest paths well formed"
    fi

    sim_check
    if ls "$OUT/evidence"/*.tar.gz >/dev/null 2>&1; then
        sim_pass "archive created"
    else
        sim_fail "no archive created"
    fi

    # All 25 sections should render, so a section that dies is not missed.
    sim_check
    _sections=`grep -cE '^[0-9]+\. ' "$REPORT" 2>/dev/null || echo 0`
    if [ "$_sections" -ge 25 ]; then
        sim_pass "$_sections numbered sections rendered"
    else
        sim_fail "only $_sections numbered sections rendered (expected >= 25)"
    fi
}

sim_main() {
    if [ "`id -u`" != "0" ]; then
        printf 'FAIL: must run as root (use: sudo sh %s)\n' "$0" >&2
        exit 1
    fi
    if [ ! -f "$COLLECTOR" ]; then
        printf 'FAIL: collector not found at %s\n' "$COLLECTOR" >&2
        exit 1
    fi

    printf '=== %s (%s) ===\n' "$OS_LABEL" "$NODENAME"

    sim_new_root
    trap 'sim_teardown "$R" >/dev/null 2>&1' EXIT INT TERM

    sim_write_universal_shims
    write_os_shims
    write_os_files
    sim_mount_all
    sim_run_collector
    sim_extract

    sim_verify_common
    verify_os

    if [ -n "$KEEP_ROOT" ]; then
        trap - EXIT INT TERM
        printf '  chroot left mounted at %s (KEEP_ROOT set)\n' "$R"
    else
        sim_teardown "$R" || printf '  WARNING: teardown incomplete\n' >&2
        trap - EXIT INT TERM
    fi

    printf '  evidence: %s\n' "$OUT/evidence"
    printf '  checks: %s   failures: %s\n' "$_checks" "$_failures"
    if [ "$_failures" -ne 0 ]; then
        printf 'RESULT: FAIL (%s)\n\n' "$OS_KEY"
        exit 1
    fi
    printf 'RESULT: PASS (%s)\n\n' "$OS_KEY"
    exit 0
}
