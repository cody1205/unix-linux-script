#!/bin/sh

# =============================================================================
# SOX ITGC OPERATING-SYSTEM EVIDENCE COLLECTION
# =============================================================================
#
# Run as:  sudo sh linux-unix-evidence-gathering-script.sh --output-dir /var/tmp/audit
#
# This script collects operating-system control evidence for a SOX IT General
# Controls audit. It reads configuration, packages what it read, and stops.
#
# It is written to be READ. Two people are expected to review it before it runs
# anywhere, and the comments throughout are addressed to them:
#
#   - the system administrator of the host it will run on, who needs to satisfy
#     themselves it cannot harm a production server;
#   - the reviewer deciding whether this is fit to be a sanctioned audit tool,
#     who needs to see that its limits are known, stated, and tested.
#
# Where a decision in this script is not obvious, the comment says why it was
# made and what the alternative would have cost. Where the evidence has a
# boundary, the boundary is disclosed in the output rather than left for a
# reader to assume it away.
#
# -----------------------------------------------------------------------------
# FOR THE SYSTEM ADMINISTRATOR: what this does to your server
# -----------------------------------------------------------------------------
#
# WHAT IT CHANGES:  Nothing.
#
# It does not create, modify, delete, enable, disable, restart, or reconfigure
# any user, group, service, scheduled job, permission, package, network setting,
# firewall rule, log, or authentication setting. It does not install anything.
# It does not require a reboot or a maintenance window.
#
# Every system command it runs is a query or status form - the same commands you
# would type to LOOK at the system. It never invokes an administrative command
# in a form that alters state. Where a platform's status flag is ambiguous, the
# safe form is chosen explicitly per platform; see print_account_status_summary
# for a worked example where the obvious approach would have been unsafe on AIX.
#
# WHAT IT WRITES:   Only inside the output directory you choose with
#                   --output-dir, plus the archive file in that same directory.
#                   Nothing is written anywhere else - not to /tmp, not to the
#                   home directory, not to any system path.
#
#                   ONE DISCLOSED SIDE EFFECT, so nobody finds it unannounced:
#                   asking your package manager for the installed software list
#                   (Section 8) opens its database, and an SQLite-backed rpm
#                   database updates its own write-ahead log files
#                   - rpmdb.sqlite-wal and rpmdb.sqlite-shm - whenever it is
#                   opened, even for a read-only query. The database CONTENTS
#                   are untouched, no package state changes, and this is
#                   identical to what happens when you type "rpm -qa" yourself.
#                   If your file integrity monitoring watches /var/lib/rpm, it
#                   will see those two files' timestamps move. Nothing else on
#                   the system is written to.
#
# WHAT IT SENDS:    Nothing. It makes no network connections, opens no sockets,
#                   and contacts no host. It cannot "phone home" because there
#                   is no code in it that could. (Name-service lookups such as
#                   getent will consult a directory server if this host is
#                   configured to use one - that is your operating system
#                   resolving a user ID, exactly as it does for ls -l, and it
#                   carries no evidence anywhere.)
#
# WHAT IT READS:    Operating-system configuration relevant to access control:
#                   accounts, groups, sudo rules, SSH settings, scheduled jobs,
#                   logging, patching, time sync, and file permissions.
#
# WHAT IT NEVER READS INTO THE PACKAGE:
#                   Password hashes (/etc/shadow, AIX /etc/security/passwd),
#                   SSH private keys, Kerberos keytabs, and LDAP bind secrets.
#                   For these it records only permissions and ownership -
#                   evidence that they are protected - never contents. Every
#                   file treated this way is listed in
#                   metadata/SENSITIVE_FILES_SKIPPED.txt so you can confirm it.
#                   It reads no user data, no application data, and no
#                   databases.
#
# WHAT IT COSTS:    Typically one to ten minutes. Two sections walk parts of the
#                   filesystem and account for nearly all of that; each
#                   announces itself on screen and reports its own elapsed time.
#                   Both stop at filesystem boundaries, so neither can descend
#                   into NFS or SAN mounts and place load on a remote filer.
#                   Everything else is individual file reads and is effectively
#                   instantaneous.
#
# IF YOU INTERRUPT IT:
#                   Press Ctrl-C at any point. It stops, marks its own output as
#                   incomplete so it cannot be mistaken for a finished
#                   collection, and exits. Nothing is left in a partial state
#                   because nothing was being changed.
#
# HOW TO CHECK ALL OF THAT YOURSELF, rather than taking it on trust.
# These are exact; each was run against this file and produced what is described.
#
#   1. See what it does, without root and without collecting anything
#      privileged:
#
#        sh linux-unix-evidence-gathering-script.sh --dry-run --output-dir /var/tmp/x
#
#   2. Prove it opens no network socket. This is the definitive check - it
#      observes the actual system calls rather than trusting the source:
#
#        strace -f -e trace=network \
#          sh linux-unix-evidence-gathering-script.sh --dry-run --output-dir /var/tmp/x \
#          2>&1 >/dev/null | grep AF_INET
#
#      Prints nothing. No internet-family socket is ever opened. (On AIX or
#      Solaris the equivalent tool is truss -f -t so_socket.)
#
#   3. See every file this script can write to. Each redirection target is a
#      variable, and this lists them:
#
#        grep -nE "^[^#]*(>|>>)[[:space:]]*\"?\\\$" \
#          linux-unix-evidence-gathering-script.sh | grep -oE '\$[A-Z_]+' | sort -u
#
#      Returns five names: $LOG_FILE, $MANIFEST_FILE, $REPORT_FILE,
#      $SENSITIVE_SKIPPED_FILE, and $_ - the last being the truncated form of
#      two local variables, $_handling_file and $_redact_target. All five are
#      files inside the output directory you chose. There is no write to a
#      system path anywhere in this script.
#
#   4. Prove the host is unchanged, empirically. The repository ships the test
#      that does this - it records the state of roughly 100,000 files before and
#      after a real collection and fails if any of them differ:
#
#        sudo sh tests/test-host-not-modified.sh
#
# A NOTE ON SEARCHING FOR NETWORK COMMANDS: grepping this file for words like
# "telnet" or "ftp" DOES return matches, and they are not what they look like.
# Section 17 searches YOUR inetd and xinetd configuration for those service
# names, because an enabled telnet or ftp service is an audit finding. That is
# this script reading your configuration in order to report on it. Check 2 above
# is the reliable test, because it observes behaviour rather than vocabulary.
#
# -----------------------------------------------------------------------------
# FOR THE REVIEWER: how this is assured
# -----------------------------------------------------------------------------
#
# PORTABILITY:      Portable POSIX sh. Targets Linux, AIX, Solaris/Illumos,
#                   HP-UX, and BSD. No bashisms - CI enforces this with
#                   checkbashisms and parse checks under sh, dash, and bash,
#                   because /bin/sh on AIX and HP-UX is not what a Linux reader
#                   would assume.
#
# TESTING:          The properties a sanctioning review turns on are each
#                   asserted by a test that fails the build:
#
#                     host-not-modified     snapshots ~100k filesystem paths
#                                           before and after a real collection
#                                           and requires zero change
#                     no-network-egress     static audit, syscall trace under
#                                           strace, and a run inside a network
#                                           namespace with no interfaces at all
#                     evidence-chain        every source consulted is accounted
#                                           for in the manifest, in both
#                                           directions
#                     hostile-filesystem    spaces, quotes, unicode, symlink
#                                           loops, unreadable and deeply nested
#                                           directories - and proof the tree was
#                                           actually examined, not just survived
#                     degraded-environment  no root, full disk, interruption:
#                                           the verdict must never overstate
#                     determinism           two collections of one host must
#                                           agree byte for byte
#
#                   Plus credential-leak and sensitive-path tests, a receipt
#                   verifier for deliveries, and four simulated platforms
#                   (RHEL, openSUSE, AIX, HP-UX). See README.md.
#
# KNOWN LIMITS, stated rather than discovered later:
#
#                   - The two filesystem scans use find -xdev and do not cross
#                     mount points, so a separately mounted subdirectory beneath
#                     a scanned path is not traversed. Deliberate: it prevents
#                     load on client network storage. Disclosed in the report.
#                   - Section 24 lists accounts the name service will enumerate.
#                     SSSD and winbind disable enumeration by default, so on a
#                     directory-joined host the list may be local accounts only.
#                     The script detects this case and says so.
#                   - AIX and HP-UX code paths are exercised by simulation, not
#                     on real hardware of those architectures.
#
# EXIT STATUS:      0 the package is usable (clean, or with warnings recorded)
#                   1 the package is not usable, or the arguments were invalid
#
# OUTPUT:           SOX-ITGC-AUDIT-LINUX-UNIX/
#                     report/     the narrative audit report
#                     raw_files/  copies of the non-sensitive files it read
#                     metadata/   MANIFEST.txt              chain of custody
#                                 SENSITIVE_FILES_SKIPPED.txt  what was withheld
#                                 COLLECTION-LOG.txt        did the run work
#                   plus SOX-ITGC-AUDIT-LINUX-UNIX-<host>-<timestamp>.tar.gz
#
#                   The report says what the host is configured to do. The
#                   collection log answers the different and equally important
#                   question of whether this collection actually worked and
#                   whether any evidence is missing.
# =============================================================================

# Restrict command lookup to standard administrative paths. This reduces the
# chance that a shell alias, user-local wrapper, or non-standard executable is
# used during evidence collection.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
readonly PATH

# Restrict permissions on generated evidence artifacts. This applies only to
# files and directories created by this script under the working directory.
umask 077

# Resolve the invoked script name for report text and usage instructions.
# This is informational and does not affect host configuration.
SCRIPT_NAME=`basename "$0" 2>/dev/null || echo linux-unix-evidence-gathering-script.sh`
readonly SCRIPT_NAME

# Supported execution modes:
# - default privileged collection, normally invoked with sudo
# - non-root dry-run mode for pre-execution review and output-format testing
# - help output
# Dry-run mode is provided so a client can inspect structure and behavior
# without granting elevated access. Privileged-only evidence may be unavailable
# during that mode.
#
# Application directory listing:
# - --app-dir PATH or --app-dir=PATH selects an application installation
#   directory to be included in the recursive directory-listing section.
# - The flag may be provided multiple times to capture more than one
#   directory.
# - When no --app-dir flags are provided and stdin is connected to a
#   terminal, the script will interactively prompt the operator for one or
#   more directories before evidence collection starts.
#
# Evidence output directory:
# - --output-dir PATH or --output-dir=PATH selects the directory in which
#   the SOX-ITGC-AUDIT-LINUX-UNIX/ collection folder and the resulting
#   tar.gz archive are created. If the directory does not exist, the script
#   will attempt to create it.
# - When --output-dir is not provided and stdin is connected to a terminal,
#   the script will interactively prompt for an output directory before
#   evidence collection starts.
# - When --output-dir is not provided and stdin is not a terminal, the
#   script falls back to the current working directory.
TEST_MODE=no
SHOW_HELP=no
ARGUMENT_ERROR=no
APP_DIRECTORIES=""
OUTPUT_DIRECTORY=""
expect_app_dir_value=no
expect_output_dir_value=no

for argument in "$@"; do
    if [ "$expect_app_dir_value" = "yes" ]; then
        APP_DIRECTORIES="$APP_DIRECTORIES
$argument"
        expect_app_dir_value=no
        continue
    fi
    if [ "$expect_output_dir_value" = "yes" ]; then
        OUTPUT_DIRECTORY=$argument
        expect_output_dir_value=no
        continue
    fi
    case "$argument" in
        --dry-run|--no-sudo-test)
            TEST_MODE=yes
            ;;
        -h|--help)
            SHOW_HELP=yes
            ;;
        --app-dir)
            expect_app_dir_value=yes
            ;;
        --app-dir=*)
            app_dir_value=${argument#--app-dir=}
            if [ -n "$app_dir_value" ]; then
                APP_DIRECTORIES="$APP_DIRECTORIES
$app_dir_value"
            fi
            ;;
        --output-dir)
            expect_output_dir_value=yes
            ;;
        --output-dir=*)
            OUTPUT_DIRECTORY=${argument#--output-dir=}
            ;;
        *)
            printf 'Unknown option: %s\n' "$argument" >&2
            ARGUMENT_ERROR=yes
            SHOW_HELP=yes
            ;;
    esac
done

if [ "$expect_app_dir_value" = "yes" ]; then
    printf 'Missing value for --app-dir option.\n' >&2
    ARGUMENT_ERROR=yes
    SHOW_HELP=yes
fi

if [ "$expect_output_dir_value" = "yes" ]; then
    printf 'Missing value for --output-dir option.\n' >&2
    ARGUMENT_ERROR=yes
    SHOW_HELP=yes
fi

# The report records whether the execution was a full privileged collection or
# a non-root test. This supports evidence traceability and reviewer context.
SCRIPT_MODE="read-only source collection with local packaging"
if [ "$TEST_MODE" = "yes" ]; then
    SCRIPT_MODE="$SCRIPT_MODE (non-root test mode enabled)"
fi
readonly SCRIPT_MODE

# Capture runtime context once at startup so the report header and archive name
# remain consistent throughout the evidence collection session.
OS_NAME=`uname -s 2>/dev/null || echo unknown`
readonly OS_NAME

HOSTNAME_VALUE=`hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown`
readonly HOSTNAME_VALUE

TIMESTAMP=`date 2>/dev/null || echo unknown`
readonly TIMESTAMP

ARCHIVE_TIMESTAMP=`date '+%Y%m%d-%H%M%S' 2>/dev/null || echo unknown_time`
readonly ARCHIVE_TIMESTAMP

SAFE_HOSTNAME=`printf '%s' "$HOSTNAME_VALUE" | tr -c 'A-Za-z0-9._-' '_'`
readonly SAFE_HOSTNAME

# Default evidence output location: the operator's current working directory.
# This default can be overridden by --output-dir on the command line or by
# the interactive output-directory prompt at startup. The path variables
# below are recomputed by apply_output_directory after the prompt resolves.
WORKING_DIRECTORY=`pwd 2>/dev/null || echo .`

# Evidence directory structure created under the output directory:
# - report/: human-readable audit report generated by this script
# - raw_files/: copied non-sensitive source files used as supporting evidence
# - metadata/: manifest and sensitive-file handling records
COLLECTION_DIRECTORY="$WORKING_DIRECTORY/SOX-ITGC-AUDIT-LINUX-UNIX"
REPORTS_DIRECTORY="$COLLECTION_DIRECTORY/report"
RAW_FILES_DIRECTORY="$COLLECTION_DIRECTORY/raw_files"
METADATA_DIRECTORY="$COLLECTION_DIRECTORY/metadata"
REPORT_FILE="$REPORTS_DIRECTORY/SOX-ITGC-AUDIT-REPORT.txt"
MANIFEST_FILE="$METADATA_DIRECTORY/MANIFEST.txt"
SENSITIVE_SKIPPED_FILE="$METADATA_DIRECTORY/SENSITIVE_FILES_SKIPPED.txt"

ARCHIVE_BASE_NAME="SOX-ITGC-AUDIT-LINUX-UNIX-$SAFE_HOSTNAME-$ARCHIVE_TIMESTAMP"
readonly ARCHIVE_BASE_NAME

# Runtime status values used for report and archive summary text. These values
# describe collection status only; they are not used to change system settings.
ARCHIVE_FILE=""
ARCHIVE_STATUS="not created"
COLLECTION_STATUS="pending"
OWNERSHIP_STATUS="not adjusted"
EFFECTIVE_UID_VALUE=`id -u 2>/dev/null || echo 1`
readonly EFFECTIVE_UID_VALUE
RUN_PRIVILEGE_MODE="elevated collection"
if [ "$EFFECTIVE_UID_VALUE" != "0" ]; then
    if [ "$TEST_MODE" = "yes" ]; then
        RUN_PRIVILEGE_MODE="non-root dry-run test"
    else
        RUN_PRIVILEGE_MODE="non-root execution"
    fi
fi
readonly RUN_PRIVILEGE_MODE

# Report-formatting helpers. These functions write text to the generated
# report only and do not interact with host configuration.
section() {
    printf '\n==================================================\n'
    printf '%s\n' "$1"
    printf '==================================================\n\n'
}

wrap_text() {
    printf '%s\n' "$1" | awk '
        BEGIN { width = 78 }
        {
            line = $0
            while (length(line) > width) {
                split_pos = width
                while (split_pos > 1 && substr(line, split_pos, 1) != " ") {
                    split_pos--
                }
                if (split_pos == 1) {
                    split_pos = width
                }
                print substr(line, 1, split_pos - 1)
                line = substr(line, split_pos + 1)
            }
            print line
        }
    '
}

# Long-format listing of a single path, human-readable size where supported.
#
# -h is a GNU/BSD extension and does not exist on AIX, HP-UX, or Solaris, so it
# is attempted first and the portable form is used when it is rejected. Without
# the fallback the listing would be empty on exactly the platforms where this
# evidence is hardest to obtain a second time.
long_listing_of() {
    ls -ldh "$1" 2>/dev/null || ls -ld "$1" 2>/dev/null
}

# The source-file block printed under every section heading.
#
# WHY THIS IS HERE
# A reviewer reading a section needs to know which file on the CLIENT's server
# the evidence below it came from, and what that file's permissions, ownership,
# and last-modified date were at the moment of collection. Previously the header
# printed only the path. The permissions and ownership are themselves control
# evidence - "who could have changed this file" - and the modification date
# frequently matters more than the contents, because it establishes when the
# configuration last changed relative to the audit period.
#
# It is printed at the top of the section, before the evidence, so the reader
# has the provenance in hand before reading the findings rather than having to
# reconcile them afterwards against the manifest.
print_section_source_files() {
    _sec_files=$1
    _sec_copy=$2

    printf '\n'
    printf 'File name and directory path on client server where the file that is\n'
    printf 'referenced in the section below is from:\n'

    printf '%s\n' "$_sec_files" | while IFS= read -r _sec_path; do
        if [ -z "$_sec_path" ]; then
            continue
        fi
        printf 'Directory: %s\n' "$_sec_path"
        if path_exists "$_sec_path"; then
            _sec_listing=`long_listing_of "$_sec_path"`
            if [ -n "$_sec_listing" ]; then
                # A directory listed with ls -ld yields one line; a path that
                # cannot be stat'd yields none, which is reported rather than
                # left blank.
                printf 'File Ownership, Access Rights, Last Modified Date: %s\n' "$_sec_listing"
            else
                printf 'File Ownership, Access Rights, Last Modified Date: not available\n'
            fi
        else
            printf 'File Ownership, Access Rights, Last Modified Date: file not present on this host\n'
        fi
        if [ "$_sec_copy" = "yes" ]; then
            record_file_reference "$_sec_path"
        fi
    done
}

section_with_explanation() {
    _sec_copy_mode=${4:-yes}
    printf '\n==================================================\n'
    printf '%s\n' "$1"
    wrap_text "$2"
    if [ -n "${3:-}" ]; then
        print_section_source_files "$3" "$_sec_copy_mode"
    fi
    printf '==================================================\n\n'
}

subsection() {
    printf '%s\n' "$1"
}

blank_line() {
    printf '\n'
}

not_available() {
    printf 'not available\n'
}

no_entries_found() {
    printf 'no entries found\n'
}

# Scan timing and operator feedback:
#
# Most of this collection is instantaneous file reads, but the sections that walk
# the filesystem (world-writable, SetUID/SetGID, and the recursive application
# directory listing) can each run for minutes on a large host. Two different
# audiences need to know about that.
#
# The operator running the script needs to see that it is still working. Without
# any output, several minutes of silence looks like a hang, and the reasonable
# reaction to a hung script on a production box is to interrupt it. Progress
# messages are therefore written to the operator's terminal on file descriptor 3,
# which holds the original stdout while the report itself is being written to the
# report file. A progress bar is deliberately not used: find produces no
# incremental output to derive progress from, so any bar would be decorative, and
# terminal control codes would corrupt the output of a non-interactive run.
#
# The reviewer reading the evidence needs the timings recorded in the package
# itself. Start and end wall-clock times let the collection be correlated against
# the client's own monitoring and change records, which is the answer to "what was
# this script doing on our server for five minutes".
#
# Portability: date +%s is not in POSIX and is missing on older HP-UX and some AIX
# builds, so elapsed seconds cannot always be computed. Wall-clock start and end
# times are therefore always recorded using plain date, which is universally
# available, and a computed elapsed time is added only where the platform
# supports it. For audit purposes the timestamps are the more useful of the two
# anyway.
SCAN_TIMING_SUMMARY=""
SCAN_TIMER_LABEL=""
SCAN_TIMER_START_WALL=""
SCAN_TIMER_START_EPOCH=""

# Epoch seconds when the platform supports it, empty string when it does not.
epoch_seconds() {
    _epoch_value=`date +%s 2>/dev/null`
    case "$_epoch_value" in
        ''|*[!0-9]*) printf '' ;;
        *)           printf '%s' "$_epoch_value" ;;
    esac
}

format_elapsed() {
    _elapsed_secs=${1:-}
    if [ -z "$_elapsed_secs" ]; then
        printf 'not available on this platform'
        return
    fi
    printf '%sm%02ds' "`expr "$_elapsed_secs" / 60`" "`expr "$_elapsed_secs" % 60`"
}

# Announce a long-running scan on the operator's terminal and start the clock.
scan_timer_start() {
    SCAN_TIMER_LABEL=$1
    SCAN_TIMER_START_WALL=`date 2>/dev/null || echo unknown`
    SCAN_TIMER_START_EPOCH=`epoch_seconds`
    printf '  %s ...\n' "$SCAN_TIMER_LABEL" >&3 2>/dev/null || :
}

# Close the clock: report to the operator, into the report, and into the manifest.
scan_timer_end() {
    _timer_section=$1
    _timer_end_wall=`date 2>/dev/null || echo unknown`
    _timer_end_epoch=`epoch_seconds`

    _timer_elapsed=""
    if [ -n "$SCAN_TIMER_START_EPOCH" ] && [ -n "$_timer_end_epoch" ]; then
        _timer_elapsed=`expr "$_timer_end_epoch" - "$SCAN_TIMER_START_EPOCH" 2>/dev/null`
    fi
    _timer_elapsed_text=`format_elapsed "$_timer_elapsed"`

    printf '    completed in %s\n' "$_timer_elapsed_text" >&3 2>/dev/null || :

    blank_line
    subsection "Scan Timing:"
    printf 'Started:   %s\n' "$SCAN_TIMER_START_WALL"
    printf 'Completed: %s\n' "$_timer_end_wall"
    printf 'Elapsed:   %s\n' "$_timer_elapsed_text"

    record_manifest_line "TIMING|section=$_timer_section|started=$SCAN_TIMER_START_WALL|completed=$_timer_end_wall|elapsed=$_timer_elapsed_text"
    log_event INFO timing "Section $_timer_section took $_timer_elapsed_text"


    SCAN_TIMING_SUMMARY="$SCAN_TIMING_SUMMARY
  Section $_timer_section: $_timer_elapsed_text ($SCAN_TIMER_START_WALL to $_timer_end_wall)"
}

# Usage text distinguishes full collection from dry-run testing so the client
# can decide which execution mode is appropriate for the review activity.
print_usage() {
    printf 'Usage: sh %s [--dry-run|--no-sudo-test] [--output-dir PATH] [--app-dir PATH ...] [--help]\n' "$SCRIPT_NAME"
    printf '\n'
    printf '  sudo sh %s\n' "$SCRIPT_NAME"
    printf '      Perform the full privileged evidence collection.\n'
    printf '\n'
    printf '  sh %s --dry-run\n' "$SCRIPT_NAME"
    printf '      Run a safe non-root test to generate a best-effort report,\n'
    printf '      collection directory, and local archive without requiring sudo.\n'
    printf '\n'
    printf '  sudo sh %s --output-dir /var/tmp/audit\n' "$SCRIPT_NAME"
    printf '      Create the evidence collection directory and tar.gz archive\n'
    printf '      under the specified output directory. The form\n'
    printf '      --output-dir=PATH is also accepted. When no --output-dir\n'
    printf '      flag is given and stdin is a terminal, the script will\n'
    printf '      interactively prompt for an output directory before\n'
    printf '      evidence collection starts. The default is the current\n'
    printf '      working directory.\n'
    printf '\n'
    printf '  sudo sh %s --app-dir /opt/myapp --app-dir /var/lib/myapp\n' "$SCRIPT_NAME"
    printf '      Include recursive directory listings for one or more\n'
    printf '      application installation directories. The flag may be\n'
    printf '      repeated. The form --app-dir=PATH is also accepted.\n'
    printf '      When no --app-dir flag is given and stdin is a terminal,\n'
    printf '      the script will interactively prompt for application\n'
    printf '      directories before evidence collection starts.\n'
    printf '\n'
    printf 'Exit status:\n'
    printf '  0   The evidence package is usable. Either nothing limited the\n'
    printf '      collection, or some evidence was limited and the collection\n'
    printf '      log records what. Warnings are normal on a live system.\n'
    printf '  1   The evidence package is NOT usable: a step failed, or the\n'
    printf '      collection could not be completed. Read the collection log\n'
    printf '      before relying on anything that was produced.\n'
    printf '\n'
    printf '      Argument errors also exit 1, before anything is collected.\n'
}

# Capability helpers centralize command and path checks. They allow the script
# to report "not available" when a platform-specific tool or file is absent,
# rather than failing the entire collection.
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

file_readable() {
    [ -r "$1" ]
}

directory_exists() {
    [ -d "$1" ]
}

path_exists() {
    [ -e "$1" ]
}

# Sensitive-path screening:
# Certain files can contain password hashes, private keys, Kerberos keytabs,
# tokens, or other credential material. For those files, the script avoids
# printing or copying full contents into the evidence package. Instead, it
# records metadata and limited summaries that support review while reducing the
# risk of unnecessary credential exposure.
is_sensitive_path() {
    case "$1" in
        /etc/shadow|/etc/gshadow|/etc/sssd/sssd.conf|/etc/krb5.keytab|/etc/krb5/krb5.keytab|/etc/ldap.secret)
            return 0
            ;;
        /etc/security/passwd|/etc/security/opasswd|/etc/opasswd|/etc/security/ldap/ldap.cfg|/etc/security/passwd.conf)
            # AIX stores password hashes in /etc/security/passwd; opasswd holds
            # password history hashes; the AIX LDAP client config embeds a bind
            # password. Treat these like /etc/shadow: metadata and safe summaries
            # only, never copy the full file into the evidence package.
            return 0
            ;;
        /root/.ssh/*|/home/*/.ssh/*|*/.ssh/id_*|*/authorized_keys|*/.rhosts|*/.shosts|*.pem|*.key)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Password hashes stored inline in /etc/passwd:
#
# On a modern Linux host /etc/passwd carries no credential material - field 2
# holds a placeholder ("x") and the hash lives in /etc/shadow, which the table
# above withholds. That is not universal. HP-UX in its historical non-shadow,
# non-trusted configuration stores the crypt hash directly in field 2 of
# /etc/passwd, and shadowing there is opt-in (pwconv) rather than the default.
# Older Solaris and some minimal or appliance builds can be in the same state.
#
# /etc/passwd is referenced by roughly a dozen sections, so on such a host the
# credential material this script exists to withhold would be copied into
# raw_files/ through the front door while /etc/shadow was being carefully held
# back. The classification table cannot catch this because the answer depends on
# the CONTENT of the file on this particular host, not on its path - and the path
# must stay collectable, since the account list is core evidence.
#
# The check is therefore a content test, evaluated once and cached. Placeholder
# values across the Unix families are treated as "no hash present":
#
#   x     Linux, Solaris shadow indirection      *     locked / HP-UX trusted mode
#   !, !! locked account (Linux, AIX)            NP, *NP*  Solaris "no password"
#   ##user  AIX shadow indirection               empty  no password set at all
#
# Anything else in field 2 is assumed to be a real hash. Lines beginning with
# + or - are NIS netgroup directives, not accounts, and are skipped.
# The content test itself, against any path, with no caching and no dependence on
# script state. Kept separate from the cached /etc/passwd wrapper below so it can
# be extracted and unit-tested against fixture files representing each platform's
# conventions - the same approach used for is_sensitive_path(), and for the same
# reason: this is a credential guard, and a guard that has never been shown to
# fire is not a guard.
#
# Returns 0 when at least one account line carries something in field 2 that is
# not a recognised placeholder.
file_has_inline_password_hashes() {
    _inline_check_path=$1
    [ -r "$_inline_check_path" ] || return 1
    awk -F: '
        /^[+-]/          { next }   # NIS netgroup directives, not accounts
        /^[[:space:]]*#/ { next }   # comments
        /^[[:space:]]*$/ { next }   # blank lines
        NF < 2           { next }   # malformed, no field 2 to judge
        $2 == ""      { next }
        $2 == "x" || $2 == "*" || $2 == "!" || $2 == "!!" { next }
        $2 == "NP" || $2 == "*NP*" || $2 == "*LK*"        { next }
        $2 == "##" $1 { next }
        { found = 1; exit }
        END { exit(found ? 0 : 1) }
    ' "$_inline_check_path" 2>/dev/null
}

PASSWD_INLINE_HASH_STATE=unknown

passwd_file_has_inline_hashes() {
    if [ "$PASSWD_INLINE_HASH_STATE" = "unknown" ]; then
        if file_has_inline_password_hashes /etc/passwd; then
            PASSWD_INLINE_HASH_STATE=yes
        else
            PASSWD_INLINE_HASH_STATE=no
        fi
    fi
    [ "$PASSWD_INLINE_HASH_STATE" = "yes" ]
}

# A copy of /etc/passwd with field 2 replaced, for the case above. Every other
# field is preserved exactly, so the account inventory - names, UIDs, GIDs,
# GECOS, home directories, and login shells - remains complete evidence. Only
# the credential is removed, and its removal is stated in the file itself so a
# reviewer cannot mistake the redaction for the host's actual configuration.
write_redacted_passwd_copy() {
    _redact_source=$1
    _redact_target=$2
    {
        printf '# NOTICE: This is a REDACTED copy of %s from %s.\n' "$_redact_source" "${HOSTNAME_VALUE:-this host}"
        printf '# This host stores password hashes inline in field 2 of /etc/passwd\n'
        printf '# rather than in a separate shadow file. The evidence collection\n'
        printf '# script replaced field 2 of every account with the literal text\n'
        printf '# <REDACTED-BY-COLLECTOR> so that no credential material leaves the\n'
        printf '# host. Every other field is reproduced exactly as it was found.\n'
        printf '#\n'
        printf '# The redaction marker is NOT the value configured on this host.\n'
        printf '# See metadata/SENSITIVE_FILES_SKIPPED.txt and the collection log.\n'
        printf '#\n'
        awk -F: 'BEGIN { OFS = ":" }
            /^[+-]/ { print; next }
            NF < 2  { print; next }
            { $2 = "<REDACTED-BY-COLLECTOR>"; print }
        ' "$_redact_source" 2>/dev/null
    } > "$_redact_target" 2>/dev/null

    # Confirm the redaction actually produced account lines. A truncated or empty
    # result must be treated as a failure rather than delivered as evidence, and
    # the caller removes the file in that case. Verifying the marker is present
    # also proves the substitution ran rather than the original being echoed.
    if [ -s "$_redact_target" ] && grep -q '<REDACTED-BY-COLLECTOR>' "$_redact_target" 2>/dev/null; then
        return 0
    fi
    return 1
}

record_manifest_line() {
    if [ -f "$MANIFEST_FILE" ]; then
        printf '%s\n' "$1" >> "$MANIFEST_FILE"
    fi
}

# Record a file as deliberately withheld.
#
# SENSITIVE_FILES_SKIPPED.txt is the file the client is told to check in order to
# confirm what was held back, so it has to be the complete list. It previously
# was not: this function was called only from copy_file_to_collection, so a
# sensitive file that went straight to print_sensitive_file_review - every
# authorized_keys reached through Section 14, among others - was recorded in the
# manifest as SENSITIVE_METADATA_ONLY and never appeared here at all. The two
# records of the same decision disagreed, and the one the client was pointed at
# was the incomplete one.
#
# Both call sites now record here, so entries can arrive twice for one file; the
# duplicate check keeps the list readable as an inventory.
record_sensitive_skip() {
    if [ -f "$SENSITIVE_SKIPPED_FILE" ]; then
        if ! grep -Fxq "$1" "$SENSITIVE_SKIPPED_FILE" 2>/dev/null; then
            printf '%s\n' "$1" >> "$SENSITIVE_SKIPPED_FILE"
            log_event INFO sensitive "$1 held back from the package by the credential safeguards; metadata recorded instead of contents"
        fi
        return
    fi
    log_event INFO sensitive "$1 held back from the package by the credential safeguards; metadata recorded instead of contents"
}

# Collection log:
#
# The report answers "what is the configuration of this host". The collection log
# answers a different question: "did this collection actually work, and is the
# evidence in this package complete". Those are separate concerns and separate
# audiences, which is why they are separate files.
#
# The log is written for three readers at once:
#   - an auditor, who needs to know whether any evidence is missing before relying
#     on the report, without needing to know Unix;
#   - the client's system administrator, who needs to see exactly what the script
#     touched on their production host and that nothing was changed;
#   - an automated reader, which needs a stable line format and an explicit
#     machine-readable verdict rather than prose it has to interpret.
#
# Each line is "timestamp | level | category | message", padded so the columns
# line up for a human but still trivially splittable on "|" by a machine. The
# file ends with a summary block containing a single RESULT token.
#
# The log deliberately records paths and outcomes only. It never contains file
# contents, credentials, or command output, because this file is the one most
# likely to be forwarded around informally - pasted into a ticket, mailed to the
# client, or handed to an automated reader - and it must stay safe to share.
LOG_FILE=""
LOG_BUFFER=""
LOG_READY=no
LOG_WARN_COUNT=0
LOG_ERROR_COUNT=0

log_timestamp() {
    date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || printf 'unknown-time'
}

# log_event LEVEL CATEGORY MESSAGE
#
# LEVEL is one of INFO, WARN, ERROR. Events raised before the evidence directory
# exists are buffered and flushed once the log file is created, so nothing that
# happens during startup is lost.
log_event() {
    _log_level=$1
    _log_category=$2
    _log_message=$3

    case "$_log_level" in
        WARN)  LOG_WARN_COUNT=`expr "$LOG_WARN_COUNT" + 1` ;;
        ERROR) LOG_ERROR_COUNT=`expr "$LOG_ERROR_COUNT" + 1` ;;
    esac

    _log_ts=`log_timestamp`
    _log_line=`printf '%s | %-5s | %-11s | %s' "$_log_ts" "$_log_level" "$_log_category" "$_log_message"`

    if [ "$LOG_READY" = "yes" ] && [ -n "$LOG_FILE" ]; then
        printf '%s\n' "$_log_line" >> "$LOG_FILE" 2>/dev/null
    else
        LOG_BUFFER="$LOG_BUFFER
$_log_line"
    fi
}

# Create the log file, write the self-describing header, and flush anything that
# was buffered before the evidence directory existed.
initialize_collection_log() {
    LOG_FILE="$METADATA_DIRECTORY/COLLECTION-LOG.txt"
    if ! : > "$LOG_FILE" 2>/dev/null; then
        LOG_FILE=""
        return 1
    fi

    {
        printf 'SOX ITGC EVIDENCE COLLECTION LOG\n'
        printf '================================\n'
        printf '\n'
        printf 'What this file is\n'
        printf '  A record of whether this evidence collection ran correctly and\n'
        printf '  whether anything prevented evidence from being gathered. It is a\n'
        printf '  companion to the audit report, not a copy of it: the report says\n'
        printf '  what the system is configured to do, this log says whether the\n'
        printf '  collection of that information succeeded.\n'
        printf '\n'
        printf 'How to read it\n'
        printf '  Each line is:  timestamp | level | category | message\n'
        printf '\n'
        printf '  INFO   Normal progress. No action needed.\n'
        printf '  WARN   The collection continued, but something limited the\n'
        printf '         evidence. Anything marked WARN should be read before\n'
        printf '         relying on the corresponding section of the report.\n'
        printf '  ERROR  Something failed. The package may be incomplete or absent.\n'
        printf '\n'
        printf '  The RESULT line in the summary at the end of this file is the\n'
        printf '  single overall verdict for the run.\n'
        printf '\n'
        printf 'For the system administrator of this host\n'
        printf '  This script is read-only. It does not create, modify, delete,\n'
        printf '  enable, disable, restart, or reconfigure anything on this system.\n'
        printf '  The only files it writes are inside its own output directory,\n'
        printf '  named in the summary below. Entries in this log describe files\n'
        printf '  that were READ, never files that were changed.\n'
        printf '\n'
        printf 'Contents and handling\n'
        printf '  This log contains file paths and outcomes only. It contains no\n'
        printf '  file contents, no passwords or hashes, and no command output, so\n'
        printf '  it can be shared more freely than the evidence package itself.\n'
        printf '\n'
        printf '================================================================\n'
        printf '\n'
    } >> "$LOG_FILE" 2>/dev/null

    LOG_READY=yes

    if [ -n "$LOG_BUFFER" ]; then
        printf '%s\n' "$LOG_BUFFER" | while IFS= read -r _log_buffered; do
            if [ -n "$_log_buffered" ]; then
                printf '%s\n' "$_log_buffered" >> "$LOG_FILE" 2>/dev/null
            fi
        done
        LOG_BUFFER=""
    fi
    return 0
}

# The archive is created after the log is closed, so nothing about it can appear
# in the summary above, and none of it can appear inside the archived copy of this
# log at all - an archive cannot record whether it was created.
#
# The addendum is opened BEFORE the archive is built so that everything the
# archive step reports lands beneath its heading rather than loose under the
# summary, and closed afterwards with the outcome and the final counts. This
# matters beyond tidiness: an archive failure raises an ERROR after the verdict
# has already been written, so without the addendum the log could read
# "COMPLETED_CLEAN" with an error logged underneath it. The closing counts here
# are the ones that account for the archive.
open_log_addendum() {
    if [ "$LOG_READY" != "yes" ] || [ -z "$LOG_FILE" ]; then
        return
    fi
    {
        printf '\n'
        printf '%s\n' '---------------------------------------------------------------'
        printf 'ADDENDUM: the archive step, which runs after the log is closed\n'
        printf '%s\n' '---------------------------------------------------------------'
        printf 'This section is absent from the copy of this log inside the archive,\n'
        printf 'because the archive was already sealed when it was written. The\n'
        printf 'RESULT above covers the collection; the archive outcome is below.\n'
        printf '\n'
    } >> "$LOG_FILE" 2>/dev/null
}

close_log_addendum() {
    if [ "$LOG_READY" != "yes" ] || [ -z "$LOG_FILE" ]; then
        return
    fi
    recount_log_levels
    {
        printf '\n'
        printf 'ARCHIVE_RESULT: %s\n' "$ARCHIVE_STATUS"
        printf 'ARCHIVE_FILE: %s\n' "${ARCHIVE_FILE:-none}"
        printf 'FINAL_ERRORS: %s\n' "$LOG_ERROR_COUNT"
        printf 'FINAL_WARNINGS: %s\n' "$LOG_WARN_COUNT"
        printf 'FINAL_RESULT: %s\n' "`collection_log_result`"
        printf '\n'
        printf 'FINAL_RESULT supersedes the RESULT above when they differ, which\n'
        printf 'happens only when the archive step itself reported a problem.\n'
    } >> "$LOG_FILE" 2>/dev/null
}

# Recompute the WARN and ERROR tallies from the log file itself.
#
# The in-memory counters undercount, and the reason is structural: log_event runs
# inside pipeline subshells - the "printf | while read" loops that walk section
# file lists and the --app-dir validation - and a counter incremented in a
# subshell is lost when that subshell exits. The log LINE is not lost, because it
# is appended directly to the file. So the file is the authoritative record, and
# every verdict and count is derived from it; the in-memory counters remain only
# as a fallback for the case where no log file could be created at all.
#
# The grep patterns match the padded column layout log_event writes
# (" | WARN  | ", " | ERROR | ") and cannot match the prose in the header or
# summary, which never carries the surrounding pipe columns.
recount_log_levels() {
    if [ "$LOG_READY" = "yes" ] && [ -f "$LOG_FILE" ]; then
        LOG_WARN_COUNT=`grep -c ' | WARN  | ' "$LOG_FILE" 2>/dev/null`
        [ -n "$LOG_WARN_COUNT" ] || LOG_WARN_COUNT=0
        LOG_ERROR_COUNT=`grep -c ' | ERROR | ' "$LOG_FILE" 2>/dev/null`
        [ -n "$LOG_ERROR_COUNT" ] || LOG_ERROR_COUNT=0
    fi
}

# Overall verdict for the run, as a single stable token.
collection_log_result() {
    recount_log_levels
    if [ "$COLLECTION_STATUS" != "ready" ]; then
        printf 'FAILED'
    elif [ "$LOG_ERROR_COUNT" -gt 0 ]; then
        printf 'COMPLETED_WITH_ERRORS'
    elif [ "$LOG_WARN_COUNT" -gt 0 ]; then
        printf 'COMPLETED_WITH_WARNINGS'
    else
        printf 'COMPLETED_CLEAN'
    fi
}

# Plain-language reading of the verdict, for a reader who is not going to parse
# the token.
collection_log_result_meaning() {
    case "$1" in
        COMPLETED_CLEAN)
            printf 'The collection completed and nothing limited the evidence gathered.'
            ;;
        COMPLETED_WITH_WARNINGS)
            printf 'The collection completed, but some evidence was limited or unavailable. Review the WARN lines above before relying on the affected report sections.'
            ;;
        COMPLETED_WITH_ERRORS)
            printf 'The collection ran but at least one step failed. Review the ERROR lines above; the evidence package may be incomplete.'
            ;;
        FAILED)
            printf 'The collection could not be completed. The evidence package should not be relied upon.'
            ;;
        *)
            printf 'Unrecognised result.'
            ;;
    esac
}

# Close the log with a summary block. The RESULT, ERRORS, and WARNINGS lines are
# deliberately bare "KEY: value" so an automated reader does not have to parse
# prose to determine the outcome.
finalize_collection_log() {
    if [ "$LOG_READY" != "yes" ] || [ -z "$LOG_FILE" ]; then
        return
    fi

    recount_log_levels
    _log_result=`collection_log_result`
    _log_meaning=`collection_log_result_meaning "$_log_result"`
    _log_files_collected=0
    if [ -f "$MANIFEST_FILE" ]; then
        _log_files_collected=`grep -c '^COPIED|' "$MANIFEST_FILE" 2>/dev/null`
        [ -n "$_log_files_collected" ] || _log_files_collected=0
    fi

    {
        printf '\n'
        printf '================================================================\n'
        printf 'SUMMARY\n'
        printf '================================================================\n'
        printf '\n'
        printf 'RESULT: %s\n' "$_log_result"
        printf 'ERRORS: %s\n' "$LOG_ERROR_COUNT"
        printf 'WARNINGS: %s\n' "$LOG_WARN_COUNT"
        printf 'FILES_COLLECTED: %s\n' "$_log_files_collected"
        printf 'HOST: %s\n' "$HOSTNAME_VALUE"
        printf 'PLATFORM: %s\n' "$OS_NAME"
        printf 'STARTED: %s\n' "$TIMESTAMP"
        printf 'FINISHED: %s\n' "`log_timestamp`"
        printf 'OUTPUT_DIRECTORY: %s\n' "$COLLECTION_DIRECTORY"
        printf 'ARCHIVE_PLANNED: %s\n' "$WORKING_DIRECTORY/$ARCHIVE_BASE_NAME"
        printf 'ARCHIVE_RESULT: reported in the addendum below, if present\n'
        printf 'CONFIGURATION_CHANGES_MADE: none\n'
        printf '\n'
        printf 'What this means\n'
        wrap_text "  $_log_meaning"
        printf '\n'
    } >> "$LOG_FILE" 2>/dev/null
}

# Record what happened to every path this collection consults.
#
# THE RULE THIS ENFORCES
# If a path was used to gain knowledge, or is referenced anywhere in the report,
# its fate must be recorded in the manifest. An auditor reading the manifest
# must be able to account for every source the report draws on, without
# exception - that is what makes the package usable as workpaper support rather
# than as an unsourced assertion.
#
# The four outcomes are recorded distinctly, because they mean different things
# to a reviewer:
#
#   COPIED               the file is in the package; compare it against the report
#   DIRECTORY_EXAMINED   the directory was read; the file count says what was in it
#   EXAMINED_ABSENT      the path does not exist on this host. Normal - this
#                        script targets several Unix families and most hosts
#                        legitimately lack most of these paths - but recorded so
#                        that "not collected" is never ambiguous between "not
#                        there" and "not looked at"
#   EXAMINED_UNREADABLE  the path EXISTS but could not be read. This is a real
#                        evidence gap and is the case that must never be silent
#
# An empty directory previously disappeared from the chain entirely: the loop
# copied nothing, so nothing was recorded, while the report still printed the
# path as a source. That is not a cosmetic omission. An empty
# /etc/ssh/sshd_config.d is itself evidence - it establishes that no drop-in
# overrides the main SSH configuration - and an empty /etc/sudoers.d likewise
# establishes that no supplementary sudo rules exist. Recording the directory
# and its file count preserves that finding.
record_file_reference() {
    ref_path=${1%/}
    if [ -z "$ref_path" ]; then
        return
    fi

    if [ -f "$ref_path" ]; then
        if [ -r "$ref_path" ]; then
            copy_file_to_collection "$ref_path"
        else
            record_reference_outcome "EXAMINED_UNREADABLE" "$ref_path" ""
            log_event WARN evidence "$ref_path exists but could not be read; it is referenced by the report and is missing from the evidence package"
        fi
    elif [ -d "$ref_path" ]; then
        _ref_count=0
        for ref_entry in "$ref_path"/*; do
            if [ -f "$ref_entry" ]; then
                _ref_count=`expr "$_ref_count" + 1`
                copy_file_to_collection "$ref_entry"
            fi
        done
        record_reference_outcome "DIRECTORY_EXAMINED" "$ref_path" "files=$_ref_count"
        if [ "$_ref_count" -eq 0 ]; then
            log_event INFO evidence "$ref_path exists but contains no files; recorded as examined and empty, which is itself evidence that nothing in it overrides the corresponding configuration"
        fi
    else
        record_reference_outcome "EXAMINED_ABSENT" "$ref_path" ""
    fi
}

# Write one manifest line per path per outcome, without repeating it.
#
# Several sections legitimately consult the same path - /etc/passwd is used by a
# dozen of them - and a manifest that repeated every consultation would obscure
# the inventory it exists to provide. The first record of an outcome is kept and
# later identical ones are suppressed.
record_reference_outcome() {
    _outcome_verb=$1
    _outcome_path=$2
    _outcome_extra=$3

    if [ ! -f "$MANIFEST_FILE" ]; then
        return
    fi
    if grep -Fq "$_outcome_verb|$_outcome_path|" "$MANIFEST_FILE" 2>/dev/null; then
        return
    fi
    if [ -n "$_outcome_extra" ]; then
        record_manifest_line "$_outcome_verb|$_outcome_path|$_outcome_extra"
    else
        record_manifest_line "$_outcome_verb|$_outcome_path|"
    fi
}

# Evidence directory preparation:
# The script recreates its own local evidence directory before collection so
# the output reflects one execution. This cleanup is limited to the directory
# named by COLLECTION_DIRECTORY under the current working directory. It does
# not remove or modify host configuration files outside that evidence folder.
prepare_collection_directory() {
    if rm -rf "$COLLECTION_DIRECTORY" 2>/dev/null && \
       mkdir -p "$REPORTS_DIRECTORY" "$RAW_FILES_DIRECTORY" "$METADATA_DIRECTORY" 2>/dev/null; then
        : > "$MANIFEST_FILE"
        : > "$SENSITIVE_SKIPPED_FILE"
        COLLECTION_STATUS="ready"
        initialize_collection_log
        log_event INFO startup "evidence directory prepared at $COLLECTION_DIRECTORY"
    else
        COLLECTION_STATUS="failed to create collection directory"
        # No log file is possible in this case, so report on the terminal.
        printf 'ERROR: could not create the evidence directory at %s\n' "$COLLECTION_DIRECTORY" >&2
        printf 'No evidence was collected. Check that the output directory is writable.\n' >&2
    fi
}

# Source-file collection:
# Non-sensitive files that are printed in the report are copied into raw_files/
# using a mirrored path structure. For example, /etc/ssh/sshd_config is copied
# under raw_files/etc/ssh/sshd_config. The source file is opened read-only and
# copied out for evidence retention; the original file is not changed.
copy_file_to_collection() {
    file_path=$1

    if [ "$COLLECTION_STATUS" != "ready" ]; then
        return
    fi

    if ! [ -f "$file_path" ] || ! [ -r "$file_path" ]; then
        return
    fi

    if is_sensitive_path "$file_path"; then
        record_sensitive_skip "$file_path"
        return
    fi

    target_path=$RAW_FILES_DIRECTORY$file_path
    target_directory=`dirname "$target_path" 2>/dev/null || echo "$RAW_FILES_DIRECTORY"`

    # The collection directory is recreated at the start of each run, so an
    # existing copy means this file was already captured during this run.
    # Skipping the re-copy keeps MANIFEST.txt free of duplicate COPIED lines
    # when a file is reached through more than one section.
    if [ -f "$target_path" ]; then
        return
    fi

    if mkdir -p "$target_directory" 2>/dev/null; then
        # A host that keeps password hashes inline in /etc/passwd gets a redacted
        # copy instead of the file itself. Withholding the file entirely would
        # remove the account inventory, which is core evidence referenced by a
        # dozen sections; copying it verbatim would ship the credentials this
        # script exists to protect. Redacting field 2 keeps all of the evidence
        # and none of the secret.
        if [ "$file_path" = "/etc/passwd" ] && passwd_file_has_inline_hashes; then
            if write_redacted_passwd_copy "$file_path" "$target_path"; then
                _src_perms=`ls -ld "$file_path" 2>/dev/null | awk 'NR == 1 { print $1 }'`
                _src_owner=`ls -ld "$file_path" 2>/dev/null | awk 'NR == 1 { print $3 ":" $4 }'`
                record_manifest_line "COPIED_REDACTED|$file_path|field=2_password_hash|source_perms=${_src_perms:-unknown}|source_owner=${_src_owner:-unknown}"
                record_sensitive_skip "$file_path (field 2 only; this host stores password hashes inline in /etc/passwd, so a redacted copy was delivered in place of the original)"
                log_event WARN sensitive "/etc/passwd on this host carries password hashes inline in field 2 rather than in a shadow file; raw_files/etc/passwd is a REDACTED copy with field 2 removed and is not a byte-for-byte reproduction of the source"
            else
                log_event ERROR sensitive "/etc/passwd carries inline password hashes but the redacted copy could not be written; the file was deliberately NOT copied, so raw_files/ has no /etc/passwd"
                rm -f "$target_path" 2>/dev/null
            fi
            return
        fi
        if cp -p "$file_path" "$target_path" 2>/dev/null || cp "$file_path" "$target_path" 2>/dev/null; then
            # The permissions and ownership of the SOURCE file are a control fact
            # and are recorded here. The permissions of our copy are not evidence
            # and are normalised at handover so the audit team can read them.
            _src_perms=`ls -ld "$file_path" 2>/dev/null | awk 'NR == 1 { print $1 }'`
            _src_owner=`ls -ld "$file_path" 2>/dev/null | awk 'NR == 1 { print $3 ":" $4 }'`
            record_manifest_line "COPIED|$file_path|source_perms=${_src_perms:-unknown}|source_owner=${_src_owner:-unknown}"
        else
            log_event WARN evidence "$file_path was readable but could not be copied into the package; the report may reference a file that was not delivered"
        fi
    else
        log_event WARN evidence "could not create the destination directory for $file_path; the file was not delivered"
    fi
}

# Checksum calculation:
# The script attempts common checksum tools available across Unix-like systems.
# These tools read file contents to calculate a reference value and do not
# write to or alter the measured file.
#
# CHECKSUM_ALGORITHM names what the selected tool actually computes. The last
# fallback, cksum, is a CRC and not a cryptographic hash at all, so any output
# that presents a checksum has to say which of the two it is holding: a reviewer
# comparing a CRC against an issued SHA-256 would otherwise see an unexplained
# mismatch and reasonably conclude the file had been altered.
CHECKSUM_ALGORITHM=unavailable
if command_exists sha256sum || command_exists shasum || command_exists digest; then
    CHECKSUM_ALGORITHM=sha256
elif command_exists cksum; then
    CHECKSUM_ALGORITHM=cksum-crc
fi
readonly CHECKSUM_ALGORITHM

print_file_checksum() {
    file_path=$1

    if file_readable "$file_path"; then
        if command_exists sha256sum; then
            sha256sum "$file_path" 2>/dev/null
        elif command_exists shasum; then
            shasum -a 256 "$file_path" 2>/dev/null
        elif command_exists digest; then
            digest -a sha256 "$file_path" 2>/dev/null
        elif command_exists cksum; then
            cksum "$file_path" 2>/dev/null
        else
            not_available
        fi
    else
        not_available
    fi
}

# File metadata review:
# The script records path, permissions, ownership, timestamps, and checksums
# where available. This information is obtained through read-only inspection
# commands and is useful for validating sensitive file posture without changing
# the file itself.
# THE RULE: if a file is named in the report, its contents are in the package.
#
# This function reports a file's permissions, ownership, and checksum. It used
# to stop there, and that was a hole in the evidence chain rather than a
# deliberate limit: Section 22 is built entirely on this function and names a
# platform-specific list of a dozen or more files - auditd.conf, audit.rules,
# rsyslog.conf, chrony.conf, inittab, pam.conf, the bootloader configuration.
# Every one of those was cited in the report, with a checksum inviting the
# reader to compare it against something, while the file itself was never
# delivered. An auditor reading the report had no way to see what any of them
# actually contained.
#
# The copy is now unconditional here, so the rule holds no matter which code
# path happens to reach a file first. copy_file_to_collection is idempotent - it
# returns early when the file is already in the package - so a file reached by
# several sections is still copied once and recorded once.
#
# Credential-bearing files are the deliberate exception and are unaffected:
# copy_file_to_collection routes them to the sensitive-file safeguards, which
# withhold the contents and record the decision in both the manifest and
# SENSITIVE_FILES_SKIPPED.txt. Section 22 naming /etc/shadow and delivering only
# its metadata is the intended behaviour, and is why the skip list exists.
print_path_metadata() {
    file_path=$1

    printf 'Path: %s\n' "$file_path"
    if path_exists "$file_path"; then
        if ls -ld "$file_path" 2>/dev/null; then
            :
        else
            not_available
        fi

        if [ -f "$file_path" ]; then
            printf 'Checksum: '
            print_file_checksum "$file_path"
            copy_file_to_collection "$file_path"
        fi
    else
        not_available
    fi
    blank_line
}

# Active-configuration extraction:
# This helper prints non-comment, non-blank lines from a readable file. It is
# used where a concise summary is more useful than printing comments and
# defaults. The source file is read only.
print_noncomment_or_not_available() {
    file_path=$1

    if file_readable "$file_path"; then
        if awk '/^[[:space:]]*#/ { next } /^[[:space:]]*$/ { next } { print; found = 1 } END { if (!found) exit 1 }' "$file_path" 2>/dev/null; then
            :
        else
            no_entries_found
        fi
    else
        not_available
    fi
}

# Sensitive-file review:
# When a file is classified as sensitive, the script does not print or copy the
# full file body. Instead, it reports metadata and a limited safe summary, such
# as an authorized_keys entry count or selected non-secret SSSD settings. This
# is intended to support audit review while avoiding broad distribution of
# credential-bearing material.
print_sensitive_file_review() {
    file_path=$1

    printf 'Sensitive file review: %s\n' "$file_path"
    print_path_metadata "$file_path"

    case "$file_path" in
        /etc/sssd/sssd.conf)
            subsection "Safe settings extracted:"
            if file_readable "$file_path"; then
                if awk -F= '
                    /^[[:space:]]*\[/ { print; found = 1; next }
                    /^[[:space:]]*(domains|services|id_provider|auth_provider|access_provider|cache_credentials|use_fully_qualified_names)[[:space:]]*=/ {
                        gsub(/^[[:space:]]+/, "", $0)
                        print
                        found = 1
                    }
                    END { if (!found) exit 1 }
                ' "$file_path" 2>/dev/null; then
                    :
                else
                    not_available
                fi
            else
                not_available
            fi
            blank_line
            ;;
        */authorized_keys)
            subsection "Safe summary:"
            if file_readable "$file_path"; then
                line_count=`awk 'END { print NR + 0 }' "$file_path" 2>/dev/null`
                printf 'Authorized key entries: %s\n' "${line_count:-0}"
            else
                not_available
            fi
            blank_line
            ;;
        */.rhosts|*/.shosts|/etc/hosts.equiv|/etc/shosts.equiv)
            subsection "Safe summary:"
            if file_readable "$file_path"; then
                line_count=`awk 'END { print NR + 0 }' "$file_path" 2>/dev/null`
                printf 'Configured trust entries: %s\n' "${line_count:-0}"
            else
                not_available
            fi
            blank_line
            ;;
        *)
            subsection "Safe summary:"
            printf 'Full file contents intentionally not printed and not copied.\n'
            blank_line
            ;;
    esac

    record_manifest_line "SENSITIVE_METADATA_ONLY|$file_path"
    # Also record it in the skip file. A file reviewed through this path is
    # withheld just as deliberately as one stopped in copy_file_to_collection,
    # and the client is directed to SENSITIVE_FILES_SKIPPED.txt to confirm what
    # was withheld - so it has to be listed there too.
    record_sensitive_skip "$file_path"
}

# Full-file evidence handling:
# This helper is used whenever the report should show a source file. Readable
# non-sensitive files are printed and copied into raw_files/. Sensitive files
# are diverted to the sensitive-file review path. Missing or unreadable files
# are clearly reported as not available. No source file is modified.
print_file_with_header() {
    file_path=$1

    printf 'File: %s\n' "$file_path"
    if is_sensitive_path "$file_path"; then
        print_sensitive_file_review "$file_path"
        return
    fi

    if file_readable "$file_path"; then
        copy_file_to_collection "$file_path"
        cat "$file_path"
        record_manifest_line "PRINTED|$file_path"
    else
        not_available
        # A file that is simply absent is normal: this script targets several
        # Unix families and most hosts legitimately lack most of these paths.
        # A file that EXISTS but cannot be read is a genuine evidence gap, and
        # is the case worth surfacing - in the report both render identically as
        # "not available", which is exactly why the log separates them.
        if path_exists "$file_path"; then
            log_event WARN evidence "$file_path exists but could not be read; its content is missing from the evidence package"
        fi
    fi
    blank_line
}

# Platform context:
# Operating-system family and privilege context are printed first because later
# evidence sources vary by platform. A "not available" result can be expected
# when a Linux-specific file is not present on AIX, Solaris, HP-UX, or BSD.
print_platform_details() {
    subsection "Operating System Details:"
    printf 'Platform: %s\n' "$OS_NAME"

    case "$OS_NAME" in
        Linux) printf 'Platform Family: Linux\n' ;;
        AIX) printf 'Platform Family: AIX\n' ;;
        SunOS) printf 'Platform Family: Solaris/Illumos\n' ;;
        HP-UX) printf 'Platform Family: HP-UX\n' ;;
        Darwin) printf 'Platform Family: Darwin/macOS\n' ;;
        FreeBSD|OpenBSD|NetBSD) printf 'Platform Family: BSD\n' ;;
        *) printf 'Platform Family: Other/Unknown Unix\n' ;;
    esac

    if command_exists uname; then
        printf 'Kernel Release: %s\n' "`uname -r 2>/dev/null || echo not available`"
        printf 'Kernel Version: %s\n' "`uname -v 2>/dev/null || echo not available`"
        printf 'Hardware Platform: %s\n' "`uname -m 2>/dev/null || echo not available`"
    else
        printf 'uname command: '
        not_available
    fi

    printf 'Execution User: %s\n' "`id -un 2>/dev/null || echo unknown`"
    printf 'Effective UID: %s\n' "`id -u 2>/dev/null || echo unknown`"
    printf 'Expected elevated invocation: sudo sh %s\n' "$SCRIPT_NAME"
    printf 'Non-root test invocation: sh %s --dry-run\n' "$SCRIPT_NAME"
    printf 'Run privilege mode: %s\n' "$RUN_PRIVILEGE_MODE"
}

# Privileged group summary:
# This function identifies membership in commonly privileged administrative
# groups. It reads group information only and does not add or remove users from
# any group.
#
# The group that confers administrative privilege is platform-specific, and
# checking only wheel and sudo meant this section reported "not available" on
# every AIX host - a platform where the privileged group is `system`, whose
# members hold most root-equivalent authority. Reporting nothing on the exact
# question the section exists to answer, on a platform in scope for these
# engagements, made the evidence look clean rather than absent.
#
#   wheel     BSD, RHEL family, Solaris - traditional su/sudo gate
#   sudo      Debian and Ubuntu - the sudoers-granted group
#   system    AIX - members hold broad administrative authority
#   adm/bin   AIX and HP-UX - historic administrative groups
#   root      the root group itself, where it has members beyond root
#   admin     HP-UX and some Linux builds
privileged_group_names() {
    printf 'wheel\nsudo\nroot\nadm\nadmin\n'
    case "$OS_NAME" in
        AIX)   printf 'system\nsecurity\nbin\n' ;;
        HP-UX) printf 'sys\nbin\n' ;;
        SunOS) printf 'sysadmin\n' ;;
    esac
}

print_group_membership_summary() {
    found=no

    if command_exists getent; then
        record_manifest_line "GETENT_QUERY|group privileged|source=name_service"
        record_file_reference /etc/group
        for _priv_group in `privileged_group_names`; do
            if getent group "$_priv_group" >/dev/null 2>&1; then
                getent group "$_priv_group" | awk -F: '{print "- " $1 ": " $4}'
                found=yes
            else
                printf '%s\n' "- $_priv_group: not present on this host"
            fi
        done
    elif file_readable /etc/group; then
        record_file_reference /etc/group
        for _priv_group in `privileged_group_names`; do
            if awk -F: '$1 == "'"$_priv_group"'" { print "- " $1 ": " $4; found = 1 } END { if (!found) exit 1 }' /etc/group 2>/dev/null; then
                found=yes
            else
                printf '%s\n' "- $_priv_group: not present on this host"
            fi
        done
    else
        not_available
        return
    fi

    if [ "$found" = no ]; then
        no_entries_found
    fi
    blank_line
    printf 'Note: an empty member list does not mean the group grants nothing. Users\n'
    printf '  whose PRIMARY group is one of the above are recorded by GID in\n'
    printf '  /etc/passwd rather than in the member field here. Read this with the\n'
    printf '  account inventory in Sections 13 and 24.\n'
}

# Duplicate identity review:
# Duplicate UID or GID values can reduce accountability because multiple names
# may map to the same numeric identity. This review reads account and group
# databases only.
print_duplicate_uid_gid_review() {
    subsection "Duplicate UID Review:"
    if file_readable /etc/passwd; then
        record_file_reference /etc/passwd
        if awk -F: '
            { uid_count[$3]++; users[$3] = users[$3] " " $1 }
            END {
                found = 0
                for (uid in uid_count) {
                    if (uid_count[uid] > 1) {
                        print "UID " uid ":" users[uid]
                        found = 1
                    }
                }
                if (!found) exit 1
            }
        ' /etc/passwd 2>/dev/null; then
            :
        else
            no_entries_found
        fi
    else
        not_available
    fi
    blank_line

    subsection "Duplicate GID Review:"
    if file_readable /etc/group; then
        record_file_reference /etc/group
        if awk -F: '
            { gid_count[$3]++; groups[$3] = groups[$3] " " $1 }
            END {
                found = 0
                for (gid in gid_count) {
                    if (gid_count[gid] > 1) {
                        print "GID " gid ":" groups[gid]
                        found = 1
                    }
                }
                if (!found) exit 1
            }
        ' /etc/group 2>/dev/null; then
            :
        else
            no_entries_found
        fi
    else
        not_available
    fi
}

# Group membership inventory:
# This function prints group membership information from the system's available
# name service interface or local group file. It does not change group records.
print_all_groups() {
    if command_exists getent; then
        record_manifest_line "GETENT_QUERY|group ALL|source=name_service"
        record_file_reference /etc/group
        getent group 2>/dev/null | awk -F: '{print $1 ": " $4}'
    elif file_readable /etc/group; then
        record_file_reference /etc/group
        awk -F: '{print $1 ": " $4}' /etc/group 2>/dev/null
    else
        not_available
    fi
}

# Password and lockout policy summary:
# This function extracts platform-relevant password aging, complexity, and
# lockout settings. It reads configuration files only and does not run password
# reset, password change, or account lockout commands.
print_auth_summary() {
    subsection "Password Aging Summary:"
    case "$OS_NAME" in
        Linux)
            if file_readable /etc/login.defs; then
                record_file_reference /etc/login.defs
                grep -E '^(PASS_MIN_LEN|PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        AIX)
            if file_readable /etc/security/user; then
                record_file_reference /etc/security/user
                awk '/^default:/{flag=1} flag && /^[[:space:]]*(minage|maxage|pwdwarntime|loginretries)[[:space:]]*=/{print}' /etc/security/user 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        SunOS|HP-UX)
            if file_readable /etc/default/passwd; then
                record_file_reference /etc/default/passwd
                grep -E '^(PASSLENGTH|MINLENGTH|MINDIFF|MAXWEEKS|MINWEEKS|WARNWEEKS)' /etc/default/passwd 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        *)
            not_available
            ;;
    esac
    blank_line

    subsection "Password Quality Summary:"
    case "$OS_NAME" in
        Linux)
            # Three sources, all reported rather than the first match only.
            # pwquality.conf holds the values on RHEL-family hosts;
            # /etc/security/pwquality.conf.d/ overrides it on current releases;
            # and Debian, Ubuntu, and SUSE configure the same module inline in
            # /etc/pam.d/common-password, which the RHEL-oriented system-auth
            # path never reads. Stopping at the first hit reported "not
            # available" for quality settings on a Debian-family host that had
            # them configured.
            _pwq_found=no
            if file_readable /etc/security/pwquality.conf; then
                record_file_reference /etc/security/pwquality.conf
                if grep -E '^[[:space:]]*(minlen|minclass|maxrepeat|maxsequence|dcredit|ucredit|lcredit|ocredit|difok|dictcheck|enforcing|enforce_for_root)' /etc/security/pwquality.conf 2>/dev/null; then
                    _pwq_found=yes
                fi
            fi
            if directory_exists /etc/security/pwquality.conf.d; then
                record_file_reference /etc/security/pwquality.conf.d
                if grep -E '^[[:space:]]*(minlen|minclass|maxrepeat|maxsequence|dcredit|ucredit|lcredit|ocredit|difok|dictcheck|enforcing|enforce_for_root)' /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
                    _pwq_found=yes
                fi
            fi
            for _pwq_pam in /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password; do
                if file_readable "$_pwq_pam"; then
                    record_file_reference "$_pwq_pam"
                    if grep -E 'pam_cracklib\.so|pam_pwquality\.so|pam_passwdqc\.so' "$_pwq_pam" 2>/dev/null; then
                        _pwq_found=yes
                    fi
                fi
            done
            if [ "$_pwq_found" = no ]; then
                not_available
            fi
            ;;
        AIX)
            if file_readable /etc/security/user; then
                record_file_reference /etc/security/user
                awk '/^default:/{flag=1} flag && /^[[:space:]]*(minlen|minother|minalpha|maxrepeats|mindiff|pwdchecks)[[:space:]]*=/{print}' /etc/security/user 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        SunOS|HP-UX)
            if file_readable /etc/default/passwd; then
                record_file_reference /etc/default/passwd
                grep -E '^(MINLENGTH|MINDIFF|MAXREPEATS|PASSLENGTH)' /etc/default/passwd 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        *)
            not_available
            ;;
    esac
    blank_line

    subsection "Account Lockout Summary:"
    case "$OS_NAME" in
        Linux)
            # The PAM stack shows WHETHER lockout is enabled; faillock.conf shows
            # WITH WHAT PARAMETERS. On RHEL 8 and later the module is enabled with
            # no inline arguments and every value - deny, unlock_time,
            # fail_interval, even whether root is subject to it - lives in
            # /etc/security/faillock.conf. Reading only the pam.d lines proves a
            # lockout control exists while saying nothing about its threshold,
            # which is the number the control actually turns on.
            _lockout_found=no
            if directory_exists /etc/pam.d; then
                record_file_reference /etc/pam.d
                printf 'PAM lockout modules in use:\n'
                if grep -E 'pam_tally2\.so|pam_faillock\.so' /etc/pam.d/* 2>/dev/null; then
                    _lockout_found=yes
                else
                    printf '  none found\n'
                fi
            fi
            blank_line
            printf 'Lockout parameters from /etc/security/faillock.conf:\n'
            if file_readable /etc/security/faillock.conf; then
                record_file_reference /etc/security/faillock.conf
                if grep -E '^[[:space:]]*(deny|unlock_time|fail_interval|even_deny_root|root_unlock_time|audit|silent|no_log_info|admin_group|dir)' /etc/security/faillock.conf 2>/dev/null; then
                    _lockout_found=yes
                else
                    printf '  file present but no parameters are set; the pam_faillock\n'
                    printf '  built-in defaults apply (deny=3, unlock_time=600)\n'
                    _lockout_found=yes
                fi
            else
                printf '  not available\n'
            fi
            if [ "$_lockout_found" = no ]; then
                not_available
            fi
            ;;
        AIX)
            if file_readable /etc/security/user; then
                record_file_reference /etc/security/user
                awk '/^default:/{flag=1} flag && /^[[:space:]]*(loginretries|account_locked)[[:space:]]*=/{print}' /etc/security/user 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        SunOS|HP-UX)
            if file_readable /etc/default/login; then
                record_file_reference /etc/default/login
                grep -E '^(RETRIES|LOCK_AFTER_RETRIES)' /etc/default/login 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        *)
            not_available
            ;;
    esac
}

# Password policy source-file capture:
# The specific files collected here depend on the detected operating system.
# The files are read and copied where appropriate; no authentication settings
# are changed.
print_auth_full_content() {
    case "$OS_NAME" in
        Linux)
            subsection "Full File Content: /etc/login.defs"
            print_file_with_header /etc/login.defs
            subsection "Full File Content: /etc/security/pwquality.conf"
            print_file_with_header /etc/security/pwquality.conf
            subsection "Full File Content: /etc/security/faillock.conf"
            print_file_with_header /etc/security/faillock.conf
            subsection "Full File Content: /etc/pam.d/system-auth"
            print_file_with_header /etc/pam.d/system-auth
            subsection "Full File Content: /etc/pam.d/password-auth"
            print_file_with_header /etc/pam.d/password-auth
            # Debian, Ubuntu, and SUSE keep the password and authentication
            # stacks here rather than in the RHEL-style system-auth files.
            subsection "Full File Content: /etc/pam.d/common-password"
            print_file_with_header /etc/pam.d/common-password
            subsection "Full File Content: /etc/pam.d/common-auth"
            print_file_with_header /etc/pam.d/common-auth
            ;;
        AIX)
            subsection "Full File Content: /etc/security/user"
            print_file_with_header /etc/security/user
            ;;
        SunOS|HP-UX)
            subsection "Full File Content: /etc/default/passwd"
            print_file_with_header /etc/default/passwd
            subsection "Full File Content: /etc/default/login"
            print_file_with_header /etc/default/login
            ;;
        *)
            not_available
            blank_line
            ;;
    esac
}

# Authentication source summary:
# This section identifies whether the host appears to use local files,
# directory services, PAM modules, SSSD, LDAP, winbind, NIS, or platform-native
# mechanisms. Commands and file reads are informational only.
print_authentication_summary() {
    subsection "Authentication Summary:"
    case "$OS_NAME" in
        Linux)
            printf 'nsswitch passwd entry with ldap/sss/winbind: '
            if file_readable /etc/nsswitch.conf; then
                record_file_reference /etc/nsswitch.conf
                grep -E 'passwd:.*(ldap|sss|winbind|nis|compat)' /etc/nsswitch.conf 2>/dev/null || not_available
            else
                not_available
            fi
            printf 'SSSD configuration present: '
            if file_readable /etc/sssd/sssd.conf; then
                record_file_reference /etc/sssd/sssd.conf
                printf 'yes\n'
            else
                printf 'no\n'
            fi
            subsection "PAM Authentication Module References:"
            if directory_exists /etc/pam.d; then
                record_file_reference /etc/pam.d
                grep -E 'pam_ldap\.so|pam_sss\.so|pam_winbind\.so' /etc/pam.d/* 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        AIX)
            if file_readable /etc/security/user; then
                record_file_reference /etc/security/user
                awk '/^[^[:space:]].*:$/ {user=$0} /^[[:space:]]*SYSTEM[[:space:]]*=/{print user " " $0; found=1} END { if (!found) exit 1 }' /etc/security/user 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        SunOS)
            if file_readable /etc/nsswitch.conf; then
                record_file_reference /etc/nsswitch.conf
                grep -E '^(passwd|group):' /etc/nsswitch.conf 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        HP-UX)
            if file_readable /etc/pam.conf; then
                record_file_reference /etc/pam.conf
                grep -E 'pam_ldap|pam_unix|pam_krb5' /etc/pam.conf 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        *)
            not_available
            ;;
    esac
}

# Authentication source-file capture:
# Platform-relevant identity and authentication files are printed or safely
# summarized. Sensitive files are routed through the sensitive-file safeguards.
print_authentication_full_content() {
    case "$OS_NAME" in
        Linux)
            subsection "Full File Content: /etc/nsswitch.conf"
            print_file_with_header /etc/nsswitch.conf
            subsection "Sensitive Review: /etc/sssd/sssd.conf"
            print_file_with_header /etc/sssd/sssd.conf
            ;;
        AIX)
            subsection "Full File Content: /etc/security/user"
            print_file_with_header /etc/security/user
            ;;
        SunOS)
            subsection "Full File Content: /etc/nsswitch.conf"
            print_file_with_header /etc/nsswitch.conf
            subsection "Full File Content: /etc/user_attr"
            print_file_with_header /etc/user_attr
            subsection "Full File Content: /etc/security/prof_attr"
            print_file_with_header /etc/security/prof_attr
            subsection "Full File Content: /etc/security/exec_attr"
            print_file_with_header /etc/security/exec_attr
            ;;
        HP-UX)
            subsection "Full File Content: /etc/pam.conf"
            print_file_with_header /etc/pam.conf
            ;;
        *)
            not_available
            blank_line
            ;;
    esac
}

# Sudo authorization summary:
# Sudo is reviewed separately from UID 0 because delegated root access may allow
# administrative activity without direct root login. This function reads sudoers
# rules only and does not run privileged commands through sudo.
print_sudo_summary() {
    subsection "Summary: Active Sudoers Rules"
    if file_readable /etc/sudoers; then
        record_file_reference /etc/sudoers
        print_noncomment_or_not_available /etc/sudoers
    else
        not_available
    fi

    if directory_exists /etc/sudoers.d; then
        found_file=no
        for file_path in /etc/sudoers.d/*; do
            if [ -f "$file_path" ]; then
                found_file=yes
                printf '\nActive entries from %s\n' "$file_path"
                print_noncomment_or_not_available "$file_path"
            fi
        done
        if [ "$found_file" = no ]; then
            printf '\n/etc/sudoers.d: '
            no_entries_found
        fi
    else
        printf '\n/etc/sudoers.d: '
        not_available
    fi
}

# Sudo source-file capture:
# The sudoers file and include directory are read for evidence. The script does
# not invoke visudo, edit sudoers, or validate / change sudo configuration.
print_sudo_full_content() {
    subsection "Full File Content: /etc/sudoers"
    print_file_with_header /etc/sudoers

    subsection "Full File Content: /etc/sudoers.d"
    if directory_exists /etc/sudoers.d; then
        found_file=no
        for file_path in /etc/sudoers.d/*; do
            if [ -f "$file_path" ]; then
                found_file=yes
                print_file_with_header "$file_path"
            fi
        done
        if [ "$found_file" = no ]; then
            no_entries_found
            blank_line
        fi
    else
        not_available
        blank_line
    fi
}

# SSH configuration summary:
# SSH settings are reviewed because SSH is commonly the primary administrative
# access path. The script reads sshd configuration and does not restart or
# reload the SSH daemon.
#
# /etc/ssh/sshd_config.d/ must be read alongside the main file, and on a current
# Linux distribution it is the more authoritative of the two.
#
# RHEL 9, Ubuntu 22.04 and later, and current SUSE all ship an sshd_config whose
# FIRST directive is "Include /etc/ssh/sshd_config.d/*.conf". sshd applies the
# first occurrence of a keyword and ignores every later one, so a setting in an
# included snippet wins outright over the same setting further down the main
# file - and the distributions use exactly that mechanism to set PermitRootLogin
# and PasswordAuthentication.
#
# Reading only the main file therefore does not merely risk missing a setting; it
# can report a value the running daemon is not enforcing, with the report showing
# "PermitRootLogin no" on a host where a drop-in has re-enabled it. Presenting
# the wrong value confidently is worse than presenting none, so the include
# directory is collected and printed, and the precedence rule is stated in the
# report where the reviewer will see it.
SSH_CONFIG_INCLUDE_DIRECTORY=/etc/ssh/sshd_config.d

print_ssh_summary() {
    subsection "Summary: Relevant SSH Settings"

    _ssh_setting_pattern='^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding|Protocol|AllowUsers|AllowGroups|DenyUsers|DenyGroups|LoginGraceTime|MaxAuthTries)[[:space:]]+'

    printf 'Settings from /etc/ssh/sshd_config:\n'
    if file_readable /etc/ssh/sshd_config; then
        record_file_reference /etc/ssh/sshd_config
        grep -E "$_ssh_setting_pattern" /etc/ssh/sshd_config 2>/dev/null || not_available
    else
        not_available
    fi
    blank_line

    subsection "Settings from $SSH_CONFIG_INCLUDE_DIRECTORY (these take precedence):"
    if directory_exists "$SSH_CONFIG_INCLUDE_DIRECTORY"; then
        record_file_reference "$SSH_CONFIG_INCLUDE_DIRECTORY"
        _ssh_include_found=no
        for _ssh_snippet in "$SSH_CONFIG_INCLUDE_DIRECTORY"/*; do
            if [ -f "$_ssh_snippet" ]; then
                _ssh_include_found=yes
                printf 'From %s:\n' "$_ssh_snippet"
                grep -E "$_ssh_setting_pattern" "$_ssh_snippet" 2>/dev/null || printf '  (no listed settings in this file)\n'
            fi
        done
        if [ "$_ssh_include_found" = no ]; then
            no_entries_found
        fi
    else
        not_available
    fi
    blank_line

    printf 'Precedence note: sshd applies the FIRST occurrence of a keyword and\n'
    printf '  ignores later ones. Where sshd_config begins with an Include of the\n'
    printf '  directory above - the default on RHEL 9, current Ubuntu, and current\n'
    printf '  SUSE - a value set in an included file OVERRIDES the same keyword in\n'
    printf '  the main file. Read the included settings above as authoritative and\n'
    printf '  the main-file settings as the fallback.\n'
    blank_line

    subsection "Include Directives in Effect:"
    if file_readable /etc/ssh/sshd_config; then
        grep -nE '^[[:space:]]*Include[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null || printf 'no Include directives found\n'
    else
        not_available
    fi
    blank_line

    # WHY THE DAEMON IS NOT ASKED DIRECTLY
    #
    # "sshd -T" would print the configuration the daemon has actually resolved,
    # which would settle any disagreement between the two sources above
    # outright. It is deliberately NOT used, and the reason is worth recording
    # because the omission looks like an oversight otherwise.
    #
    # sshd -T opens an AF_INET socket and calls connect() on it while working
    # out its local addressing. Nothing is transmitted - it is a UDP socket used
    # for local address determination - but the syscalls are real and would
    # appear in any packet capture, auditd rule, or EDR product watching the
    # collection run on a client's production host.
    #
    # This tool's guarantee to the client is that it initiates no network
    # activity whatsoever. That guarantee is worth more than the convenience of
    # a resolved configuration dump, because a guarantee with a footnote is not
    # a guarantee: the client's security team would find the socket before they
    # found the explanation, and every subsequent assurance would be re-opened.
    # The two files above are the authoritative record and are collected in
    # full, so nothing that matters is lost by asking the filesystem instead of
    # the daemon.
    #
    # tests/test-no-network-egress.sh enforces this: it fails the build if any
    # AF_INET socket is opened during a collection.
    subsection "Effective Configuration:"
    printf 'Not queried from the running daemon by design. Determining the\n'
    printf '  effective configuration from sshd itself requires invoking the daemon\n'
    printf '  binary, which opens a network socket while resolving its local\n'
    printf '  addressing. This collection makes no network calls of any kind, so\n'
    printf '  the configuration files above are used instead. Where they disagree,\n'
    printf '  the precedence rule stated above determines which value applies.\n'
}

# SSH source-file capture:
# The SSH daemon configuration is printed and copied when readable, together with
# every file in the include directory, which on current Linux distributions holds
# the settings that actually take effect. Collection is read-only and does not
# alter access settings.
print_sshd_full_content() {
    subsection "Full File Content: /etc/ssh/sshd_config"
    print_file_with_header /etc/ssh/sshd_config

    subsection "Full File Content: $SSH_CONFIG_INCLUDE_DIRECTORY"
    if directory_exists "$SSH_CONFIG_INCLUDE_DIRECTORY"; then
        _ssh_full_found=no
        for _ssh_snippet in "$SSH_CONFIG_INCLUDE_DIRECTORY"/*; do
            if [ -f "$_ssh_snippet" ]; then
                _ssh_full_found=yes
                print_file_with_header "$_ssh_snippet"
            fi
        done
        if [ "$_ssh_full_found" = no ]; then
            no_entries_found
            blank_line
        fi
    else
        not_available
        blank_line
    fi
}

# su activity log review:
# Where present, sulog is read to provide evidence of account switching
# activity. The log file is not truncated, rotated, or modified.
sulog_candidates() {
    # /var/adm/sulog is the traditional location on AIX, HP-UX, and Solaris;
    # /var/log/sulog is used by some Linux builds. Both are checked so su
    # history is not reported as unavailable on a host that is recording it.
    printf '/var/log/sulog\n/var/adm/sulog\n'
}

print_sulog_content() {
    found=no

    for sulog_path in `sulog_candidates`; do
        if [ -f "$sulog_path" ]; then
            print_file_with_header "$sulog_path"
            found=yes
        fi
    done

    if [ "$found" = no ]; then
        not_available
        blank_line
    fi
}

# Package inventory:
# Native package-manager commands are used only in query/list mode. The script
# does not install, remove, upgrade, downgrade, or reconfigure software.
#
# The NATIVE packaging system for the detected platform is queried first, before
# falling back to whatever else is installed. Probing for rpm first is wrong on
# any Unix that is not Linux, and wrong in a way that produces a confident,
# complete-looking answer about the wrong population:
#
#   AIX      ships rpm by default for the AIX Toolbox for Open Source Software.
#            "rpm -qa" there lists the Toolbox freeware and NOT the installp
#            filesets that make up the operating system - the actual software
#            inventory an ITGC review is asking about. lslpp is the native tool.
#   HP-UX    can carry rpm from the Internet Express bundle; swlist is native.
#   Solaris  can carry rpm from OpenCSW or the companion DVD; pkginfo is native.
#
# Getting this wrong does not fail loudly. It reports the wrong inventory as if
# it were the right one, which is worse than reporting nothing.
#
# INVOKING rpm WHEN IT IS NOT THE NATIVE PACKAGE MANAGER MODIFIES THE HOST.
#
# This is the reason the selection below tests for a package DATABASE rather
# than for a binary. On a Debian or Ubuntu host that happens to have the rpm
# package installed - not unusual; it arrives with alien and various vendor
# tooling - "rpm -qa" run as root finds no RPM database and CREATES ONE:
#
#     /root/.rpmdb/rpmdb.sqlite
#     /root/.rpmdb/rpmdb.sqlite-shm
#     /root/.rpmdb/rpmdb.sqlite-wal
#
# Three files written into root's home directory by a script whose entire
# premise is that it writes nothing outside its own output directory. On a
# client running file integrity monitoring that is an alert, raised against the
# auditors, during an audit. It was found by tests/test-host-not-modified.sh and
# reproduced directly before this fix was written.
#
# Selecting on the database also fixes the accuracy problem in the same stroke:
# a host with an rpm binary and no rpm database has no RPM-managed software to
# report, so querying rpm there could only ever produce an empty or misleading
# answer.
# Testing for the directory /var/lib/rpm is NOT sufficient, and the first
# attempt at this fix failed for exactly that reason. On Debian and Ubuntu:
#
#   - the rpm package ships /var/lib/rpm as an EMPTY directory, so the
#     directory exists on a host that has no RPM-managed software at all; and
#   - it configures rpm's database path to ~/.rpmdb - a per-user database -
#     rather than to /var/lib/rpm, which is why the file it creates lands in
#     root's home directory.
#
# The reliable test is therefore to ask rpm where its database actually is, and
# then check whether a database FILE exists there. "rpm --eval" only expands a
# macro; it was verified to create nothing. The three filenames cover the
# backends in use: sqlite (rpm 4.16+), Berkeley DB (older), and ndb/lmdb.
rpm_database_present() {
    command_exists rpm || return 1
    _rpm_dbpath=`rpm --eval '%{_dbpath}' 2>/dev/null`
    case "$_rpm_dbpath" in
        ''|%*) _rpm_dbpath=/var/lib/rpm ;;
    esac
    [ -f "$_rpm_dbpath/rpmdb.sqlite" ] ||
    [ -f "$_rpm_dbpath/Packages" ] ||
    [ -f "$_rpm_dbpath/data.mdb" ]
}

# dpkg keeps its inventory in a single status file. Its presence and non-zero
# size is what distinguishes a host dpkg actually manages from one that merely
# has the binary installed.
dpkg_database_present() {
    [ -s /var/lib/dpkg/status ]
}

# True only when rpm is both installed AND has a database to read, so that
# calling it cannot create one.
rpm_usable() {
    command_exists rpm && rpm_database_present
}

dpkg_usable() {
    command_exists dpkg && dpkg_database_present
}

print_package_inventory() {
    _pkg_done=no

    case "$OS_NAME" in
        AIX)
            if command_exists lslpp; then
                printf 'Command: lslpp -L (native AIX installp/RPM inventory)\n'
                lslpp -L 2>/dev/null || not_available
                _pkg_done=yes
            fi
            ;;
        HP-UX)
            if command_exists swlist; then
                printf 'Command: swlist (native HP-UX SD-UX inventory)\n'
                swlist 2>/dev/null || not_available
                _pkg_done=yes
            fi
            ;;
        SunOS)
            if command_exists pkg; then
                printf 'Command: pkg list (native IPS inventory)\n'
                pkg list </dev/null 2>/dev/null || not_available
                _pkg_done=yes
            elif command_exists pkginfo; then
                printf 'Command: pkginfo (native SVR4 package inventory)\n'
                pkginfo 2>/dev/null || not_available
                _pkg_done=yes
            fi
            ;;
    esac

    if [ "$_pkg_done" = "yes" ]; then
        return
    fi

    if rpm_usable; then
        printf 'Command: rpm -qa\n'
        rpm -qa 2>/dev/null || not_available
    elif dpkg_usable; then
        printf 'Command: dpkg -l\n'
        dpkg -l 2>/dev/null || not_available
    elif command_exists pkginfo; then
        printf 'Command: pkginfo\n'
        pkginfo 2>/dev/null || not_available
    elif command_exists swlist; then
        printf 'Command: swlist\n'
        swlist 2>/dev/null || not_available
    elif command_exists lslpp; then
        printf 'Command: lslpp -L\n'
        lslpp -L 2>/dev/null || not_available
    else
        not_available
    fi
}

# Recent login activity:
# The script queries available login history records to support review of
# account usage. It does not alter login records or session state.
print_recent_login_activity() {
    if command_exists last; then
        printf 'Command: last (limited to 50 most recent entries)\n'
        last 2>/dev/null | awk 'NR <= 50 { print }' || not_available
    else
        not_available
    fi
}

# World-writable file and directory review:
#
# Why this matters for the audit:
# A world-writable file can be modified by any account on the host. Two control
# failures follow from that. If the file is a script or binary executed by a
# privileged account (from cron, from a startup script, or through a sudo rule),
# any user can obtain privileged execution, which defeats the restriction of
# administrative access. If the file is application configuration or data in
# financial-reporting scope, unauthorized modification of that data is possible,
# which defeats the integrity of the reported figures. The findings here are
# intended to be read together with the cron evidence in Sections 12 and 21, the
# startup evidence in Section 16, and the sudo evidence in Section 4, so a
# reviewer can determine whether anything privileged actually executes a
# world-writable path.
#
# Why the scan is scoped rather than filesystem-wide:
# This script runs on live client production systems, and an unbounded scan is
# the one part of the collection that could plausibly affect service. A find
# across a whole root filesystem on a host with large data volumes can run for a
# very long time and generate sustained metadata I/O while it does. The scan is
# therefore restricted to the directories where world-write is a genuine control
# failure - system binaries, system configuration, and application install roots
# - and skips data volumes entirely. This mirrors the pruning already applied to
# the SetUID scan below.
#
# Why -xdev is used, and what it costs:
# -xdev stops find at filesystem boundaries. Without it the scan can descend into
# NFS or SAN mounts that happen to live under a scoped path, which pushes load
# onto a remote filer, can stall on an unresponsive mount, and can take an
# unpredictable amount of time. That is an unacceptable risk on a production
# host. The cost of -xdev is that a separately mounted subdirectory beneath a
# scoped path is not traversed, so the population can under-report. That trade is
# made deliberately in favour of not disturbing the client, and the report
# discloses the boundary explicitly so a reviewer knows the limit of the
# evidence rather than assuming completeness.
#
# Why /tmp, /var/tmp, and /dev/shm are excluded:
# Those directories are world-writable by design. Listing their contents would
# produce a large volume of expected findings and bury the ones that matter. The
# actual control on a shared temporary directory is the sticky bit, which stops
# one user deleting or renaming another user's files, so the script verifies the
# sticky bit on those directories instead of enumerating them.
#
# Why only metadata is recorded:
# The script reports path, permissions, and ownership. It never prints or copies
# the contents of a world-writable file. Contents are not needed to evidence the
# control, and a world-writable file can hold anything, including client data
# that has no business leaving the host inside an audit package.
#
# Output is capped, and the cap is disclosed when it is reached, because silent
# truncation would make a host with thousands of findings look the same as a
# clean one.
WORLD_WRITABLE_MAX_ENTRIES=500
readonly WORLD_WRITABLE_MAX_ENTRIES

# Directories that are world-writable by design; the sticky bit is the control.
world_writable_expected_shared_dirs() {
    printf '/tmp\n/var/tmp\n/dev/shm\n/var/lock\n'
}

# Application installation roots supplied by the operator with --app-dir.
#
# These are always listed as scan roots in their own right, even when they sit
# underneath a directory that is already being scanned such as /opt. That looks
# redundant but it is required once -xdev is in use: find does not cross a
# filesystem boundary, so if /opt/someapp is a separate mount, scanning /opt stops
# at the boundary and never enters it. Naming the application root explicitly
# makes find start inside that filesystem, so the tree the operator specifically
# asked about is covered either way. Where the root is not a separate mount this
# does traverse the same files twice, which is why the callers pass their results
# through sort -u before reporting.
operator_app_scan_roots() {
    if [ -z "$APP_DIRECTORIES" ]; then
        return
    fi
    printf '%s\n' "$APP_DIRECTORIES" | while IFS= read -r _app_scan_root; do
        if [ -n "$_app_scan_root" ] && [ -d "$_app_scan_root" ]; then
            printf '%s\n' "$_app_scan_root"
        fi
    done
}

# Scope of the SetUID/SetGID scan: binary paths, plus any application roots the
# operator supplied. Emitted one per line so callers can split on newlines only.
setuid_search_paths() {
    for candidate in /bin /sbin /usr/bin /usr/sbin /usr/lib /usr/libexec /usr/local/bin /usr/local/sbin /usr/local/lib /opt; do
        if [ -d "$candidate" ]; then
            printf '%s\n' "$candidate"
        fi
    done
    operator_app_scan_roots
}

# Scope of the world-writable scan: system binary and configuration paths, plus
# any application roots the operator supplied.
world_writable_search_paths() {
    for candidate in /etc /bin /sbin /usr/bin /usr/sbin /usr/lib /usr/libexec /usr/local /opt; do
        if [ -d "$candidate" ]; then
            printf '%s\n' "$candidate"
        fi
    done
    operator_app_scan_roots
}

print_world_writable_review() {
    if ! command_exists find; then
        not_available
        return
    fi

    # The scan roots are held in the positional parameters rather than in a
    # space-separated string, and IFS is narrowed to a newline while the list is
    # split.
    #
    # This is not stylistic. An application root supplied with --app-dir can
    # legitimately contain spaces, for example /srv/Finance App. Collecting the
    # roots into one string and passing it to find unquoted lets the shell split
    # it on spaces, so find receives /srv/Finance and App, neither of which
    # exists, and silently scans neither. The report would still print the intact
    # path under "Paths scanned" and show no findings, which reads as a clean
    # result for a directory that was never examined - the worst possible
    # outcome, and for exactly the tree the operator asked about. Holding the
    # roots as separate arguments and expanding them as "$@" keeps each path
    # whole. A path containing a newline is not supported.
    _ww_saved_ifs=$IFS
    IFS='
'
    set -- `world_writable_search_paths`
    IFS=$_ww_saved_ifs

    if [ "$#" -eq 0 ]; then
        not_available
        return
    fi

    subsection "Scan Scope and Limits:"
    printf 'Paths scanned:\n'
    for _ww_path in "$@"; do
        printf '  %s\n' "$_ww_path"
    done
    printf 'Filesystem boundary: not crossed (find -xdev). Separately mounted\n'
    printf '  subdirectories beneath the paths above are not traversed, so this\n'
    printf '  population may under-report. This bound is deliberate: it prevents\n'
    printf '  the scan from loading NFS or SAN mounts on a production host.\n'
    printf 'Excluded by design: %s\n' "`world_writable_expected_shared_dirs | tr '\n' ' '`"
    printf '  (world-writable by design; the sticky bit is verified below instead)\n'
    printf 'Recorded per finding: path, permissions, ownership. File contents are\n'
    printf '  never printed or copied into this evidence package.\n'
    printf 'Maximum entries listed per category: %s\n' "$WORLD_WRITABLE_MAX_ENTRIES"
    blank_line

    # Fetch one more than the cap so an exceeded cap can be detected and stated
    # rather than silently truncating the population.
    ww_limit_probe=`expr "$WORLD_WRITABLE_MAX_ENTRIES" + 1`

    subsection "World-Writable Files:"
    ww_files=`find "$@" -xdev -type f -perm -0002 -print 2>/dev/null | sort -u | head -n "$ww_limit_probe"`
    # grep -c always prints a count but exits 1 when that count is zero, so it
    # must not be guarded with "|| echo 0" - that would emit the count twice and
    # break the numeric comparison below, leaving a clean host with a blank
    # section instead of an explicit "no entries found".
    ww_file_count=`printf '%s' "$ww_files" | grep -c . 2>/dev/null`
    [ -n "$ww_file_count" ] || ww_file_count=0
    ww_file_tally="entries=$ww_file_count|truncated=no"
    if [ "$ww_file_count" -eq 0 ]; then
        no_entries_found
    else
        if [ "$ww_file_count" -gt "$WORLD_WRITABLE_MAX_ENTRIES" ]; then
            printf 'NOTE: more than %s world-writable files were found. The list below\n' "$WORLD_WRITABLE_MAX_ENTRIES"
            printf 'is truncated to the first %s entries.\n' "$WORLD_WRITABLE_MAX_ENTRIES"
            blank_line
            ww_files=`printf '%s\n' "$ww_files" | head -n "$WORLD_WRITABLE_MAX_ENTRIES"`
            # The scan stops one past the cap, so the exact population is not
            # known once the cap is exceeded. Record that honestly rather than
            # reporting the probe count as if it were the true total.
            ww_file_tally="entries=more than $WORLD_WRITABLE_MAX_ENTRIES|listed=$WORLD_WRITABLE_MAX_ENTRIES|truncated=yes"
            log_event WARN evidence "more than $WORLD_WRITABLE_MAX_ENTRIES world-writable files exist; Section 10 lists the first $WORLD_WRITABLE_MAX_ENTRIES only and the full population is not in this package"
        fi
        printf '%s\n' "$ww_files" | while IFS= read -r _ww_entry; do
            if [ -n "$_ww_entry" ]; then
                ls -ld "$_ww_entry" 2>/dev/null || printf '%s (metadata not available)\n' "$_ww_entry"
            fi
        done
    fi
    record_manifest_line "WORLD_WRITABLE_SCAN|files|roots=$#|xdev=yes|$ww_file_tally"
    blank_line

    # A world-writable directory without the sticky bit is often worse than a
    # world-writable file: any user can delete or replace files they do not own
    # inside it, including files owned by root.
    subsection "World-Writable Directories Without the Sticky Bit:"
    ww_dirs=`find "$@" -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | sort -u | head -n "$ww_limit_probe"`
    ww_dir_count=`printf '%s' "$ww_dirs" | grep -c . 2>/dev/null`
    [ -n "$ww_dir_count" ] || ww_dir_count=0
    ww_dir_tally="entries=$ww_dir_count|truncated=no"
    if [ "$ww_dir_count" -eq 0 ]; then
        no_entries_found
    else
        if [ "$ww_dir_count" -gt "$WORLD_WRITABLE_MAX_ENTRIES" ]; then
            printf 'NOTE: more than %s such directories were found. The list below is\n' "$WORLD_WRITABLE_MAX_ENTRIES"
            printf 'truncated to the first %s entries.\n' "$WORLD_WRITABLE_MAX_ENTRIES"
            blank_line
            ww_dirs=`printf '%s\n' "$ww_dirs" | head -n "$WORLD_WRITABLE_MAX_ENTRIES"`
            ww_dir_tally="entries=more than $WORLD_WRITABLE_MAX_ENTRIES|listed=$WORLD_WRITABLE_MAX_ENTRIES|truncated=yes"
            log_event WARN evidence "more than $WORLD_WRITABLE_MAX_ENTRIES world-writable directories without a sticky bit exist; Section 10 lists the first $WORLD_WRITABLE_MAX_ENTRIES only"
        fi
        printf '%s\n' "$ww_dirs" | while IFS= read -r _ww_entry; do
            if [ -n "$_ww_entry" ]; then
                ls -ld "$_ww_entry" 2>/dev/null || printf '%s (metadata not available)\n' "$_ww_entry"
            fi
        done
    fi
    record_manifest_line "WORLD_WRITABLE_SCAN|directories_without_sticky|roots=$#|xdev=yes|$ww_dir_tally"
    blank_line

    # The control test for the by-design shared directories.
    subsection "Sticky Bit Verification for Shared Temporary Directories:"
    for _ww_shared in `world_writable_expected_shared_dirs`; do
        if [ -d "$_ww_shared" ]; then
            printf 'Directory: %s\n' "$_ww_shared"
            ls -ld "$_ww_shared" 2>/dev/null || not_available

            # Recorded in the manifest as examined-for-metadata-only.
            #
            # These directories are named in the report, so under the rule that
            # anything referenced must be accounted for, they belong in the
            # chain of custody. Their CONTENTS are deliberately not collected -
            # /tmp on a live server holds other people's data and none of the
            # audit's business - and their mode is the evidence being gathered,
            # so the verb records exactly that rather than implying a file was
            # copied.
            record_reference_outcome "DIRECTORY_METADATA_ONLY" "$_ww_shared" \
                "reason=world_writable_by_design|evidence=mode_and_sticky_bit|contents_not_collected=yes"

            # The sticky bit only matters where the directory is actually
            # world-writable. Reporting a missing sticky bit on a directory that
            # is not world-writable would be a false positive the client would
            # have to rebut, so the two conditions are distinguished here. The
            # other-write bit is read from the ls mode string (character 9)
            # because POSIX test has no world-writable predicate.
            _ww_mode=`ls -ld "$_ww_shared" 2>/dev/null | awk 'NR == 1 { print $1 }'`
            _ww_other_write=`printf '%s' "$_ww_mode" | cut -c9 2>/dev/null`

            if [ -k "$_ww_shared" ]; then
                printf 'Sticky bit: present (expected)\n'
            elif [ "$_ww_other_write" = "w" ]; then
                printf 'Sticky bit: ABSENT - this directory is world-writable, so any user\n'
                printf '  can delete or rename files owned by others here\n'
            else
                printf 'Sticky bit: absent, but this directory is not world-writable, so the\n'
                printf '  sticky bit is not required\n'
            fi
            blank_line
        fi
    done
}

# SetUID / SetGID file review:
#
# A SetUID program runs with the privileges of the file's owner rather than those
# of the user who started it, so a SetUID root binary lets an unprivileged user
# execute code as root. That is legitimate for a small number of system tools, but
# each one is a potential privilege-escalation path, so the population is
# inventoried for review. SetGID behaves the same way for group privileges.
#
# The scan is bounded exactly as the world-writable scan in Section 10 is, and for
# the same reason: this runs on live client production systems.
#
# - Scope is pruned to binary and application paths rather than whole filesystems.
# - find -xdev stops the scan at filesystem boundaries so it cannot descend into
#   NFS or SAN mounts, place load on a remote filer, or stall on an unresponsive
#   mount. The cost is that a separately mounted subdirectory beneath a scoped
#   path is not traversed, so the population can under-report. That trade is made
#   deliberately in favour of not disturbing the client, and the boundary is
#   disclosed in the report so a reviewer knows the limit of the evidence rather
#   than assuming the list is complete.
# - Application roots supplied with --app-dir are scanned as roots in their own
#   right, which is what keeps -xdev from skipping an application tree that lives
#   on its own mount. Results are passed through sort -u because a root that is
#   not a separate mount would otherwise be traversed twice.
print_setuid_setgid_files() {
    if ! command_exists find; then
        not_available
        return
    fi

    # Roots are held as positional parameters so that an application path
    # containing spaces survives as a single argument; see the equivalent comment
    # in print_world_writable_review for why this matters.
    _suid_saved_ifs=$IFS
    IFS='
'
    set -- `setuid_search_paths`
    IFS=$_suid_saved_ifs

    if [ "$#" -eq 0 ]; then
        not_available
        return
    fi

    subsection "Scan Scope and Limits:"
    printf 'Paths scanned:\n'
    for _suid_path in "$@"; do
        printf '  %s\n' "$_suid_path"
    done
    printf 'Filesystem boundary: not crossed (find -xdev). Separately mounted\n'
    printf '  subdirectories beneath the paths above are not traversed, so this\n'
    printf '  population may under-report. This bound is deliberate: it prevents\n'
    printf '  the scan from loading NFS or SAN mounts on a production host.\n'
    printf 'Recorded per finding: full path. File contents are not printed or\n'
    printf '  copied into this evidence package.\n'
    blank_line

    # -perm -4000 matches "has at least the SetUID bit set". find interprets a
    # leading digit as octal, so -4000 and -04000 are the same number written two
    # ways; the pair that used to be here read as two distinct tests but was one
    # test performed twice.
    subsection "SetUID Files:"
    _suid_list=`find "$@" -xdev -type f -perm -4000 -print 2>/dev/null | sort -u`
    if [ -n "$_suid_list" ]; then
        printf '%s\n' "$_suid_list"
    else
        no_entries_found
    fi
    blank_line

    subsection "SetGID Files:"
    _sgid_list=`find "$@" -xdev -type f -perm -2000 -print 2>/dev/null | sort -u`
    if [ -n "$_sgid_list" ]; then
        printf '%s\n' "$_sgid_list"
    else
        no_entries_found
    fi
}

# Cron spool fallback:
# Some Unix variants store user crontabs in spool files rather than exposing
# them consistently through crontab command options. This function reads known
# spool locations when available and does not create or modify scheduled jobs.
print_user_cron_from_spool() {
    user_name=$1

    for file_path in /var/spool/cron/crontabs/"$user_name" /var/spool/cron/"$user_name" /usr/spool/cron/crontabs/"$user_name" /usr/spool/cron/"$user_name"; do
        if [ -f "$file_path" ] && [ -r "$file_path" ]; then
            print_file_with_header "$file_path"
            return 0
        fi
    done

    return 1
}

# Cron and scheduled task review:
# The script reads system crontabs, cron include directories, and user crontab
# output where available. It does not add, remove, enable, disable, or edit
# scheduled jobs.
print_cron_content() {
    subsection "System-wide Cron Jobs: /etc/crontab"
    print_file_with_header /etc/crontab

    subsection "Cron Jobs in /etc/cron.d"
    if directory_exists /etc/cron.d; then
        found_file=no
        for file_path in /etc/cron.d/*; do
            if [ -f "$file_path" ]; then
                found_file=yes
                print_file_with_header "$file_path"
            fi
        done
        if [ "$found_file" = no ]; then
            no_entries_found
            blank_line
        fi
    else
        not_available
        blank_line
    fi

    subsection "User Cron Jobs"
    if file_readable /etc/passwd; then
        while IFS=: read -r user _password _uid _gid _gecos _home _shell; do
            printf 'Cron jobs for user: %s\n' "$user"
            if command_exists crontab; then
                # stdin from /dev/null: this loop is fed by "< /etc/passwd", and
                # crontab reads stdin when it is not given a subcommand it
                # recognises. On a platform where "crontab -u" is not supported
                # (AIX, HP-UX, Solaris all use "crontab -l user" instead) the
                # command would otherwise read the account list as if it were a
                # new crontab being installed, consuming the loop's input.
                if crontab -u "$user" -l </dev/null 2>/dev/null; then
                    :
                elif print_user_cron_from_spool "$user"; then
                    :
                else
                    not_available
                fi
            elif print_user_cron_from_spool "$user"; then
                :
            else
                not_available
            fi
            blank_line
        done < /etc/passwd
    else
        not_available
        blank_line
    fi
}

# Service-account threshold:
# UID numbering conventions vary by operating system. This helper selects a
# conservative platform-specific threshold for likely service accounts.
service_uid_cutoff() {
    case "$OS_NAME" in
        AIX|SunOS|HP-UX) printf '100\n' ;;
        Darwin|FreeBSD|OpenBSD|NetBSD) printf '500\n' ;;
        *) printf '1000\n' ;;
    esac
}

# Service-account inventory:
# Likely service accounts are identified from account metadata. This function
# reads /etc/passwd and does not modify account state.
print_service_accounts() {
    uid_cutoff=`service_uid_cutoff`

    if file_readable /etc/passwd; then
        record_file_reference /etc/passwd
        printf 'Service account UID threshold: %s\n' "$uid_cutoff"
        # The threshold is substituted into the awk program text rather than
        # passed with -v. Solaris /usr/bin/awk is the original pre-POSIX awk and
        # does not support -v: the command fails outright, the || fallback fires,
        # and the section prints "no entries found" on a host that is full of
        # service accounts. A silent, clean-looking answer for a population that
        # was never examined is the worst failure mode this collection has, so
        # the portable form is used. The value is produced by
        # service_uid_cutoff() from a fixed internal set (100/500/1000) and never
        # comes from the environment, so there is nothing here to inject.
        awk -F: '($3 < '"$uid_cutoff"') { print $1 ":" $3 ":" $4 ":" $6 ":" $7; found = 1 } END { if (!found) exit 1 }' /etc/passwd 2>/dev/null || no_entries_found
    else
        not_available
    fi
}

# Account lifecycle status:
# Tools such as passwd, chage, or lsuser are used only with status/list
# options. The script does not reset passwords, lock accounts, unlock accounts,
# change expiration dates, or modify login shells.
#
# The status flag is selected per platform rather than tried in sequence, and
# that is a safety requirement rather than a tidiness one:
#
#   passwd -S user   Linux (shadow-utils) - print status. Safe.
#   passwd -s user   Solaris and HP-UX    - show status. Safe.
#   passwd -s user   AIX                  - CHANGE THE LOGIN SHELL. Not safe.
#
# AIX rejects -S, so a blind "try -S, fall back to -s" sequence lands on AIX's
# shell-changing form, running as root, once per account. That is an attempted
# modification of the client's account database from a script whose entire
# premise is that it changes nothing. The flag is therefore chosen by platform
# and AIX is served by lsuser, which is its native read-only query tool.
#
# Every per-account command in this file also redirects stdin from /dev/null.
# These loops are fed by "< /etc/passwd", so any command inside that reads stdin
# consumes the account list as its own input: the loop then skips accounts, and
# an interactive tool receives passwd lines as its answers to prompts.
print_account_status_summary() {
    subsection "Account Status Summary:"
    if file_readable /etc/passwd; then
        record_file_reference /etc/passwd
        found=no

        case "$OS_NAME" in
            AIX)
                # AIX: never invoke passwd here. lsuser is the read-only query.
                if command_exists lsuser; then
                    printf 'Command: lsuser -a account_locked expires login shell ALL\n'
                    if lsuser -a account_locked expires login shell ALL </dev/null 2>/dev/null; then
                        found=yes
                    fi
                fi
                ;;
            SunOS|HP-UX)
                if command_exists passwd; then
                    printf 'Command: passwd -s (per account)\n'
                    while IFS=: read -r user _rest; do
                        if passwd -s "$user" </dev/null 2>/dev/null; then
                            found=yes
                        fi
                    done < /etc/passwd
                fi
                ;;
            *)
                if command_exists passwd; then
                    printf 'Command: passwd -S (per account)\n'
                    while IFS=: read -r user _rest; do
                        if passwd -S "$user" </dev/null 2>/dev/null; then
                            found=yes
                        fi
                    done < /etc/passwd
                fi
                ;;
        esac

        if [ "$found" = no ] && command_exists lsuser && [ "$OS_NAME" != "AIX" ]; then
            lsuser -a account_locked expires login shell ALL </dev/null 2>/dev/null && found=yes
        fi
        if [ "$found" = no ]; then
            not_available
        fi
    else
        not_available
    fi
}

# Password expiry detail:
# Expiration information is queried for review purposes only. No user password
# values or password changes are performed.
print_password_expiry_details() {
    subsection "Password Expiry Details by Account:"
    if file_readable /etc/passwd; then
        record_file_reference /etc/passwd
        found=no
        # chage is Linux-only and read-only with -l. lsuser is the AIX
        # equivalent. Both take stdin from /dev/null so they cannot consume the
        # account list this loop is reading; see print_account_status_summary.
        if command_exists chage; then
            while IFS=: read -r user _rest; do
                printf 'User: %s\n' "$user"
                if chage -l "$user" </dev/null 2>/dev/null; then
                    found=yes
                else
                    not_available
                fi
                blank_line
            done < /etc/passwd
        elif command_exists lsuser; then
            lsuser -a maxage minage pwdwarntime expires account_locked ALL </dev/null 2>/dev/null && found=yes
        fi
        if [ "$found" = no ] && ! command_exists chage && ! command_exists lsuser; then
            not_available
        fi
    else
        not_available
    fi
}

# Home directory and SSH key posture:
# The script lists ownership and permission metadata for home directories,
# .ssh directories, and authorized_keys files. Authorized keys are summarized
# rather than printed in full.
print_ssh_home_permission_review() {
    subsection "Home Directory, .ssh, and authorized_keys Permission Review:"
    found=no

    if file_readable /etc/passwd; then
        record_file_reference /etc/passwd
        while IFS=: read -r user _password _uid _gid _gecos home_dir _shell; do
            if [ -n "$home_dir" ] && [ "$home_dir" != "/" ] && [ -d "$home_dir" ]; then
                printf 'User: %s\n' "$user"
                ls -ld "$home_dir" 2>/dev/null || not_available
                if [ -d "$home_dir/.ssh" ]; then
                    ls -ld "$home_dir/.ssh" 2>/dev/null || not_available
                    found=yes
                fi
                if [ -f "$home_dir/.ssh/authorized_keys" ]; then
                    ls -l "$home_dir/.ssh/authorized_keys" 2>/dev/null || not_available
                    print_sensitive_file_review "$home_dir/.ssh/authorized_keys"
                    found=yes
                fi
                blank_line
            fi
        done < /etc/passwd
    fi

    if [ "$found" = no ]; then
        no_entries_found
    fi
}

# Legacy trust-file review:
# Files such as .rhosts, .shosts, and hosts.equiv can grant legacy trust-based
# access. The script reviews their presence and content handling without
# removing, editing, or disabling them.
print_legacy_trust_content() {
    subsection "Legacy Trust Files:"
    found=no

    for trust_path in /etc/hosts.equiv /etc/shosts.equiv; do
        if [ -f "$trust_path" ]; then
            record_file_reference "$trust_path"
            print_file_with_header "$trust_path"
            found=yes
        fi
    done

    if file_readable /etc/passwd; then
        record_file_reference /etc/passwd
        while IFS=: read -r user _password _uid _gid _gecos home_dir _shell; do
            if [ -n "$home_dir" ] && [ "$home_dir" != "/" ]; then
                for trust_file in "$home_dir/.rhosts" "$home_dir/.shosts"; do
                    if [ -f "$trust_file" ]; then
                        printf 'User: %s\n' "$user"
                        print_file_with_header "$trust_file"
                        found=yes
                    fi
                done
            fi
        done < /etc/passwd
    fi

    if [ "$found" = no ]; then
        no_entries_found
    fi
}

# Shell timeout and login banner review:
# Timeout and banner settings are read from common shell and login files. The
# script does not enforce timeout values or change banner text.
print_shell_timeout_and_banner_summary() {
    subsection "Shell Timeout Settings:"
    record_file_reference /etc/profile
    record_file_reference /etc/bashrc
    record_file_reference /etc/ksh.kshrc
    record_file_reference /etc/csh.cshrc
    record_file_reference /etc/profile.d
    record_file_reference /etc/security/login.cfg
    if grep -E '(^[[:space:]]*TMOUT=|^[[:space:]]*readonly[[:space:]]+TMOUT|^[[:space:]]*export[[:space:]]+TMOUT|^[[:space:]]*autologout[[:space:]]*=)' /etc/profile /etc/bashrc /etc/ksh.kshrc /etc/csh.cshrc /etc/profile.d/*.sh /etc/security/login.cfg 2>/dev/null; then
        :
    else
        not_available
    fi
    blank_line

    subsection "Login Banner Files:"
    print_file_with_header /etc/issue
    print_file_with_header /etc/issue.net
    print_file_with_header /etc/motd
    print_file_with_header /etc/ssh/banner
}

# Audit logging and forwarding review:
# Logging configuration supports SOX / ITGC detective-control review. The
# script reads audit, journaling, syslog, and sudo logging settings only. It
# does not enable, disable, restart, rotate, or forward logs.
print_audit_logging_summary() {
    subsection "Audit / Logging Configuration Summary:"
    case "$OS_NAME" in
        Linux)
            record_file_reference /etc/audit/auditd.conf
            record_file_reference /etc/systemd/journald.conf
            grep -E '^[[:space:]]*(max_log_file|max_log_file_action|num_logs|space_left_action|admin_space_left_action|disk_full_action|Storage|ForwardToSyslog|Compress|SystemMaxUse|SystemKeepFree)[[:space:]]*[= ]' /etc/audit/auditd.conf /etc/systemd/journald.conf 2>/dev/null || not_available
            ;;
        AIX)
            print_file_with_header /etc/security/audit/config
            ;;
        SunOS)
            print_file_with_header /etc/security/audit_control
            ;;
        HP-UX)
            print_file_with_header /etc/syslog.conf
            ;;
        *)
            not_available
            ;;
    esac
    blank_line

    subsection "Remote Log Forwarding Indicators:"
    record_file_reference /etc/rsyslog.conf
    record_file_reference /etc/rsyslog.d
    record_file_reference /etc/syslog.conf
    record_file_reference /etc/syslog-ng/syslog-ng.conf
    record_file_reference /etc/syslog-ng/conf.d
    record_file_reference /etc/systemd/journald.conf
    grep -E '(^[^#].*@@?[A-Za-z0-9._-]+|action\(.*omfwd|destination.*(tcp|udp)|forward_to|loghost)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/conf.d/*.conf /etc/systemd/journald.conf 2>/dev/null || not_available
    blank_line

    subsection "Sudo Logging Indicators:"
    record_file_reference /etc/sudoers
    record_file_reference /etc/sudoers.d
    grep -E '(logfile=|log_input|log_output|iolog_dir)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || not_available
}

# Service and startup review:
# Native service-framework commands are used in list/query mode. The script
# does not start, stop, enable, disable, restart, or reload services.
print_service_startup_summary() {
    case "$OS_NAME" in
        Linux)
            if command_exists systemctl; then
                printf 'Command: systemctl list-unit-files --type=service\n'
                systemctl list-unit-files --type=service 2>/dev/null || not_available
            else
                print_file_with_header /etc/inittab
            fi
            ;;
        AIX)
            if command_exists lssrc; then
                printf 'Command: lssrc -a\n'
                lssrc -a 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        SunOS)
            if command_exists svcs; then
                printf 'Command: svcs -a\n'
                svcs -a 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        HP-UX)
            print_file_with_header /etc/rc.config
            print_file_with_header /etc/inittab
            ;;
        *)
            not_available
            ;;
    esac
}

# Network exposure review:
# Listener and network configuration evidence is collected through read-only
# commands and file reads. The script does not open ports, close ports, modify
# firewall rules, or change network services.
print_network_exposure_summary() {
    subsection "Listening Network Services:"
    if command_exists ss; then
        printf 'Command: ss -lntup\n'
        ss -lntup 2>/dev/null || not_available
    elif command_exists netstat; then
        printf 'Command: netstat -an\n'
        netstat -an 2>/dev/null || not_available
    else
        not_available
    fi
    blank_line

    subsection "Firewall / Exports / Legacy Network Services:"
    print_file_with_header /etc/exports
    print_file_with_header /etc/dfs/dfstab
    print_file_with_header /etc/inetd.conf
    print_file_with_header /etc/inet/inetd.conf
    record_file_reference /etc/services
    record_file_reference /etc/xinetd.d

    # /etc/services is deliberately NOT searched for these names.
    #
    # That file is the IANA port-number registry shipped with every Unix ever
    # made. It contains "telnet 23/tcp" and "ftp 21/tcp" on a host that has had
    # telnet and ftp removed entirely, so including it guaranteed this check
    # produced hits on 100% of hosts. The finding was therefore worthless as a
    # signal and worse than worthless in practice: the client had to write a
    # rebuttal explaining that a port-number definition is not a running service,
    # for every engagement, and a reviewer who stopped reading at the match would
    # record a legacy-service exposure that did not exist.
    #
    # What actually evidences the control is inetd/xinetd configuration, which
    # says whether the service is CONFIGURED TO RUN. Commented-out lines are
    # excluded for the same reason - a disabled entry is not an exposure.
    printf 'Legacy service entries enabled in inetd/xinetd configuration:\n'
    if grep -E '^[[:space:]]*[^#[:space:]].*(telnet|rlogin|rexec|rsh|tftp|ftp)' \
        /etc/inetd.conf /etc/inet/inetd.conf /etc/xinetd.d/* 2>/dev/null; then
        :
    else
        printf '  no enabled legacy service entries found\n'
    fi
    blank_line
    printf 'Note: /etc/services is collected as a reference file but is NOT searched\n'
    printf '  for these service names. It is the IANA port-number registry present on\n'
    printf '  every Unix host and defines telnet and ftp port numbers even where those\n'
    printf '  services are not installed, so matching against it produces a finding on\n'
    printf '  every host and evidences nothing.\n'
}

# Patch and update indicators:
# Package metadata and history are queried to support change and maintenance
# review. The script performs no patching, installation, removal, or update
# action.
#
# Ordered by native packaging system per platform, for the same reason as the
# inventory above: "rpm -qa --last" on AIX reports the install history of Toolbox
# freeware rather than of the operating system's own filesets, which would
# misrepresent the host's patch position rather than merely omit it.
print_patch_update_summary() {
    case "$OS_NAME" in
        AIX)
            if command_exists lslpp; then
                printf 'Command: lslpp -h (native AIX fileset install/update history)\n'
                lslpp -h 2>/dev/null || not_available
                return
            fi
            ;;
        HP-UX)
            if command_exists swlist; then
                printf 'Command: swlist -l product (native HP-UX product list)\n'
                swlist -l product 2>/dev/null || not_available
                return
            fi
            ;;
        SunOS)
            if command_exists pkg; then
                printf 'Command: pkg list -u (IPS updates available)\n'
                pkg list -u </dev/null 2>/dev/null || not_available
                return
            elif command_exists showrev; then
                printf 'Command: showrev -p (native Solaris patch list)\n'
                showrev -p 2>/dev/null || not_available
                return
            fi
            ;;
    esac

    if rpm_usable; then
        printf 'Command: rpm -qa --last\n'
        rpm -qa --last 2>/dev/null || not_available
    elif dpkg_usable; then
        print_file_with_header /var/log/dpkg.log
    elif command_exists lslpp; then
        printf 'Command: lslpp -h\n'
        lslpp -h 2>/dev/null || not_available
    elif command_exists swlist; then
        printf 'Command: swlist -l product\n'
        swlist -l product 2>/dev/null || not_available
    else
        not_available
    fi
}

# Backup, capacity, and operational indicators:
# This section reads capacity information and selected operations-related
# configuration files. It does not initiate backups, restore data, rotate logs,
# or change monitoring configuration.
print_backup_operational_summary() {
    if command_exists df; then
        df -k 2>/dev/null || not_available
    else
        not_available
    fi
    blank_line
    print_file_with_header /etc/logrotate.conf
    print_file_with_header /etc/newsyslog.conf
    print_file_with_header /usr/openv/netbackup/bp.conf
    print_file_with_header /opt/tivoli/tsm/client/ba/bin/dsm.opt
}

# Time synchronization configuration:
# Time settings are important for reliable log correlation. The script reads
# common NTP and chrony configuration files only and does not change time,
# restart time services, or alter time sources.
print_time_sync_summary() {
    print_file_with_header /etc/chrony.conf
    print_file_with_header /etc/chrony/chrony.conf
    print_file_with_header /etc/ntp.conf
    print_file_with_header /etc/inet/ntp.conf
    # systemd-timesyncd is the DEFAULT time client on Ubuntu Server and on
    # several other current distributions, and it uses neither chrony nor ntpd.
    # Without this file the section reported "not available" for every source on
    # a host whose clock was in fact synchronised and disciplined - which reads
    # as a missing control where there is none.
    print_file_with_header /etc/systemd/timesyncd.conf
    if directory_exists /etc/systemd/timesyncd.conf.d; then
        record_file_reference /etc/systemd/timesyncd.conf.d
        for _ts_snippet in /etc/systemd/timesyncd.conf.d/*; do
            if [ -f "$_ts_snippet" ]; then
                print_file_with_header "$_ts_snippet"
            fi
        done
    fi

    # Whether the clock is actually in sync, as distinct from how it is
    # configured to sync. Configuration alone does not evidence a working
    # control, in the same way Section 15's logging configuration does not
    # evidence that logging is operating.
    subsection "Synchronisation Status:"
    if command_exists timedatectl; then
        printf 'Command: timedatectl\n'
        timedatectl </dev/null 2>/dev/null || not_available
    elif command_exists chronyc; then
        printf 'Command: chronyc tracking\n'
        chronyc tracking </dev/null 2>/dev/null || not_available
    elif command_exists ntpq; then
        printf 'Command: ntpq -p\n'
        ntpq -p </dev/null 2>/dev/null || not_available
    elif command_exists lssrc; then
        printf 'Command: lssrc -s xntpd (AIX)\n'
        lssrc -s xntpd </dev/null 2>/dev/null || not_available
    else
        not_available
    fi
}

# Supplemental scheduler evidence:
# This function reads additional scheduler files and logs where available. It
# does not schedule, reschedule, or execute tasks.
print_additional_scheduler_content() {
    print_file_with_header /etc/anacrontab
    print_file_with_header /var/log/cron
    print_file_with_header /var/log/cron.log
}

# Critical file integrity review:
# This section records metadata and checksums for selected operating-system
# files. Checksums provide a point-in-time reference for review without editing
# or replacing the files being measured.
print_critical_file_integrity() {
    subsection "Sensitive File Metadata and Checksums:"
    case "$OS_NAME" in
        Linux)
            sensitive_paths="/etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/pam.conf /etc/login.defs /etc/audit/auditd.conf /etc/audit/audit.rules /etc/rsyslog.conf /etc/chrony.conf /etc/default/grub /boot/grub2/grub.cfg /etc/inittab"
            ;;
        AIX)
            sensitive_paths="/etc/passwd /etc/security/passwd /etc/security/user /etc/security/audit/config /etc/syslog.conf /etc/inittab"
            ;;
        SunOS)
            sensitive_paths="/etc/passwd /etc/shadow /etc/user_attr /etc/security/prof_attr /etc/security/exec_attr /etc/security/audit_control /etc/default/passwd /etc/ssh/sshd_config /etc/system"
            ;;
        HP-UX)
            sensitive_paths="/etc/passwd /etc/shadow /etc/default/passwd /etc/pam.conf /etc/syslog.conf /etc/inittab"
            ;;
        *)
            sensitive_paths="/etc/passwd /etc/group /etc/ssh/sshd_config"
            ;;
    esac

    for sensitive_path in $sensitive_paths; do
        print_path_metadata "$sensitive_path"
    done
}

# Does this host resolve accounts from a directory service?
#
# Used to decide whether an empty name-service enumeration is worth a WARN. On a
# standalone host, enumeration returning only local accounts is the correct and
# complete answer, and warning about it would put a warning on the verdict of
# every standalone collection - which is how a reviewer learns to stop reading
# warnings. On a directory-joined host the same observation means the account
# population is genuinely incomplete, and that must be surfaced.
#
# Indicators are read-only and cheap: the name service switch configuration, the
# presence of an SSSD configuration, and PAM module references.
host_uses_directory_service() {
    if file_readable /etc/nsswitch.conf; then
        if grep -Eq '^[[:space:]]*passwd:.*(ldap|sss|winbind|nis|ad)' /etc/nsswitch.conf 2>/dev/null; then
            return 0
        fi
    fi
    if file_readable /etc/sssd/sssd.conf; then
        return 0
    fi
    if directory_exists /etc/pam.d; then
        if grep -lq 'pam_ldap\.so\|pam_sss\.so\|pam_winbind\.so\|pam_krb5\.so' /etc/pam.d/* 2>/dev/null; then
            return 0
        fi
    fi
    if file_readable /etc/pam.conf; then
        if grep -q 'pam_ldap\|pam_krb5' /etc/pam.conf 2>/dev/null; then
            return 0
        fi
    fi
    # AIX records the authentication registry per user in /etc/security/user.
    if file_readable /etc/security/user; then
        if grep -Eq '^[[:space:]]*SYSTEM[[:space:]]*=.*(LDAP|KRB5|NIS|compat)' /etc/security/user 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Interactive user account inventory:
# Service accounts (Section 13) and UID 0 accounts (Section 1) are reviewed
# elsewhere. This function lists the remaining accounts that a person could
# plausibly log in with: UID 0 accounts plus accounts at or above the
# platform service-account threshold whose login shell is not a known
# non-interactive shell (nologin or false). This reads /etc/passwd only and
# does not modify any account.
print_interactive_user_accounts() {
    uid_cutoff=`service_uid_cutoff`

    printf 'Criteria: UID 0, or UID >= %s with a login shell other than nologin/false\n' "$uid_cutoff"
    printf 'Format: user:uid:gid:home:shell\n'
    blank_line

    # Use getent passwd so that accounts sourced from LDAP, SSSD, NIS, or
    # Active Directory are included alongside local /etc/passwd entries.
    # Falling back to /etc/passwd only when getent is absent.
    #
    # The cutoff is substituted into the awk program text rather than passed with
    # -v, because Solaris /usr/bin/awk does not support -v; see the equivalent
    # comment in print_service_accounts.
    if command_exists getent; then
        record_manifest_line "GETENT_QUERY|passwd ALL|source=name_service"
        record_file_reference /etc/passwd

        # Enumeration boundary, disclosed the same way Sections 10 and 11
        # disclose their -xdev boundary.
        #
        # "getent passwd" with no argument asks the name service to ENUMERATE
        # every account. Directory back-ends commonly refuse: SSSD ships with
        # enum_users disabled by default, and winbind with "winbind enum users =
        # no", both because enumerating a large directory is expensive. Those
        # accounts still resolve perfectly when looked up BY NAME, so the host
        # authenticates directory users normally while enumeration returns
        # nothing but the local file.
        #
        # The practical consequence for this section is that on a host joined to
        # AD or LDAP, this list may be local accounts only - while reading as the
        # complete population of people who can log in. That cannot be silently
        # assumed either way, so the counts are reported and the limitation is
        # stated. Equal counts do not prove enumeration is disabled (a host with
        # no directory at all looks identical); they mean the question has to be
        # settled against the authentication evidence in Section 3.
        _iua_getent_count=`getent passwd 2>/dev/null | grep -c . 2>/dev/null`
        [ -n "$_iua_getent_count" ] || _iua_getent_count=0
        _iua_local_count=0
        if file_readable /etc/passwd; then
            _iua_local_count=`grep -c . /etc/passwd 2>/dev/null`
            [ -n "$_iua_local_count" ] || _iua_local_count=0
        fi

        printf 'Source: getent passwd (name service: local files plus any directory)\n'
        printf 'Accounts returned by name service enumeration: %s\n' "$_iua_getent_count"
        printf 'Accounts present in local /etc/passwd: %s\n' "$_iua_local_count"
        if [ "$_iua_getent_count" -le "$_iua_local_count" ]; then
            # Whether this is a real evidence gap depends on whether the host
            # uses a directory at all. On a standalone host it is the complete
            # and correct answer and must not raise a warning, or every
            # standalone collection would carry one and reviewers would learn to
            # ignore the warnings that matter.
            if host_uses_directory_service; then
                printf 'Enumeration boundary: THIS HOST IS CONFIGURED TO USE A DIRECTORY\n'
                printf '  SERVICE (see Section 3), but name service enumeration returned no\n'
                printf '  accounts beyond the local file. Directory accounts are therefore\n'
                printf '  almost certainly NOT represented below: SSSD and winbind disable\n'
                printf '  enumeration by default while still resolving accounts by name, so\n'
                printf '  those users can log in to this host without appearing here.\n'
                printf '  THIS LIST IS INCOMPLETE. Obtain the directory-sourced population\n'
                printf '  from the directory itself.\n'
                record_manifest_line "ENUMERATION_BOUNDARY|getent passwd|returned=$_iua_getent_count|local=$_iua_local_count|directory_configured=yes|directory_accounts_likely_absent=yes"
                log_event WARN evidence "this host is configured for directory authentication but name service enumeration returned only local accounts ($_iua_getent_count vs $_iua_local_count); Section 24 does not contain directory accounts and the interactive-user population is incomplete"
            else
                printf 'Enumeration boundary: local accounts only, and no directory service\n'
                printf '  is configured on this host (see Section 3), so this is the\n'
                printf '  complete population rather than a truncated one.\n'
                record_manifest_line "ENUMERATION_BOUNDARY|getent passwd|returned=$_iua_getent_count|local=$_iua_local_count|directory_configured=no|directory_accounts_likely_absent=no"
            fi
        else
            printf 'Enumeration boundary: the name service returned more accounts than\n'
            printf '  the local file holds, so directory-sourced accounts are included.\n'
            record_manifest_line "ENUMERATION_BOUNDARY|getent passwd|returned=$_iua_getent_count|local=$_iua_local_count|directory_accounts_likely_absent=no"
        fi
        blank_line

        if getent passwd 2>/dev/null | awk -F: '
            $7 !~ /(nologin|false)$/ && ($3 == 0 || $3 >= '"$uid_cutoff"') {
                print $1 ":" $3 ":" $4 ":" $6 ":" $7
                found = 1
            }
            END { if (!found) exit 1 }
        '; then
            :
        else
            no_entries_found
        fi
    elif file_readable /etc/passwd; then
        printf 'Source: /etc/passwd (getent not available on this host)\n'
        printf 'Enumeration boundary: local accounts only. Accounts sourced from a\n'
        printf '  directory service are not represented in this list.\n'
        record_manifest_line "ENUMERATION_BOUNDARY|/etc/passwd|getent=absent|directory_accounts_likely_absent=yes"
        blank_line
        if awk -F: '
            $7 !~ /(nologin|false)$/ && ($3 == 0 || $3 >= '"$uid_cutoff"') {
                print $1 ":" $3 ":" $4 ":" $6 ":" $7
                found = 1
            }
            END { if (!found) exit 1 }
        ' /etc/passwd 2>/dev/null; then
            :
        else
            no_entries_found
        fi
    else
        not_available
    fi
}

# Authentication log sampling:
# Logging configuration alone does not show that logging is operating. This
# function prints the most recent lines from common authentication logs so
# the evidence shows login and privilege activity was actually being
# recorded at collection time. Only the displayed sample lines leave the
# host; the full log file is intentionally not copied because production
# authentication logs can be very large and may contain unrelated user
# activity. Each sampled log is recorded in the manifest as LOG_SAMPLED.
# The log files are read only and are not truncated, rotated, or modified.
AUTH_LOG_SAMPLE_LINES=50
readonly AUTH_LOG_SAMPLE_LINES

auth_log_candidates() {
    printf '/var/log/auth.log\n/var/log/secure\n/var/log/authlog\n/var/adm/authlog\n'
}

print_auth_log_samples() {
    found=no

    for log_path in `auth_log_candidates`; do
        if [ -f "$log_path" ] && [ -r "$log_path" ]; then
            printf 'Log file: %s (last %s lines)\n' "$log_path" "$AUTH_LOG_SAMPLE_LINES"
            if tail -n "$AUTH_LOG_SAMPLE_LINES" "$log_path" 2>/dev/null; then
                record_manifest_line "LOG_SAMPLED|$log_path|lines=$AUTH_LOG_SAMPLE_LINES"
                found=yes
            else
                not_available
            fi
            blank_line
        fi
    done

    # Sources are tried in descending order of evidential quality:
    #   1. a dedicated auth log (above) - purpose-built, nothing but auth events
    #   2. the systemd journal filtered to the auth and authpriv facilities
    #   3. the general syslog file, unfiltered - last resort
    #
    # The filtered journal must be preferred over the general syslog file. On a
    # busy systemd host the last 50 lines of /var/log/messages can be entirely
    # kernel and application traffic with no authentication events in it, while
    # journalctl --facility=auth,authpriv returns the most recent SSH, sudo, su,
    # and PAM events regardless of how noisy the host is. Sampling the general
    # log first would satisfy the section with strictly weaker evidence.
    if [ "$found" = no ] && command_exists journalctl; then
        printf 'No dedicated authentication log found; sampling systemd journal auth/authpriv facilities (last %s lines)\n' "$AUTH_LOG_SAMPLE_LINES"
        # Restrict to syslog facilities auth (4) and authpriv (10) so the sample
        # contains SSH, sudo, su, and PAM events rather than unrelated noise.
        # Header lines such as "-- No entries --" are stripped so that an empty
        # journal is not mistaken for evidence that logging is operating.
        journal_sample=`journalctl -n "$AUTH_LOG_SAMPLE_LINES" --no-pager --facility=auth,authpriv 2>/dev/null | grep -v '^-- '`
        if [ -n "$journal_sample" ]; then
            printf '%s\n' "$journal_sample"
            record_manifest_line "LOG_SAMPLED|journalctl|facility=auth,authpriv|lines=$AUTH_LOG_SAMPLE_LINES"
            found=yes
        else
            not_available
        fi
        blank_line
    fi

    # Last resort: hosts that route auth and authpriv into the general syslog file
    # and have no journal, such as AIX with a default syslog.conf or an older
    # non-systemd Linux. This is unfiltered, so it is only reached when neither a
    # dedicated auth log nor a filtered journal is available.
    if [ "$found" = no ]; then
        for log_path in /var/log/messages /var/adm/messages; do
            if [ -f "$log_path" ] && [ -r "$log_path" ]; then
                printf 'No dedicated authentication log or journal available; sampling general syslog %s (last %s lines)\n' "$log_path" "$AUTH_LOG_SAMPLE_LINES"
                if tail -n "$AUTH_LOG_SAMPLE_LINES" "$log_path" 2>/dev/null; then
                    record_manifest_line "LOG_SAMPLED|$log_path|source=general_syslog_fallback|lines=$AUTH_LOG_SAMPLE_LINES"
                    found=yes
                else
                    not_available
                fi
                blank_line
            fi
        done
    fi

    if [ "$found" = no ]; then
        not_available
    fi
}

# Evidence archive creation:
# The archive step packages the locally generated evidence directory into a
# single file for retention or transfer. It operates only on the evidence
# directory created by this script and writes the archive to the current working
# directory.
create_collection_archive() {
    archive_base=$WORKING_DIRECTORY/$ARCHIVE_BASE_NAME

    if [ "$COLLECTION_STATUS" != "ready" ]; then
        ARCHIVE_STATUS="skipped because collection directory was not ready"
        log_event ERROR archive "archive skipped because the evidence directory was never created"
        return
    fi

    if command_exists tar; then
        if command_exists gzip; then
            if tar -cf "$archive_base.tar" -C "$WORKING_DIRECTORY" SOX-ITGC-AUDIT-LINUX-UNIX 2>/dev/null && gzip -f "$archive_base.tar" 2>/dev/null; then
                ARCHIVE_FILE=$archive_base.tar.gz
                ARCHIVE_STATUS="created"
                log_event INFO archive "compressed archive created at $ARCHIVE_FILE"
                return
            fi
        fi
        if tar -cf "$archive_base.tar" -C "$WORKING_DIRECTORY" SOX-ITGC-AUDIT-LINUX-UNIX 2>/dev/null; then
            ARCHIVE_FILE=$archive_base.tar
            ARCHIVE_STATUS="created"
            log_event WARN archive "gzip unavailable or failed; created an uncompressed archive at $ARCHIVE_FILE"
            return
        fi
    fi

    ARCHIVE_STATUS="failed"
    log_event ERROR archive "could not create an archive; the evidence directory at $COLLECTION_DIRECTORY must be transferred manually"
}

# Application directory listing flags:
# The desired listing on Linux is `ls -RlthBA`, which produces a recursive,
# long-format, time-sorted, human-readable, hidden-files-included view that
# omits backup files (`-B`). Several of those flags are GNU extensions and do
# not exist on every Unix family, and some have different meanings on BSD ls
# (for example, BSD `-B` forces printing of non-printable characters rather
# than ignoring backup files). This helper selects a comparable flag set per
# detected operating system so the resulting evidence has consistent meaning.
application_listing_ls_flags() {
    case "$OS_NAME" in
        Linux)
            printf '%s\n' '-RlthBA'
            ;;
        Darwin|FreeBSD|OpenBSD|NetBSD)
            printf '%s\n' '-RlthA'
            ;;
        AIX|SunOS|HP-UX)
            printf '%s\n' '-RltA'
            ;;
        *)
            printf '%s\n' '-RltA'
            ;;
    esac
}

# Recursive listing of an application installation directory:
# This helper validates the supplied path and runs a recursive ls listing on
# it. The listing is read-only metadata: filenames, permissions, ownership,
# size, and modification time. No file contents are read, modified, copied,
# or removed by this helper. Errors during traversal (for example, an
# unreadable subdirectory under the supplied root) are suppressed so a single
# unreadable element does not abort the listing of the rest of the tree.
print_application_directory_listing() {
    app_path=$1

    printf 'Application directory: %s\n' "$app_path"

    if [ -z "$app_path" ]; then
        printf 'Result: no path provided\n'
        blank_line
        return
    fi

    if ! path_exists "$app_path"; then
        printf 'Result: path does not exist\n'
        record_manifest_line "APP_DIR_MISSING|$app_path"
        blank_line
        return
    fi

    if ! directory_exists "$app_path"; then
        printf 'Result: path is not a directory\n'
        record_manifest_line "APP_DIR_NOT_DIRECTORY|$app_path"
        blank_line
        return
    fi

    if ! [ -r "$app_path" ]; then
        printf 'Result: directory is not readable by the current user\n'
        record_manifest_line "APP_DIR_UNREADABLE|$app_path"
        blank_line
        return
    fi

    if ! command_exists ls; then
        printf 'Result: ls command not available on this host\n'
        blank_line
        return
    fi

    listing_flags=`application_listing_ls_flags`
    printf 'Operating system family: %s\n' "$OS_NAME"
    printf 'ls flags applied: %s\n' "$listing_flags"
    blank_line

    subsection "Recursive Listing:"
    ls $listing_flags "$app_path" 2>/dev/null || not_available
    record_manifest_line "APP_DIR_LISTED|$app_path|flags=$listing_flags"
    blank_line
}

# Interactive output directory prompt:
# When the operator does not pass --output-dir on the command line and stdin
# is connected to a terminal, the script asks for the directory in which the
# evidence collection folder and tar.gz archive should be created. The prompt
# runs before stdout is redirected into the report file so the question is
# visible on the operator's terminal. If stdin is not a terminal, the prompt
# is skipped and the current working directory is used.
prompt_for_output_directory() {
    if [ -n "$OUTPUT_DIRECTORY" ]; then
        return
    fi
    if [ ! -t 0 ]; then
        return
    fi

    printf '\n'
    printf 'Evidence Output Directory\n'
    printf '%s\n' '-------------------------'
    printf 'The script will create the SOX-ITGC-AUDIT-LINUX-UNIX/ collection\n'
    printf 'folder and the resulting tar.gz archive inside the output\n'
    printf 'directory you choose. If the directory does not exist, the\n'
    printf 'script will attempt to create it.\n'
    printf '\n'
    printf 'Default (press Enter to accept): %s\n' "$WORKING_DIRECTORY"
    printf 'Or type an absolute path for a different output directory.\n'
    printf '\n'

    printf 'Output directory: '
    if IFS= read -r entered_output_path; then
        if [ -n "$entered_output_path" ]; then
            case "$entered_output_path" in
                /*)
                    OUTPUT_DIRECTORY=$entered_output_path
                    ;;
                *)
                    printf 'Path must be absolute (start with /). Using default: %s\n' "$WORKING_DIRECTORY" >&2
                    ;;
            esac
        fi
    fi
    printf '\n'
}

# Apply the chosen output directory:
# If the operator supplied --output-dir or answered the prompt with a path,
# this function validates and adopts it. The collection directory and all
# derived file paths are recomputed from the chosen output directory. If the
# requested directory cannot be created or is not writable, the function
# falls back to the current working directory and prints a notice on the
# operator's terminal.
apply_output_directory() {
    if [ -n "$OUTPUT_DIRECTORY" ]; then
        if ! [ -d "$OUTPUT_DIRECTORY" ]; then
            mkdir -p "$OUTPUT_DIRECTORY" 2>/dev/null
        fi
        if [ -d "$OUTPUT_DIRECTORY" ] && [ -w "$OUTPUT_DIRECTORY" ]; then
            WORKING_DIRECTORY=$OUTPUT_DIRECTORY
        else
            printf 'Output directory %s is not accessible. Falling back to %s.\n' "$OUTPUT_DIRECTORY" "$WORKING_DIRECTORY" >&2
        fi
    fi

    COLLECTION_DIRECTORY="$WORKING_DIRECTORY/SOX-ITGC-AUDIT-LINUX-UNIX"
    REPORTS_DIRECTORY="$COLLECTION_DIRECTORY/report"
    RAW_FILES_DIRECTORY="$COLLECTION_DIRECTORY/raw_files"
    METADATA_DIRECTORY="$COLLECTION_DIRECTORY/metadata"
    REPORT_FILE="$REPORTS_DIRECTORY/SOX-ITGC-AUDIT-REPORT.txt"
    MANIFEST_FILE="$METADATA_DIRECTORY/MANIFEST.txt"
    SENSITIVE_SKIPPED_FILE="$METADATA_DIRECTORY/SENSITIVE_FILES_SKIPPED.txt"
}

# Ownership adjustment for the evidence package:
# When the script is invoked via sudo, files it creates are owned by root.
# The audit operator who initiated sudo will normally need to handle, copy,
# email, or upload the evidence without continued root access. After the
# archive is written, this function chowns the collection directory and the
# archive file to the user who invoked sudo (SUDO_USER) and that user's
# primary group. The archive file is also set to mode 0640 so that the
# operator and their primary group can read it. Inner files keep the
# restrictive umask 077 because they may contain sensitive configuration.
# When SUDO_USER is not set (for example, dry-run or non-root execution),
# no ownership change is attempted.
# Extraction guidance shipped inside the package.
#
# The single most common way an evidence package becomes unreadable is being
# extracted with sudo. GNU tar restores the archived numeric UID and GID when it
# runs as root, and those numbers come from the CLIENT's account database, where
# they mean nothing on the auditor's machine. Extracted as an ordinary user, tar
# assigns the files to whoever ran it and the package just opens. The instinct
# when files "look like root files" is to reach for sudo, which is precisely what
# causes the problem, so it is stated here in the package itself rather than in a
# document that travels separately and gets lost.
write_handling_instructions() {
    _handling_file="$COLLECTION_DIRECTORY/HOW-TO-READ-THIS-EVIDENCE.txt"
    {
        printf 'HOW TO READ THIS EVIDENCE PACKAGE\n'
        printf '=================================\n'
        printf '\n'
        printf 'Extracting the archive\n'
        printf '%s\n' '----------------------'
        printf 'Extract it as your normal user account. Do NOT use sudo:\n'
        printf '\n'
        printf '    tar -xzf %s.tar.gz\n' "$ARCHIVE_BASE_NAME"
        printf '\n'
        printf 'Extracting with sudo is the usual cause of an unreadable package.\n'
        printf 'As root, tar restores the numeric user and group IDs recorded in\n'
        printf 'the archive. Those numbers come from the client system and mean\n'
        printf 'nothing on yours, so the files end up owned by an account you do\n'
        printf 'not have. Extracted as yourself, the files belong to you and open\n'
        printf 'normally.\n'
        printf '\n'
        printf 'If the files are still unreadable\n'
        printf '%s\n' '---------------------------------'
        printf 'Take ownership of your own copy and make it readable to you and\n'
        printf 'your team. This changes only the copy you extracted:\n'
        printf '\n'
        printf '    chown -R "$(id -un)":"$(id -gn)" SOX-ITGC-AUDIT-LINUX-UNIX\n'
        printf '    chmod -R u=rwX,g=rX,o= SOX-ITGC-AUDIT-LINUX-UNIX\n'
        printf '\n'
        printf 'Do not use chmod -R 777. It is not needed, and it makes the\n'
        printf 'evidence readable to every account on your machine.\n'
        printf '\n'
        printf 'Check this package before you rely on it\n'
        printf '%s\n' '----------------------------------------'
        printf 'A package can look complete - right folders, plausible sizes -\n'
        printf 'while being a truncated delivery. Two commands tell you:\n'
        printf '\n'
        printf '    grep -E "^(FINAL_)?RESULT:" SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt\n'
        printf '    grep -c "Execution Summary" SOX-ITGC-AUDIT-LINUX-UNIX/report/SOX-ITGC-AUDIT-REPORT.txt\n'
        printf '\n'
        printf 'The first prints the collection verdict. COMPLETED_CLEAN means\n'
        printf 'nothing limited the evidence; COMPLETED_WITH_WARNINGS means read\n'
        printf 'the WARN lines in that log first; COMPLETED_WITH_ERRORS or FAILED\n'
        printf 'means ask for a fresh collection. If FINAL_RESULT is present it\n'
        printf 'supersedes RESULT, because it also accounts for the archive step.\n'
        printf '\n'
        printf 'The second must print 1. A 0 means the report was cut short before\n'
        printf 'the collection finished, so what you have is a partial delivery\n'
        printf 'regardless of how complete it looks.\n'
        printf '\n'
        printf 'The audit team also has verify-package.sh, which runs these and\n'
        printf 'several more checks and returns a pass/fail exit code.\n'
        printf '\n'
        printf 'What is in here\n'
        printf '%s\n' '---------------'
        printf '  report/SOX-ITGC-AUDIT-REPORT.txt\n'
        printf '      The audit report. Start here.\n'
        printf '  metadata/COLLECTION-LOG.txt\n'
        printf '      Whether the collection worked and whether any evidence is\n'
        printf '      missing. Read the RESULT line before relying on the report.\n'
        printf '  metadata/MANIFEST.txt\n'
        printf '      Every file used, with the permissions and ownership it had\n'
        printf '      on the source system.\n'
        printf '  metadata/SENSITIVE_FILES_SKIPPED.txt\n'
        printf '      Credential files deliberately withheld. Their absence is by\n'
        printf '      design, not a collection failure.\n'
        printf '  raw_files/\n'
        printf '      Copies of the source files, under their original paths.\n'
        printf '\n'
        printf 'A note on file permissions in this package\n'
        printf '%s\n' '------------------------------------------'
        printf 'Files under raw_files/ carry the EXACT permissions they had on the\n'
        printf 'source system. They are copies of the client'"'"'s files and their\n'
        printf 'modes are part of the evidence, so nothing here rewrites them.\n'
        printf '\n'
        printf 'One consequence: a source file that was readable only by its owner\n'
        printf 'is still restrictive here, so a colleague opening the package from a\n'
        printf 'shared location may not be able to read every individual file. If\n'
        printf 'that happens, take a copy and adjust the copy - see the section\n'
        printf 'above. Do not conclude the file is missing; check MANIFEST.txt,\n'
        printf 'which records the permissions and ownership each file had on the\n'
        printf 'source system.\n'
        printf '\n'
        printf 'The report, the manifest, this file, the collection log, and all\n'
        printf 'directories are 0640 and 0750 respectively. Those did not exist on\n'
        printf 'the client system, so their permissions are handover settings and\n'
        printf 'are NOT evidence of anything.\n'
        printf '\n'
        printf 'Handling\n'
        printf '%s\n' '--------'
        printf 'This package describes access control on a production system.\n'
        printf 'Treat it as confidential and transfer it over an encrypted channel.\n'
    } > "$_handling_file" 2>/dev/null

    if [ -f "$_handling_file" ]; then
        record_manifest_line "GENERATED|$_handling_file"
        log_event INFO handover "extraction and handling instructions written to $_handling_file"
    fi
}

# Handing the package over so the audit team can actually read it:
#
# During collection the evidence is deliberately restrictive (umask 077, root
# owned) so it is not exposed while it sits on the client's production server.
# That posture is correct there and wrong the moment the package leaves: an
# auditor who receives a tree they cannot open will reach for sudo or
# chmod -R 777, and the second of those is worse than the problem.
#
# The package is therefore normalised at handover, but NOT uniformly, because
# the two kinds of content in it mean different things:
#
#   raw_files/    Copies of the client's files. Their permissions are carried
#                 over verbatim by cp -p and are left ALONE. The mode of a
#                 collected file is an attribute of the evidence, and an auditor
#                 comparing a copy against the report should see exactly what was
#                 on the source system, not something this script rewrote. A
#                 consequence is that a source file readable only by its owner
#                 stays that way in the package, so a colleague may not be able
#                 to open every individual file without taking a copy of it. That
#                 is the deliberate trade: fidelity over convenience.
#
#   everything    The report, manifest, collection log, handling instructions,
#   else          and all directories. None of these existed on the client
#                 system, so their permissions are not evidence of anything. They
#                 are set to 0640, and directories to 0750, so the package can be
#                 navigated and the report and log can be read by the operator
#                 and their team.
#
# Directories are normalised throughout, including under raw_files/. A directory
# that cannot be entered makes everything beneath it unreachable regardless of
# the files' own modes, and the directories in raw_files/ are created by this
# script to mirror the source layout - they are not copies of the client's
# directories and carry none of their permissions.
normalize_package_permissions() {
    if [ ! -d "$COLLECTION_DIRECTORY" ]; then
        return
    fi
    _perm_ok=yes

    # Generated content: safe to normalise, none of it is evidence of a mode.
    chmod 0750 "$COLLECTION_DIRECTORY" 2>/dev/null || _perm_ok=no
    for _perm_dir in "$REPORTS_DIRECTORY" "$METADATA_DIRECTORY"; do
        if [ -d "$_perm_dir" ]; then
            chmod -R u=rwX,g=rX,o= "$_perm_dir" 2>/dev/null || _perm_ok=no
        fi
    done
    for _perm_top in "$COLLECTION_DIRECTORY"/*.txt; do
        if [ -f "$_perm_top" ]; then
            chmod 0640 "$_perm_top" 2>/dev/null || _perm_ok=no
        fi
    done

    # raw_files/: directories only. The copied files keep the modes they had on
    # the source system.
    if [ -d "$RAW_FILES_DIRECTORY" ]; then
        find "$RAW_FILES_DIRECTORY" -type d -exec chmod 0750 {} \; 2>/dev/null || _perm_ok=no
    fi

    if [ "$_perm_ok" = "yes" ]; then
        log_event INFO handover "package normalised for handover: directories 0750, generated files 0640; collected files under raw_files/ keep their original source permissions"
    else
        log_event WARN handover "could not normalise permissions on the whole package; some of it may be unreadable to the audit team after transfer"
    fi
}

# Resolve the operator who invoked sudo, if any.
handover_target_owner() {
    if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = "root" ]; then
        return 1
    fi
    _handover_group=""
    if command_exists id; then
        _handover_group=`id -gn "$SUDO_USER" 2>/dev/null`
    fi
    if [ -n "$_handover_group" ]; then
        printf '%s:%s' "$SUDO_USER" "$_handover_group"
    else
        printf '%s' "$SUDO_USER"
    fi
    return 0
}

# Ownership of the evidence tree. Runs before the archive is created so the
# archive records the operator as owner rather than root.
apply_ownership_to_evidence() {
    if ! target_owner=`handover_target_owner`; then
        OWNERSHIP_STATUS="not adjusted (no SUDO_USER detected)"
        log_event INFO handover "no SUDO_USER present, so evidence ownership was left unchanged; whoever transfers this package may need elevated access to read it"
        return
    fi

    chown_ok=yes
    if [ -d "$COLLECTION_DIRECTORY" ]; then
        chown -R "$target_owner" "$COLLECTION_DIRECTORY" 2>/dev/null || chown_ok=no
    fi

    if [ "$chown_ok" = "yes" ]; then
        OWNERSHIP_STATUS="evidence owned by $target_owner (directories 0750, files 0640)"
        log_event INFO handover "evidence ownership transferred to $target_owner so it can be moved and read without root"
    else
        OWNERSHIP_STATUS="ownership adjustment to $target_owner encountered errors"
        log_event WARN handover "could not transfer ownership of the evidence to $target_owner; the files remain owned by root and will need elevated access to read"
    fi
}

# Ownership of the archive itself, which can only run once the archive exists.
apply_ownership_to_archive() {
    if [ -z "$ARCHIVE_FILE" ] || [ ! -f "$ARCHIVE_FILE" ]; then
        return
    fi
    if ! _archive_owner=`handover_target_owner`; then
        return
    fi
    chown "$_archive_owner" "$ARCHIVE_FILE" 2>/dev/null
    chmod 0640 "$ARCHIVE_FILE" 2>/dev/null
}

# Interactive application directory prompt:
# When the operator does not pass --app-dir flags on the command line and
# stdin is connected to a terminal, the script asks the operator for one or
# more application installation directories. The prompt runs before stdout is
# redirected into the report file so the questions appear directly on the
# operator's terminal. If stdin is not a terminal, the prompt is skipped so
# non-interactive runs (for example, scheduled or piped invocations) do not
# block waiting for input.
prompt_for_app_directories() {
    if [ -n "$APP_DIRECTORIES" ]; then
        return
    fi
    if [ ! -t 0 ]; then
        return
    fi

    printf '\n'
    printf 'Application Installation Directory Listing\n'
    printf '%s\n' '------------------------------------------'
    printf 'You may include one or more application installation directories\n'
    printf 'in the evidence collection. The script will run a recursive\n'
    printf 'directory listing on each directory you provide.\n'
    printf '\n'
    printf 'Enter one absolute path per line.\n'
    printf 'Press Enter on an empty line to finish.\n'
    printf 'Press Enter immediately to skip this section.\n'
    printf '\n'

    while :; do
        printf 'Application directory path: '
        if ! IFS= read -r entered_path; then
            printf '\n'
            break
        fi
        if [ -z "$entered_path" ]; then
            break
        fi
        APP_DIRECTORIES="$APP_DIRECTORIES
$entered_path"
    done
    printf '\n'
}

# Section source file helpers: each returns the newline-delimited list of
# files that the corresponding section references on the detected OS. These
# are passed to section_with_explanation so the report header records where
# the evidence was drawn from.
section1_source_files()  { printf '/etc/passwd\n/etc/group\n'; }
section2_source_files()  {
    case "$OS_NAME" in
        Linux)   printf '/etc/login.defs\n/etc/security/pwquality.conf\n/etc/security/faillock.conf\n/etc/pam.d/system-auth\n/etc/pam.d/password-auth\n/etc/pam.d/common-password\n/etc/pam.d/common-auth\n' ;;
        AIX)     printf '/etc/security/user\n' ;;
        SunOS|HP-UX) printf '/etc/default/passwd\n/etc/default/login\n' ;;
    esac
}
section3_source_files()  {
    case "$OS_NAME" in
        Linux)   printf '/etc/nsswitch.conf\n/etc/sssd/sssd.conf\n/etc/pam.d\n' ;;
        AIX)     printf '/etc/security/user\n' ;;
        SunOS)   printf '/etc/nsswitch.conf\n/etc/user_attr\n/etc/security/prof_attr\n/etc/security/exec_attr\n' ;;
        HP-UX)   printf '/etc/pam.conf\n' ;;
    esac
}
section4_source_files()  { printf '/etc/sudoers\n/etc/sudoers.d\n'; }
section5_source_files()  { printf '/etc/group\n'; }
section6_source_files()  { sulog_candidates; }
section7_source_files()  { printf '/etc/ssh/sshd_config\n%s\n' "$SSH_CONFIG_INCLUDE_DIRECTORY"; }
section12_source_files() { printf '/etc/crontab\n/etc/cron.d\n/var/spool/cron/crontabs\n'; }
section13_source_files() { printf '/etc/passwd\n'; }
section14_source_files() { printf '/etc/passwd\n/etc/hosts.equiv\n/etc/issue\n/etc/issue.net\n/etc/motd\n/etc/ssh/banner\n/etc/profile\n'; }
section15_source_files() {
    case "$OS_NAME" in
        Linux)   printf '/etc/audit/auditd.conf\n/etc/systemd/journald.conf\n/etc/rsyslog.conf\n/etc/rsyslog.d\n/etc/syslog-ng/syslog-ng.conf\n/etc/sudoers\n/etc/sudoers.d\n' ;;
        AIX)     printf '/etc/security/audit/config\n/etc/syslog.conf\n' ;;
        SunOS)   printf '/etc/security/audit_control\n' ;;
        HP-UX)   printf '/etc/syslog.conf\n' ;;
    esac
}
section16_source_files() {
    case "$OS_NAME" in
        HP-UX)   printf '/etc/rc.config\n/etc/inittab\n' ;;
        Linux)   printf '' ;;
        *)       printf '/etc/inittab\n' ;;
    esac
}
section17_source_files() { printf '/etc/exports\n/etc/inetd.conf\n/etc/inet/inetd.conf\n/etc/services\n'; }
section18_source_files() {
    case "$OS_NAME" in
        Linux) if command_exists dpkg; then printf '/var/log/dpkg.log\n'; fi ;;
    esac
}
section19_source_files() { printf '/etc/logrotate.conf\n/etc/newsyslog.conf\n'; }
section20_source_files() { printf '/etc/chrony.conf\n/etc/chrony/chrony.conf\n/etc/ntp.conf\n/etc/inet/ntp.conf\n/etc/systemd/timesyncd.conf\n'; }
section21_source_files() { printf '/etc/anacrontab\n/var/log/cron\n/var/log/cron.log\n'; }
section22_source_files() {
    case "$OS_NAME" in
        Linux)   printf '/etc/passwd\n/etc/shadow\n/etc/group\n/etc/sudoers\n/etc/ssh/sshd_config\n/etc/login.defs\n/etc/audit/auditd.conf\n/etc/rsyslog.conf\n/etc/chrony.conf\n' ;;
        AIX)     printf '/etc/passwd\n/etc/security/passwd\n/etc/security/user\n/etc/security/audit/config\n/etc/syslog.conf\n/etc/inittab\n' ;;
        SunOS)   printf '/etc/passwd\n/etc/shadow\n/etc/user_attr\n/etc/ssh/sshd_config\n/etc/system\n' ;;
        HP-UX)   printf '/etc/passwd\n/etc/shadow\n/etc/pam.conf\n/etc/syslog.conf\n/etc/inittab\n' ;;
        *)       printf '/etc/passwd\n/etc/group\n/etc/ssh/sshd_config\n' ;;
    esac
}
section24_source_files() { printf '/etc/passwd\n'; }
section25_source_files() {
    for log_candidate in `auth_log_candidates`; do
        if [ -f "$log_candidate" ]; then
            printf '%s\n' "$log_candidate"
        fi
    done
}

# Main execution sequence:
# 1. Display help and exit if requested. No filesystem changes occur on this
#    path so --help and argument errors leave the working directory untouched.
# 2. Require elevated privileges for full collection unless dry-run mode is
#    explicitly selected. The sudo check exits before any directory is
#    created or removed.
# 3. Interactively prompt for the evidence output directory when no
#    --output-dir flag was provided and stdin is a terminal. This must run
#    before the application-directory prompt so the operator can confirm
#    where the evidence will land before configuring its contents.
# 4. Apply the chosen output directory and recompute the derived collection
#    paths so subsequent steps write into the operator-selected location.
# 5. Interactively prompt for application installation directories when no
#    --app-dir flag was provided and stdin is a terminal.
# 6. Prepare the local evidence directory. This step removes any prior
#    evidence directory at the same path, so it is intentionally deferred
#    until after help, sudo, and prompt handling so that early-exit paths
#    do not disturb a previously generated collection in the working
#    directory.
# 7. Redirect report output into the local report file.
# 8. Execute the evidence sections in a consistent order.
# 9. Package the evidence directory into a local archive.
# 10. Chown the collection directory and archive to the operator who
#     invoked sudo, so the evidence can be handled, copied, or transferred
#     without further root access.

if [ "$SHOW_HELP" = "yes" ]; then
    print_usage
    if [ "$ARGUMENT_ERROR" = "yes" ]; then
        exit 1
    fi
    exit 0
fi

if [ "$EFFECTIVE_UID_VALUE" != "0" ] && [ "$TEST_MODE" != "yes" ]; then
    printf '%s\n' 'This script must be run with sudo.'
    printf 'Use: sudo sh %s\n' "$SCRIPT_NAME"
    printf 'Safe local test mode: sh %s --dry-run\n' "$SCRIPT_NAME"
    exit 1
fi

# Interactive selection of the evidence output directory. This runs before
# the application-directory prompt and before stdout is redirected into the
# report file so the question is visible on the operator's terminal.
prompt_for_output_directory

# Recompute all evidence path variables based on the chosen output
# directory. Subsequent steps write to and read from these recomputed paths.
apply_output_directory

# Interactive collection of application installation directories. This runs
# before stdout is redirected into the report file so the prompts appear on
# the operator's terminal. When --app-dir flags were passed on the command
# line or stdin is not a terminal, this returns immediately and the section
# uses whatever was supplied (or none, if nothing was supplied).
prompt_for_app_directories

prepare_collection_directory

# Interruption handling.
#
# The filesystem-walking sections can run for minutes, and an operator watching a
# production host will sometimes stop the script - Ctrl-C, a closed session, a
# terminated job. Until now that left behind a collection directory containing a
# report cut off mid-section and a log with no verdict, which is indistinguishable
# from a package that was damaged in transfer. The receipt verifier would reject
# it correctly, but only after it had been sent, and nobody on either side would
# know why.
#
# The trap marks the package as abandoned, in the log where the verdict is read
# from and on the operator's terminal, so an interrupted run is recognisable as
# an interrupted run. It writes a verdict and exits; it does not attempt to
# finish the collection or build an archive, because the evidence is genuinely
# incomplete and packaging it would disguise that.
#
# EXIT is deliberately not trapped: a normal completion must not be relabelled.
handle_interruption() {
    _interrupt_signal=$1
    COLLECTION_STATUS="interrupted by $_interrupt_signal before completion"

    log_event ERROR completion "collection was interrupted by $_interrupt_signal before it finished; this package is incomplete and must not be relied upon"

    # Mark the report itself. At this point stdout is the report file, so this
    # lands at the point of truncation where a reader will actually meet it. The
    # report deliberately still lacks its "Execution Summary" heading, which is
    # what the receipt verifier keys on to reject a partial delivery - this
    # notice explains the truncation to a human without concealing it from the
    # tool.
    printf '\n'
    printf '==================================================\n'
    printf 'COLLECTION INTERRUPTED - THIS REPORT IS INCOMPLETE\n'
    printf '==================================================\n'
    printf 'The collection was stopped by %s before it finished.\n' "$_interrupt_signal"
    printf 'Sections below this point were never collected. Do not rely on\n'
    printf 'this report, and do not treat an absent section as evidence that\n'
    printf 'the corresponding control is absent.\n'
    printf 'Nothing on the host was changed; the script is read-only.\n'

    if [ "$LOG_READY" = "yes" ] && [ -n "$LOG_FILE" ]; then
        recount_log_levels
        {
            printf '\n'
            printf '================================================================\n'
            printf 'SUMMARY (INTERRUPTED RUN)\n'
            printf '================================================================\n'
            printf '\n'
            printf 'RESULT: FAILED\n'
            printf 'ERRORS: %s\n' "$LOG_ERROR_COUNT"
            printf 'WARNINGS: %s\n' "$LOG_WARN_COUNT"
            printf 'INTERRUPTED_BY: %s\n' "$_interrupt_signal"
            printf 'HOST: %s\n' "$HOSTNAME_VALUE"
            printf 'STARTED: %s\n' "$TIMESTAMP"
            printf 'FINISHED: %s\n' "`log_timestamp`"
            printf 'CONFIGURATION_CHANGES_MADE: none\n'
            printf '\n'
            printf 'What this means\n'
            printf '  The collection was stopped before it completed. The evidence in\n'
            printf '  this directory is partial: sections after the interruption never\n'
            printf '  ran, and no archive was created. Do not send this package as\n'
            printf '  evidence. Re-run the collection when convenient.\n'
            printf '\n'
            printf '  Nothing on this host was changed. The script is read-only, and\n'
            printf '  being interrupted cannot leave the system in a modified state.\n'
        } >> "$LOG_FILE" 2>/dev/null
    fi

    {
        printf '\n'
        printf '================================================================\n'
        printf 'COLLECTION INTERRUPTED (%s)\n' "$_interrupt_signal"
        printf '  The evidence in %s is incomplete.\n' "$COLLECTION_DIRECTORY"
        printf '  No archive was created. Do not send this package as evidence.\n'
        printf '  Nothing on this host was changed; the script is read-only.\n'
        printf '  Full log: %s\n' "${LOG_FILE:-not created}"
        printf '================================================================\n'
    } >&3 2>/dev/null || :

    exit 130
}

# Startup context. Recorded first so a reader can tell what was run, where, and
# under what privileges without needing the report.
log_event INFO startup "collection started on $HOSTNAME_VALUE (platform $OS_NAME)"
log_event INFO startup "run mode: $RUN_PRIVILEGE_MODE"
log_event INFO startup "invoked as: $SCRIPT_NAME"
log_event INFO startup "this script is read-only and makes no configuration changes to this host"
if [ "$EFFECTIVE_UID_VALUE" != "0" ]; then
    log_event WARN startup "running without root privileges; files readable only by root will be missing from this package"
fi
if [ -n "$APP_DIRECTORIES" ]; then
    printf '%s\n' "$APP_DIRECTORIES" | while IFS= read -r _log_app_dir; do
        if [ -n "$_log_app_dir" ]; then
            if [ -d "$_log_app_dir" ]; then
                log_event INFO startup "application directory selected for listing: $_log_app_dir"
            else
                log_event WARN startup "application directory $_log_app_dir does not exist or is not a directory; it was not listed"
            fi
        fi
    done
fi

# Preserve the original stdout on file descriptor 3. The script writes the
# report to the report file first, then replays the completed report to the
# operator at the end of the run.
exec 3>&1

# Installed only now that file descriptor 3 exists, since the handler reports the
# interruption on the operator's terminal through it. Everything before this
# point is prompt handling and directory creation, which completes in
# milliseconds; the minutes-long work all happens after here.
trap 'handle_interruption SIGINT' INT
trap 'handle_interruption SIGTERM' TERM
trap 'handle_interruption SIGHUP' HUP

if [ "$COLLECTION_STATUS" = "ready" ]; then
    exec > "$REPORT_FILE"
fi

printf 'SOX ITGC Audit Data Collection\n'
printf 'Generated: %s\n' "$TIMESTAMP"
printf 'Hostname: %s\n' "$HOSTNAME_VALUE"
printf 'Script Mode: %s\n' "$SCRIPT_MODE"
printf 'Run Privilege Mode: %s\n' "$RUN_PRIVILEGE_MODE"
printf 'Output Destination: report file with stdout replay at completion\n'
printf 'Evidence Output Directory: %s\n' "$WORKING_DIRECTORY"
printf 'Evidence Collection Directory: %s\n' "$COLLECTION_DIRECTORY"
printf 'Report File: %s\n' "$REPORT_FILE"
printf 'Manifest File: %s\n' "$MANIFEST_FILE"
printf 'Sensitive Skip File: %s\n' "$SENSITIVE_SKIPPED_FILE"
printf 'Client Elevated Run Instruction: sudo sh %s\n' "$SCRIPT_NAME"
printf 'Client Non-Root Test Instruction: sh %s --dry-run\n' "$SCRIPT_NAME"

# Identify the exact script that produced this package.
#
# The client is given a SHA-256 with the instructions and asked to confirm it
# before running anything. That check happens on their host and leaves no trace,
# so nothing in the delivered evidence has so far tied the package back to a
# specific version of the collector. Recording the checksum here closes the loop:
# the value in the report can be compared against the value issued to the client
# and against the file in version control, which is what lets a reviewer of the
# workpapers establish which code produced which evidence.
#
# $0 is the path the script was invoked by, so this measures the file that is
# actually running rather than a file of the same name elsewhere.
printf 'Collector Script Path: %s\n' "$0"
if [ -f "$0" ]; then
    # The algorithm is named from the tool that was actually used rather than
    # assumed to be SHA-256. print_file_checksum falls back to cksum where no
    # SHA-256 tool exists, and cksum is a CRC: reporting a CRC under a SHA-256
    # heading would be a false statement in an audit artifact, and a reviewer
    # comparing it against the issued SHA-256 would find a mismatch with no
    # explanation for it.
    _self_checksum=`print_file_checksum "$0" | awk 'NR == 1 { print $1 }'`
    if [ -n "$_self_checksum" ]; then
        printf 'Collector Script Checksum: %s (%s)\n' "$_self_checksum" "$CHECKSUM_ALGORITHM"
        record_manifest_line "COLLECTOR_SELF|$0|algorithm=$CHECKSUM_ALGORITHM|checksum=$_self_checksum"
        log_event INFO startup "collector script $0 measured as $CHECKSUM_ALGORITHM $_self_checksum"
        if [ "$CHECKSUM_ALGORITHM" != "sha256" ]; then
            printf '  NOTE: no SHA-256 tool is available on this host, so the value\n'
            printf '  above is a %s and will NOT match the SHA-256 issued with the\n' "$CHECKSUM_ALGORITHM"
            printf '  run instructions. Compare it against a %s of the same file.\n' "$CHECKSUM_ALGORITHM"
            log_event WARN startup "no SHA-256 tool on this host; the collector self-checksum is a $CHECKSUM_ALGORITHM and cannot be compared against the issued SHA-256"
        fi
    else
        printf 'Collector Script Checksum: not available (no checksum tool on this host)\n'
        record_manifest_line "COLLECTOR_SELF|$0|checksum=unavailable"
    fi
else
    printf 'Collector Script Checksum: not available (script path not resolvable)\n'
    record_manifest_line "COLLECTOR_SELF|$0|checksum=unavailable"
fi

if [ "$TEST_MODE" = "yes" ] && [ "$EFFECTIVE_UID_VALUE" != "0" ]; then
    printf 'Test Mode Notice: running without sudo; privileged-only files and commands may show not available.\n'
fi

if [ -n "$APP_DIRECTORIES" ]; then
    printf 'Application Directories Selected for Recursive Listing:\n'
    printf '%s\n' "$APP_DIRECTORIES" | while IFS= read -r app_dir_header_entry; do
        if [ -n "$app_dir_header_entry" ]; then
            printf '  - %s\n' "$app_dir_header_entry"
        fi
    done
else
    printf 'Application Directories Selected for Recursive Listing: none\n'
fi

# Evidence section execution:
# Each section prints explanatory context followed by the relevant read-only
# evidence. Sections may query commands or read files, but they do not perform
# configuration changes on the host.
section_with_explanation "Platform Details" "Explanation: This section identifies the operating system family, kernel details, execution user, and privilege context for the host where the script was run. It provides the baseline context needed to interpret the remaining sections and confirms that the script was executed with elevated privileges as expected." ""
print_platform_details

_sec1_files=`section1_source_files`
section_with_explanation "1. Accounts and Groups with Root or Root Equivalent Access" "Explanation: This section identifies accounts with UID 0, users in key privileged groups, and duplicate UID or GID conditions. For a SOX IT audit, this helps determine who has root-equivalent access and whether identity administration appears clean and accountable." "$_sec1_files"
subsection "Users with UID 0 (Root Equivalent Accounts):"
if file_readable /etc/passwd; then
    awk -F: '($3 == 0) { print $1; found = 1 } END { if (!found) exit 1 }' /etc/passwd 2>/dev/null || no_entries_found
else
    not_available
fi
blank_line
subsection "Users in the wheel or sudo groups:"
print_group_membership_summary
blank_line
print_duplicate_uid_gid_review

_sec2_files=`section2_source_files`
section_with_explanation "2. Password Parameters / Requirements" "Explanation: This section gathers password aging, password quality, and account lockout settings from platform-relevant configuration files only. It avoids clutter from irrelevant operating-system files and helps show whether logical access requirements are configured on the host." "$_sec2_files"
print_auth_summary
blank_line
subsection "Full Content Review Files"
print_auth_full_content

_sec3_files=`section3_source_files`
section_with_explanation "3. Authentication Configuration" "Explanation: This section identifies the primary authentication sources and supporting configuration for the detected operating system. It is designed to show whether authentication is local, centralized, or mixed without printing irrelevant files for other Unix families." "$_sec3_files"
print_authentication_summary
blank_line
subsection "Full Content Review Files"
print_authentication_full_content

_sec4_files=`section4_source_files`
section_with_explanation "4. Accounts and Groups Able to Sudo to Root" "Explanation: This section focuses on delegated privileged access through sudo where present. For a SOX IT audit, sudo rights are highly relevant because they allow a user to perform root-level activity even when the user does not log in directly as root." "$_sec4_files"
print_sudo_summary
blank_line
subsection "Full Content Review Files"
print_sudo_full_content

_sec5_files=`section5_source_files`
section_with_explanation "5. Groups and Their Members" "Explanation: This section lists group memberships recorded on the host. Group-based access often grants administrative, operational, or application-related capabilities and is therefore important when evaluating logical access for financially relevant systems." "$_sec5_files"
print_all_groups

_sec6_files=`section6_source_files`
section_with_explanation "6. sulog Contents" "Explanation: This section looks for su activity logs where available. These records can help trace privilege escalation through su and support detective controls over administrator activity." "$_sec6_files"
print_sulog_content

_sec7_files=`section7_source_files`
section_with_explanation "7. SSH Configuration" "Explanation: This section shows security-relevant SSH settings and the SSH daemon configuration file. It helps assess whether remote administrative access appears to be restricted in a reasonable manner." "$_sec7_files"
print_ssh_summary
blank_line
subsection "Full Content Review Files"
print_sshd_full_content

section_with_explanation "8. Installed Packages" "Explanation: This section provides the installed software inventory as reported by the platform package management tools. It can help identify security agents, administration tools, database clients, and unexpected software that may affect the control environment." ""
print_package_inventory

section_with_explanation "9. Recent Login Activity" "Explanation: This section shows recent login history using the system's available login records. It is limited to a manageable amount of output to reduce noise while still supporting review of privileged and unusual logins." ""
print_recent_login_activity

section_with_explanation "10. World-Writable Files and Directories" "Explanation: This section identifies files and directories that any account on the host can modify. A world-writable file that is executed by a privileged account allows an unprivileged user to obtain privileged execution, and a world-writable application file allows unauthorized modification of data or programs in financial-reporting scope. Read this together with the cron evidence in Sections 12 and 21, the startup evidence in Section 16, and the sudo evidence in Section 4 to determine whether anything privileged executes a world-writable path. The scan is deliberately pruned to system binary, system configuration, and application installation paths, and does not cross filesystem boundaries, so that it cannot place load on data volumes or network-mounted filesystems on a production host; the resulting limits are stated in the output. Directories that are world-writable by design, such as /tmp, are not enumerated. Instead their sticky bit is verified, which is the actual control on a shared temporary directory. Only path, permission, and ownership metadata is recorded. The contents of a world-writable file are never printed or copied into this evidence package." ""
scan_timer_start "Scanning system and application paths for world-writable files"
print_world_writable_review
scan_timer_end "10 (world-writable)"

section_with_explanation "11. SetUID and SetGID Files" "Explanation: A SetUID program runs with the privileges of the file owner rather than those of the user who started it, so a SetUID root binary allows an unprivileged user to execute code with root privileges. A small number of system tools legitimately require this, but each one is a potential privilege-escalation path, so the population is inventoried for review. SetGID behaves the same way for group privileges. The scan is deliberately pruned to standard system and application binary paths rather than the entire filesystem, and does not cross filesystem boundaries, so that it cannot place load on data volumes or network-mounted filesystems on a production host. The resulting limits are stated in the output so a reviewer can see the bound on the evidence rather than assuming the population is complete. Application directories supplied at runtime are scanned as roots in their own right so that an application tree residing on its own mount is still covered." ""
scan_timer_start "Scanning system and application paths for SetUID/SetGID files"
print_setuid_setgid_files
scan_timer_end "11 (SetUID/SetGID)"

_sec12_files=`section12_source_files`
section_with_explanation "12. Scheduled Cron Jobs" "Explanation: This section shows system-wide and user cron jobs where available. Scheduled jobs matter because they can run automatically with elevated or application-specific permissions and can therefore affect controlled processing." "$_sec12_files"
print_cron_content

_sec13_files=`section13_source_files`
section_with_explanation "13. Service Accounts" "Explanation: This section lists lower-UID accounts that are commonly used for system services, background processes, or applications rather than normal human users." "$_sec13_files"
print_service_accounts

_sec14_files=`section14_source_files`
section_with_explanation "14. Account Status, SSH Keys, and Legacy Trust" "Explanation: This section summarizes account status, password expiry, home directory and SSH permission posture, and legacy trust files. Sensitive files such as authorized_keys and trust files are reviewed through metadata and safe summaries rather than full content output." "$_sec14_files"
print_account_status_summary
blank_line
print_password_expiry_details
blank_line
print_ssh_home_permission_review
blank_line
print_legacy_trust_content
blank_line
print_shell_timeout_and_banner_summary

_sec15_files=`section15_source_files`
section_with_explanation "15. Audit Logging and Log Forwarding" "Explanation: This section captures platform-relevant logging configuration, indicators of log forwarding, and sudo logging settings. It avoids printing large amounts of irrelevant logging configuration for other operating systems." "$_sec15_files"
print_audit_logging_summary

_sec16_files=`section16_source_files`
section_with_explanation "16. Service and Startup Configuration" "Explanation: This section captures service and startup information using the native service model for the detected operating system, such as systemd, SRC, SMF, or traditional startup files." "$_sec16_files"
print_service_startup_summary

_sec17_files=`section17_source_files`
section_with_explanation "17. Network Exposure and Firewall Configuration" "Explanation: This section shows listening network services, selected firewall or export configuration, and indicators of older insecure network services." "$_sec17_files"
print_network_exposure_summary

_sec18_files=`section18_source_files`
section_with_explanation "18. Patch, Update, and Change Indicators" "Explanation: This section captures host-level evidence of package or patch maintenance using the native package history or package listing tools available on the detected operating system." "$_sec18_files"
print_patch_update_summary

_sec19_files=`section19_source_files`
section_with_explanation "19. Backup, Capacity, and Operational Indicators" "Explanation: This section gathers practical operations evidence such as filesystem capacity and selected backup or log rotation configuration files." "$_sec19_files"
print_backup_operational_summary

_sec20_files=`section20_source_files`
section_with_explanation "20. Time Synchronization" "Explanation: This section captures available time synchronization configuration files such as chrony or NTP." "$_sec20_files"
print_time_sync_summary

_sec21_files=`section21_source_files`
section_with_explanation "21. Additional Scheduled Tasks and Timers" "Explanation: This section captures supplemental scheduler files such as anacron and cron log files where present." "$_sec21_files"
print_additional_scheduler_content

_sec22_files=`section22_source_files`
section_with_explanation "22. Critical File Integrity and Sensitive File Permissions" "Explanation: This section shows metadata and checksums for selected sensitive operating-system files, using an operating-system-specific file list so the output stays relevant to the detected platform." "$_sec22_files"
print_critical_file_integrity

section_with_explanation "23. Application Installation Directory Recursive Listing" "Explanation: This section captures a recursive directory listing for one or more application installation directories specified by the operator at runtime. It supports SOX / ITGC reviews of application file inventories by recording filenames, ownership, permissions, sizes, and modification times for every file under the supplied roots. The ls command is read-only and does not change file content, ownership, or permissions. The flags are adjusted per operating system because the desired Linux flag set ls -RlthBA includes GNU extensions (-h human-readable sizes and -B ignore backups) that are not present, or that have different meanings, on AIX, Solaris, HP-UX, and BSD. Equivalent flag sets are used on those platforms so the resulting evidence remains comparable across hosts. Application directories are listed as metadata only; the script does not copy the contents of these directories into the evidence package." "$APP_DIRECTORIES" "no"
if [ -z "$APP_DIRECTORIES" ]; then
    printf 'No application directories were specified.\n'
    printf 'Application directories can be supplied with the --app-dir flag,\n'
    printf 'or by responding to the interactive prompt at script startup.\n'
else
    scan_timer_start "Listing application installation directories recursively"
    printf '%s\n' "$APP_DIRECTORIES" | while IFS= read -r app_path_entry; do
        if [ -n "$app_path_entry" ]; then
            print_application_directory_listing "$app_path_entry"
        fi
    done
    scan_timer_end "23 (application directory listing)"
fi

_sec24_files=`section24_source_files`
section_with_explanation "24. Interactive User Accounts" "Explanation: This section lists the accounts that a person could plausibly use to log in to this host: UID 0 accounts plus accounts at or above the platform service-account threshold whose login shell is not a known non-interactive shell. For a SOX IT audit, this provides the population of named human users for logical access review, complementing the UID 0 review in Section 1 and the service-account inventory in Section 13." "$_sec24_files"
print_interactive_user_accounts

_sec25_files=`section25_source_files`
section_with_explanation "25. Authentication Log Samples" "Explanation: This section shows the most recent entries from the host's authentication logs to demonstrate that login and privilege activity was actually being recorded at the time of collection. It complements Section 15, which shows how logging is configured, by providing evidence that logging is operating. Only the sampled lines shown here are included in the evidence; the full log files are intentionally not copied because production authentication logs can be very large. Each sampled log is recorded in the manifest as LOG_SAMPLED." "$_sec25_files" "no"
print_auth_log_samples

section "Execution Summary"
printf 'Status: completed\n'
printf 'Behavior: report file plus local evidence packaging\n'
printf 'Output directory: %s\n' "$WORKING_DIRECTORY"
printf 'Files created in output directory: %s\n' "$COLLECTION_DIRECTORY"
printf 'Collection directory status: %s\n' "$COLLECTION_STATUS"
printf 'Archive file (planned): %s.tar.gz\n' "$WORKING_DIRECTORY/$ARCHIVE_BASE_NAME"
printf '  (or .tar if gzip is unavailable on this host)\n'
printf 'Archive note: the archive is created after this report and the collection\n'
printf '  log are finalized, so that both are complete inside it. An archive cannot\n'
printf '  record the outcome of its own creation; that result is printed on the\n'
printf '  operator terminal and appended to the collection log on disk.\n'
printf 'Report file: %s\n' "$REPORT_FILE"
printf 'Manifest file: %s\n' "$MANIFEST_FILE"
printf 'Sensitive skip file: %s\n' "$SENSITIVE_SKIPPED_FILE"
printf 'Configuration changes made: none\n'

# Runtime of the filesystem-walking sections. Everything else in this collection
# is effectively instantaneous, so these are the only figures a client or reviewer
# would need in order to account for the script's time on the host.
blank_line
subsection "Scan Timing (filesystem-walking sections only):"
if [ -n "$SCAN_TIMING_SUMMARY" ]; then
    printf '%s\n' "$SCAN_TIMING_SUMMARY" | while IFS= read -r _timing_line; do
        if [ -n "$_timing_line" ]; then
            printf '%s\n' "$_timing_line"
        fi
    done
else
    printf '  no timed scans were run\n'
fi

# Transfer ownership of the evidence package to the operator who invoked
# sudo. This runs after the report is finalized so that subsequent operator
# actions (copy, scp, email, ftp) do not require sudo.
log_event INFO completion "evidence collection finished"

# Point the report at the log, so a reader who starts from the report knows where
# to check whether the evidence is complete.
blank_line
subsection "Collection Log:"
printf 'A record of whether this collection ran correctly, and of anything that\n'
printf 'limited the evidence gathered, is in:\n'
printf '  %s\n' "${LOG_FILE:-not created}"
printf 'Review that file before relying on any section reported as not available.\n'

record_manifest_line "COLLECTION_LOG|${LOG_FILE:-not created}"

# Order from here matters and is the reason the archive is built last.
#
# The archive is what actually reaches the audit team, so everything that belongs
# in the package has to be finished before it is created. Building it earlier
# produced an archive whose report stopped short of the execution summary and
# whose collection log had no RESULT verdict, while the copies left behind on the
# client's server were complete - so the delivered evidence was the truncated one.
#
# Permissions and ownership are also applied before archiving, because the modes
# recorded inside a tar are the modes the recipient gets.
write_handling_instructions
normalize_package_permissions
apply_ownership_to_evidence

# The summary block closes the log, so everything that has something to report
# must have run by now. Only the archive follows, and it appends an addendum.
finalize_collection_log

open_log_addendum
create_collection_archive
apply_ownership_to_archive
close_log_addendum

if [ -r "$REPORT_FILE" ]; then
    cat "$REPORT_FILE" >&3
fi

# Leave the operator with the verdict and where to find the detail. This is the
# last thing printed, so it is what remains on screen after the run.
_final_result=`collection_log_result`
{
    printf '\n'
    printf '================================================================\n'
    printf 'COLLECTION RESULT: %s\n' "$_final_result"
    printf '  errors: %s   warnings: %s\n' "$LOG_ERROR_COUNT" "$LOG_WARN_COUNT"
    printf '%s\n' "  `collection_log_result_meaning "$_final_result"`"
    printf '  Full log: %s\n' "${LOG_FILE:-not created}"
    printf '================================================================\n'
} >&3 2>/dev/null || :

# Exit status, so that an automated caller learns the same thing a human reads.
#
# This previously exited 0 unconditionally. A collection that failed outright -
# an unwritable output directory, no evidence directory, no log - still returned
# success, so any wrapper script, scheduled job, or intake process that checked
# $? was told the collection had worked. The verdict on screen said FAILED while
# the exit status said fine, and automation believes the exit status.
#
#   0  the package is usable: COMPLETED_CLEAN, or COMPLETED_WITH_WARNINGS.
#      Warnings are the normal outcome on a real host - they mean some evidence
#      was limited, not that the collection failed - so they must not be treated
#      as an error by a caller. The auditor reads them; the script succeeded.
#
#   1  the package is NOT usable: COMPLETED_WITH_ERRORS, or FAILED. A step
#      failed or the collection could not be completed. Do not send the package
#      without reading the log first.
#
# Deliberately only two values. A finer scale would invite callers to branch on
# distinctions that belong in the log, and the log is the authoritative record.
case "$_final_result" in
    COMPLETED_CLEAN|COMPLETED_WITH_WARNINGS)
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
