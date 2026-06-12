#!/bin/sh

# SOX ITGC Audit Data Collection Script
# Shell-only version intended to be run as:
#   sudo sh linux-unix-evidence-gathering-script.sh
#
# Client review statement:
# This script is intended for controlled SOX ITGC evidence collection on
# Unix-like operating systems, including Linux, AIX, Solaris / Illumos, HP-UX,
# BSD, and related platforms. It gathers configuration, access, logging,
# scheduling, service, network, patch, backup, time synchronization, and file
# integrity evidence that is commonly requested during operating-system control
# reviews.
#
# Operating model:
# - The script performs observation and evidence packaging only.
# - It does not create, modify, delete, enable, disable, restart, or reconfigure
#   operating-system users, groups, services, jobs, permissions, packages,
#   network settings, logging settings, or authentication settings.
# - Source files from the host are read and, where appropriate, copied into the
#   evidence package. The original source files are not modified.
# - The script writes only to the evidence directory that it creates in the
#   current working directory selected by the operator, plus the resulting
#   archive file in that same working directory.
# - Sensitive files, such as password shadow files, private keys, keytabs, and
#   SSH key material, are not printed or copied in full. The script records
#   metadata or safe summaries for those files instead.
#
# Evidence outputs:
# - report/ contains the narrative audit report.
# - raw_files/ contains copied non-sensitive source files.
# - metadata/ contains the manifest and sensitive-file tracking log.
# - commands/ contains a local command-output style artifact.
# - SOX-ITGC-AUDIT-LINUX-UNIX-<hostname>-<timestamp>.* is the packaged archive.

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

# Evidence directory structure created under the working directory:
# - report/: human-readable audit report generated by this script
# - raw_files/: copied non-sensitive source files used as supporting evidence
# - metadata/: manifest and sensitive-file handling records
# - commands/: locally generated command-output style artifact
COLLECTION_DIRECTORY="$WORKING_DIRECTORY/SOX-ITGC-AUDIT-LINUX-UNIX"
REPORTS_DIRECTORY="$COLLECTION_DIRECTORY/report"
RAW_FILES_DIRECTORY="$COLLECTION_DIRECTORY/raw_files"
METADATA_DIRECTORY="$COLLECTION_DIRECTORY/metadata"
COMMANDS_DIRECTORY="$COLLECTION_DIRECTORY/commands"
REPORT_FILE="$REPORTS_DIRECTORY/SOX-ITGC-AUDIT-REPORT.txt"
COMMAND_LOG_FILE="$COMMANDS_DIRECTORY/combined-command-output.txt"
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

section_with_explanation() {
    _sec_copy_mode=${4:-yes}
    printf '\n==================================================\n'
    printf '%s\n' "$1"
    wrap_text "$2"
    if [ -n "${3:-}" ]; then
        printf '\n'
        printf '%s\n' "$3" | while IFS= read -r _sec_path; do
            if [ -n "$_sec_path" ]; then
                printf 'File Path: %s\n' "$_sec_path"
                if [ "$_sec_copy_mode" = "yes" ]; then
                    record_file_reference "$_sec_path"
                fi
            fi
        done
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
        /root/.ssh/*|/home/*/.ssh/*|*/.ssh/id_*|*/authorized_keys|*/.rhosts|*/.shosts|*.pem|*.key)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

record_manifest_line() {
    if [ -f "$MANIFEST_FILE" ]; then
        printf '%s\n' "$1" >> "$MANIFEST_FILE"
    fi
}

record_sensitive_skip() {
    if [ -f "$SENSITIVE_SKIPPED_FILE" ]; then
        printf '%s\n' "$1" >> "$SENSITIVE_SKIPPED_FILE"
    fi
}

record_file_reference() {
    ref_path=$1
    if [ -z "$ref_path" ]; then
        return
    fi
    if [ -f "$ref_path" ]; then
        copy_file_to_collection "$ref_path"
    elif [ -d "$ref_path" ]; then
        for ref_entry in "$ref_path"/*; do
            if [ -f "$ref_entry" ]; then
                copy_file_to_collection "$ref_entry"
            fi
        done
    fi
}

# Evidence directory preparation:
# The script recreates its own local evidence directory before collection so
# the output reflects one execution. This cleanup is limited to the directory
# named by COLLECTION_DIRECTORY under the current working directory. It does
# not remove or modify host configuration files outside that evidence folder.
prepare_collection_directory() {
    if rm -rf "$COLLECTION_DIRECTORY" 2>/dev/null && \
       mkdir -p "$REPORTS_DIRECTORY" "$RAW_FILES_DIRECTORY" "$METADATA_DIRECTORY" "$COMMANDS_DIRECTORY" 2>/dev/null; then
        : > "$MANIFEST_FILE"
        : > "$SENSITIVE_SKIPPED_FILE"
        COLLECTION_STATUS="ready"
    else
        COLLECTION_STATUS="failed to create collection directory"
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
        if cp -p "$file_path" "$target_path" 2>/dev/null || cp "$file_path" "$target_path" 2>/dev/null; then
            record_manifest_line "COPIED|$file_path"
        fi
    fi
}

# Checksum calculation:
# The script attempts common checksum tools available across Unix-like systems.
# These tools read file contents to calculate a reference value and do not
# write to or alter the measured file.
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

# Pattern-based evidence extraction:
# This helper searches readable files for security-relevant settings and prints
# matching lines. It performs read-only text matching and does not edit files.
print_matching_lines_or_not_available() {
    pattern=$1
    file_path=$2

    if file_readable "$file_path"; then
        if grep -E "$pattern" "$file_path" 2>/dev/null; then
            :
        else
            not_available
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
# groups such as wheel and sudo. It reads group information only and does not
# add or remove users from any group.
print_group_membership_summary() {
    found=no

    if command_exists getent; then
        record_manifest_line "GETENT_QUERY|group wheel,sudo|source=name_service"
        record_file_reference /etc/group
        if getent group wheel >/dev/null 2>&1; then
            getent group wheel | awk -F: '{print "- wheel: " $4}'
            found=yes
        else
            printf '%s\n' '- wheel: not available'
        fi
        if getent group sudo >/dev/null 2>&1; then
            getent group sudo | awk -F: '{print "- sudo: " $4}'
            found=yes
        else
            printf '%s\n' '- sudo: not available'
        fi
    elif file_readable /etc/group; then
        record_file_reference /etc/group
        awk -F: '$1 == "wheel" || $1 == "sudo" { print "- " $1 ": " $4; found = 1 } END { if (!found) exit 1 }' /etc/group 2>/dev/null || no_entries_found
    else
        not_available
    fi
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
            if file_readable /etc/security/pwquality.conf; then
                record_file_reference /etc/security/pwquality.conf
                grep -E '^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)' /etc/security/pwquality.conf 2>/dev/null || not_available
            elif file_readable /etc/pam.d/system-auth; then
                record_file_reference /etc/pam.d/system-auth
                grep -E 'pam_cracklib\.so|pam_pwquality\.so' /etc/pam.d/system-auth 2>/dev/null || not_available
            else
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
            if directory_exists /etc/pam.d; then
                record_file_reference /etc/pam.d
                grep -E 'pam_tally2\.so|pam_faillock\.so' /etc/pam.d/* 2>/dev/null || not_available
            else
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
            subsection "Full File Content: /etc/pam.d/system-auth"
            print_file_with_header /etc/pam.d/system-auth
            subsection "Full File Content: /etc/pam.d/password-auth"
            print_file_with_header /etc/pam.d/password-auth
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
print_ssh_summary() {
    subsection "Summary: Relevant SSH Settings"
    if file_readable /etc/ssh/sshd_config; then
        record_file_reference /etc/ssh/sshd_config
        grep -E '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding|Protocol|AllowUsers|AllowGroups|DenyUsers|DenyGroups|LoginGraceTime|MaxAuthTries)[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null || not_available
    else
        not_available
    fi
}

# SSH source-file capture:
# The SSH daemon configuration is printed and copied when readable. Collection
# is read-only and does not alter access settings.
print_sshd_full_content() {
    subsection "Full File Content: /etc/ssh/sshd_config"
    print_file_with_header /etc/ssh/sshd_config
}

# su activity log review:
# Where present, sulog is read to provide evidence of account switching
# activity. The log file is not truncated, rotated, or modified.
print_sulog_content() {
    print_file_with_header /var/log/sulog
}

# Package inventory:
# Native package-manager commands are used only in query/list mode. The script
# does not install, remove, upgrade, downgrade, or reconfigure software.
print_package_inventory() {
    if command_exists rpm; then
        rpm -qa 2>/dev/null || not_available
    elif command_exists dpkg; then
        dpkg -l 2>/dev/null || not_available
    elif command_exists pkginfo; then
        pkginfo 2>/dev/null || not_available
    elif command_exists swlist; then
        swlist 2>/dev/null || not_available
    elif command_exists lslpp; then
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
        last 2>/dev/null | awk 'NR <= 50 { print }' || not_available
    else
        not_available
    fi
}

# SetUID / SetGID file review:
# The search is intentionally limited to common binary and application paths so
# the scan remains practical and avoids broad traversal of temporary, mounted,
# or pseudo filesystems. The find command lists matching files only.
print_setuid_setgid_files() {
    if ! command_exists find; then
        not_available
        return
    fi

    search_paths=""
    for candidate in /bin /sbin /usr/bin /usr/sbin /usr/lib /usr/libexec /usr/local/bin /usr/local/sbin /usr/local/lib /opt; do
        if [ -d "$candidate" ]; then
            search_paths="$search_paths $candidate"
        fi
    done

    if [ -z "$search_paths" ]; then
        not_available
        return
    fi

    subsection "Pruned Search Scope:"
    printf '%s\n' "$search_paths"
    blank_line

    subsection "SetUID Files:"
    find $search_paths -type f \( -perm -4000 -o -perm -04000 \) -print 2>/dev/null || not_available
    blank_line

    subsection "SetGID Files:"
    find $search_paths -type f \( -perm -2000 -o -perm -02000 \) -print 2>/dev/null || not_available
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
                if crontab -u "$user" -l 2>/dev/null; then
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
        awk -F: -v cutoff="$uid_cutoff" '($3 < cutoff) { print $1 ":" $3 ":" $4 ":" $6 ":" $7; found = 1 } END { if (!found) exit 1 }' /etc/passwd 2>/dev/null || no_entries_found
    else
        not_available
    fi
}

# Account lifecycle status:
# Tools such as passwd, chage, or lsuser are used only with status/list
# options. The script does not reset passwords, lock accounts, unlock accounts,
# change expiration dates, or modify login shells.
print_account_status_summary() {
    subsection "Account Status Summary:"
    if file_readable /etc/passwd; then
        record_file_reference /etc/passwd
        found=no
        if command_exists passwd; then
            while IFS=: read -r user _rest; do
                if passwd -S "$user" 2>/dev/null || passwd -s "$user" 2>/dev/null; then
                    found=yes
                fi
            done < /etc/passwd
        fi
        if [ "$found" = no ] && command_exists lsuser; then
            lsuser -a account_locked expires login shell ALL 2>/dev/null && found=yes
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
        if command_exists chage; then
            while IFS=: read -r user _rest; do
                printf 'User: %s\n' "$user"
                if chage -l "$user" 2>/dev/null; then
                    found=yes
                else
                    not_available
                fi
                blank_line
            done < /etc/passwd
        elif command_exists lsuser; then
            lsuser -a maxage minage pwdwarntime expires account_locked ALL 2>/dev/null && found=yes
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
                systemctl list-unit-files --type=service 2>/dev/null || not_available
            else
                print_file_with_header /etc/inittab
            fi
            ;;
        AIX)
            if command_exists lssrc; then
                lssrc -a 2>/dev/null || not_available
            else
                not_available
            fi
            ;;
        SunOS)
            if command_exists svcs; then
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
    if command_exists ss; then
        ss -lntup 2>/dev/null || not_available
    elif command_exists netstat; then
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
    grep -E '(telnet|rlogin|rexec|rsh|ftp)' /etc/inetd.conf /etc/inet/inetd.conf /etc/xinetd.d/* /etc/services 2>/dev/null || not_available
}

# Patch and update indicators:
# Package metadata and history are queried to support change and maintenance
# review. The script performs no patching, installation, removal, or update
# action.
print_patch_update_summary() {
    if command_exists rpm; then
        rpm -qa --last 2>/dev/null || not_available
    elif command_exists dpkg; then
        print_file_with_header /var/log/dpkg.log
    elif command_exists lslpp; then
        lslpp -h 2>/dev/null || not_available
    elif command_exists swlist; then
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

# Interactive user account inventory:
# Service accounts (Section 13) and UID 0 accounts (Section 1) are reviewed
# elsewhere. This function lists the remaining accounts that a person could
# plausibly log in with: UID 0 accounts plus accounts at or above the
# platform service-account threshold whose login shell is not a known
# non-interactive shell (nologin or false). This reads /etc/passwd only and
# does not modify any account.
print_interactive_user_accounts() {
    uid_cutoff=`service_uid_cutoff`

    if file_readable /etc/passwd; then
        printf 'Criteria: UID 0, or UID >= %s with a login shell other than nologin/false\n' "$uid_cutoff"
        printf 'Format: user:uid:gid:home:shell\n'
        blank_line
        awk -F: -v cutoff="$uid_cutoff" '
            $7 !~ /(nologin|false)$/ && ($3 == 0 || $3 >= cutoff) {
                print $1 ":" $3 ":" $4 ":" $6 ":" $7
                found = 1
            }
            END { if (!found) exit 1 }
        ' /etc/passwd 2>/dev/null || no_entries_found
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

    if [ "$found" = no ] && command_exists journalctl; then
        printf 'No authentication log files found; sampling systemd journal (last %s lines)\n' "$AUTH_LOG_SAMPLE_LINES"
        if journalctl -n "$AUTH_LOG_SAMPLE_LINES" --no-pager 2>/dev/null; then
            record_manifest_line "LOG_SAMPLED|journalctl|lines=$AUTH_LOG_SAMPLE_LINES"
            found=yes
        fi
        blank_line
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
        return
    fi

    if command_exists tar; then
        if command_exists gzip; then
            if tar -cf "$archive_base.tar" -C "$WORKING_DIRECTORY" SOX-ITGC-AUDIT-LINUX-UNIX 2>/dev/null && gzip -f "$archive_base.tar" 2>/dev/null; then
                ARCHIVE_FILE=$archive_base.tar.gz
                ARCHIVE_STATUS="created"
                return
            fi
        fi
        if tar -cf "$archive_base.tar" -C "$WORKING_DIRECTORY" SOX-ITGC-AUDIT-LINUX-UNIX 2>/dev/null; then
            ARCHIVE_FILE=$archive_base.tar
            ARCHIVE_STATUS="created"
            return
        fi
    fi

    ARCHIVE_STATUS="failed"
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
    printf '-------------------------\n'
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
            OUTPUT_DIRECTORY=$entered_output_path
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
    COMMANDS_DIRECTORY="$COLLECTION_DIRECTORY/commands"
    REPORT_FILE="$REPORTS_DIRECTORY/SOX-ITGC-AUDIT-REPORT.txt"
    COMMAND_LOG_FILE="$COMMANDS_DIRECTORY/combined-command-output.txt"
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
apply_ownership_to_evidence() {
    if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = "root" ]; then
        OWNERSHIP_STATUS="not adjusted (no SUDO_USER detected)"
        return
    fi

    target_group=""
    if command_exists id; then
        target_group=`id -gn "$SUDO_USER" 2>/dev/null`
    fi
    if [ -n "$target_group" ]; then
        target_owner="$SUDO_USER:$target_group"
    else
        target_owner="$SUDO_USER"
    fi

    chown_ok=yes
    if [ -d "$COLLECTION_DIRECTORY" ]; then
        chown -R "$target_owner" "$COLLECTION_DIRECTORY" 2>/dev/null || chown_ok=no
    fi
    if [ -n "$ARCHIVE_FILE" ] && [ -f "$ARCHIVE_FILE" ]; then
        chown "$target_owner" "$ARCHIVE_FILE" 2>/dev/null || chown_ok=no
        chmod 0640 "$ARCHIVE_FILE" 2>/dev/null || chown_ok=no
    fi

    if [ "$chown_ok" = "yes" ]; then
        OWNERSHIP_STATUS="evidence owned by $target_owner (archive mode 0640)"
    else
        OWNERSHIP_STATUS="ownership adjustment to $target_owner encountered errors"
    fi
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
    printf '------------------------------------------\n'
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
        Linux)   printf '/etc/login.defs\n/etc/security/pwquality.conf\n/etc/pam.d/system-auth\n/etc/pam.d/password-auth\n' ;;
        AIX)     printf '/etc/security/user\n' ;;
        SunOS|HP-UX) printf '/etc/default/passwd\n/etc/default/login\n' ;;
    esac
}
section3_source_files()  {
    case "$OS_NAME" in
        Linux)   printf '/etc/nsswitch.conf\n/etc/sssd/sssd.conf\n/etc/pam.d/\n' ;;
        AIX)     printf '/etc/security/user\n' ;;
        SunOS)   printf '/etc/nsswitch.conf\n/etc/user_attr\n/etc/security/prof_attr\n/etc/security/exec_attr\n' ;;
        HP-UX)   printf '/etc/pam.conf\n' ;;
    esac
}
section4_source_files()  { printf '/etc/sudoers\n/etc/sudoers.d/\n'; }
section5_source_files()  { printf '/etc/group\n'; }
section6_source_files()  { printf '/var/log/sulog\n'; }
section7_source_files()  { printf '/etc/ssh/sshd_config\n'; }
section12_source_files() { printf '/etc/crontab\n/etc/cron.d/\n/var/spool/cron/crontabs/\n'; }
section13_source_files() { printf '/etc/passwd\n'; }
section14_source_files() { printf '/etc/passwd\n/etc/hosts.equiv\n/etc/issue\n/etc/issue.net\n/etc/motd\n/etc/ssh/banner\n/etc/profile\n'; }
section15_source_files() {
    case "$OS_NAME" in
        Linux)   printf '/etc/audit/auditd.conf\n/etc/systemd/journald.conf\n/etc/rsyslog.conf\n/etc/rsyslog.d/\n/etc/syslog-ng/syslog-ng.conf\n/etc/sudoers\n/etc/sudoers.d/\n' ;;
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
section20_source_files() { printf '/etc/chrony.conf\n/etc/chrony/chrony.conf\n/etc/ntp.conf\n/etc/inet/ntp.conf\n'; }
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

# Preserve the original stdout on file descriptor 3. The script writes the
# report to the report file first, then replays the completed report to the
# operator at the end of the run.
exec 3>&1
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

section_with_explanation "10. World-Writable Files" "Explanation: This section remains intentionally omitted in this version." ""
printf 'intentionally omitted\n'

section_with_explanation "11. SetUID and SetGID Files" "Explanation: This section identifies SetUID and SetGID files, but the scan is intentionally pruned to standard system and application binary paths rather than the entire filesystem. This reduces runtime and avoids broad traversal of mounted, pseudo, and temporary filesystems while still capturing the most relevant binaries." ""
print_setuid_setgid_files

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
    printf '%s\n' "$APP_DIRECTORIES" | while IFS= read -r app_path_entry; do
        if [ -n "$app_path_entry" ]; then
            print_application_directory_listing "$app_path_entry"
        fi
    done
fi

_sec24_files=`section24_source_files`
section_with_explanation "24. Interactive User Accounts" "Explanation: This section lists the accounts that a person could plausibly use to log in to this host: UID 0 accounts plus accounts at or above the platform service-account threshold whose login shell is not a known non-interactive shell. For a SOX IT audit, this provides the population of named human users for logical access review, complementing the UID 0 review in Section 1 and the service-account inventory in Section 13." "$_sec24_files"
print_interactive_user_accounts

_sec25_files=`section25_source_files`
section_with_explanation "25. Authentication Log Samples" "Explanation: This section shows the most recent entries from the host's authentication logs to demonstrate that login and privilege activity was actually being recorded at the time of collection. It complements Section 15, which shows how logging is configured, by providing evidence that logging is operating. Only the sampled lines shown here are included in the evidence; the full log files are intentionally not copied because production authentication logs can be very large. Each sampled log is recorded in the manifest as LOG_SAMPLED." "$_sec25_files" "no"
print_auth_log_samples

create_collection_archive

section "Execution Summary"
printf 'Status: completed\n'
printf 'Behavior: report file plus local evidence packaging\n'
printf 'Output directory: %s\n' "$WORKING_DIRECTORY"
printf 'Files created in output directory: %s\n' "$COLLECTION_DIRECTORY"
printf 'Collection directory status: %s\n' "$COLLECTION_STATUS"
printf 'Archive status: %s\n' "$ARCHIVE_STATUS"
printf 'Archive file: %s\n' "${ARCHIVE_FILE:-not available}"
printf 'Report file: %s\n' "$REPORT_FILE"
printf 'Manifest file: %s\n' "$MANIFEST_FILE"
printf 'Sensitive skip file: %s\n' "$SENSITIVE_SKIPPED_FILE"
printf 'Command log file: %s\n' "$COMMAND_LOG_FILE"
printf 'Configuration changes made: none\n'

if [ -r "$REPORT_FILE" ] && [ "$COLLECTION_STATUS" = "ready" ]; then
    cp "$REPORT_FILE" "$COMMAND_LOG_FILE" 2>/dev/null || :
fi

# Transfer ownership of the evidence package to the operator who invoked
# sudo. This runs after the report and command log are finalized so that
# subsequent operator actions (copy, scp, email, ftp) do not require sudo.
apply_ownership_to_evidence
printf 'Ownership status: %s\n' "$OWNERSHIP_STATUS"

if [ -r "$REPORT_FILE" ]; then
    cat "$REPORT_FILE" >&3
fi
