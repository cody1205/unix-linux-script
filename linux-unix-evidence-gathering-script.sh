#!/bin/sh

# SOX ITGC Audit Data Collection Script
# Read-only against source files; writes report to stdout and
# packages copied evidence files in the current working directory.

PATH=/usr/sbin:/usr/bin:/sbin:/bin
readonly PATH

SECTION_SEPARATOR='=================================================================='
readonly SECTION_SEPARATOR

GUIDANCE_WRAP_WIDTH=62
readonly GUIDANCE_WRAP_WIDTH

SCRIPT_MODE="read-only source collection with local packaging"
readonly SCRIPT_MODE

OS_NAME=$(uname -s 2>/dev/null || echo unknown)
readonly OS_NAME

HOSTNAME_VALUE=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)
readonly HOSTNAME_VALUE

TIMESTAMP=$(date 2>/dev/null || echo unknown)
readonly TIMESTAMP

ARCHIVE_TIMESTAMP=$(date '+%Y%m%d-%H%M%S' 2>/dev/null || echo unknown_time)
readonly ARCHIVE_TIMESTAMP

SAFE_HOSTNAME=$(printf '%s' "$HOSTNAME_VALUE" | tr -c 'A-Za-z0-9._-' '_')
readonly SAFE_HOSTNAME

WORKING_DIRECTORY=$(pwd 2>/dev/null || echo .)
readonly WORKING_DIRECTORY

COLLECTION_DIRECTORY="$WORKING_DIRECTORY/SOX-ITGC-AUDIT-LINUX-UNIX"
readonly COLLECTION_DIRECTORY

COLLECTION_FILES_DIRECTORY="$COLLECTION_DIRECTORY/files"
readonly COLLECTION_FILES_DIRECTORY

REPORT_FILE="$COLLECTION_DIRECTORY/SOX-ITGC-AUDIT-REPORT.txt"
readonly REPORT_FILE

MANIFEST_FILE="$COLLECTION_DIRECTORY/MANIFEST.txt"
readonly MANIFEST_FILE

ARCHIVE_BASE_NAME="SOX-ITGC-AUDIT-LINUX-UNIX-$SAFE_HOSTNAME-$ARCHIVE_TIMESTAMP"
readonly ARCHIVE_BASE_NAME

ARCHIVE_FILE=""
ARCHIVE_STATUS="not created"
COLLECTION_STATUS="pending"

section() {
    printf '\n%s\n' "$SECTION_SEPARATOR"
    printf '%s\n' "$1"
    printf '%s\n\n' "$SECTION_SEPARATOR"
}

print_wrapped_text() {
    printf '%s\n' "$1" | awk -v width="$GUIDANCE_WRAP_WIDTH" '
        {
            line = ""
            for (i = 1; i <= NF; i++) {
                word = $i
                if (line == "") {
                    line = word
                } else if (length(line) + length(word) + 1 <= width) {
                    line = line " " word
                } else {
                    print line
                    line = word
                }
            }
            if (line != "") {
                print line
            }
        }
    '
}

print_guidance_block() {
    printf '%s\n' "$1"
    print_wrapped_text "$2"
    blank_line
}

print_section_guidance() {
    case "$1" in
        "Platform Details")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section identifies the operating system family, kernel release, kernel version, and hardware type of the host where the script was run."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Read this first because it tells you which later files, commands, and control mechanisms are likely to exist. Linux, AIX, Solaris, HP-UX, and BSD systems often store security settings in different places."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "A Linux host will usually show Linux-specific files later, while AIX or Solaris may show different authentication and password sources. If a later section says \"not available,\" compare it to the platform here before assuming a control is missing."
            print_guidance_block "WHY IT MATTERS:" "This is the context section. It explains how the rest of the evidence should be interpreted and helps an auditor or reviewer avoid applying the wrong expectation to the wrong operating system."
            ;;
        "1. Accounts and Groups with Root or Root Equivalent Access")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section shows which accounts are literally root-equivalent because they have UID 0, and which users belong to powerful administrative groups such as wheel or sudo."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "In Unix and Linux, UID 0 is the real superuser identity. Any account with UID 0 has the same power as root even if the account name is something else. Group-based access is slightly different because it usually means a user can elevate to root rather than being root at all times."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Seeing only \"root\" under UID 0 is typical and usually easier to govern. Seeing extra UID 0 accounts is a stronger risk signal because those accounts may bypass naming conventions and reduce accountability. Seeing many names in wheel or sudo means privileged access is broadly distributed and should be compared against approved administrator lists."
            print_guidance_block "WHY IT MATTERS:" "This section helps answer the question \"who can fully control this system?\" It is one of the most important areas for access management, segregation of duties, and privileged account review."
            ;;
        "2. Password Parameters / Requirements")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section gathers password policy settings such as minimum length, aging rules, warning periods, complexity settings, and account lockout behavior from the files used by the host platform."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Treat this section as the system's password policy evidence. Longer minimum lengths, aging intervals, complexity requirements, and lockout thresholds generally indicate stronger controls, although the exact acceptable settings depend on your policy standard."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "\"not available\" can mean the setting is stored somewhere else on that platform, the file is unreadable, or the system uses another authentication method. Values such as very low minimum length, no lockout, or extremely long maximum password age can indicate weaker control enforcement."
            print_guidance_block "WHY IT MATTERS:" "This section supports questions like \"how strong must passwords be?\" and \"what happens after repeated failed logins?\" It is often mapped to identity, access, and account management controls in audits."
            ;;
        "3. Authentication Configuration")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section shows how the host decides where user identities come from and which authentication modules are referenced. Examples include local files, LDAP, SSSD, winbind, NIS, and PAM configuration."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Read this as the \"where does the system trust identities from?\" section. If you see local files only, authentication is mostly local. If you see LDAP, SSSD, winbind, or similar terms, the system is likely tied to a centralized identity source."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "\"SSSD configuration present: yes\" usually means the host is integrated with a central directory. PAM module references tell you which authentication path is actually being enforced. If the section is sparse on older Unix, that may reflect platform differences rather than absence of authentication controls."
            print_guidance_block "WHY IT MATTERS:" "Password rules alone do not tell you where identities are managed. This section helps you understand whether users are local, centrally managed, domain-based, or mixed, which is critical for account lifecycle and access review."
            ;;
        "4. Accounts and Groups Able to Sudo to Root")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section shows the active sudo rules that allow a person or group to run commands as root or as another privileged account."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Read each non-comment line as an authorization rule. User names, group names, host filters, command lists, and special flags such as NOPASSWD describe exactly who can elevate and under what conditions."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Rules that grant ALL privileges are broader than rules limited to specific commands. NOPASSWD means elevation can happen without re-entering a password, which may be acceptable in some automation cases but is generally a higher-risk pattern for interactive users. If there are multiple sudoers include files, all of them matter."
            print_guidance_block "WHY IT MATTERS:" "A user does not need UID 0 to control a server if sudo grants root access. This section is the practical privilege-escalation evidence and is essential when reviewing administrative access."
            ;;
        "5. Groups and Their Members")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section lists system groups and the members recorded for each group."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Groups are shared permission containers. Membership in a group may grant access to files, services, devices, applications, or administrative capabilities. Reviewers typically focus on sensitive groups first, such as admin, wheel, sudo, security, system, database, or application support groups."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Some groups will have no listed members because access may be managed in another source or because only primary group membership is used. Very large group memberships can indicate broad access distribution and should be compared to approved role definitions."
            print_guidance_block "WHY IT MATTERS:" "Group membership is a major part of access provisioning on Unix-like systems. This section helps connect user access to actual permission structures on the host."
            ;;
        "6. sulog Contents")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section shows the contents of the su log if the platform keeps one. It may record attempts to switch to another account, often root."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Each entry is usually evidence that one user attempted to become another user, commonly through the su command. Positive entries often mean a successful switch, while some platforms also log failed attempts or terminal details."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "A populated log can help show who elevated to root and when. \"not available\" may simply mean the host does not use sulog logging, stores it elsewhere, or does not have the file enabled."
            print_guidance_block "WHY IT MATTERS:" "This is useful operational evidence for tracing privileged activity, especially on systems where su is still used alongside or instead of sudo."
            ;;
        "7. SSH Configuration")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section highlights important Secure Shell daemon settings such as whether root can log in directly, whether passwords are allowed, whether key-based authentication is enabled, and whether empty passwords or X11 forwarding are allowed."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Think of this as the remote access policy for the server. Settings like \"PermitRootLogin no\" and \"PasswordAuthentication no\" generally indicate tighter remote-access control than allowing direct root password login."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Password-based SSH may still be acceptable in some environments, but it is generally less restrictive than key-based access. If direct root login is enabled, reviewers usually ask for compensating controls. \"not available\" may mean SSH is not installed, the daemon is managed differently, or the file is unreadable."
            print_guidance_block "WHY IT MATTERS:" "SSH is one of the most common administrative entry points into Unix and Linux servers. This section helps determine how securely administrators can reach the host from the network."
            ;;
#        "8. Installed Packages")
#            print_guidance_block "WHAT YOU ARE SEEING:" "This section lists installed software packages using the package manager available on the host."
#            print_guidance_block "HOW TO MAKE SENSE OF IT:" "This is software inventory evidence. Reviewers often look for security-relevant packages such as SSH, sudo, audit tools, backup agents, monitoring agents, database software, or packages that should not be present."
#            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "The format changes by platform. Linux package names often include version and architecture, AIX uses lslpp output, Solaris may show pkg information, and HP-UX may use swlist. Large inventories are normal; the key is identifying relevant packages and versions."
#            print_guidance_block "WHY IT MATTERS:" "Installed software affects security posture, patching scope, and compliance obligations. This section helps verify what software is actually present on the host."
#            ;;
        "9. Recent Login Activity")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section shows recent login or session activity from commands such as last, lastlogin, or who."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Each line is typically a record of a user session, showing who logged in, from where, when, and sometimes whether the session is still active. Look for administrator accounts, remote source systems, unusual times, and unexpected account usage."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "\"still logged in\" means the session is ongoing. Remote addresses can help identify whether access came from a jump host, workstation, or unknown source. Sparse or unavailable output can mean the log source is rotated, disabled, stored elsewhere, or not readable."
            print_guidance_block "WHY IT MATTERS:" "This section gives evidence of real usage, not just configured access. It helps answer whether powerful accounts are actually being used and from where."
            ;;
#        "10. World-Writable Files")
#            print_guidance_block "WHAT YOU ARE SEEING:" "This section lists files that any user on the system can modify because the world-writable permission bit is set."
#            print_guidance_block "HOW TO MAKE SENSE OF IT:" "World-writable means the file is writable by \"others,\" not just the owner or a trusted group. Some temporary or application-generated files may be expected, but sensitive system files should not appear here."
#            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "A few temporary files under locations like /tmp or /var/tmp may be normal depending on application behavior. World-writable files in system directories, application binaries, scripts, or configuration paths are more concerning because they can allow tampering or privilege escalation paths."
#            print_guidance_block "WHY IT MATTERS:" "Overly permissive file permissions are a common control weakness. This section helps identify places where a low-privilege user might be able to alter data, scripts, or executable content."
#            ;;
        "11. SetUID and SetGID Files")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section lists files with the setuid or setgid permission bits set. These special bits cause a program to run with the permissions of the file owner or group instead of the user launching it."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Some entries are expected and necessary, such as passwd or su, because those tools need controlled privileged behavior. The review focus is on unfamiliar binaries, custom scripts, or unexpected application files appearing in this list."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Standard operating system utilities are common. Custom setuid or setgid files deserve extra scrutiny because they can create privilege escalation paths. The more custom or obscure the file, the more important it is to confirm business need and secure ownership."
            print_guidance_block "WHY IT MATTERS:" "These files can intentionally or unintentionally grant elevated capability. This section is important for identifying privileged execution surfaces on the server."
            ;;
        "12. Scheduled Cron Jobs")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section shows scheduled tasks from system crontabs, cron include directories, and user-specific cron entries or spool files."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Read each line as \"something on this host runs automatically at a scheduled time.\" Focus on what account owns the job, what command or script runs, and whether the job executes with privileged rights such as root."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Root-owned cron jobs are not automatically a problem, but they should be expected, documented, and secured. User cron jobs can reveal automation, data movement, backups, or maintenance routines that may carry elevated access or business risk. \"not available\" may mean the user has no crontab, cron is stored elsewhere, or the script could not read it."
            print_guidance_block "WHY IT MATTERS:" "Scheduled jobs often perform critical actions without human interaction. This section helps identify automated privileged processes and hidden operational dependencies."
            ;;
        "13. Service Accounts")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section lists lower-UID accounts that are likely service, daemon, or system accounts rather than normal human user accounts."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "The script uses a platform-sensitive UID threshold to separate likely service accounts from regular users. The output shows the account name, UID, GID, home directory, and shell so you can tell whether the account looks interactive or non-interactive."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Accounts with shells like nologin, false, or restricted shells are often non-interactive service accounts. Accounts with full interactive shells may still be valid service IDs, but they deserve more scrutiny because they may be used for both services and human access. Different platforms use different UID numbering conventions, so use the printed threshold as context rather than as an absolute rule of truth."
            print_guidance_block "WHY IT MATTERS:" "Service accounts often own applications, scheduled jobs, or background processes. This section helps distinguish technical IDs from human users and supports reviews of non-person access."
            ;;
        "14. Account Status, SSH Keys, and Legacy Trust")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section adds lifecycle and remote-access evidence for user accounts, including account status indicators, password expiry details, authorized SSH keys, legacy trust files, shell timeout settings, and login banners."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Use this section to determine whether accounts are active or locked, whether passwords expire, whether users can log in with SSH keys, and whether older trust mechanisms like hosts.equiv or .rhosts still exist."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Locked or expired accounts are usually lower risk than active accounts. Authorized keys can be legitimate but should align to approved access. Legacy trust files are generally high-risk because they can bypass stronger authentication controls. Missing shell timeout or banner settings may indicate weaker session management or warning-banner enforcement."
            print_guidance_block "WHY IT MATTERS:" "This section supports account lifecycle, remote access, and user accountability testing. It helps auditors move beyond 'who exists' to 'how can they authenticate and is the account governed properly?'"
            ;;
        "15. Audit Logging and Log Forwarding")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section captures host auditing and logging configuration, including native audit settings, syslog or journal settings, remote forwarding indicators, and sudo command logging configuration."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Read this section to determine whether the operating system is configured to create, retain, and potentially forward logs that could support privileged activity reviews and investigations."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "If audit configuration files exist but services are not active, logging may be incomplete. Remote forwarding entries are generally positive because they support centralized monitoring. Missing sudo logfile or weak retention settings can reduce the usefulness of evidence after the fact."
            print_guidance_block "WHY IT MATTERS:" "SOX-relevant systems often depend on detective controls over privileged and sensitive activity. Logging that cannot be trusted, retained, or reviewed weakens those controls."
            ;;
        "16. Service and Startup Configuration")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section shows which services or subsystems are enabled, running, or configured to start automatically, along with startup-related configuration sources used by the platform."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Use this section to understand the operational baseline of the server. Compare running and enabled services to the intended purpose of the host and look for unexpected services or startup entries."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Application, monitoring, backup, and security agents may be expected. Unexpected services, old startup scripts, or unnecessary remote-access daemons can indicate configuration drift or unauthorized changes."
            print_guidance_block "WHY IT MATTERS:" "A SOX in-scope host should run only what is needed and should start those services in a controlled way. This section helps support secure configuration and change management review."
            ;;
        "17. Network Exposure and Firewall Configuration")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section shows network listeners, firewall rules where available, file-sharing exports, and references to older or less secure network services."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Treat this as the host's exposure profile. Listening ports show what is reachable on the network, while firewall output shows how access may be restricted or allowed."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "A small number of expected listeners is easier to justify than a wide open footprint. Legacy services such as telnet, rsh, rexec, or insecure FTP are usually red flags. Exported shares may be valid but should be tightly controlled."
            print_guidance_block "WHY IT MATTERS:" "Even if user accounts are well controlled, an exposed or weakly protected service can undermine the control environment. This section supports review of network-facing access paths."
            ;;
        "18. Patch, Update, and Change Indicators")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section captures host-level indicators of operating system patch state, package update history, reboot timing, and repository or patch-management configuration files where available."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Use this section as technical evidence about the server's maintenance state. It does not prove approvals or testing, but it can show whether updates appear to be occurring and what patch tooling is in use."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Recent patch history may indicate active maintenance. Long gaps, obsolete kernel levels, or missing patch-management evidence can suggest a weak change-management or vulnerability-management posture. Different Unix platforms expose this evidence very differently."
            print_guidance_block "WHY IT MATTERS:" "SOX change controls are not just about application changes. Operating system patches and infrastructure changes can also affect financially relevant systems and should be governed appropriately."
            ;;
        "19. Backup, Capacity, and Operational Indicators")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section gathers practical operations evidence such as filesystem capacity, possible backup-related processes or configuration files, log rotation settings, boot history, and monitoring-agent indicators."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Read this as a set of operational clues about whether the host is being maintained, monitored, and backed up. It does not prove restore testing, but it can reveal whether backup and support tooling appears to exist."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "High filesystem usage can threaten logging, batch jobs, and application processing. Backup or monitoring agents may be expected on production systems. Their absence is not always a failure, but it should align with the documented operating model."
            print_guidance_block "WHY IT MATTERS:" "Operations controls support availability, recoverability, and timely detection of issues. Those are often important supporting controls around financial reporting systems."
            ;;
        "20. Time Synchronization")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section captures time-sync configuration and status from services such as chrony, NTP, or platform-native time daemons."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Time synchronization keeps logs, jobs, alerts, and transactions aligned across systems. Look for both configuration files and live status output where available."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Different platforms use different daemons, but some kind of controlled time source is usually expected. Missing or unhealthy time-sync evidence can weaken investigations and make event correlation unreliable."
            print_guidance_block "WHY IT MATTERS:" "Accurate time is foundational for audit logging, incident review, and reconciling system events to business activity."
            ;;
        "21. Additional Scheduled Tasks and Timers")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section expands beyond classic cron to capture other schedulers and timed execution paths such as at jobs, anacron, systemd timers, and related log files where available."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Use this section to find jobs that may not appear in normal crontabs. Review the owner, schedule, and command or unit being executed."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Modern Linux systems may use systemd timers rather than cron. One-time at jobs can be legitimate but can also be a less visible way to execute administrative changes. Missing logs may limit reviewability."
            print_guidance_block "WHY IT MATTERS:" "Unattended tasks can make changes, move data, or run privileged commands. A complete audit view should include more than just cron."
            ;;
        "22. Critical File Integrity and Sensitive File Permissions")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section shows metadata and checksums for selected sensitive operating system files, along with kernel or boot-related configuration files where available."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Use ownership, permissions, timestamps, and checksums to understand whether critical files appear tightly controlled and to support later change comparisons if needed."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "Strict permissions on files like passwd, shadow, sudoers, SSH configuration, audit settings, and bootloader files are generally expected. Unexpected owners, broad permissions, or surprising modification times can warrant follow-up."
            print_guidance_block "WHY IT MATTERS:" "Sensitive operating system files govern authentication, privilege, startup behavior, and auditing. Their integrity is directly relevant to secure configuration and change control."
            ;;
        "Execution Summary")
            print_guidance_block "WHAT YOU ARE SEEING:" "This final section summarizes whether the script completed and restates its operating behavior."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Use this as a quick integrity check for the evidence package. It tells you whether the script believes it completed, where it wrote the local collection directory, whether it created an archive, and whether it changed source configuration."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "A completed status supports the reliability of the collected output, although reviewers should still look for \"not available\" lines in earlier sections. If archive creation failed, the copied directory may still exist. If collection-directory creation failed, the report may still print but source-file packaging will be incomplete."
            print_guidance_block "WHY IT MATTERS:" "Audit collection should be transparent about where evidence was written and whether packaging succeeded. This section makes those collection characteristics explicit at the end of the report."
            ;;
    esac
}

section_with_guidance() {
    printf '\n%s\n' "$SECTION_SEPARATOR"
    printf '%s\n\n' "$1"
    print_section_guidance "$1"
    printf '%s\n\n' "$SECTION_SEPARATOR"
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

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

prepare_collection_directory() {
    if rm -rf "$COLLECTION_FILES_DIRECTORY" 2>/dev/null && mkdir -p "$COLLECTION_FILES_DIRECTORY" 2>/dev/null; then
        rm -f "$REPORT_FILE" "$MANIFEST_FILE" 2>/dev/null || :
        : > "$MANIFEST_FILE"
        COLLECTION_STATUS="ready"
    else
        COLLECTION_STATUS="failed to create collection directory"
    fi
}

record_copied_file() {
    file_path=$1

    if [ "$COLLECTION_STATUS" = "ready" ] && [ -f "$MANIFEST_FILE" ]; then
        if ! grep -F -x "$file_path" "$MANIFEST_FILE" >/dev/null 2>&1; then
            printf '%s\n' "$file_path" >> "$MANIFEST_FILE"
        fi
    fi
}

copy_file_to_collection() {
    file_path=$1

    if [ -r "$file_path" ] && [ -f "$file_path" ] && [ "$COLLECTION_STATUS" = "ready" ]; then
        target_path=$COLLECTION_FILES_DIRECTORY$file_path
        target_directory=$(dirname "$target_path" 2>/dev/null || echo "$COLLECTION_FILES_DIRECTORY")

        if mkdir -p "$target_directory" 2>/dev/null; then
            if cp -p "$file_path" "$target_path" 2>/dev/null || cp "$file_path" "$target_path" 2>/dev/null; then
                record_copied_file "$file_path"
            fi
        fi
    fi
}

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

        if command_exists compress; then
            if tar -cf "$archive_base.tar" -C "$WORKING_DIRECTORY" SOX-ITGC-AUDIT-LINUX-UNIX 2>/dev/null && compress -f "$archive_base.tar" 2>/dev/null; then
                ARCHIVE_FILE=$archive_base.tar.Z
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

    if command_exists zip; then
        if zip -rq "$archive_base.zip" SOX-ITGC-AUDIT-LINUX-UNIX 2>/dev/null; then
            ARCHIVE_FILE=$archive_base.zip
            ARCHIVE_STATUS="created"
            return
        fi
    fi

    ARCHIVE_STATUS="failed"
}

grep_extended() {
    if printf 'x\n' | grep -E 'x' >/dev/null 2>&1; then
        grep -E "$@"
    elif command_exists egrep; then
        egrep "$@"
    else
        return 1
    fi
}

file_readable() {
    if [ -r "$1" ]; then
        copy_file_to_collection "$1"
        return 0
    fi

    return 1
}

directory_exists() {
    [ -d "$1" ]
}

path_exists() {
    [ -e "$1" ]
}

no_entries_found() {
    printf 'no entries found\n'
}

print_command_output_or_not_available() {
    command_name=$1
    shift

    if command_exists "$command_name"; then
        if "$command_name" "$@" 2>/dev/null; then
            :
        else
            not_available
        fi
    else
        not_available
    fi
}

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

print_directory_listing_or_not_available() {
    directory_path=$1

    if directory_exists "$directory_path"; then
        if ls -la "$directory_path" 2>/dev/null; then
            :
        else
            not_available
        fi
    else
        not_available
    fi
}

print_matching_processes() {
    pattern=$1

    if command_exists ps; then
        if ps -ef 2>/dev/null | awk -v pattern="$pattern" '
            $0 ~ pattern && $0 !~ /awk -v pattern/ {
                print
                found = 1
            }
            END { if (!found) exit 1 }
        '; then
            :
        else
            no_entries_found
        fi
    else
        not_available
    fi
}

print_passwd_users() {
    if file_readable /etc/passwd; then
        awk -F: '{print $1}' /etc/passwd 2>/dev/null
    fi
}

print_matching_lines_from_files() {
    pattern=$1
    shift
    found_match=no

    for file_path in "$@"; do
        if file_readable "$file_path"; then
            if grep_extended "$pattern" "$file_path" 2>/dev/null; then
                found_match=yes
            fi
        fi
    done

    [ "$found_match" = yes ]
}

print_noncomment_or_not_available() {
    file_path=$1

    if file_readable "$file_path"; then
        if awk '
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*$/ { next }
            { print; found = 1 }
            END { if (!found) exit 1 }
        ' "$file_path" 2>/dev/null; then
            :
        else
            no_entries_found
        fi
    else
        not_available
    fi
}

print_directory_file_contents() {
    directory_path=$1
    found_file=no

    if directory_exists "$directory_path"; then
        for file_path in "$directory_path"/*; do
            if [ -f "$file_path" ]; then
                found_file=yes
                print_file_with_header "$file_path"
            fi
        done
    fi

    [ "$found_file" = yes ]
}

print_matching_lines_in_directory() {
    pattern=$1
    directory_path=$2
    found_match=no

    if directory_exists "$directory_path"; then
        for file_path in "$directory_path"/*; do
            if [ -f "$file_path" ]; then
                if grep_extended "$pattern" "$file_path" 2>/dev/null; then
                    found_match=yes
                fi
            fi
        done
    fi

    [ "$found_match" = yes ]
}

print_first_available_file() {
    for file_path in "$@"; do
        if file_readable "$file_path"; then
            cat "$file_path"
            return 0
        fi
    done

    return 1
}

service_uid_cutoff() {
    if file_readable /etc/login.defs; then
        sys_uid_min=$(awk '
            $1 == "SYS_UID_MIN" {
                print $2
                exit
            }
        ' /etc/login.defs 2>/dev/null)
        if [ -n "$sys_uid_min" ]; then
            printf '%s\n' "$sys_uid_min"
            return 0
        fi
    fi

    case "$OS_NAME" in
        AIX|SunOS|HP-UX)
            printf '100\n'
            ;;
        Darwin|FreeBSD|OpenBSD|NetBSD)
            printf '500\n'
            ;;
        *)
            printf '1000\n'
            ;;
    esac
}

print_file_with_header() {
    file_path=$1

    printf 'File: %s\n' "$file_path"
    if file_readable "$file_path"; then
        cat "$file_path"
    else
        not_available
    fi
    blank_line
}

print_platform_details() {
    subsection "Operating System Details:"
    printf 'Platform: %s\n' "$OS_NAME"

    case "$OS_NAME" in
        Linux)
            printf 'Platform Family: Linux\n'
            ;;
        AIX)
            printf 'Platform Family: AIX\n'
            ;;
        SunOS)
            printf 'Platform Family: Solaris/Illumos\n'
            ;;
        HP-UX)
            printf 'Platform Family: HP-UX\n'
            ;;
        Darwin)
            printf 'Platform Family: Darwin/macOS\n'
            ;;
        FreeBSD|OpenBSD|NetBSD)
            printf 'Platform Family: BSD\n'
            ;;
        *)
            printf 'Platform Family: Other/Unknown Unix\n'
            ;;
    esac

    if command_exists uname; then
        if uname -r >/dev/null 2>&1; then
            printf 'Kernel Release: %s\n' "$(uname -r 2>/dev/null)"
        else
            printf 'Kernel Release: '
            not_available
        fi
        if uname -v >/dev/null 2>&1; then
            printf 'Kernel Version: %s\n' "$(uname -v 2>/dev/null)"
        else
            printf 'Kernel Version: '
            not_available
        fi
        if uname -m >/dev/null 2>&1; then
            printf 'Hardware Platform: %s\n' "$(uname -m 2>/dev/null)"
        else
            printf 'Hardware Platform: '
            not_available
        fi
    else
        printf 'uname command: '
        not_available
    fi
}

print_group_membership_summary() {
    found_group=no

    if command_exists getent; then
        if getent group wheel >/dev/null 2>&1; then
            getent group wheel | awk -F: '{print "- wheel: " $4}'
            found_group=yes
        else
            printf '%s\n' '- wheel: not available'
        fi
        if getent group sudo >/dev/null 2>&1; then
            getent group sudo | awk -F: '{print "- sudo: " $4}'
            found_group=yes
        else
            printf '%s\n' '- sudo: not available'
        fi
    elif file_readable /etc/group; then
        if awk -F: '
            $1 == "wheel" || $1 == "sudo" {
                print "- " $1 ": " $4
                found = 1
            }
            END { if (!found) exit 1 }
        ' /etc/group 2>/dev/null; then
            found_group=yes
        fi
    else
        not_available
        return
    fi

    if [ "$found_group" = no ]; then
        no_entries_found
    fi
}

print_all_groups() {
    if command_exists getent; then
        getent group | awk -F: '{print $1 ": " $4}'
    elif file_readable /etc/group; then
        awk -F: '{print $1 ": " $4}' /etc/group
    else
        not_available
    fi
}

print_auth_summary() {
    subsection "Password Aging Summary:"
    if print_matching_lines_from_files '^(PASS_MIN_LEN|PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)[[:space:]]+' /etc/login.defs; then
        :
    elif print_matching_lines_from_files '^(MINWEEKS|MAXWEEKS|WARNWEEKS|PASSLENGTH|MINLENGTH|PASSWORD_MIN_LENGTH|PASSWORD_MAXDAYS|PASSWORD_MINDAYS|PASSWORD_WARNDAYS)[[:space:]]*=' /etc/default/passwd /etc/default/login /etc/default/security /etc/security/policy.conf; then
        :
    elif print_matching_lines_from_files '(^default:|^[[:space:]]*(minage|maxage|pwdwarntime)[[:space:]]*=)' /etc/security/user; then
        :
    else
        not_available
    fi
    blank_line

    subsection "Password Quality Summary:"
    if print_matching_lines_from_files '^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)[[:space:]]*=' /etc/security/pwquality.conf; then
        :
    elif print_matching_lines_from_files 'pam_cracklib\.so|pam_pwquality\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.conf; then
        :
    elif print_matching_lines_from_files '(^default:|^[[:space:]]*(minlen|minother|minalpha|maxrepeats|mindiff|pwdchecks)[[:space:]]*=)' /etc/security/user; then
        :
    elif print_matching_lines_from_files '^(MINLENGTH|MINDIFF|MAXREPEATS|PASSLENGTH|PASSWORD_MIN_LENGTH)[[:space:]]*=' /etc/default/passwd /etc/default/security; then
        :
    else
        not_available
    fi
    blank_line

    subsection "Account Lockout Summary:"
    if print_matching_lines_in_directory 'pam_tally2\.so|pam_faillock\.so' /etc/pam.d; then
        :
    elif print_matching_lines_from_files 'pam_tally2\.so|pam_faillock\.so' /etc/pam.conf; then
        :
    elif print_matching_lines_from_files '(^default:|^[[:space:]]*(loginretries|account_locked)[[:space:]]*=)' /etc/security/user; then
        :
    elif print_matching_lines_from_files '^(RETRIES|SYSLOG_FAILED_LOGINS|LOCK_AFTER_RETRIES)[[:space:]]*=' /etc/default/login /etc/security/policy.conf; then
        :
    else
        not_available
    fi
}

print_auth_full_content() {
    subsection "Full File Content: /etc/login.defs"
    print_file_with_header /etc/login.defs

    subsection "Full File Content: /etc/security/pwquality.conf"
    print_file_with_header /etc/security/pwquality.conf

    subsection "Full File Content: /etc/pam.d/system-auth"
    print_file_with_header /etc/pam.d/system-auth

    subsection "Full File Content: /etc/pam.d/password-auth"
    print_file_with_header /etc/pam.d/password-auth

    subsection "Full File Content: /etc/default/passwd"
    print_file_with_header /etc/default/passwd

    subsection "Full File Content: /etc/default/login"
    print_file_with_header /etc/default/login

    subsection "Full File Content: /etc/default/security"
    print_file_with_header /etc/default/security

    subsection "Full File Content: /etc/security/policy.conf"
    print_file_with_header /etc/security/policy.conf

    subsection "Full File Content: /etc/security/user"
    print_file_with_header /etc/security/user

    subsection "Full File Content: /etc/pam.conf"
    print_file_with_header /etc/pam.conf
}

print_authentication_summary() {
    subsection "Authentication Summary:"

    printf 'Name service passwd/auth references: '
    if print_matching_lines_from_files '^(passwd|group|hosts|services):.*(ldap|sss|winbind|nis|compat)' /etc/nsswitch.conf; then
        :
    elif print_matching_lines_from_files '=(LDAP|DCE|NIS|NIS_4)' /etc/netsvc.conf; then
        :
    else
        not_available
    fi

    printf 'SSSD configuration present: '
    if file_readable /etc/sssd/sssd.conf; then
        printf 'yes\n'
    else
        printf 'no\n'
    fi

    subsection "PAM Authentication Module References:"
    if print_matching_lines_in_directory 'pam_ldap\.so|pam_sss\.so|pam_winbind\.so' /etc/pam.d; then
        :
    elif print_matching_lines_from_files 'pam_ldap\.so|pam_sss\.so|pam_winbind\.so' /etc/pam.conf; then
        :
    elif print_matching_lines_from_files '(^default:|^[[:space:]]*SYSTEM[[:space:]]*=)' /etc/security/user; then
        :
    else
        not_available
    fi
}

print_authentication_full_content() {
    subsection "Full File Content: /etc/nsswitch.conf"
    print_file_with_header /etc/nsswitch.conf

    subsection "Full File Content: /etc/sssd/sssd.conf"
    print_file_with_header /etc/sssd/sssd.conf

    subsection "Full File Content: /etc/netsvc.conf"
    print_file_with_header /etc/netsvc.conf

    subsection "Full File Content: /etc/pam.conf"
    print_file_with_header /etc/pam.conf
}

print_sudo_summary() {
    found_sudoers=no

    subsection "Summary: Active Sudoers Rules"
    for file_path in /etc/sudoers /usr/local/etc/sudoers /opt/csw/etc/sudoers /etc/opt/csw/sudoers; do
        if file_readable "$file_path"; then
            printf 'Active entries from %s\n' "$file_path"
            print_noncomment_or_not_available "$file_path"
            blank_line
            found_sudoers=yes
        fi
    done

    for directory_path in /etc/sudoers.d /usr/local/etc/sudoers.d /opt/csw/etc/sudoers.d /etc/opt/csw/sudoers.d; do
        if directory_exists "$directory_path"; then
            for file_path in "$directory_path"/*; do
                if [ -f "$file_path" ]; then
                    printf 'Active entries from %s\n' "$file_path"
                    print_noncomment_or_not_available "$file_path"
                    blank_line
                    found_sudoers=yes
                fi
            done
        fi
    done

    if [ "$found_sudoers" = no ]; then
        not_available
    fi
}

print_sudo_full_content() {
    found_sudoers=no

    for file_path in /etc/sudoers /usr/local/etc/sudoers /opt/csw/etc/sudoers /etc/opt/csw/sudoers; do
        if file_readable "$file_path"; then
            subsection "Full File Content: $file_path"
            print_file_with_header "$file_path"
            found_sudoers=yes
        fi
    done

    for directory_path in /etc/sudoers.d /usr/local/etc/sudoers.d /opt/csw/etc/sudoers.d /etc/opt/csw/sudoers.d; do
        if directory_exists "$directory_path"; then
            subsection "Full File Content: $directory_path"
            if print_directory_file_contents "$directory_path"; then
                found_sudoers=yes
            else
                not_available
                blank_line
            fi
        fi
    done

    if [ "$found_sudoers" = no ]; then
        subsection "Full File Content: sudoers configuration"
        not_available
        blank_line
    fi
}

print_ssh_summary() {
    subsection "Summary: Relevant SSH Settings"
    if print_matching_lines_from_files '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding|Protocol)[[:space:]]+' /etc/ssh/sshd_config /usr/local/etc/sshd_config; then
        :
    else
        not_available
    fi
}

print_sshd_full_content() {
    subsection "Full File Content: /etc/ssh/sshd_config"
    print_file_with_header /etc/ssh/sshd_config

    subsection "Full File Content: /usr/local/etc/sshd_config"
    print_file_with_header /usr/local/etc/sshd_config
}

print_sulog_content() {
    if print_first_available_file /var/log/sulog /var/adm/sulog; then
        :
    else
        not_available
    fi
}

#print_package_inventory() {
#    if command_exists rpm; then
#        rpm -qa 2>/dev/null || not_available
#    elif command_exists dpkg; then
#        dpkg -l 2>/dev/null || not_available
#    elif command_exists pkginfo; then
#        pkginfo 2>/dev/null || not_available
#    elif command_exists swlist; then
#        swlist 2>/dev/null || not_available
#    elif command_exists lslpp; then
#        lslpp -L 2>/dev/null || not_available
#    elif command_exists pkg; then
#        pkg info 2>/dev/null || not_available
#    else
#        not_available
#    fi
#}

print_recent_login_activity() {
    if command_exists last; then
        if last 2>/dev/null; then
            :
        else
            not_available
        fi
    elif command_exists lastlogin; then
        if lastlogin 2>/dev/null; then
            :
        else
            not_available
        fi
    elif command_exists who; then
        if who -a 2>/dev/null; then
            :
        else
            not_available
        fi
    else
        not_available
    fi
}

#print_world_writable_files() {
#    if command_exists find; then
#        find / -type f -perm -0002 -print 2>/dev/null || find / -type f -perm -2 -print 2>/dev/null || not_available
#    else
#        not_available
#    fi
#}

print_setuid_setgid_files() {
    if command_exists find; then
        subsection "SetUID Files:"
        find / -type f -perm -4000 -print 2>/dev/null || find / -type f -perm -04000 -print 2>/dev/null || not_available
        blank_line

        subsection "SetGID Files:"
        find / -type f -perm -2000 -print 2>/dev/null || find / -type f -perm -02000 -print 2>/dev/null || not_available
    else
        not_available
    fi
}

print_user_cron_from_spool() {
    user_name=$1

    if print_first_available_file \
        /var/spool/cron/crontabs/"$user_name" \
        /var/spool/cron/"$user_name" \
        /usr/spool/cron/crontabs/"$user_name" \
        /usr/spool/cron/"$user_name"; then
        return 0
    fi

    return 1
}

print_cron_content() {
    subsection "System-wide Cron Jobs: /etc/crontab"
    print_file_with_header /etc/crontab

    subsection "Cron Jobs in /etc/cron.d"
    if print_directory_file_contents /etc/cron.d; then
        :
    else
        not_available
        blank_line
    fi

    subsection "User Cron Jobs"
    if file_readable /etc/passwd; then
        while IFS=: read -r user _rest; do
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

print_service_accounts() {
    uid_cutoff=$(service_uid_cutoff)

    if file_readable /etc/passwd; then
        printf 'Service account UID threshold: %s\n' "$uid_cutoff"
        if awk -F: -v cutoff="$uid_cutoff" '
            ($3 < cutoff) {
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

print_account_status_summary() {
    subsection "Account Status Summary:"
    if file_readable /etc/passwd; then
        found_output=no
        if command_exists passwd; then
            if passwd -S root >/dev/null 2>&1; then
                while IFS=: read -r user _rest; do
                    if passwd -S "$user" 2>/dev/null; then
                        found_output=yes
                    fi
                done < /etc/passwd
            elif passwd -s root >/dev/null 2>&1; then
                while IFS=: read -r user _rest; do
                    if passwd -s "$user" 2>/dev/null; then
                        found_output=yes
                    fi
                done < /etc/passwd
            fi
        fi

        if [ "$found_output" = no ] && command_exists lsuser; then
            if lsuser -a account_locked expires login shell ALL 2>/dev/null; then
                found_output=yes
            fi
        fi

        if [ "$found_output" = no ]; then
            not_available
        fi
    else
        not_available
    fi
}

print_password_expiry_details() {
    subsection "Password Expiry Details by Account:"
    if file_readable /etc/passwd; then
        found_output=no
        if command_exists chage; then
            while IFS=: read -r user _rest; do
                printf 'User: %s\n' "$user"
                if chage -l "$user" 2>/dev/null; then
                    found_output=yes
                else
                    not_available
                fi
                blank_line
            done < /etc/passwd
        elif command_exists lsuser; then
            if lsuser -a maxage minage pwdwarntime expires account_locked ALL 2>/dev/null; then
                found_output=yes
            fi
        fi

        if [ "$found_output" = no ] && ! command_exists chage && ! command_exists lsuser; then
            not_available
        fi
    else
        not_available
    fi
}

print_authorized_keys_content() {
    subsection "Authorized SSH Keys:"
    found_keys=no

    if file_readable /etc/passwd; then
        while IFS=: read -r user _password _uid _gid _gecos home_dir shell_path; do
            if [ -n "$home_dir" ] && [ "$home_dir" != "/" ]; then
                authorized_keys_path=$home_dir/.ssh/authorized_keys
                if file_readable "$authorized_keys_path"; then
                    printf 'User: %s\n' "$user"
                    print_file_with_header "$authorized_keys_path"
                    found_keys=yes
                fi
            fi
        done < /etc/passwd
    fi

    if [ "$found_keys" = no ]; then
        no_entries_found
    fi
}

print_legacy_trust_content() {
    subsection "Legacy Trust Files:"
    found_trust_file=no

    if file_readable /etc/hosts.equiv; then
        print_file_with_header /etc/hosts.equiv
        found_trust_file=yes
    fi

    if file_readable /etc/shosts.equiv; then
        print_file_with_header /etc/shosts.equiv
        found_trust_file=yes
    fi

    if file_readable /etc/passwd; then
        while IFS=: read -r user _password _uid _gid _gecos home_dir shell_path; do
            if [ -n "$home_dir" ] && [ "$home_dir" != "/" ]; then
                for trust_file in "$home_dir"/.rhosts "$home_dir"/.shosts; do
                    if file_readable "$trust_file"; then
                        printf 'User: %s\n' "$user"
                        print_file_with_header "$trust_file"
                        found_trust_file=yes
                    fi
                done
            fi
        done < /etc/passwd
    fi

    if [ "$found_trust_file" = no ]; then
        no_entries_found
    fi
}

print_shell_timeout_and_banner_summary() {
    subsection "Shell Timeout Settings:"
    if print_matching_lines_from_files '(^[[:space:]]*TMOUT=|^[[:space:]]*readonly[[:space:]]+TMOUT|^[[:space:]]*export[[:space:]]+TMOUT|^[[:space:]]*autologout[[:space:]]*=)' /etc/profile /etc/bashrc /etc/ksh.kshrc /etc/csh.cshrc /etc/profile.d/*.sh /etc/security/login.cfg; then
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

print_audit_logging_summary() {
    subsection "Native Audit Status:"
    found_output=no

    if command_exists auditctl; then
        if auditctl -s 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists audit; then
        if audit query 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists auditconfig; then
        if auditconfig -getpolicy 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ]; then
        not_available
    fi
    blank_line

    subsection "Audit and Log Configuration Summary:"
    if print_matching_lines_from_files '^[[:space:]]*(max_log_file|max_log_file_action|num_logs|space_left_action|admin_space_left_action|disk_full_action|Storage|ForwardToSyslog|Compress|SystemMaxUse|SystemKeepFree)[[:space:]]*[= ]' /etc/audit/auditd.conf /etc/systemd/journald.conf /etc/security/audit/config /etc/security/audit_control; then
        :
    else
        not_available
    fi
    blank_line

    subsection "Remote Log Forwarding Indicators:"
    if print_matching_lines_from_files '(^[^#].*@@?[A-Za-z0-9._-]+|action\(.*omfwd|destination.*(tcp|udp)|forward_to|loghost)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/conf.d/*.conf /etc/systemd/journald.conf; then
        :
    else
        not_available
    fi
    blank_line

    subsection "Sudo Logging Indicators:"
    if print_matching_lines_from_files '(logfile=|log_input|log_output|iolog_dir)' /etc/sudoers /etc/sudoers.d/* /usr/local/etc/sudoers /usr/local/etc/sudoers.d/*; then
        :
    else
        not_available
    fi
}

print_audit_logging_full_content() {
    subsection "Full File Content: /etc/audit/auditd.conf"
    print_file_with_header /etc/audit/auditd.conf

    subsection "Full File Content: /etc/audit/audit.rules"
    print_file_with_header /etc/audit/audit.rules

    subsection "Full File Content: /etc/audit/rules.d"
    if print_directory_file_contents /etc/audit/rules.d; then
        :
    else
        not_available
        blank_line
    fi

    subsection "Full File Content: /etc/systemd/journald.conf"
    print_file_with_header /etc/systemd/journald.conf

    subsection "Full File Content: /etc/rsyslog.conf"
    print_file_with_header /etc/rsyslog.conf

    subsection "Full File Content: /etc/rsyslog.d"
    if print_directory_file_contents /etc/rsyslog.d; then
        :
    else
        not_available
        blank_line
    fi

    subsection "Full File Content: /etc/syslog.conf"
    print_file_with_header /etc/syslog.conf

    subsection "Full File Content: /etc/syslog-ng/syslog-ng.conf"
    print_file_with_header /etc/syslog-ng/syslog-ng.conf

    subsection "Full File Content: /etc/syslog-ng/conf.d"
    if print_directory_file_contents /etc/syslog-ng/conf.d; then
        :
    else
        not_available
        blank_line
    fi

    subsection "Full File Content: /etc/security/audit/config"
    print_file_with_header /etc/security/audit/config

    subsection "Full File Content: /etc/security/audit_control"
    print_file_with_header /etc/security/audit_control
}

print_service_startup_summary() {
    subsection "Enabled or Startup Services:"
    found_output=no

    if command_exists systemctl; then
        if systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists chkconfig; then
        if chkconfig --list 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists svcs; then
        if svcs -a 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists lssrc; then
        if lssrc -a 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists service; then
        if service --status-all 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ]; then
        not_available
    fi
    blank_line

    subsection "Running Services and Agent Processes:"
    print_matching_processes 'splunkd|qualys|falcon-sensor|tanium|datadog-agent|zabbix_agentd|nrpe|newrelic|telegraf|ossec|auditd|rsyslogd|syslog-ng|sshd'
    blank_line

    subsection "Startup Configuration Files:"
    print_file_with_header /etc/inittab
    print_file_with_header /etc/rc.config
    print_file_with_header /etc/default/grub

    subsection "Startup Directories:"
    if print_directory_listing_or_not_available /etc/init.d; then
        :
    fi
    blank_line
    if print_directory_listing_or_not_available /etc/rc.d; then
        :
    fi
    blank_line
    if print_directory_listing_or_not_available /etc/rc2.d; then
        :
    fi
    blank_line
    if print_directory_listing_or_not_available /etc/rc3.d; then
        :
    fi
}

print_network_exposure_summary() {
    subsection "Listening Ports and Services:"
    found_output=no

    if command_exists ss; then
        if ss -lntup 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists netstat; then
        if netstat -an 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists lsof; then
        if lsof -i -n -P 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ]; then
        not_available
    fi
    blank_line

    subsection "Firewall Configuration:"
    found_output=no

    if command_exists firewall-cmd; then
        if firewall-cmd --list-all 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists nft; then
        if nft list ruleset 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists iptables; then
        if iptables -S 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists pfctl; then
        if pfctl -sr 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists ipfstat; then
        if ipfstat -io 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ]; then
        not_available
    fi
    blank_line

    subsection "Network Share and Legacy Service Configuration:"
    print_file_with_header /etc/exports
    print_file_with_header /etc/dfs/dfstab
    print_file_with_header /etc/inet/inetd.conf

    subsection "Legacy Insecure Service References:"
    if print_matching_lines_from_files '(telnet|rlogin|rexec|rsh|ftp)' /etc/inetd.conf /etc/inet/inetd.conf /etc/xinetd.d/* /etc/services; then
        :
    else
        not_available
    fi
}

print_patch_update_summary() {
    subsection "Operating System Patch or Maintenance Level:"
    found_output=no

    if command_exists oslevel; then
        if oslevel -s 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists swlist; then
        if swlist -l patch 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists pkg; then
        if pkg history 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists rpm; then
        if rpm -qa --last 2>/dev/null | sed -n '1,20p'; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists dpkg; then
        if file_readable /var/log/dpkg.log; then
            if awk 'NR <= 20 { print }' /var/log/dpkg.log 2>/dev/null; then
                found_output=yes
            fi
        fi
    fi

    if [ "$found_output" = no ]; then
        not_available
    fi
    blank_line

    subsection "Package Manager History and Update Indicators:"
    found_output=no

    if command_exists dnf; then
        if dnf history list 2>/dev/null | sed -n '1,20p'; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists yum; then
        if yum history list 2>/dev/null | sed -n '1,20p'; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists instfix; then
        if instfix -i 2>/dev/null | sed -n '1,20p'; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists pkg; then
        if pkg history 2>/dev/null | sed -n '1,20p'; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ]; then
        not_available
    fi
    blank_line

    subsection "Repository and Patch Configuration Files:"
    print_file_with_header /etc/yum.conf
    print_file_with_header /etc/dnf/dnf.conf
    print_file_with_header /etc/apt/sources.list

    subsection "Repository Configuration Directories:"
    if print_directory_file_contents /etc/yum.repos.d; then
        :
    else
        not_available
        blank_line
    fi
    if print_directory_file_contents /etc/apt/sources.list.d; then
        :
    else
        not_available
        blank_line
    fi
}

print_backup_operational_summary() {
    subsection "Filesystem Capacity:"
    if command_exists df; then
        if df -k 2>/dev/null; then
            :
        else
            not_available
        fi
    else
        not_available
    fi
    blank_line

    subsection "Filesystem Inode Capacity:"
    if command_exists df; then
        if df -i 2>/dev/null; then
            :
        else
            not_available
        fi
    else
        not_available
    fi
    blank_line

    subsection "Backup and Recovery Process Indicators:"
    print_matching_processes 'netbackup|bpbkar|bpbrm|bpjava|tsm|dsmcad|dsmc|veeam|commvault|cvd|bacula|rubrik|cohesity|avamar|nsrexecd|savefs|backup'
    blank_line

    subsection "Monitoring Agent Indicators:"
    print_matching_processes 'splunkd|qualys|falcon-sensor|tanium|datadog-agent|zabbix_agentd|nrpe|newrelic|telegraf|ossec|auditd'
    blank_line

    subsection "Backup and Log Rotation Configuration Files:"
    print_file_with_header /etc/logrotate.conf
    print_file_with_header /etc/newsyslog.conf
    print_file_with_header /usr/openv/netbackup/bp.conf
    print_file_with_header /opt/tivoli/tsm/client/ba/bin/dsm.opt
    print_file_with_header /etc/bacula/bacula-dir.conf
    print_file_with_header /etc/nsr/nsrla.res

    subsection "Backup and Log Rotation Directories:"
    if print_directory_file_contents /etc/logrotate.d; then
        :
    else
        not_available
        blank_line
    fi

    subsection "Boot and Uptime Indicators:"
    if command_exists who; then
        if who -b 2>/dev/null; then
            :
        else
            not_available
        fi
    else
        not_available
    fi
    blank_line

    if command_exists uptime; then
        if uptime 2>/dev/null; then
            :
        else
            not_available
        fi
    else
        not_available
    fi
}

print_time_sync_summary() {
    subsection "Time Synchronization Status:"
    found_output=no

    if command_exists timedatectl; then
        if timedatectl status 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists chronyc; then
        if chronyc tracking 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists ntpq; then
        if ntpq -p 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists ntpstat; then
        if ntpstat 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ] && command_exists lssrc; then
        if lssrc -s xntpd 2>/dev/null; then
            found_output=yes
        fi
    fi

    if [ "$found_output" = no ]; then
        not_available
    fi
    blank_line

    subsection "Time Synchronization Configuration Files:"
    print_file_with_header /etc/chrony.conf
    print_file_with_header /etc/chrony/chrony.conf
    print_file_with_header /etc/ntp.conf
    print_file_with_header /etc/inet/ntp.conf
}

print_additional_scheduler_content() {
    subsection "Systemd Timers:"
    if command_exists systemctl; then
        if systemctl list-timers --all --no-pager 2>/dev/null; then
            :
        else
            not_available
        fi
    else
        not_available
    fi
    blank_line

    subsection "At Jobs:"
    if command_exists atq; then
        if atq 2>/dev/null; then
            :
        else
            no_entries_found
        fi
    elif command_exists at; then
        if at -l 2>/dev/null; then
            :
        else
            no_entries_found
        fi
    else
        not_available
    fi
    blank_line

    subsection "Anacron and Additional Scheduler Files:"
    print_file_with_header /etc/anacrontab
    if print_directory_listing_or_not_available /var/spool/anacron; then
        :
    fi
    blank_line
    print_file_with_header /var/log/cron
    print_file_with_header /var/log/cron.log
}

print_critical_file_integrity() {
    subsection "Sensitive File Metadata and Checksums:"
    for sensitive_path in \
        /etc/passwd \
        /etc/shadow \
        /etc/group \
        /etc/sudoers \
        /etc/ssh/sshd_config \
        /etc/pam.conf \
        /etc/login.defs \
        /etc/security/user \
        /etc/security/audit/config \
        /etc/security/audit_control \
        /etc/audit/auditd.conf \
        /etc/audit/audit.rules \
        /etc/syslog.conf \
        /etc/rsyslog.conf \
        /etc/ntp.conf \
        /etc/chrony.conf \
        /etc/default/grub \
        /boot/grub2/grub.cfg \
        /boot/grub/menu.lst \
        /etc/inittab; do
        print_path_metadata "$sensitive_path"
    done

    subsection "Kernel and Security Parameter Indicators:"
    if command_exists sysctl; then
        if sysctl kernel.randomize_va_space net.ipv4.ip_forward fs.suid_dumpable kernel.modules_disabled 2>/dev/null; then
            :
        else
            not_available
        fi
    else
        not_available
    fi
    blank_line

    subsection "Kernel Parameter Configuration Files:"
    print_file_with_header /etc/sysctl.conf
    if print_directory_file_contents /etc/sysctl.d; then
        :
    else
        not_available
        blank_line
    fi
}

prepare_collection_directory

exec 3>&1
if [ "$COLLECTION_STATUS" = "ready" ]; then
    exec > "$REPORT_FILE"
fi

printf 'SOX ITGC Audit Data Collection\n'
printf 'Generated: %s\n' "$TIMESTAMP"
printf 'Hostname: %s\n' "$HOSTNAME_VALUE"
printf 'Script Mode: %s\n' "$SCRIPT_MODE"
printf 'Output Destination: report file with stdout replay at completion\n'
printf 'Evidence Collection Directory: %s\n' "$COLLECTION_DIRECTORY"
printf 'Manifest File: %s\n' "$MANIFEST_FILE"

section_with_guidance "Platform Details"
print_platform_details

section_with_guidance "1. Accounts and Groups with Root or Root Equivalent Access"
subsection "Users with UID 0 (Root Equivalent Accounts):"
if file_readable /etc/passwd; then
    if awk -F: '
        ($3 == 0) {
            print $1
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
blank_line

subsection "Users in the wheel or sudo groups:"
print_group_membership_summary

section_with_guidance "2. Password Parameters / Requirements"
print_auth_summary
blank_line
subsection "Full Content Review Files"
print_auth_full_content

section_with_guidance "3. Authentication Configuration"
print_authentication_summary
blank_line
subsection "Full Content Review Files"
print_authentication_full_content

section_with_guidance "4. Accounts and Groups Able to Sudo to Root"
print_sudo_summary
blank_line
subsection "Full Content Review Files"
print_sudo_full_content

section_with_guidance "5. Groups and Their Members"
print_all_groups

section_with_guidance "6. sulog Contents"
print_sulog_content

section_with_guidance "7. SSH Configuration"
print_ssh_summary
blank_line
subsection "Full Content Review Files"
print_sshd_full_content

# section_with_guidance "8. Installed Packages"
# print_package_inventory

section_with_guidance "9. Recent Login Activity"
print_recent_login_activity

# section_with_guidance "10. World-Writable Files"
# print_world_writable_files

section_with_guidance "11. SetUID and SetGID Files"
print_setuid_setgid_files

section_with_guidance "12. Scheduled Cron Jobs"
print_cron_content

section_with_guidance "13. Service Accounts"
print_service_accounts

section_with_guidance "14. Account Status, SSH Keys, and Legacy Trust"
print_account_status_summary
blank_line
print_password_expiry_details
blank_line
print_authorized_keys_content
blank_line
print_legacy_trust_content
blank_line
print_shell_timeout_and_banner_summary

section_with_guidance "15. Audit Logging and Log Forwarding"
print_audit_logging_summary
blank_line
subsection "Full Content Review Files"
print_audit_logging_full_content

section_with_guidance "16. Service and Startup Configuration"
print_service_startup_summary

section_with_guidance "17. Network Exposure and Firewall Configuration"
print_network_exposure_summary

section_with_guidance "18. Patch, Update, and Change Indicators"
print_patch_update_summary

section_with_guidance "19. Backup, Capacity, and Operational Indicators"
print_backup_operational_summary

section_with_guidance "20. Time Synchronization"
print_time_sync_summary

section_with_guidance "21. Additional Scheduled Tasks and Timers"
print_additional_scheduler_content

section_with_guidance "22. Critical File Integrity and Sensitive File Permissions"
print_critical_file_integrity

create_collection_archive

section_with_guidance "Execution Summary"
printf 'Status: completed\n'
printf 'Behavior: stdout report plus local evidence packaging\n'
printf 'Files created in working directory: %s\n' "$COLLECTION_DIRECTORY"
printf 'Collection directory status: %s\n' "$COLLECTION_STATUS"
printf 'Archive status: %s\n' "$ARCHIVE_STATUS"
printf 'Archive file: %s\n' "${ARCHIVE_FILE:-not available}"
printf 'Report file: %s\n' "$REPORT_FILE"
printf 'Manifest file: %s\n' "$MANIFEST_FILE"
printf 'Configuration changes made: none\n'

create_collection_archive

if [ -r "$REPORT_FILE" ]; then
    cat "$REPORT_FILE" >&3
fi
