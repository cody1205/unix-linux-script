#!/bin/sh

# SOX ITGC Audit Data Collection Script
# Read-only evidence collection script that writes to stdout only.

PATH=/usr/sbin:/usr/bin:/sbin:/bin
readonly PATH

SECTION_SEPARATOR='=================================================================='
readonly SECTION_SEPARATOR

GUIDANCE_WRAP_WIDTH=62
readonly GUIDANCE_WRAP_WIDTH

SCRIPT_MODE="read-only"
readonly SCRIPT_MODE

OS_NAME=$(uname -s 2>/dev/null || echo unknown)
readonly OS_NAME

HOSTNAME_VALUE=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)
readonly HOSTNAME_VALUE

TIMESTAMP=$(date 2>/dev/null || echo unknown)
readonly TIMESTAMP

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
        "8. Installed Packages")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section lists installed software packages using the package manager available on the host."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "This is software inventory evidence. Reviewers often look for security-relevant packages such as SSH, sudo, audit tools, backup agents, monitoring agents, database software, or packages that should not be present."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "The format changes by platform. Linux package names often include version and architecture, AIX uses lslpp output, Solaris may show pkg information, and HP-UX may use swlist. Large inventories are normal; the key is identifying relevant packages and versions."
            print_guidance_block "WHY IT MATTERS:" "Installed software affects security posture, patching scope, and compliance obligations. This section helps verify what software is actually present on the host."
            ;;
        "9. Recent Login Activity")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section shows recent login or session activity from commands such as last, lastlogin, or who."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Each line is typically a record of a user session, showing who logged in, from where, when, and sometimes whether the session is still active. Look for administrator accounts, remote source systems, unusual times, and unexpected account usage."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "\"still logged in\" means the session is ongoing. Remote addresses can help identify whether access came from a jump host, workstation, or unknown source. Sparse or unavailable output can mean the log source is rotated, disabled, stored elsewhere, or not readable."
            print_guidance_block "WHY IT MATTERS:" "This section gives evidence of real usage, not just configured access. It helps answer whether powerful accounts are actually being used and from where."
            ;;
        "10. World-Writable Files")
            print_guidance_block "WHAT YOU ARE SEEING:" "This section lists files that any user on the system can modify because the world-writable permission bit is set."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "World-writable means the file is writable by \"others,\" not just the owner or a trusted group. Some temporary or application-generated files may be expected, but sensitive system files should not appear here."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "A few temporary files under locations like /tmp or /var/tmp may be normal depending on application behavior. World-writable files in system directories, application binaries, scripts, or configuration paths are more concerning because they can allow tampering or privilege escalation paths."
            print_guidance_block "WHY IT MATTERS:" "Overly permissive file permissions are a common control weakness. This section helps identify places where a low-privilege user might be able to alter data, scripts, or executable content."
            ;;
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
        "Execution Summary")
            print_guidance_block "WHAT YOU ARE SEEING:" "This final section summarizes whether the script completed and restates its operating behavior."
            print_guidance_block "HOW TO MAKE SENSE OF IT:" "Use this as a quick integrity check for the evidence file. It tells you whether the script believes it completed, whether it only wrote to standard output, and whether it created files or made configuration changes."
            print_guidance_block "COMMON VARIATIONS AND IMPLICATIONS:" "A completed status supports the reliability of the collected output, although reviewers should still look for \"not available\" lines in earlier sections. If this section ever reported file creation or configuration changes, that would change the evidence handling expectations."
            print_guidance_block "WHY IT MATTERS:" "Audit collection scripts should be easy to defend as read-only and non-invasive. This section makes those collection characteristics explicit at the end of the report."
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
    [ -r "$1" ]
}

directory_exists() {
    [ -d "$1" ]
}

no_entries_found() {
    printf 'no entries found\n'
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
    elif command_exists pkg; then
        pkg info 2>/dev/null || not_available
    else
        not_available
    fi
}

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

print_world_writable_files() {
    if command_exists find; then
        find / -type f -perm -0002 -print 2>/dev/null || find / -type f -perm -2 -print 2>/dev/null || not_available
    else
        not_available
    fi
}

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

printf 'SOX ITGC Audit Data Collection\n'
printf 'Generated: %s\n' "$TIMESTAMP"
printf 'Hostname: %s\n' "$HOSTNAME_VALUE"
printf 'Script Mode: %s\n' "$SCRIPT_MODE"
printf 'Output Destination: stdout\n'

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

section_with_guidance "8. Installed Packages"
print_package_inventory

section_with_guidance "9. Recent Login Activity"
print_recent_login_activity

section_with_guidance "10. World-Writable Files"
print_world_writable_files

section_with_guidance "11. SetUID and SetGID Files"
print_setuid_setgid_files

section_with_guidance "12. Scheduled Cron Jobs"
print_cron_content

section_with_guidance "13. Service Accounts"
print_service_accounts

section_with_guidance "Execution Summary"
printf 'Status: completed\n'
printf 'Behavior: stdout only, read-only collection\n'
printf 'Files created on target host: none\n'
printf 'Configuration changes made: none\n'
