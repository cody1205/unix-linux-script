#!/bin/sh

# SOX ITGC Audit Data Collection Script
# Read-only evidence collection script that writes to stdout only.

PATH=/usr/sbin:/usr/bin:/sbin:/bin
readonly PATH

SCRIPT_MODE="read-only"
readonly SCRIPT_MODE

OS_NAME=$(uname -s 2>/dev/null || echo unknown)
readonly OS_NAME

HOSTNAME_VALUE=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)
readonly HOSTNAME_VALUE

TIMESTAMP=$(date 2>/dev/null || echo unknown)
readonly TIMESTAMP

section() {
    printf '\n==================================================\n'
    printf '%s\n' "$1"
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

section "Platform Details"
print_platform_details

section "1. Accounts and Groups with Root or Root Equivalent Access"
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

section "2. Password Parameters / Requirements"
print_auth_summary
blank_line
subsection "Full Content Review Files"
print_auth_full_content

section "3. Authentication Configuration"
print_authentication_summary
blank_line
subsection "Full Content Review Files"
print_authentication_full_content

section "4. Accounts and Groups Able to Sudo to Root"
print_sudo_summary
blank_line
subsection "Full Content Review Files"
print_sudo_full_content

section "5. Groups and Their Members"
print_all_groups

section "6. sulog Contents"
print_sulog_content

section "7. SSH Configuration"
print_ssh_summary
blank_line
subsection "Full Content Review Files"
print_sshd_full_content

section "8. Installed Packages"
print_package_inventory

section "9. Recent Login Activity"
print_recent_login_activity

section "10. World-Writable Files"
print_world_writable_files

section "11. SetUID and SetGID Files"
print_setuid_setgid_files

section "12. Scheduled Cron Jobs"
print_cron_content

section "13. Service Accounts"
print_service_accounts

section "Execution Summary"
printf 'Status: completed\n'
printf 'Behavior: stdout only, read-only collection\n'
printf 'Files created on target host: none\n'
printf 'Configuration changes made: none\n'
