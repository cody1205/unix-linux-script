#!/bin/sh
# HP-UX 11i v3 (B.11.31) - "hpux-ins-app01" (Itanium)
# A long-lived insurance policy-administration and DB2 server. Authentication is
# PAM plus LDAP-UX, password policy lives in /etc/default/passwd, software is
# managed by SD-UX (swlist), and telnet/r-services are still listening.
#
# This fixture also covers the no-getent case: HP-UX does not ship getent, so the
# collector must fall back to reading /etc/passwd and /etc/group directly.
#
# SIMULATION: real HP-UX runs only on PA-RISC/Itanium, so this drives the
# collector's HP-UX code paths against realistic data on x86. See README.md.
. "`dirname "$0"`/common.sh"

OS_KEY=hpux
OS_LABEL="HP-UX 11i v3 B.11.31 (simulated)"
UNAME_S=HP-UX
UNAME_R=B.11.31
UNAME_V=U
UNAME_M=ia64
NODENAME=hpux-ins-app01
APPDIR=/opt/policyadmin
# HP-UX ships none of these. Blocking getent forces the file-read fallback that a
# real HP-UX host takes. rpm, dpkg, and ss must also appear absent because the
# collector probes them before the HP-UX natives (swlist for software, netstat for
# listeners), and CI runners have all three installed. Names the host lacks are
# skipped harmlessly.
BLOCKERS="dpkg chage getent rpm ss systemctl journalctl pkginfo lslpp"

write_os_shims() {
    cat > "$RSHIMS/swlist" <<'EOF'
#!/bin/sh
case "$*" in
 *product*)
   cat <<'L'
# Initializing...
# Target:  hpux-ins-app01:/
#
  BUNDLE11i             B.11.31.2409   HP-UX 11i v3 September 2024 Patch Bundle
  OnlineDiag            B.11.31.28.09  HPUX 11.31 Support Tools Bundle
  HPUX-LDAP-Auth        B.11.31.06     LDAP-UX Integration
  T1471AA               A.05.60.001    HP-UX Secure Shell
  KRB5-Client           E.1.6.2.10     Kerberos V5 Client
  Db2v115               11.5.9.0       IBM DB2 Universal Database
  DataProtector         A.11.00        HPE Data Protector Client
L
   ;;
 *)
   cat <<'L'
# Target:  hpux-ins-app01:/
  HPUXBaseOS            B.11.31        HP-UX Base OS
  HPUXBaseAux           B.11.31.2409   HP-UX Base OS Auxiliary
  HPUX-LDAP-Auth        B.11.31.06     LDAP-UX Integration
  T1471AA               A.05.60.001    HP-UX Secure Shell
  OnlineDiag            B.11.31.28.09  HPUX Support Tools
L
   ;;
esac
EOF

    cat > "$RSHIMS/netstat" <<'EOF'
#!/bin/sh
cat <<'L'
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp        0      0  *.22                   *.*                    LISTEN
tcp        0      0  *.23                   *.*                    LISTEN
tcp        0      0  *.512                  *.*                    LISTEN
tcp        0      0  *.513                  *.*                    LISTEN
tcp        0      0  *.514                  *.*                    LISTEN
tcp        0      0  *.50000                *.*                    LISTEN
tcp        0      0  hpux-ins-app01.22      10.70.4.6.49881        ESTABLISHED
udp        0      0  *.123                  *.*
L
EOF

    cat > "$RSHIMS/passwd" <<'EOF'
#!/bin/sh
case "$1" in
 -s|-S)
   u=$2
   line=`awk -F: -v u="$u" '$1==u{print}' /etc/shadow 2>/dev/null`
   [ -z "$line" ] && exit 1
   h=`echo "$line"|cut -d: -f2`; lc=`echo "$line"|cut -d: -f3`
   mn=`echo "$line"|cut -d: -f4`; mx=`echo "$line"|cut -d: -f5`; wn=`echo "$line"|cut -d: -f6`
   case "$h" in ''|'*'*) st=LK;; '!'*) st=LK;; *) st=PS;; esac
   d=`date -d "@$((lc*86400))" +%m/%d/%y 2>/dev/null`
   echo "$u $st $d ${mn:-0} ${mx:-63} ${wn:-7}"
   exit 0;;
esac
exit 1
EOF

    chmod 0755 "$RSHIMS/swlist" "$RSHIMS/netstat" "$RSHIMS/passwd"
}

write_os_files() {
    # HP-UX conventions: /sbin/sh shells, nobody at UID -2.
    cat > "$R/etc/passwd" <<'EOF'
root:x:0:3::/home/root:/sbin/sh
daemon:x:1:5::/:/sbin/sh
bin:x:2:2::/usr/bin:/sbin/sh
sys:x:3:3::/:
adm:x:4:4::/var/adm:/sbin/sh
uucp:x:5:3::/var/spool/uucppublic:/usr/lbin/uucp/uucico
lp:x:9:7::/var/spool/lp:/sbin/sh
nobody:x:-2:60001::/:
sshd:x:104:105:sshd priv sep:/var/empty:/sbin/sh
ldapadm:x:105:106:LDAP-UX admin:/home/ldapadm:/sbin/sh
db2inst1:x:110:110:DB2 instance:/home/db2inst1:/usr/bin/ksh
pdprotect:x:111:111:Data Protector:/home/pdprotect:/sbin/sh
awright:x:1001:20:Alan Wright - HP-UX Admin:/home/awright:/usr/bin/ksh
schew:x:1002:20:Sandra Chew - DBA:/home/schew:/usr/bin/ksh
ribrahim:x:1003:20:Rashid Ibrahim - Policy App Owner:/home/ribrahim:/usr/bin/ksh
dpark:x:1004:21:Diane Park - IT Audit (RO):/home/dpark:/usr/bin/ksh
gmoore:x:1005:20:Greg Moore - Admin (TERMINATED):/home/gmoore:/usr/bin/ksh
vendorsup:x:1006:20:Vendor support - policy engine:/home/vendorsup:/usr/bin/ksh
svcpolicy:x:1200:110:Policy batch service account:/home/svcpolicy:/usr/bin/ksh
EOF

    # No wheel or sudo group here - HP-UX sites use their own admin group, so
    # the collector's wheel/sudo lookup should legitimately find nothing.
    cat > "$R/etc/group" <<'EOF'
root:x:0:root
other:x:1:root
bin:x:2:root,bin
sys:x:3:root,uucp
adm:x:4:root,adm
daemon:x:5:root
mail:x:6:root
lp:x:7:root,lp
users:x:20:awright,schew,ribrahim,gmoore,vendorsup
auditgrp:x:21:dpark
sshd:x:105:
dba:x:110:schew,db2inst1,svcpolicy
hpuxadmin:x:200:awright,ribrahim
policyadmin:x:201:ribrahim,vendorsup,svcpolicy
EOF

    # HP-UX standard-mode shadow. gmoore was terminated and is *LOCKED*.
    cat > "$R/etc/shadow" <<'EOF'
root:GkQ2mFhX9pL0w:19680:0:63:7:::
daemon:*:19501::::::
bin:*:19501::::::
sshd:*:19501::::::
db2inst1:aB3cD5eF7gH9i:19670:1:63:7:::
awright:jK2lM4nO6pQ8r:19710:1:42:7:::
schew:sT4uV6wX8yZ0a:19695:1:42:7:::
ribrahim:bC6dE8fG0hI2j:19660:1:63:7:::
dpark:kL8mN0oP2qR4s:19705:1:63:7:::
gmoore:*LOCKED*:19540:1:42:7:::
vendorsup:tU0vW2xY4zA6b:19600:1:30:7::19905:
svcpolicy:cD2eF4gH6iJ8k:19500:0:0:0:::
EOF
    chmod 400 "$R/etc/shadow"

    cat > "$R/etc/default/passwd" <<'EOF'
# /etc/default/passwd - HP-UX password policy
MIN_PASSWORD_LENGTH=8
PASSWORD_MIN_UPPER_CASE_CHARS=1
PASSWORD_MIN_LOWER_CASE_CHARS=1
PASSWORD_MIN_DIGIT_CHARS=1
PASSWORD_MIN_SPECIAL_CHARS=1
PASSWORD_HISTORY_DEPTH=8
PASSWORD_MAXDAYS=63
PASSWORD_MINDAYS=1
PASSWORD_WARNDAYS=7
PASSLENGTH=8
MINLENGTH=8
MINDIFF=4
MAXWEEKS=9
MINWEEKS=1
WARNWEEKS=1
EOF
    cat > "$R/etc/default/login" <<'EOF'
# /etc/default/login
UMASK=077
CONSOLE=/dev/console
PASSREQ=YES
RETRIES=3
LOCK_AFTER_RETRIES=YES
DISABLETIME=60
SLEEPTIME=4
TIMEOUT=60
EOF

    cat > "$R/etc/pam.conf" <<'EOF'
#
# PAM configuration - HP-UX 11.31 with LDAP-UX
#
login   auth    required   libpam_hpsec.so.1
login   auth    sufficient libpam_unix.so.1
login   auth    sufficient libpam_ldap.so.1 try_first_pass
login   auth    required   libpam_krb5.so.1 try_first_pass
sshd    auth    required   libpam_hpsec.so.1
sshd    auth    sufficient libpam_unix.so.1
sshd    auth    sufficient libpam_ldap.so.1 try_first_pass
sshd    auth    required   libpam_deny.so.1
OTHER   auth    sufficient libpam_unix.so.1
OTHER   auth    required   libpam_ldap.so.1 try_first_pass

login   account required   libpam_hpsec.so.1
login   account sufficient libpam_unix.so.1
login   account required   libpam_ldap.so.1
sshd    account required   libpam_hpsec.so.1
sshd    account sufficient libpam_unix.so.1
sshd    account required   libpam_ldap.so.1
OTHER   account required   libpam_unix.so.1

login   password required  libpam_hpsec.so.1
login   password sufficient libpam_unix.so.1
login   password required  libpam_ldap.so.1
OTHER   password required  libpam_unix.so.1

login   session required   libpam_hpsec.so.1
login   session required   libpam_unix.so.1
sshd    session required   libpam_unix.so.1
OTHER   session required   libpam_unix.so.1
EOF

    mkdir -p "$R/etc/opt/ldapux"
    cat > "$R/etc/opt/ldapux/ldapux_client.conf" <<'EOF'
# LDAP-UX client profile (retrieved from the directory)
preferredServerList: ldaps://dir01.meridianins.local:636 ldaps://dir02.meridianins.local:636
defaultBaseDN: dc=meridianins,dc=local
profileTTL: 3600
authenticationMethod: tls:simple
serviceSearchDescriptor passwd: ou=People,dc=meridianins,dc=local?sub
serviceSearchDescriptor group: ou=Groups,dc=meridianins,dc=local?sub
EOF

    cat > "$R/etc/nsswitch.conf" <<'EOF'
passwd:   files ldap
group:    files ldap
hosts:    files dns
netgroup: ldap
EOF

    cat > "$R/etc/sudoers" <<'EOF'
## /etc/sudoers - Meridian Insurance HP-UX standard
Defaults    env_reset
Defaults    secure_path=/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/usr/contrib/bin
Defaults    logfile=/var/adm/sudo.log
Defaults    syslog=auth
Defaults    requiretty
Defaults    passwd_tries=3

Cmnd_Alias  SWADMIN = /usr/sbin/swinstall, /usr/sbin/swremove, /usr/sbin/swlist
Cmnd_Alias  DBADMIN = /home/db2inst1/sqllib/adm/db2start, /home/db2inst1/sqllib/adm/db2stop
Cmnd_Alias  SYSOPS  = /usr/sbin/ioscan, /usr/sbin/vgdisplay, /usr/sbin/lvextend
Cmnd_Alias  BOUNCE  = /sbin/init.d/policyengine start, /sbin/init.d/policyengine stop

User_Alias  UXADMINS = awright, ribrahim

root        ALL=(ALL) ALL
%hpuxadmin  ALL=(ALL) ALL
UXADMINS    ALL=(ALL) NOPASSWD: ALL
%dba        ALL=(db2inst1) NOPASSWD: DBADMIN
%policyadmin ALL=(root) NOPASSWD: BOUNCE
schew       ALL=(root) SYSOPS
svcpolicy   ALL=(root) NOPASSWD: /opt/policyadmin/bin/nightly_rating.ksh
# vendor account - temporary, broad; audit flagged for removal
vendorsup   ALL=(ALL) NOPASSWD: ALL

#includedir /etc/sudoers.d
EOF
    chmod 440 "$R/etc/sudoers"
    cat > "$R/etc/sudoers.d/dba_hpux" <<'EOF'
%dba ALL=(root) NOPASSWD: /sbin/init.d/db2fmcd start, /sbin/init.d/db2fmcd stop
EOF
    chmod 440 "$R/etc/sudoers.d/dba_hpux"

    cat > "$R/etc/ssh/sshd_config" <<'EOF'
# HP-UX Secure Shell (T1471AA) - Meridian hardened
Port 22
PermitRootLogin no
MaxAuthTries 4
LoginGraceTime 60
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
ClientAliveInterval 300
Banner /etc/issue
AllowGroups hpuxadmin dba auditgrp policyadmin
DenyUsers gmoore
EOF

    cat > "$R/etc/rc.config" <<'EOF'
#!/sbin/sh
# /etc/rc.config - sources all /etc/rc.config.d/* control scripts
set -a
for f in /etc/rc.config.d/*
do
    if [ -f "$f" ]; then . "$f"; fi
done
SSHD_START=1
NTPDATE_SERVER="ntp1.meridianins.local"
XNTPD=1
export NFS_CLIENT=1
export LDAPUX=1
EOF
    cat > "$R/etc/inittab" <<'EOF'
init:3:initdefault:
brc1::bootwait:/sbin/bcheckrc </dev/console >/dev/console 2>&1
rc:23456:wait:/sbin/rc </dev/console >/dev/console 2>&1
cons:123456:respawn:/usr/sbin/getty console console
ssh:234:respawn:/opt/ssh/sbin/sshd -D
slp:34:respawn:/usr/lbin/slpd
pdm:234:respawn:/opt/omni/lbin/crs
policy:3:once:/sbin/init.d/policyengine start
EOF

    cat > "$R/etc/syslog.conf" <<'EOF'
mail.debug                      /var/adm/syslog/mail.log
*.info;mail.none                /var/adm/syslog/syslog.log
*.alert                         /dev/console
*.emerg                         *
auth.notice                     /var/adm/authlog
# forward to the enterprise log concentrator
*.debug                         @loghost.meridianins.local
EOF
    cat > "$R/etc/ntp.conf" <<'EOF'
server ntp1.meridianins.local prefer
server ntp2.meridianins.local
driftfile /etc/ntp.drift
EOF

    cat > "$R/var/spool/cron/crontabs/root" <<'EOF'
0 2 * * * /opt/policyadmin/bin/policy_eod.ksh >/var/adm/policy/eod.log 2>&1
0 4 * * 0 /usr/sbin/fbackup -f /dev/rmt/0m -i /
30 5 * * 1 /usr/local/sbin/access_recert.ksh
EOF
    printf '0 1 * * * /home/db2inst1/scripts/db2_backup.ksh\n' > "$R/var/spool/cron/crontabs/db2inst1"
    printf '0 0 * * * /opt/policyadmin/bin/nightly_rating.ksh\n' > "$R/var/spool/cron/crontabs/svcpolicy"

    cat > "$R/etc/issue" <<'EOF'
********************************************************************************
 Meridian Insurance - HP-UX Production (hpux-ins-app01)
 AUTHORIZED USE ONLY. This SOX-regulated system is monitored and logged.
********************************************************************************
EOF
    cat > "$R/etc/motd" <<'EOF'
--------------------------------------------------------------------------------
 hpux-ins-app01 | HP-UX 11i v3 | Policy Administration + DB2 | Owner: UNIX Team
 Backups: Data Protector (fbackup weekly). Patch bundle: 2024-09. SOX: YES.
--------------------------------------------------------------------------------
EOF
    cat > "$R/etc/profile" <<'EOF'
# /etc/profile (HP-UX)
TMOUT=900
export TMOUT
umask 077
PATH=/usr/bin:/usr/sbin:/sbin:/usr/contrib/bin
export PATH
EOF
    printf '# system csh resource file\nset autologout=15\numask 077\n' > "$R/etc/csh.cshrc"

    # r-services trust still in place - audit finding.
    cat > "$R/etc/hosts.equiv" <<'EOF'
+
appnode02.meridianins.local
dbnode03.meridianins.local db2inst1
EOF

    for u in awright schew ribrahim dpark gmoore vendorsup svcpolicy db2inst1; do
        mkdir -p "$R/home/$u/.ssh"
        chmod 700 "$R/home/$u/.ssh"
    done
    cat > "$R/home/awright/.ssh/authorized_keys" <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCAlanWrightHPUXadminKey2024 awright@ux-jump01
EOF
    cat > "$R/home/svcpolicy/.ssh/authorized_keys" <<'EOF'
command="/opt/policyadmin/bin/nightly_rating.ksh",no-pty ssh-rsa AAAAB3NzaPolicyBatchKeyFromScheduler svcpolicy@sched01
EOF
    chmod 600 "$R/home/awright/.ssh/authorized_keys" "$R/home/svcpolicy/.ssh/authorized_keys"
    cat > "$R/home/db2inst1/.rhosts" <<'EOF'
dbnode03 db2inst1
+ +
EOF

    mkdir -p "$R/opt/policyadmin/bin" "$R/opt/policyadmin/etc" \
             "$R/opt/policyadmin/log" "$R/var/adm/policy"
    printf '#!/usr/bin/ksh\n# nightly policy rating batch\nexit 0\n' > "$R/opt/policyadmin/bin/nightly_rating.ksh"
    chmod 755 "$R/opt/policyadmin/bin/nightly_rating.ksh"
    printf 'tier=PROD\ndb=DB2:POLICYPRD\n' > "$R/opt/policyadmin/etc/policy.conf"
    : > "$R/opt/policyadmin/bin/pa_setuid"
    chmod 4755 "$R/opt/policyadmin/bin/pa_setuid"

    cat > "$R/etc/.sim_df" <<'EOF'
Filesystem          kbytes    used   avail %used Mounted on
/dev/vg00/lvol3    1048576  524288  524288   50% /
/dev/vg00/lvol1     524288  204800  319488   39% /stand
/dev/vg00/lvol8   10485760 7340032 3145728   70% /usr
/dev/vg00/lvol7    4194304 2621440 1572864   63% /var
/dev/vg01/policy  52428800 36700160 15728640  70% /opt/policyadmin
/dev/vg01/db2     209715200 146800640 62914560 70% /home/db2inst1
EOF
    cat > "$R/etc/.sim_last" <<'EOF'
awright   pts/0        10.70.4.6         Jun 16 08:12   still logged in
schew     pts/1        10.70.4.30        Jun 16 07:55 - 09:10  (01:15)
svcpolic  pts/2        10.70.2.9         Jun 16 00:00 - 00:52  (00:52)
db2inst1  pts/1        hpux-ins-app01    Jun 16 01:00 - 03:20  (02:20)
gmoore    pts/3        198.51.100.23     May 30 21:04 - 21:05  (00:01)
root      pts/0        10.70.4.6         Jun 15 17:40 - 18:15  (00:35)

wtmp begins Jun  8 06:00
EOF
    cat > "$R/etc/.sim_setuid" <<'EOF'
/usr/bin/su
/usr/bin/passwd
/usr/bin/login
/usr/bin/rlogin
/usr/bin/remsh
/usr/bin/sudo
/usr/sbin/swinstall
/opt/policyadmin/bin/pa_setuid
EOF
    cat > "$R/etc/.sim_setgid" <<'EOF'
/usr/bin/mail
/usr/bin/write
/usr/sbin/lpsched
EOF
    # This host has a world-writable /var/tmp with NO sticky bit, so any user can
    # delete or rename another user's files there. Exercises the missing-sticky-bit
    # finding; the other fixtures carry the expected 1777.
    chmod 0777 "$R/var/tmp"
    cat > "$R/etc/.sim_ww_files" <<'EOF'
/opt/policyadmin/etc/policy.conf
EOF
    chmod 0666 "$R/opt/policyadmin/etc/policy.conf"

    # HP-UX writes su history to /var/adm/sulog, so this fixture covers that
    # location while the RHEL fixture covers /var/log/sulog.
    cat > "$R/var/adm/sulog" <<'EOF'
SU 06/16 08:15 + pts/0 awright-root
SU 06/15 22:40 - pts/3 gmoore-root
EOF
    cat > "$R/var/adm/authlog" <<'EOF'
Jun 16 08:12:03 hpux-ins-app01 sshd[4021]: Accepted publickey for awright from 10.70.4.6 port 49881
Jun 16 08:15:44 hpux-ins-app01 su: + pts/0 awright-root
Jun 16 07:55:12 hpux-ins-app01 sshd[3980]: Accepted password for schew from 10.70.4.30 port 51002
May 30 21:04:55 hpux-ins-app01 sshd[28110]: Failed password for gmoore from 198.51.100.23 port 55210
EOF
}

verify_os() {
    assert_report_matches 'Platform Family: HP-UX' 'HP-UX platform family reported'
    assert_report_matches 'Kernel Release: B\.11\.31' 'HP-UX release reported'
    assert_report_matches 'Hardware Platform: ia64' 'Itanium architecture reported'
    assert_report_matches 'libpam_ldap\.so' 'PAM LDAP authentication detected'
    assert_report_matches 'libpam_krb5\.so' 'Kerberos PAM module captured'
    assert_report_matches 'PASSLENGTH=8' 'HP-UX password policy captured'
    assert_report_matches 'MAXWEEKS=9' 'HP-UX password aging captured'
    assert_report_matches 'LOCK_AFTER_RETRIES=YES' 'HP-UX lockout policy captured'
    assert_report_matches 'Command: swlist' 'SD-UX inventory labelled with its command'
    assert_report_matches 'HPUX-LDAP-Auth' 'LDAP-UX bundle captured in inventory'
    assert_report_matches 'vendorsup   ALL=\(ALL\) NOPASSWD: ALL' 'vendor sudo rule captured'
    assert_report_matches 'SSHD_START=1' 'rc.config startup evidence captured'
    assert_report_matches 'Service account UID threshold: 100' 'HP-UX service-account cutoff applied'
    # No getent on HP-UX: the collector must still resolve accounts from files.
    assert_report_matches '^root$' 'UID 0 account resolved without getent'
    # HP-UX records su history at /var/adm/sulog.
    assert_report_matches 'File: /var/adm/sulog' 'su history located at the HP-UX path'
    assert_report_matches 'awright-root' 'su events captured'

    # Section 10: this host's /var/tmp is world-writable with no sticky bit.
    assert_report_matches 'Sticky bit: ABSENT' 'missing sticky bit reported on shared temp directory'
    assert_report_matches '/opt/policyadmin/etc/policy\.conf' 'world-writable application config surfaced'

    sim_check
    if grep -q '^/etc/shadow$' "$SKIPPED" 2>/dev/null; then
        sim_pass "/etc/shadow withheld from the package"
    else
        sim_fail "/etc/shadow not recorded as skipped"
    fi
    # The HP-UX policy file has no hashes and must still be collected.
    sim_check
    if [ -f "$E/raw_files/etc/default/passwd" ]; then
        sim_pass "/etc/default/passwd collected as evidence"
    else
        sim_fail "/etc/default/passwd missing from raw_files/ (over-blocked?)"
    fi
}

sim_main
