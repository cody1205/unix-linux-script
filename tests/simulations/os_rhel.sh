#!/bin/sh
# Red Hat Enterprise Linux 8 - "rhel-fin-app01"
# A long-lived financial-services application server: SSSD-backed LDAP with
# Kerberos SSO, layered sudoers including a break-glass rule and a stale
# contractor rule, Oracle and Tomcat service accounts, TLS syslog forwarding.
. "`dirname "$0"`/common.sh"

OS_KEY=rhel
OS_LABEL="Red Hat Enterprise Linux 8"
UNAME_S=Linux
UNAME_R=4.18.0-553.16.1.el8_10.x86_64
UNAME_V='#1 SMP Thu Jun 20 12:38:14 EDT 2024'
UNAME_M=x86_64
NODENAME=rhel-fin-app01.corp.acmefinancial.com
APPDIR="/srv/Finance App"
# A second application root that deliberately does NOT exist in the fixture. Its
# purpose is the WARN it triggers: that warning is raised from inside a pipeline
# subshell, which is exactly the path that once lost its increment and let the
# verdict read COMPLETED_CLEAN above a WARN line. This fixture therefore expects
# a WARNINGS verdict, and the count-vs-lines assertion in common.sh has a real
# warning to check.
APPDIR2=/srv/retired-app
EXPECTED_RESULT=COMPLETED_WITH_WARNINGS
BLOCKERS=""

write_os_shims() {
    cat > "$RSHIMS/rpm" <<'EOF'
#!/bin/sh
case "$*" in
 *--last*)
   cat <<'L'
kernel-4.18.0-553.16.1.el8_10             Thu 20 Jun 2024 09:14:52 AM EDT
sssd-2.9.4-1.el8                          Tue 11 Jun 2024 02:03:11 PM EDT
openssh-server-8.0p1-24.el8               Tue 11 Jun 2024 02:02:58 PM EDT
audit-3.0.7-5.el8                         Mon 15 Apr 2024 10:41:20 AM EDT
sudo-1.9.5p2-1.el8_9                      Mon 15 Apr 2024 10:41:02 AM EDT
L
   ;;
 *)
   cat <<'L'
kernel-4.18.0-553.16.1.el8_10.x86_64
glibc-2.28-236.el8_9.13.x86_64
systemd-239-82.el8_10.x86_64
sssd-2.9.4-1.el8.x86_64
sssd-ldap-2.9.4-1.el8.x86_64
sssd-krb5-2.9.4-1.el8.x86_64
krb5-workstation-1.18.2-27.el8_10.x86_64
openldap-2.4.46-18.el8.x86_64
openssh-server-8.0p1-24.el8.x86_64
sudo-1.9.5p2-1.el8_9.x86_64
audit-3.0.7-5.el8.x86_64
rsyslog-8.2102.0-15.el8.x86_64
rsyslog-gnutls-8.2102.0-15.el8.x86_64
chrony-4.5-1.el8.x86_64
pam-1.3.1-33.el8.x86_64
authselect-1.2.6-2.el8.x86_64
tomcat-9.0.87-1.el8.noarch
java-11-openjdk-headless-11.0.23.0.9-3.el8.x86_64
oracle-instantclient19.3-basic-19.3.0.0.0-1.x86_64
CrowdStrike-falcon-sensor-7.14.0-16703.el8.x86_64
splunkforwarder-9.2.1-78803f08aabb.x86_64
L
   ;;
esac
EOF

    cat > "$RSHIMS/ss" <<'EOF'
#!/bin/sh
cat <<'L'
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=1142,fd=3))
tcp   LISTEN 0      100        127.0.0.1:25         0.0.0.0:*     users:(("master",pid=1310,fd=13))
tcp   LISTEN 0      128          0.0.0.0:8080       0.0.0.0:*     users:(("java",pid=2201,fd=44))
tcp   LISTEN 0      128          0.0.0.0:1521       0.0.0.0:*     users:(("tnslsnr",pid=1998,fd=8))
udp   UNCONN 0      0            0.0.0.0:123        0.0.0.0:*     users:(("chronyd",pid=1002,fd=5))
L
EOF

    cat > "$RSHIMS/systemctl" <<'EOF'
#!/bin/sh
case "$*" in
 *list-unit-files*)
   cat <<'L'
UNIT FILE                     STATE     VENDOR PRESET
auditd.service                enabled   enabled
chronyd.service               enabled   enabled
crond.service                 enabled   enabled
falcon-sensor.service         enabled   disabled
firewalld.service             enabled   enabled
oracle-db.service             enabled   disabled
rsyslog.service               enabled   enabled
sshd.service                  enabled   enabled
sssd.service                  enabled   enabled
tomcat.service                enabled   disabled

10 unit files listed.
L
   ;;
 *) exit 0;;
esac
EOF

    # Files-backed getent keeps directory enumeration deterministic.
    cat > "$RSHIMS/getent" <<'EOF'
#!/bin/sh
db=$1; key=${2:-}
f=/etc/$db
[ -f "$f" ] || exit 2
if [ -n "$key" ]; then awk -F: -v k="$key" '$1==k{print; e=1} END{exit !e}' "$f"; else cat "$f"; fi
EOF

    cat > "$RSHIMS/passwd" <<'EOF'
#!/bin/sh
case "$1" in
 -S|-s)
   u=$2
   line=`awk -F: -v u="$u" '$1==u{print}' /etc/shadow 2>/dev/null`
   [ -z "$line" ] && { echo "passwd: Unknown user name '$u'." >&2; exit 1; }
   h=`echo "$line" | cut -d: -f2`
   lc=`echo "$line" | cut -d: -f3`; mn=`echo "$line" | cut -d: -f4`
   mx=`echo "$line" | cut -d: -f5`; wn=`echo "$line" | cut -d: -f6`
   case "$h" in ''|'!!') st=LK;; '!'*|'*'*) st=LK;; *) st=PS;; esac
   d=`date -d "@$((lc*86400))" +%m/%d/%Y 2>/dev/null`
   echo "$u $st $d ${mn:-0} ${mx:-99999} ${wn:-7} -1 (Password set, SHA512 crypt.)"
   exit 0;;
esac
exit 1
EOF

    cat > "$RSHIMS/chage" <<'EOF'
#!/bin/sh
[ "$1" = -l ] || exit 1
u=$2
line=`awk -F: -v u="$u" '$1==u{print}' /etc/shadow 2>/dev/null`
[ -z "$line" ] && exit 1
lc=`echo "$line"|cut -d: -f3`; mn=`echo "$line"|cut -d: -f4`
mx=`echo "$line"|cut -d: -f5`; wn=`echo "$line"|cut -d: -f6`
inact=`echo "$line"|cut -d: -f7`; acct=`echo "$line"|cut -d: -f8`
pdate=`date -d "@$((lc*86400))" "+%b %d, %Y" 2>/dev/null`
if [ -n "$mx" ] && [ "$mx" -gt 0 ] 2>/dev/null; then
  edate=`date -d "@$(((lc+mx)*86400))" "+%b %d, %Y" 2>/dev/null`
else edate=never; fi
if [ -n "$acct" ] && [ "$acct" -gt 0 ] 2>/dev/null; then
  adate=`date -d "@$((acct*86400))" "+%b %d, %Y" 2>/dev/null`
else adate=never; fi
echo "Last password change                                    : $pdate"
echo "Password expires                                        : $edate"
echo "Password inactive                                       : ${inact:-never}"
echo "Account expires                                         : $adate"
echo "Minimum number of days between password change          : ${mn:-0}"
echo "Maximum number of days between password change          : ${mx:-99999}"
echo "Number of days of warning before password expires       : ${wn:-7}"
EOF

    chmod 0755 "$RSHIMS/rpm" "$RSHIMS/ss" "$RSHIMS/systemctl" \
               "$RSHIMS/getent" "$RSHIMS/passwd" "$RSHIMS/chage"
}

write_os_files() {
    cat > "$R/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
chrony:x:993:990::/var/lib/chrony:/sbin/nologin
sssd:x:992:989:User for sssd:/:/sbin/nologin
tomcat:x:91:91:Apache Tomcat:/opt/finapp:/sbin/nologin
oracle:x:54321:54321:Oracle Software Owner:/u01/app/oracle:/bin/bash
jdoe:x:1001:1001:Jennifer Doe - Sr UNIX Admin:/home/jdoe:/bin/bash
asmith:x:1002:1002:Aaron Smith - Database Admin:/home/asmith:/bin/bash
rjones:x:1003:1003:Robert Jones - App Owner:/home/rjones:/bin/bash
mgarcia:x:1004:1004:Maria Garcia - Internal Audit (RO):/home/mgarcia:/bin/bash
kwilson:x:1005:1005:Kevin Wilson - Contractor (EXPIRED):/home/kwilson:/bin/bash
tchen:x:1006:1006:Tina Chen - Release Engineer:/home/tchen:/bin/bash
svc_backup:x:1200:1200:NetBackup service account:/home/svc_backup:/bin/bash
svc_deploy:x:1201:1201:CI/CD deploy account:/home/svc_deploy:/bin/bash
EOF

    cat > "$R/etc/group" <<'EOF'
root:x:0:
bin:x:1:
daemon:x:2:
adm:x:4:jdoe
wheel:x:10:jdoe,asmith
sshd:x:74:
chrony:x:990:
sssd:x:989:
tomcat:x:91:svc_deploy
oracle:x:54321:asmith,svc_backup
dba:x:1500:asmith,oracle,svc_backup
appadmin:x:1501:rjones,tchen,svc_deploy
finance:x:1502:mgarcia
auditors:x:1503:mgarcia
domainadmins:x:1600:jdoe
jdoe:x:1001:
asmith:x:1002:
rjones:x:1003:
mgarcia:x:1004:
kwilson:x:1005:
tchen:x:1006:
svc_backup:x:1200:
svc_deploy:x:1201:
EOF

    # Mixed posture: active, locked service accounts, one expired contractor.
    cat > "$R/etc/shadow" <<'EOF'
root:$6$Xq3z9mKf$2bknQeJ8oPq1sRt3uV5wX7yZ9aB1cD3eF5gH7iJ9kL1mN3oP5qR7sT9uV1wX3y:19700:1:90:7:::
bin:*:19501:0:99999:7:::
daemon:*:19501:0:99999:7:::
sshd:!!:19501::::::
chrony:!!:19501::::::
sssd:!!:19501::::::
tomcat:!!:19501::::::
oracle:$6$Ab12Cd34$eF56gH78iJ90kL12mN34oP56qR78sT90uV12wX34yZ56aB78cD90eF12g:19680:1:90:7:::
jdoe:$6$Kf9Lm2Np$qR3sT5uV7wX9yZ1aB3cD5eF7gH9iJ1kL3mN5oP7qR9sT1uV3wX5yZ7a:19710:1:90:14:::
asmith:$6$Pq5Rt7Uv$wX9yZ1aB3cD5eF7gH9iJ1kL3mN5oP7qR9sT1uV3wX5yZ7aB9cD1eF3g:19695:1:90:14:::
rjones:$6$Zx1Cv3Bn$mN5oP7qR9sT1uV3wX5yZ7aB9cD1eF3gH5iJ7kL9mN1oP3qR5sT7uV9w:19660:1:180:14:::
mgarcia:$6$Qw2Er4Ty$uV3wX5yZ7aB9cD1eF3gH5iJ7kL9mN1oP3qR5sT7uV9wX1yZ3aB5cD7e:19705:1:90:14:::
kwilson:$6$Lk8Jh6Gf$D5eF7gH9iJ1kL3mN5oP7qR9sT1uV3wX5yZ7aB9cD1eF3gH5iJ7kL9mN:19600:1:90:7::20269:
tchen:$6$Mn4Bv6Cx$eF3gH5iJ7kL9mN1oP3qR5sT7uV9wX1yZ3aB5cD7eF9gH1iJ3kL5mN7oP:19702:1:90:14:::
svc_backup:$6$Rt6Yu8Io$gH9iJ1kL3mN5oP7qR9sT1uV3wX5yZ7aB9cD1eF3gH5iJ7kL9mN1oP3q:19500:0:99999:7:::
svc_deploy:$6$Ws3Ed5Rf$iJ1kL3mN5oP7qR9sT1uV3wX5yZ7aB9cD1eF3gH5iJ7kL9mN1oP3qR5s:19500:0:99999:7:::
EOF
    chmod 000 "$R/etc/shadow"

    cat > "$R/etc/sudoers" <<'EOF'
## /etc/sudoers - Acme Financial standard build (managed by Ansible)
Defaults    !visiblepw
Defaults    always_set_home
Defaults    env_reset
Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin
Defaults    logfile=/var/log/sudo.log
Defaults    syslog=authpriv
Defaults    requiretty
Defaults    timestamp_timeout=5

Cmnd_Alias  SERVICES = /usr/bin/systemctl start *, /usr/bin/systemctl stop *, /usr/bin/systemctl restart *
Cmnd_Alias  SOFTWARE = /usr/bin/dnf, /usr/bin/rpm, /usr/bin/yum
Cmnd_Alias  DBADMIN  = /u01/app/oracle/product/19.3/bin/sqlplus, /u01/app/oracle/product/19.3/bin/lsnrctl
Cmnd_Alias  STORAGE  = /usr/bin/mount, /usr/bin/umount, /usr/sbin/lvm

User_Alias  UNIXADMINS = jdoe, tchen
User_Alias  DBAS       = asmith, %dba

root        ALL=(ALL)       ALL
%wheel      ALL=(ALL)       ALL
UNIXADMINS  ALL=(ALL)       NOPASSWD: ALL
%appadmin   ALL=(ALL)       SERVICES, SOFTWARE
DBAS        ALL=(oracle)    NOPASSWD: DBADMIN
rjones      ALL=(tomcat)    NOPASSWD: /usr/bin/systemctl restart tomcat
%finance    ALL=(ALL)       /usr/bin/less /var/log/finapp/*
svc_deploy  ALL=(root)      NOPASSWD: /opt/finapp/bin/deploy.sh, SERVICES

#includedir /etc/sudoers.d
EOF
    chmod 440 "$R/etc/sudoers"

    cat > "$R/etc/sudoers.d/10_ansible_break_glass" <<'EOF'
# Emergency break-glass access - reviewed quarterly (JIRA ITGC-2291)
%domainadmins ALL=(ALL) NOPASSWD: ALL
EOF
    cat > "$R/etc/sudoers.d/20_oracle" <<'EOF'
oracle ALL=(ALL) NOPASSWD: /usr/bin/systemctl start oracle-db, /usr/bin/systemctl stop oracle-db
%dba   ALL=(root) /usr/sbin/lsof, /usr/bin/kill
EOF
    cat > "$R/etc/sudoers.d/90_contractors" <<'EOF'
# Contractor kwilson - time-boxed; account expired but rule left in place
kwilson ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/tail *
EOF
    chmod 440 "$R/etc/sudoers.d"/*

    cat > "$R/etc/nsswitch.conf" <<'EOF'
passwd:     sss files systemd
shadow:     files sss
group:      sss files systemd
hosts:      files dns myhostname
netgroup:   sss
sudoers:    files sss
EOF

    cat > "$R/etc/sssd/sssd.conf" <<'EOF'
[sssd]
domains = corp.acmefinancial.com
config_file_version = 2
services = nss, pam, sudo, ssh

[domain/corp.acmefinancial.com]
id_provider = ldap
auth_provider = krb5
chpass_provider = krb5
access_provider = ldap
ldap_uri = ldaps://dc01.corp.acmefinancial.com, ldaps://dc02.corp.acmefinancial.com
ldap_search_base = dc=corp,dc=acmefinancial,dc=com
ldap_default_bind_dn = cn=sssd-bind,ou=ServiceAccounts,dc=corp,dc=acmefinancial,dc=com
ldap_default_authtok = REDACTED_BIND_PASSWORD
ldap_id_use_start_tls = true
ldap_tls_reqcert = demand
krb5_realm = CORP.ACMEFINANCIAL.COM
krb5_store_password_if_offline = true
cache_credentials = true
ldap_access_filter = (memberOf=cn=linux-app-login,ou=Groups,dc=corp,dc=acmefinancial,dc=com)
use_fully_qualified_names = false
EOF
    chmod 600 "$R/etc/sssd/sssd.conf"

    cat > "$R/etc/krb5.conf" <<'EOF'
[libdefaults]
 default_realm = CORP.ACMEFINANCIAL.COM
 dns_lookup_kdc = true
 ticket_lifetime = 10h
 forwardable = true
[realms]
 CORP.ACMEFINANCIAL.COM = {
  kdc = dc01.corp.acmefinancial.com
  admin_server = dc01.corp.acmefinancial.com
 }
EOF

    cat > "$R/etc/pam.d/system-auth" <<'EOF'
#%PAM-1.0
# Generated by authselect with profile "sssd"
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        sufficient    pam_sss.so forward_pass
auth        required      pam_faillock.so authfail deny=5 unlock_time=900
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3
password    sufficient    pam_unix.so sha512 shadow use_authtok remember=5
password    sufficient    pam_sss.so use_authtok
password    required      pam_deny.so

session     required      pam_limits.so
session     optional      pam_sss.so
session     required      pam_unix.so
EOF
    cp "$R/etc/pam.d/system-auth" "$R/etc/pam.d/password-auth"

    cat > "$R/etc/login.defs" <<'EOF'
MAIL_DIR        /var/spool/mail
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_MIN_LEN    14
PASS_WARN_AGE   14
UID_MIN         1000
UID_MAX         60000
CREATE_HOME     yes
UMASK           077
ENCRYPT_METHOD  SHA512
EOF

    cat > "$R/etc/security/pwquality.conf" <<'EOF'
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
enforcing = 1
EOF

    # A drop-in that CONTRADICTS the hardened main file below.
    #
    # This is the RHEL 9 / current-Ubuntu layout: sshd_config opens with an
    # Include of this directory, and sshd honours the FIRST occurrence of a
    # keyword, so what is set here WINS over the main file. A vendor or a change
    # ticket dropping a file in here is how a host that reads as hardened ends up
    # permitting root login and password authentication.
    #
    # The fixture is built this way deliberately: a collector that reads only
    # sshd_config reports "PermitRootLogin no" on this host, which is not what
    # the daemon enforces. Reporting the wrong value confidently is worse than
    # reporting nothing, so verify_os asserts that BOTH values reach the report
    # and that the precedence is explained.
    mkdir -p "$R/etc/ssh/sshd_config.d"
    cat > "$R/etc/ssh/sshd_config.d/50-vendor-remote-support.conf" <<'EOF'
# Added by vendor remote-support onboarding, CHG0041882
PermitRootLogin yes
PasswordAuthentication yes
EOF
    cat > "$R/etc/ssh/sshd_config" <<'EOF'
# Acme Financial hardened sshd (CIS RHEL8 baseline)
Include /etc/ssh/sshd_config.d/*.conf
Port 22
Protocol 2
PermitRootLogin no
MaxAuthTries 4
LoginGraceTime 60
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
GSSAPIAuthentication yes
UsePAM yes
X11Forwarding no
ClientAliveInterval 300
Banner /etc/ssh/banner
AllowGroups wheel appadmin dba auditors domainadmins
DenyUsers kwilson
EOF
    cat > "$R/etc/ssh/banner" <<'EOF'
********************************************************************************
*  ACME FINANCIAL - AUTHORIZED USE ONLY                                        *
*  All activity is logged and monitored. Unauthorized access is prohibited     *
*  and may be subject to criminal and civil penalties (SOX / GLBA).            *
********************************************************************************
EOF

    cat > "$R/etc/crontab" <<'EOF'
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=unixops@acmefinancial.com
17 3 * * *  root    /usr/local/sbin/patch-report.sh
30 2 * * 0  root    /usr/sbin/aide --check
EOF
    cat > "$R/etc/cron.d/finapp-batch" <<'EOF'
# Nightly finance batch close - owned by app team (CHG0044821)
0 1 * * *   svc_deploy  /opt/finapp/bin/nightly-close.sh >> /var/log/finapp/batch.log 2>&1
*/15 * * * * oracle     /u01/app/oracle/scripts/tablespace-check.sh
EOF
    cat > "$R/var/spool/cron/crontabs/root" <<'EOF'
0 6 * * 1 /usr/local/sbin/weekly-user-recert.sh
EOF
    cat > "$R/var/spool/cron/crontabs/oracle" <<'EOF'
0 4 * * * /u01/app/oracle/scripts/rman-backup.sh full
EOF

    cat > "$R/etc/rsyslog.conf" <<'EOF'
module(load="imuxsock")
module(load="imjournal" StateFile="imjournal.state")
*.info;mail.none;authpriv.none;cron.none   /var/log/messages
authpriv.*                                 /var/log/secure
# forward everything to the central SIEM over TLS
*.* action(type="omfwd" target="siem.corp.acmefinancial.com" port="6514"
           protocol="tcp" StreamDriver="gtls" StreamDriverMode="1")
EOF
    cat > "$R/etc/rsyslog.d/10-splunk.conf" <<'EOF'
authpriv.*  @@loghost.corp.acmefinancial.com:514
EOF
    cat > "$R/etc/audit/auditd.conf" <<'EOF'
log_file = /var/log/audit/audit.log
max_log_file = 50
max_log_file_action = ROTATE
num_logs = 10
space_left_action = SYSLOG
admin_space_left_action = SINGLE
disk_full_action = HALT
EOF
    cat > "$R/etc/systemd/journald.conf" <<'EOF'
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
SystemMaxUse=2G
EOF
    cat > "$R/etc/chrony.conf" <<'EOF'
server ntp1.corp.acmefinancial.com iburst
server ntp2.corp.acmefinancial.com iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
EOF

    cat > "$R/etc/issue" <<'EOF'
Acme Financial - Authorized access only. Activity is monitored.
EOF
    cp "$R/etc/issue" "$R/etc/issue.net"
    cat > "$R/etc/motd" <<'EOF'
-------------------------------------------------------------------------------
 rhel-fin-app01  |  PROD  |  Owner: UNIX Operations  |  App: FinApp GL close
 Patching: 3rd Sat monthly | Backups: NetBackup nightly | SOX in-scope: YES
-------------------------------------------------------------------------------
EOF
    cat > "$R/etc/profile.d/tmout.sh" <<'EOF'
# CIS 5.4.5 idle session timeout
TMOUT=900
readonly TMOUT
export TMOUT
EOF
    printf '# /etc/profile\numask 077\n' > "$R/etc/profile"
    printf '# /etc/bashrc\n[ -z "$TMOUT" ] && export TMOUT=900\n' > "$R/etc/bashrc"

    for u in jdoe asmith rjones mgarcia tchen svc_backup svc_deploy oracle; do
        mkdir -p "$R/home/$u/.ssh"
        chmod 700 "$R/home/$u/.ssh"
    done
    mkdir -p "$R/u01/app/oracle"
    cat > "$R/home/jdoe/.ssh/authorized_keys" <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2kf0lQ9jExampleKeyForJenniferDoeAdmin01 jdoe@corp-laptop
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgExampleBreakGlassKeyRotatedQuarterly02 jdoe@jump01
EOF
    cat > "$R/home/svc_deploy/.ssh/authorized_keys" <<'EOF'
command="/opt/finapp/bin/deploy.sh",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAADeployCIKeyFromJenkins03 jenkins@ci01
EOF
    chmod 600 "$R/home/jdoe/.ssh/authorized_keys" "$R/home/svc_deploy/.ssh/authorized_keys"

    # Legacy trust - the kind of finding auditors look for
    cat > "$R/home/oracle/.rhosts" <<'EOF'
+ oracle
db02.corp.acmefinancial.com oracle
EOF
    echo "dbnode02 root" > "$R/etc/hosts.equiv"

    mkdir -p "$R/opt/finapp/bin" "$R/opt/finapp/conf" "$R/opt/finapp/logs" \
             "$R/opt/finapp/lib" "$R/var/log/finapp"
    # An application root whose path contains a space, deliberately outside the
    # standard scanned paths so it is reachable ONLY as an --app-dir root. If the
    # roots are ever word-split again, find gets "/srv/Finance" and "App", scans
    # neither, and the report shows a clean result for a tree it never examined.
    mkdir -p "$R/srv/Finance App/bin"
    printf '#!/bin/bash\n# FinApp deploy hook\nexit 0\n' > "$R/opt/finapp/bin/deploy.sh"
    chmod 755 "$R/opt/finapp/bin/deploy.sh"
    printf 'app.env=PROD\ndb.url=jdbc:oracle:thin:@db01:1521/FINPDB\n' > "$R/opt/finapp/conf/app.properties"
    : > "$R/opt/finapp/logs/finapp.log"
    : > "$R/opt/finapp/lib/finapp-core-4.2.1.jar"
    : > "$R/opt/finapp/bin/runas_oracle"
    chmod 4755 "$R/opt/finapp/bin/runas_oracle"

    cat > "$R/etc/.sim_last" <<'EOF'
jdoe     pts/0        10.20.4.15       Tue Jun 16 14:02   still logged in
asmith   pts/1        10.20.4.31       Tue Jun 16 13:41 - 14:10  (00:29)
svc_dep  pts/2        10.30.1.9        Tue Jun 16 01:00 - 01:04  (00:04)
root     pts/0        10.20.4.15       Mon Jun 15 09:15 - 17:40  (08:25)
kwilson  pts/3        198.51.100.77    Fri Jun 12 22:14 - 22:19  (00:05)
reboot   system boot  4.18.0-553.16.1. Fri Jun 12 06:03   still running

wtmp begins Fri Jun 12 06:03:52 2024
EOF
    cat > "$R/etc/.sim_df" <<'EOF'
Filesystem                   1K-blocks      Used Available Use% Mounted on
/dev/mapper/rhel-root         52403200  31882624  20520576  61% /
/dev/mapper/rhel-var          20961280  14203904   6757376  68% /var
/dev/mapper/rhel-varlog       10475520   7340032   3135488  71% /var/log
/dev/mapper/vg_data-u01      524288000 402653184 121634816  77% /u01
/dev/sda1                       999320    215040    784280  22% /boot
EOF
    cat > "$R/etc/.sim_setuid" <<'EOF'
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/libexec/openssh/ssh-keysign
/opt/finapp/bin/runas_oracle
EOF
    cat > "$R/etc/.sim_setgid" <<'EOF'
/usr/bin/write
/usr/bin/ssh-agent
/usr/sbin/postdrop
EOF
    # The finding that matters most: nightly-close.sh is executed by the
    # svc_deploy cron job in /etc/cron.d/finapp-batch AND is world-writable, so
    # any account on the host can alter what that scheduled job runs. Section 10
    # must surface it so it can be cross-referenced against the cron evidence.
    chmod 0777 "$R/opt/finapp/bin/nightly-close.sh" 2>/dev/null || \
        { printf '#!/bin/bash\nexit 0\n' > "$R/opt/finapp/bin/nightly-close.sh"; chmod 0777 "$R/opt/finapp/bin/nightly-close.sh"; }
    chmod 0777 "$R/opt/finapp/logs"
    printf '#!/bin/sh\nexit 0\n' > "$R/srv/Finance App/bin/rating.sh"
    chmod 0666 "$R/srv/Finance App/bin/rating.sh"
    cat > "$R/etc/.sim_ww_files" <<'EOF'
/opt/finapp/bin/nightly-close.sh
/etc/finapp-shared.conf
/srv/Finance App/bin/rating.sh
EOF
    cat > "$R/etc/.sim_ww_dirs" <<'EOF'
/opt/finapp/logs
EOF
    printf 'shared.mode=rw\n' > "$R/etc/finapp-shared.conf"
    chmod 0666 "$R/etc/finapp-shared.conf"

    cat > "$R/var/log/secure" <<'EOF'
Jun 16 14:02:11 rhel-fin-app01 sshd[20441]: Accepted publickey for jdoe from 10.20.4.15 port 51122 ssh2: ED25519 SHA256:abc123
Jun 16 14:02:11 rhel-fin-app01 sshd[20441]: pam_unix(sshd:session): session opened for user jdoe by (uid=0)
Jun 16 14:03:44 rhel-fin-app01 sudo:     jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/bin/systemctl restart tomcat
Jun 16 13:41:02 rhel-fin-app01 sshd[20388]: Accepted keyboard-interactive/pam for asmith from 10.20.4.31 port 40122 ssh2
Jun 16 01:00:03 rhel-fin-app01 sshd[19001]: Accepted publickey for svc_deploy from 10.30.1.9 port 33440 ssh2: ED25519
Jun 12 22:14:55 rhel-fin-app01 sshd[15522]: Failed password for kwilson from 198.51.100.77 port 55021 ssh2
Jun 12 22:15:07 rhel-fin-app01 sshd[15522]: error: maximum authentication attempts exceeded for kwilson from 198.51.100.77
Jun 15 09:15:22 rhel-fin-app01 su[8123]: pam_unix(su-l:session): session opened for user oracle by jdoe(uid=0)
EOF
    cat > "$R/var/log/sulog" <<'EOF'
SU 06/15 09:15 + pts/0 jdoe-oracle
SU 06/14 18:22 - pts/2 tchen-root
SU 06/16 08:05 + pts/0 jdoe-root
EOF
}

verify_os() {
    assert_report_matches 'Kernel Release: 4\.18\.0-553' 'RHEL kernel release reported'

    # sshd_config.d precedence. The fixture's drop-in re-enables root login and
    # password authentication over a main file that forbids both, which is the
    # scenario that makes reading only sshd_config actively misleading rather
    # than merely incomplete.
    assert_report_matches '50-vendor-remote-support\.conf' \
        'sshd_config.d drop-in file located and read'
    assert_report_matches 'PermitRootLogin yes' \
        'the drop-in value that actually takes effect is reported'
    assert_report_matches 'PermitRootLogin no' \
        'the overridden main-file value is still reported for comparison'
    assert_report_matches 'a value set in an included file OVERRIDES' \
        'precedence between the two is explained rather than left to the reader'
    assert_report_matches 'Include /etc/ssh/sshd_config\.d' \
        'the Include directive that creates the precedence is shown'
    sim_check
    if grep -q 'COPIED|/etc/ssh/sshd_config.d/50-vendor-remote-support.conf' "$E/metadata/MANIFEST.txt" 2>/dev/null; then
        sim_pass "the drop-in is delivered in raw_files/ and recorded in the manifest"
    else
        sim_fail "the drop-in was not copied into the evidence package"
    fi

    # Enumeration boundary: this fixture is SSSD-joined, so Section 24's
    # population is local-only and must say so.
    assert_report_matches 'THIS HOST IS CONFIGURED TO USE A DIRECTORY' \
        'Section 24 discloses that SSSD accounts are missing from the population'

    assert_report_matches 'passwd: +sss files' 'SSSD detected as the identity source'
    assert_report_matches 'SSSD configuration present: yes' 'sssd.conf detected'
    assert_report_matches 'pam_sss\.so' 'PAM SSSD module reference captured'
    assert_report_matches 'krb5' 'Kerberos configuration captured'
    assert_report_matches '%domainadmins ALL=\(ALL\) NOPASSWD: ALL' 'break-glass sudo rule captured'
    assert_report_matches '^- wheel: jdoe,asmith' 'wheel group membership resolved'
    assert_report_matches 'Command: rpm -qa' 'package inventory labelled with its command'
    assert_report_matches 'sssd-ldap' 'RPM inventory content captured'
    assert_report_matches 'Command: ss -lntup' 'listener enumeration labelled'
    assert_report_matches 'PASS_MAX_DAYS   90' 'password aging policy captured'
    assert_report_matches 'Authorized key entries: 2' 'authorized_keys summarized not printed'

    # Section 10: a world-writable script that a cron job executes is the finding
    # this section exists for, and it must be cross-referenceable with Section 12.
    assert_report_matches '/opt/finapp/bin/nightly-close\.sh' 'world-writable cron-executed script surfaced'
    assert_report_matches '/opt/finapp/logs' 'world-writable directory without sticky bit surfaced'
    assert_report_matches 'Sticky bit: present \(expected\)' 'sticky bit verified on shared temp directories'
    assert_report_matches 'Filesystem boundary: not crossed' 'scan limits disclosed in the report'
    # Both filesystem-walking scans must disclose the boundary, not just Section 10.
    sim_check
    _boundary_disclosures=`grep -c 'Filesystem boundary: not crossed' "$REPORT" 2>/dev/null`
    if [ "${_boundary_disclosures:-0}" -ge 2 ]; then
        sim_pass "both world-writable and SetUID scans disclose the boundary"
    else
        sim_fail "expected boundary disclosure in both scan sections, found ${_boundary_disclosures:-0}"
    fi
    # The operator-supplied application root is scanned in its own right, which is
    # what stops -xdev skipping an application tree that sits on its own mount.
    # An application root containing a space must survive as one argument. If the
    # roots are word-split again, find gets "/srv/Finance" and "App" and this tree
    # is silently skipped while the report still lists it.
    # The scan root must reach find as ONE argument. Asserted against the
    # arguments find was actually invoked with, not against the report text: the
    # report prints the roots from the same list, so a report-only check would
    # pass even while find received two nonexistent paths.
    sim_check
    if grep -qx '/srv/Finance App' "$FIND_ARGV" 2>/dev/null; then
        sim_pass "app root containing a space reached find as a single argument"
    else
        sim_fail "app root was split before reaching find; got: `tr '\n' ' ' < "$FIND_ARGV" 2>/dev/null`"
    fi
    # The word-split artefact must not appear anywhere in the report either.
    sim_check
    if grep -qE '^  App$|^  /srv/Finance$' "$REPORT" 2>/dev/null; then
        sim_fail "scan scope shows a word-split path fragment"
    else
        sim_pass "no word-split path fragments in the scan scope"
    fi
    assert_report_matches '/srv/Finance App/bin/rating\.sh' 'world-writable file inside the spaced app root found'
    # The same script must also appear as a scheduled job, so the two sections can
    # be joined during the review.
    assert_report_matches 'svc_deploy  /opt/finapp/bin/nightly-close\.sh' 'cron job referencing that script captured'
    # Under the cap the manifest must state an exact count and say so. The
    # over-cap case must never report the probe count as if it were the true
    # population; that is asserted by the wording checked here staying accurate.
    sim_check
    if grep -q 'WORLD_WRITABLE_SCAN|files|.*|truncated=no' "$MANIFEST" 2>/dev/null; then
        sim_pass "world-writable tally records whether the list was truncated"
    else
        sim_fail "world-writable manifest entry does not record truncation state"
    fi

    # Metadata only: the contents of a world-writable file must never be copied.
    sim_check
    if [ -f "$E/raw_files/opt/finapp/bin/nightly-close.sh" ]; then
        sim_fail "world-writable file contents copied into raw_files/"
    else
        sim_pass "world-writable file contents not copied"
    fi
    # /etc/shadow must be withheld
    # The nonexistent second app root must be warned about, in the log.
    sim_check
    if grep -q ' | WARN  | .*retired-app does not exist' "$LOGFILE" 2>/dev/null; then
        sim_pass "missing application directory raised a WARN in the collection log"
    else
        sim_fail "no WARN in the collection log for the missing /srv/retired-app"
    fi

    sim_check
    if grep -q '^/etc/shadow$' "$SKIPPED" 2>/dev/null; then
        sim_pass "/etc/shadow withheld from the package"
    else
        sim_fail "/etc/shadow not recorded as skipped"
    fi
}

sim_main
