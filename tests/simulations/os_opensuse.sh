#!/bin/sh
# openSUSE Leap 15.6 - "suse-erp-db02"
# A long-lived manufacturing ERP database server (SAP + PostgreSQL) joined to
# Active Directory via Samba winbind. Deliberately a DIFFERENT SSO model than the
# RHEL fixture's SSSD/LDAP+Kerberos, so both authentication code paths are
# covered: sudo rights are granted to AD groups and there is no sssd.conf.
. "`dirname "$0"`/common.sh"

OS_KEY=opensuse
OS_LABEL="openSUSE Leap 15.6"
UNAME_S=Linux
UNAME_R=5.14.21-150500.55.83-default
UNAME_V='#1 SMP PREEMPT_DYNAMIC Tue Jun 4 09:11:32 UTC 2024 (a1b2c3d)'
UNAME_M=x86_64
NODENAME=suse-erp-db02.ad.globexmfg.local
APPDIR=/opt/globex-erp
BLOCKERS=""

write_os_shims() {
    cat > "$RSHIMS/rpm" <<'EOF'
#!/bin/sh
case "$*" in
 *--last*)
   cat <<'L'
kernel-default-5.14.21-150500.55.83.1      Tue Jun  4 09:40:02 2024
samba-winbind-4.19.4-150500.3.30.1         Mon Jun  3 22:10:41 2024
sudo-1.9.9-150500.7.6.1                    Fri May 10 14:02:19 2024
chrony-4.5-150500.3.6.1                    Wed Apr 17 08:20:55 2024
L
   ;;
 *)
   cat <<'L'
kernel-default-5.14.21-150500.55.83.1.x86_64
glibc-2.31-150300.63.1.x86_64
systemd-249.17-150400.8.40.1.x86_64
samba-winbind-4.19.4-150500.3.30.1.x86_64
samba-client-4.19.4-150500.3.30.1.x86_64
sssd-winbind-idmap-2.9.1-150500.3.12.1.x86_64
krb5-1.20.1-150500.3.3.1.x86_64
pam-1.3.0-150000.6.61.1.x86_64
sudo-1.9.9-150500.7.6.1.x86_64
openssh-server-8.4p1-150300.3.30.1.x86_64
audit-3.0.6-150400.4.16.1.x86_64
rsyslog-8.2306.0-150600.1.8.x86_64
chrony-4.5-150500.3.6.1.x86_64
postgresql15-server-15.6-150600.1.3.x86_64
SAPHostAgent-7.22-150600.1.1.x86_64
globex-erp-agent-3.8.2-1.x86_64
falcon-sensor-7.14.0-16703.suse15.x86_64
L
   ;;
esac
EOF

    cat > "$RSHIMS/ss" <<'EOF'
#!/bin/sh
cat <<'L'
Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128           0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=1201,fd=3))
tcp   LISTEN 0      244         127.0.0.1:5432       0.0.0.0:*     users:(("postgres",pid=2410,fd=7))
tcp   LISTEN 0      128           0.0.0.0:5432       0.0.0.0:*     users:(("postgres",pid=2410,fd=8))
tcp   LISTEN 0      50            0.0.0.0:1128       0.0.0.0:*     users:(("saphostexec",pid=1777,fd=6))
udp   UNCONN 0      0             0.0.0.0:123        0.0.0.0:*     users:(("chronyd",pid=1004,fd=5))
L
EOF

    cat > "$RSHIMS/systemctl" <<'EOF'
#!/bin/sh
case "$*" in
 *list-unit-files*)
   cat <<'L'
UNIT FILE                    STATE     PRESET
auditd.service               enabled   disabled
chronyd.service              enabled   enabled
cron.service                 enabled   enabled
falcon-sensor.service        enabled   disabled
postgresql.service           enabled   disabled
saphostagent.service         enabled   disabled
sshd.service                 enabled   enabled
winbind.service              enabled   disabled
smb.service                  disabled  disabled
rsyslog.service              enabled   enabled

10 unit files listed.
L
   ;;
 *) exit 0;;
esac
EOF

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
   [ -z "$line" ] && { echo "passwd: user '$u' does not exist" >&2; exit 1; }
   h=`echo "$line"|cut -d: -f2`; lc=`echo "$line"|cut -d: -f3`
   mn=`echo "$line"|cut -d: -f4`; mx=`echo "$line"|cut -d: -f5`; wn=`echo "$line"|cut -d: -f6`
   case "$h" in ''|'!!') st=LK;; '!'*|'*'*) st=LK;; *) st=PS;; esac
   d=`date -d "@$((lc*86400))" +%Y-%m-%d 2>/dev/null`
   echo "$u $st $d ${mn:-0} ${mx:-99999} ${wn:-7} -1"
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
mx=`echo "$line"|cut -d: -f5`; wn=`echo "$line"|cut -d: -f6`; acct=`echo "$line"|cut -d: -f8`
pdate=`date -d "@$((lc*86400))" "+%b %d, %Y" 2>/dev/null`
if [ -n "$mx" ] && [ "$mx" -gt 0 ] 2>/dev/null; then edate=`date -d "@$(((lc+mx)*86400))" "+%b %d, %Y" 2>/dev/null`; else edate=never; fi
if [ -n "$acct" ] && [ "$acct" -gt 0 ] 2>/dev/null; then adate=`date -d "@$((acct*86400))" "+%b %d, %Y" 2>/dev/null`; else adate=never; fi
echo "Last password change                                    : $pdate"
echo "Password expires                                        : $edate"
echo "Password inactive                                       : never"
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
daemon:x:2:2:Daemon:/sbin:/usr/sbin/nologin
messagebus:x:499:499:User for D-Bus:/run/dbus:/usr/sbin/nologin
sshd:x:498:65531:SSH daemon:/var/lib/sshd:/usr/sbin/nologin
chrony:x:497:496:Chrony daemon:/var/lib/chrony:/usr/sbin/nologin
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash
sapadm:x:496:495:SAP Host Agent:/usr/sap:/bin/bash
winbind:x:495:494:Winbind daemon:/var/lib/samba:/usr/sbin/nologin
tprince:x:1000:100:Thomas Prince - SAP Basis Admin:/home/tprince:/bin/bash
lschmidt:x:1001:100:Lena Schmidt - Linux Admin:/home/lschmidt:/bin/bash
dkumar:x:1002:100:Deepak Kumar - DBA:/home/dkumar:/bin/bash
awong:x:1003:100:Alice Wong - ERP Functional:/home/awong:/bin/bash
pmueller:x:1004:100:Peter Mueller - Ext Auditor (RO):/home/pmueller:/bin/bash
rfoster:x:1005:100:Ray Foster - Ops (disabled - left co):/home/rfoster:/bin/bash
svc_saptrans:x:1200:100:SAP transport mover:/home/svc_saptrans:/bin/bash
svc_pgbackup:x:1201:100:Postgres backup account:/home/svc_pgbackup:/bin/bash
EOF

    # AD-mapped groups carry RID-range GIDs from the winbind idmap config.
    cat > "$R/etc/group" <<'EOF'
root:x:0:
daemon:x:2:
bin:x:1:
sys:x:3:
wheel:x:10:
users:x:100:
sshd:x:65531:
postgres:x:26:svc_pgbackup
sapsys:x:79:sapadm,tprince,svc_saptrans
dba:x:1500:dkumar,svc_pgbackup,postgres
erpadmin:x:1501:tprince,awong,svc_saptrans
linuxadmin:x:1502:lschmidt
auditors:x:1503:pmueller
AD__domain_admins:x:16777216:tprince
AD__erp-linux-sudo:x:16777320:tprince,lschmidt,dkumar
EOF

    # rfoster is disabled with a ! prefix after leaving the company.
    cat > "$R/etc/shadow" <<'EOF'
root:$6$Su5eLeap$aB1cD3eF5gH7iJ9kL1mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7:19680:1:365:7:::
daemon:*:19501::::::
sshd:!:19501::::::
chrony:!:19501::::::
winbind:!:19501::::::
postgres:$6$Pg15erp$cD3eF5gH7iJ9kL1mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7mN9:19670:1:90:7:::
sapadm:$6$Sap22ha$eF5gH7iJ9kL1mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7mN9oP1q:19660:1:90:7:::
tprince:$6$Tp99bas$gH7iJ9kL1mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7mN9oP1qR3s:19715:1:60:14:::
lschmidt:$6$Ls88lin$iJ9kL1mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7mN9oP1qR3sT5u:19708:1:60:14:::
dkumar:$6$Dk77dba$kL1mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7mN9oP1qR3sT5uV7wX:19690:1:60:14:::
awong:$6$Aw66erp$mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7mN9oP1qR3sT5uV7wX9yZ1a:19700:1:90:14:::
pmueller:$6$Pm55aud$oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7mN9oP1qR3sT5uV7wX9yZ1aB3:19712:1:90:14:::
rfoster:!$6$Rf44ops$qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7mN9oP1qR3sT5uV7wX9yZ1aB3cD5:19540:1:90:7:::
svc_saptrans:$6$Ss33trn$sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7mN9oP1qR3sT5uV7wX9yZ1aB3cD5eF7:19500:0:99999:7:::
svc_pgbackup:$6$Sp22bak$uV1wX3yZ5aB7cD9eF1gH3iJ5kL7mN9oP1qR3sT5uV7wX9yZ1aB3cD5eF7gH9:19500:0:99999:7:::
EOF
    chmod 000 "$R/etc/shadow"

    cat > "$R/etc/sudoers" <<'EOF'
## sudoers - Globex Manufacturing openSUSE build (SaltStack managed)
Defaults always_set_home
Defaults env_reset
Defaults secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults !targetpw
Defaults logfile="/var/log/sudo.log", log_input, log_output
Defaults timestamp_timeout=0

Cmnd_Alias PGADMIN = /usr/bin/psql, /usr/bin/pg_ctl, /usr/lib/postgresql15/bin/*
Cmnd_Alias SAPCTL  = /usr/sap/hostctrl/exe/saphostctrl, /usr/bin/systemctl restart saphostagent
Cmnd_Alias PKG     = /usr/bin/zypper

Host_Alias ERPDB = suse-erp-db02

root         ALL=(ALL) ALL
%wheel       ALL=(ALL) ALL
%linuxadmin  ALL=(ALL) NOPASSWD: ALL
%AD__erp-linux-sudo ERPDB=(ALL) NOPASSWD: SAPCTL, PKG, /usr/bin/systemctl
%dba         ALL=(postgres) NOPASSWD: PGADMIN
awong        ALL=(ALL) /usr/bin/less /var/log/globex-erp/*
svc_saptrans ALL=(sapadm) NOPASSWD: /usr/sap/trans/bin/tp

#includedir /etc/sudoers.d
EOF
    chmod 440 "$R/etc/sudoers"

    cat > "$R/etc/sudoers.d/globex_dba" <<'EOF'
# DBA on-call elevated - approved CHG globex CR-2024-1187
%dba ALL=(root) NOPASSWD: /usr/bin/systemctl restart postgresql, /usr/bin/journalctl -u postgresql
EOF
    cat > "$R/etc/sudoers.d/emergency" <<'EOF'
# break glass, synced from AD, reviewed semi-annually
%AD__domain_admins ALL=(ALL) NOPASSWD: ALL
EOF
    chmod 440 "$R/etc/sudoers.d"/*

    # winbind, not SSSD - deliberately no /etc/sssd/sssd.conf here
    cat > "$R/etc/nsswitch.conf" <<'EOF'
passwd: compat winbind
group:  compat winbind
shadow: compat
hosts:  files dns
netgroup: files
EOF

    cat > "$R/etc/pam.d/common-auth" <<'EOF'
auth    required    pam_env.so
auth    sufficient  pam_unix.so try_first_pass
auth    required    pam_winbind.so use_first_pass krb5_auth krb5_ccache_type=FILE
EOF
    cat > "$R/etc/pam.d/common-account" <<'EOF'
account requisite   pam_unix.so try_first_pass
account sufficient  pam_localuser.so
account required    pam_winbind.so
EOF
    cat > "$R/etc/pam.d/common-password" <<'EOF'
password requisite  pam_cracklib.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
password sufficient pam_unix.so use_authtok sha512 shadow remember=6
password required   pam_winbind.so use_authtok
EOF
    cat > "$R/etc/pam.d/common-session" <<'EOF'
session required    pam_limits.so
session required    pam_unix.so
session optional    pam_winbind.so
EOF
    cat > "$R/etc/pam.d/sshd" <<'EOF'
auth     include    common-auth
account  include    common-account
password include    common-password
session  include    common-session
EOF

    mkdir -p "$R/etc/samba"
    cat > "$R/etc/samba/smb.conf" <<'EOF'
[global]
    workgroup = AD
    realm = AD.GLOBEXMFG.LOCAL
    security = ADS
    kerberos method = secrets and keytab
    winbind use default domain = yes
    winbind refresh tickets = yes
    idmap config * : backend = tdb
    idmap config * : range = 10000-19999
    idmap config AD : backend = rid
    idmap config AD : range = 16777216-33554431
    template shell = /bin/bash
EOF

    cat > "$R/etc/login.defs" <<'EOF'
MAIL_DIR        /var/spool/mail
PASS_MAX_DAYS   60
PASS_MIN_DAYS   1
PASS_MIN_LEN    12
PASS_WARN_AGE   14
SYS_UID_MIN     100
SYS_UID_MAX     499
UID_MIN         1000
CREATE_HOME     yes
UMASK           077
ENCRYPT_METHOD  SHA512
EOF

    cat > "$R/etc/security/pwquality.conf" <<'EOF'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
EOF

    cat > "$R/etc/ssh/sshd_config" <<'EOF'
# Globex ERP DB - SUSE hardened sshd
Port 22
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 45
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
ClientAliveInterval 600
Banner /etc/ssh/banner
AllowGroups wheel linuxadmin erpadmin dba auditors AD__erp-linux-sudo
EOF
    cat > "$R/etc/ssh/banner" <<'EOF'
###############################################################################
# Globex Manufacturing - ERP Production Database (SAP + PostgreSQL)           #
# SOX in-scope system. All sessions are recorded.                             #
###############################################################################
EOF

    cat > "$R/etc/crontab" <<'EOF'
SHELL=/bin/bash
PATH=/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=basis-team@globexmfg.com
30 1 * * *  root         /usr/local/sbin/zypper-patchcheck.sh
0 2 * * *   svc_pgbackup /opt/globex-erp/bin/pg_backup.sh full >> /var/log/globex-erp/backup.log 2>&1
EOF
    cat > "$R/etc/cron.d/sap-trans" <<'EOF'
*/10 * * * * svc_saptrans /usr/sap/trans/bin/import_queue.sh
0 22 * * 5   sapadm       /usr/sap/hostctrl/exe/saphostctrl -function CheckUpdate
EOF
    printf '15 5 * * * /usr/local/sbin/ad-membership-recert.sh\n' > "$R/var/spool/cron/crontabs/root"
    printf '0 3 * * 0 /usr/lib/postgresql15/bin/vacuumdb --all --analyze\n' > "$R/var/spool/cron/crontabs/postgres"

    cat > "$R/etc/audit/auditd.conf" <<'EOF'
log_file = /var/log/audit/audit.log
max_log_file = 30
max_log_file_action = ROTATE
num_logs = 8
space_left_action = EMAIL
admin_space_left_action = SUSPEND
EOF
    cat > "$R/etc/systemd/journald.conf" <<'EOF'
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
SystemMaxUse=1G
EOF
    cat > "$R/etc/rsyslog.conf" <<'EOF'
$ModLoad imuxsock
$ModLoad imklog
auth,authpriv.*                 /var/log/messages
*.*;mail.none;authpriv.none     -/var/log/messages
# forward to the Globex central relay over RELP
*.*  @@rsyslog-relay.ad.globexmfg.local:6514
EOF
    cat > "$R/etc/rsyslog.d/remote.conf" <<'EOF'
# duplicate the auth stream to the SIEM collector
authpriv.*  @siem-collector.ad.globexmfg.local:514
EOF
    cat > "$R/etc/chrony.conf" <<'EOF'
pool ntp.ad.globexmfg.local iburst
driftfile /var/lib/chrony/drift
rtcsync
EOF

    cat > "$R/etc/issue" <<'EOF'
Globex Manufacturing openSUSE Leap 15.6
Authorized use only. This is a SOX-regulated production system.
EOF
    cp "$R/etc/issue" "$R/etc/issue.net"
    cat > "$R/etc/motd" <<'EOF'
===============================================================================
 suse-erp-db02 | PROD | SAP ERP + PostgreSQL 15 | Owner: Basis Team
 Change freeze: month-end close (last 3 business days). SOX in-scope: YES.
===============================================================================
EOF
    cat > "$R/etc/profile.d/timeout.sh" <<'EOF'
# idle shell timeout (Globex hardening standard GX-SEC-014)
readonly TMOUT=600
export TMOUT
EOF
    printf '# /etc/profile (openSUSE)\numask 077\n' > "$R/etc/profile"
    printf '# /etc/bash.bashrc stub\n: "${TMOUT:=600}"; export TMOUT\n' > "$R/etc/bashrc"

    for u in tprince lschmidt dkumar awong pmueller rfoster svc_saptrans svc_pgbackup postgres; do
        mkdir -p "$R/home/$u/.ssh"
        chmod 700 "$R/home/$u/.ssh"
    done
    mkdir -p "$R/var/lib/pgsql" "$R/usr/sap"
    cat > "$R/home/lschmidt/.ssh/authorized_keys" <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILenaSchmidtAdminWorkstationKey01 lschmidt@ws-admin-07
EOF
    cat > "$R/home/svc_pgbackup/.ssh/authorized_keys" <<'EOF'
from="10.40.2.0/24",command="/opt/globex-erp/bin/pg_backup.sh",no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADAQABPgBackupKeyFromBackupServer02 backup@bkp01
EOF
    chmod 600 "$R/home/lschmidt/.ssh/authorized_keys" "$R/home/svc_pgbackup/.ssh/authorized_keys"

    mkdir -p "$R/opt/globex-erp/bin" "$R/opt/globex-erp/conf" \
             "$R/opt/globex-erp/logs" "$R/var/log/globex-erp"
    printf '#!/bin/bash\n# nightly PostgreSQL basebackup\nexit 0\n' > "$R/opt/globex-erp/bin/pg_backup.sh"
    chmod 750 "$R/opt/globex-erp/bin/pg_backup.sh"
    printf 'erp.tier=PROD\ndb.host=localhost:5432\n' > "$R/opt/globex-erp/conf/erp.conf"
    : > "$R/opt/globex-erp/logs/erp.log"
    : > "$R/opt/globex-erp/bin/saprunas"
    chmod 4750 "$R/opt/globex-erp/bin/saprunas"

    cat > "$R/etc/.sim_last" <<'EOF'
tprince  pts/0        10.40.4.22       Tue Jun 16 15:10   still logged in
dkumar   pts/1        10.40.4.51       Tue Jun 16 14:55 - 15:20  (00:25)
svc_pgb  pts/2        10.40.2.14       Tue Jun 16 02:00 - 02:07  (00:07)
lschmidt pts/0        10.40.4.19       Mon Jun 15 08:30 - 18:02  (09:32)
rfoster  pts/4        203.0.113.44     Wed May 22 19:40 - 19:41  (00:01)
reboot   system boot  5.14.21-150500.5 Wed Jun  4 05:12   still running

wtmp begins Wed Jun  4 05:12:00 2024
EOF
    cat > "$R/etc/.sim_df" <<'EOF'
Filesystem                    1K-blocks      Used Available Use% Mounted on
/dev/system/root               41932800  22648832  17184768  57% /
/dev/system/var                20961280  12582912   8378368  61% /var
/dev/pg_vg/pgdata             838860800 512000000 326860800  62% /var/lib/pgsql
/dev/sap_vg/usrsap             52428800  33554432  18874368  64% /usr/sap
/dev/sda1                        524288    102400    421888  20% /boot
EOF
    cat > "$R/etc/.sim_setuid" <<'EOF'
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/su
/usr/bin/chfn
/usr/lib/ssh/ssh-keysign
/usr/sap/hostctrl/exe/saposcol
/opt/globex-erp/bin/saprunas
EOF
    cat > "$R/etc/.sim_setgid" <<'EOF'
/usr/bin/wall
/usr/bin/write
/usr/bin/crontab
EOF

    cat > "$R/var/log/messages" <<'EOF'
2024-06-16T15:10:44 suse-erp-db02 sshd[8821]: Accepted publickey for tprince from 10.40.4.22 port 49122 ssh2: ED25519
2024-06-16T15:12:02 suse-erp-db02 sudo:  tprince : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/systemctl restart saphostagent
2024-06-16T14:55:31 suse-erp-db02 sshd[8720]: Accepted keyboard-interactive/pam for dkumar from 10.40.4.51 port 51002 ssh2
2024-05-22T19:40:12 suse-erp-db02 sshd[30011]: Failed password for rfoster from 203.0.113.44 port 55210 ssh2
EOF
    # Deliberately NO dedicated /var/log/secure here. Stock openSUSE routes auth
    # and authpriv into /var/log/messages, so this fixture is what exercises the
    # collector's general-syslog fallback for Section 25. The RHEL fixture covers
    # the dedicated-auth-log path.
}

verify_os() {
    assert_report_matches 'Kernel Release: 5\.14\.21-150500' 'openSUSE kernel release reported'
    assert_report_matches 'passwd: compat winbind' 'winbind detected as the identity source'
    assert_report_matches 'SSSD configuration present: no' 'correctly reports no SSSD on this host'
    assert_report_matches 'pam_winbind\.so' 'PAM winbind module reference captured'
    assert_report_matches '%AD__domain_admins ALL=\(ALL\) NOPASSWD: ALL' 'AD break-glass sudo rule captured'
    assert_report_matches '%AD__erp-linux-sudo' 'sudo rights granted to an AD group captured'
    assert_report_matches 'samba-winbind' 'SUSE package inventory captured'
    assert_report_matches 'PASS_MAX_DAYS   60' 'password aging policy captured'
    assert_report_matches 'postgresql' 'database service evidence captured'
    assert_report_matches 'sampling general syslog /var/log/messages' 'general syslog fallback used when no dedicated auth log exists'
    assert_report_matches 'Accepted publickey for tprince' 'authentication events captured from general syslog'
    sim_check
    if grep -q '^/etc/shadow$' "$SKIPPED" 2>/dev/null; then
        sim_pass "/etc/shadow withheld from the package"
    else
        sim_fail "/etc/shadow not recorded as skipped"
    fi
}

sim_main
