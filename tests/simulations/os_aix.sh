#!/bin/sh
# IBM AIX 7.2 TL5 - "aix-fin-batch01" (POWER9)
# A long-lived bank batch/settlement and DB2 server. Authentication is
# LDAP-backed via secldapclntd (per-user SYSTEM=LDAP stanzas), password hashes
# live in /etc/security/passwd, services run under SRC.
#
# This fixture found the credential leak that motivated the harness: AIX keeps
# password hashes in /etc/security/passwd, not /etc/shadow, and the collector
# was copying that file into raw_files/ in full.
#
# SIMULATION: real AIX runs only on IBM POWER, so this drives the collector's
# AIX code paths against realistic AIX data on an x86 kernel. See README.md.
. "`dirname "$0"`/common.sh"

OS_KEY=aix
OS_LABEL="IBM AIX 7.2 TL5 (simulated)"
UNAME_S=AIX
UNAME_R=2
UNAME_V=7
UNAME_M=00F8A24C4C00
NODENAME=aix-fin-batch01
APPDIR=/usr/lpp/corebank
# AIX ships none of these; it uses lslpp/lsuser instead.
BLOCKERS="dpkg chage"

write_os_shims() {
    cat > "$RSHIMS/lslpp" <<'EOF'
#!/bin/sh
case "$*" in
 *-h*)
   cat <<'L'
  Fileset                         Level     Action       Date       Time
  ----------------------------------------------------------------------------
  bos.rte                         7.2.5.100 COMMIT       06/02/24   09:14:33
  bos.net.tcp.client              7.2.5.100 COMMIT       06/02/24   09:14:35
  openssh.base.server             8.1.102.2100 COMMIT    05/11/24   22:03:10
  idsldap.clt64bit62.rte          6.4.0.20  COMMIT       04/18/24   08:22:41
L
   ;;
 *)
   cat <<'L'
  Fileset                      Level  State  Description
  ----------------------------------------------------------------------------
Path: /usr/lib/objrepos
  bos.rte                    7.2.5.100  C     Base Operating System Runtime
  bos.rte.security           7.2.5.100  C     Base Security Function
  bos.net.tcp.client         7.2.5.100  C     TCP/IP Client Support
  bos.mp64                   7.2.5.100  C     Base Operating System 64-bit MP
  openssh.base.client        8.1.102.2100 C   Open Secure Shell Commands
  openssh.base.server        8.1.102.2100 C   Open Secure Shell Server
  idsldap.clt64bit62.rte     6.4.0.20   C     IBM Directory Server - Client
  security.acf               7.2.5.0    C     ACF/PKCS11 Device Support
  db2_v115.db2engn           11.5.9.0   C     DB2 Engine
  tivoli.tsm.client.ba.64bit 8.1.21.0   C     TSM Backup-Archive Client
L
   ;;
esac
EOF

    cat > "$RSHIMS/lssrc" <<'EOF'
#!/bin/sh
cat <<'L'
Subsystem         Group            PID          Status
 syslogd          ras              4784356      active
 sshd             ssh              5243088      active
 xntpd            tcpip            6029500      active
 secldapclntd     ldap             5898962      active
 inetd            tcpip            4325658      active
 qdaemon          spooler          4128046      active
 ctrmc            rsct             3801220      active
 db2fmcd          -                6357190      active
 nfsd             nfs              -            inoperative
L
EOF

    # lsuser -a <attrs> ALL, synthesized from /etc/passwd plus fixture policy.
    # Note: avoid the awk variable name "exp" - it collides with awk's built-in.
    cat > "$RSHIMS/lsuser" <<'EOF'
#!/bin/sh
attrs=""
for a in "$@"; do
  case "$a" in -a|ALL) ;; *) attrs="$attrs $a";; esac
done
awk -F: -v attrs="$attrs" '
  $1=="" {next}
  {
    u=$1; shell=$7
    locked="false"; axp="0"; login="true"
    if (u=="tsmith") locked="true"
    if (u=="contract1") axp="0630245959"
    if (shell ~ /(nologin|false)$/) login="false"
    line=u
    n=split(attrs, A, " ")
    for(i=1;i<=n;i++){
      a=A[i]; v="0"
      if(a=="account_locked") v=locked
      else if(a=="expires") v=axp
      else if(a=="login") v=login
      else if(a=="shell") v=shell
      else if(a=="maxage") v="13"
      else if(a=="minage") v="1"
      else if(a=="pwdwarntime") v="14"
      line=line " " a "=" v
    }
    print line
  }
' /etc/passwd
EOF

    cat > "$RSHIMS/getent" <<'EOF'
#!/bin/sh
db=$1; key=${2:-}
f=/etc/$db
[ -f "$f" ] || exit 2
if [ -n "$key" ]; then awk -F: -v k="$key" '$1==k{print; e=1} END{exit !e}' "$f"; else cat "$f"; fi
EOF

    cat > "$RSHIMS/netstat" <<'EOF'
#!/bin/sh
cat <<'L'
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  *.512                  *.*                    LISTEN
tcp4       0      0  *.513                  *.*                    LISTEN
tcp4       0      0  *.60000                *.*                    LISTEN
tcp4       0      0  aix-fin-batch01.22     10.60.4.9.51122        ESTABLISHED
udp4       0      0  *.123                  *.*
L
EOF

    # AIX passwd has no -S; force the collector onto its lsuser fallback.
    printf '#!/bin/sh\nexit 1\n' > "$RSHIMS/passwd"

    chmod 0755 "$RSHIMS/lslpp" "$RSHIMS/lssrc" "$RSHIMS/lsuser" \
               "$RSHIMS/getent" "$RSHIMS/netstat" "$RSHIMS/passwd"
}

write_os_files() {
    # AIX uses "!" password placeholders and low UIDs for service accounts.
    cat > "$R/etc/passwd" <<'EOF'
root:!:0:0::/:/usr/bin/ksh
daemon:!:1:1::/etc:
bin:!:2:2::/bin:
sys:!:3:3::/usr/sys:
adm:!:4:4::/var/adm:
uucp:!:5:5::/usr/lib/uucp:
guest:!:100:100::/home/guest:
nobody:!:4294967294:4294967294::/:
sshd:*:203:201::/var/empty:/usr/bin/ksh
ldap:*:204:202::/home/ldap:/usr/bin/ksh
db2inst1:!:210:210:DB2 Instance Owner:/home/db2inst1:/usr/bin/ksh
db2fenc1:!:211:211:DB2 Fenced User:/home/db2fenc1:/usr/bin/ksh
jbanks:!:1001:200:Julia Banks - AIX Sysadmin:/home/jbanks:/usr/bin/ksh
rpatel:!:1002:200:Ravi Patel - DBA:/home/rpatel:/usr/bin/ksh
mokafor:!:1003:200:Michael Okafor - Batch Ops:/home/mokafor:/usr/bin/ksh
lgreen:!:1004:201:Laura Green - Internal Audit (RO):/home/lgreen:/usr/bin/ksh
tsmith:*:1005:200:Tim Smith - Admin (LEFT BANK):/home/tsmith:/usr/bin/ksh
contract1:!:1006:200:Contractor - Core Banking:/home/contract1:/usr/bin/ksh
svcbatch:!:1200:210:Nightly batch service account:/home/svcbatch:/usr/bin/ksh
EOF

    cat > "$R/etc/group" <<'EOF'
system:!:0:root,jbanks
staff:!:1:ipsec
bin:!:2:root,bin
sys:!:3:root,bin,sys
adm:!:4:bin,adm
security:!:7:root,jbanks
cron:!:8:root
audit:!:10:root,lgreen
sshd:!:201:
ldap:!:202:
dba:!:210:rpatel,db2inst1,svcbatch
aixadmin:!:200:jbanks,rpatel,mokafor,tsmith,contract1
auditors:!:201:lgreen
EOF

    # AIX password hashes. This file must never be copied into raw_files/ -
    # the {ssha512} markers below are what the common leak assertion detects.
    cat > "$R/etc/security/passwd" <<'EOF'
root:
	password = {ssha512}06$xqR3mKf9nLp2$Zk8RedactedHashMaterialaB
	lastupdate = 1717243200
	flags =

jbanks:
	password = {ssha512}06$Kf9Lm2Np5Rt7$qR3RedactedHashMaterialcD
	lastupdate = 1718020800
	flags =

tsmith:
	password = *
	lastupdate = 1701302400
	flags = ADMCHG

svcbatch:
	password = {ssha512}06$Rt6Yu8Io1Pq3$gH9RedactedHashMaterialeF
	lastupdate = 1704067200
	flags = NOCHECK
EOF
    chmod 000 "$R/etc/security/passwd"

    # Policy defaults plus per-user SYSTEM= stanzas naming the auth source.
    # This file has no hashes and MUST remain collectable.
    cat > "$R/etc/security/user" <<'EOF'
default:
	admin = false
	login = true
	su = true
	rlogin = true
	sugroups = ALL
	tpath = nosak
	ttys = ALL
	auth1 = SYSTEM
	umask = 077
	registry = files
	SYSTEM = "compat"
	pwdwarntime = 14
	account_locked = false
	loginretries = 4
	histexpire = 26
	histsize = 8
	minage = 1
	maxage = 13
	maxexpired = 2
	minalpha = 2
	minother = 2
	minlen = 8
	mindiff = 4
	maxrepeats = 2
	dictionlist = /usr/share/dict/words

root:
	registry = files
	SYSTEM = "compat"
	loginretries = 0
	rlogin = false
	admin = true

jbanks:
	SYSTEM = "LDAP or compat"
	registry = LDAP
	admin = true
	admgroups = security,aixadmin

rpatel:
	SYSTEM = "LDAP"
	registry = LDAP

tsmith:
	SYSTEM = "compat"
	registry = files
	account_locked = true

contract1:
	SYSTEM = "LDAP"
	registry = LDAP
	maxage = 4
	expires = 0630245959

svcbatch:
	SYSTEM = "compat"
	registry = files
	maxage = 0
	loginretries = 0
EOF

    # AIX LDAP client config embeds a bind password, so it is sensitive too.
    mkdir -p "$R/etc/security/ldap"
    cat > "$R/etc/security/ldap/ldap.cfg" <<'EOF'
ldapservers:ldap01.corp.bank.local,ldap02.corp.bank.local
binddn:cn=aixbind,ou=svc,dc=corp,dc=bank,dc=local
bindpwd:{DES}REDACTED
authtype:ldap_auth
useSSL:yes
userbasedn:ou=People,dc=corp,dc=bank,dc=local
groupbasedn:ou=Groups,dc=corp,dc=bank,dc=local
EOF
    chmod 600 "$R/etc/security/ldap/ldap.cfg"

    cat > "$R/etc/security/login.cfg" <<'EOF'
default:
	sak_enabled = false
	logindisable = 5
	logininterval = 300
	loginreenable = 30
	logindelay = 5
	herald = "\n\n*** aix-fin-batch01 - AUTHORIZED USE ONLY ***\n\nThis is a
regulated banking system. All activity is logged and reviewed under SOX and
FFIEC.\n\nlogin: "

usw:
	shells = /bin/sh,/bin/bsh,/bin/csh,/bin/ksh,/usr/bin/ksh,/usr/bin/bash
	maxlogins = 32
	logintimeout = 60
	auth_type = STD_AUTH
EOF

    cat > "$R/etc/sudoers" <<'EOF'
## /etc/sudoers - Core Bank AIX standard (manual change control)
Defaults        env_reset
Defaults        secure_path=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/etc
Defaults        logfile=/var/log/sudo.log
Defaults        timestamp_timeout=5
Defaults        requiretty

Cmnd_Alias      DB2ADMIN = /home/db2inst1/sqllib/adm/db2start, /home/db2inst1/sqllib/adm/db2stop, /usr/bin/db2
Cmnd_Alias      SRCCTL   = /usr/bin/startsrc, /usr/bin/stopsrc, /usr/bin/refresh
Cmnd_Alias      LVM      = /usr/sbin/mklv, /usr/sbin/extendlv, /usr/sbin/chfs, /usr/sbin/mount

User_Alias      SYSADMINS = jbanks, mokafor
Runas_Alias     DBRUN = db2inst1, db2fenc1

root            ALL=(ALL) ALL
%system         ALL=(ALL) ALL
SYSADMINS       ALL=(ALL) NOPASSWD: ALL
%dba            ALL=(DBRUN) NOPASSWD: DB2ADMIN
%aixadmin       ALL=(root)  SRCCTL, LVM
rpatel          ALL=(db2inst1) NOPASSWD: /usr/bin/db2
svcbatch        ALL=(root)  NOPASSWD: /usr/lpp/corebank/bin/run_nightly.ksh
# contractor - broad access, flagged by audit for removal after 06/30
contract1       ALL=(ALL) NOPASSWD: ALL

#includedir /etc/sudoers.d
EOF
    chmod 440 "$R/etc/sudoers"
    cat > "$R/etc/sudoers.d/db2_oncall" <<'EOF'
# DBA on-call - restart DB2 without a password during the batch window
%dba ALL=(root) NOPASSWD: /usr/bin/startsrc -s db2fmcd, /usr/bin/stopsrc -s db2fmcd
EOF
    chmod 440 "$R/etc/sudoers.d/db2_oncall"

    cat > "$R/etc/ssh/sshd_config" <<'EOF'
# AIX OpenSSH - Core Bank hardened
Port 22
PermitRootLogin no
MaxAuthTries 4
LoginGraceTime 60
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
ClientAliveInterval 300
Banner /etc/ssh/banner
AllowGroups system aixadmin dba auditors
DenyUsers tsmith
EOF
    cat > "$R/etc/ssh/banner" <<'EOF'
*******************************************************************************
*  CORE BANK - AIX PRODUCTION (aix-fin-batch01)                               *
*  Authorized access only. Regulated under SOX / FFIEC / GLBA.                *
*******************************************************************************
EOF

    # AIX has no crontab -l for other users here; spool files are the source.
    cat > "$R/var/spool/cron/crontabs/root" <<'EOF'
0 2 * * * /usr/lpp/corebank/bin/eod_settlement.ksh >/var/log/corebank/eod.log 2>&1
30 3 * * * /usr/sbin/mksysb -i /backup/mksysb.img
0 5 * * 1 /usr/local/sbin/user_recert.ksh
EOF
    cat > "$R/var/spool/cron/crontabs/db2inst1" <<'EOF'
0 1 * * * /home/db2inst1/scripts/db2_backup.ksh online
0 */6 * * * /home/db2inst1/scripts/db2_archive.ksh
EOF
    printf '15 0 * * * /usr/lpp/corebank/bin/run_nightly.ksh\n' > "$R/var/spool/cron/crontabs/svcbatch"

    cat > "$R/etc/syslog.conf" <<'EOF'
*.info;auth.none;authpriv.none    /var/adm/messages
auth.info                         /var/adm/authlog
authpriv.*                        /var/adm/authlog
*.emerg                           *
# forward everything to the enterprise syslog relay
*.debug                           @siem-relay.corp.bank.local
mail.debug                        /var/adm/maillog
EOF
    mkdir -p "$R/etc/security/audit"
    cat > "$R/etc/security/audit/config" <<'EOF'
start:
	binmode = on
	streammode = on

bin:
	trail = /audit/trail
	bin1 = /audit/bin1
	bin2 = /audit/bin2
	binsize = 10240
	freespace = 65536

classes:
	general = USER_SU,PASSWORD_Change,FILE_Owner,FILE_Mode,PROC_SetUserIDs
	authent = USER_Login,USER_Logout,USER_Remove,USER_Create,USER_Change
	files   = FILE_Open,FILE_Write,FILE_Unlink,FILE_Rename

users:
	root = general,authent,files
	jbanks = general,authent
	svcbatch = files
EOF
    cat > "$R/etc/ntp.conf" <<'EOF'
server ntp1.corp.bank.local prefer
server ntp2.corp.bank.local
driftfile /etc/ntp.drift
EOF

    cat > "$R/etc/inittab" <<'EOF'
init:2:initdefault:
brc::sysinit:/sbin/rc.boot 3 >/dev/console 2>&1
rc:23456789:wait:/etc/rc 2>&1 | alog -tboot > /dev/console
srcmstr:23456789:respawn:/usr/sbin/srcmstr
ssh:2:once:/usr/bin/startsrc -s sshd > /dev/console 2>&1
secldapclntd:2:once:/usr/bin/startsrc -s secldapclntd > /dev/console 2>&1
xntpd:2:once:/usr/bin/startsrc -s xntpd > /dev/console 2>&1
qdaemon:23456789:wait:/usr/bin/startsrc -sqdaemon
cron:23456789:respawn:/usr/sbin/cron
corebank:2:once:/usr/lpp/corebank/bin/start_listener.ksh > /dev/console 2>&1
EOF

    cat > "$R/etc/motd" <<'EOF'
*******************************************************************************
 aix-fin-batch01  |  AIX 7.2 TL5  |  Core Banking EOD/Settlement + DB2
 Owner: AIX Systems Group | Backups: mksysb + TSM | SOX in-scope: YES
*******************************************************************************
EOF
    cat > "$R/etc/issue" <<'EOF'
Core Bank AIX system - authorized use only. Monitored under SOX/FFIEC.
EOF
    cat > "$R/etc/profile" <<'EOF'
# /etc/profile (AIX)
TMOUT=900
readonly TMOUT
export TMOUT
export PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/sbin
EOF
    printf '# system-wide ksh rc\nTMOUT=900\nexport TMOUT\n' > "$R/etc/ksh.kshrc"

    # Legacy r-command trust - a serious audit finding on a regulated host.
    cat > "$R/etc/hosts.equiv" <<'EOF'
+ root
db2node02.corp.bank.local
batchnode03.corp.bank.local db2inst1
EOF
    mkdir -p "$R/home/db2inst1"
    cat > "$R/home/db2inst1/.rhosts" <<'EOF'
db2node02 db2inst1
+ +
EOF

    for u in jbanks rpatel mokafor lgreen tsmith contract1 svcbatch db2inst1; do
        mkdir -p "$R/home/$u/.ssh"
        chmod 700 "$R/home/$u/.ssh"
    done
    cat > "$R/home/jbanks/.ssh/authorized_keys" <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCjuliaBanksAIXAdminKeyRotated2024Q2 jbanks@admin-jump
EOF
    cat > "$R/home/svcbatch/.ssh/authorized_keys" <<'EOF'
command="/usr/lpp/corebank/bin/run_nightly.ksh",no-pty ssh-rsa AAAAB3NzaC1yc2EAAAABatchSchedulerKeyFromControlM svcbatch@ctrlm
EOF
    chmod 600 "$R/home/jbanks/.ssh/authorized_keys" "$R/home/svcbatch/.ssh/authorized_keys"

    mkdir -p "$R/usr/lpp/corebank/bin" "$R/usr/lpp/corebank/cfg" \
             "$R/usr/lpp/corebank/log" "$R/var/log/corebank"
    printf '#!/usr/bin/ksh\n# Core banking nightly batch\nexit 0\n' > "$R/usr/lpp/corebank/bin/run_nightly.ksh"
    chmod 755 "$R/usr/lpp/corebank/bin/run_nightly.ksh"
    printf 'env=PROD\ndb=DB2:COREPRD\n' > "$R/usr/lpp/corebank/cfg/corebank.cfg"
    : > "$R/usr/lpp/corebank/bin/setid_helper"
    chmod 4755 "$R/usr/lpp/corebank/bin/setid_helper"

    cat > "$R/var/log/sulog" <<'EOF'
SU 06/16 02:00 + pts/0 svcbatch-db2inst1
SU 06/15 22:14 - pts/2 contract1-root
SU 06/16 08:05 + pts/0 jbanks-root
SU 06/14 03:10 + ??? root-db2inst1
EOF
    cat > "$R/var/adm/authlog" <<'EOF'
Jun 16 02:00:01 aix-fin-batch01 auth|security:info sshd[5243088]: Accepted publickey for svcbatch from 10.60.2.14
Jun 16 08:05:12 aix-fin-batch01 auth|security:info sshd[5243120]: Accepted password for jbanks from 10.60.4.9
Jun 16 08:06:44 aix-fin-batch01 auth|security:notice sudo: jbanks : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/stopsrc -s db2fmcd
Jun 15 22:14:08 aix-fin-batch01 auth|security:info sshd[5243090]: Failed password for contract1 from 203.0.113.9
Jun 15 22:14:55 aix-fin-batch01 auth|security:notice sudo: contract1 : TTY=pts/2 ; USER=root ; COMMAND=/usr/bin/ksh
Jun 14 03:10:22 aix-fin-batch01 auth|security:info login: LOGIN on '/dev/pts/1' from 'batchnode03'
EOF

    cat > "$R/etc/.sim_df" <<'EOF'
Filesystem    1024-blocks      Used      Free %Used Mounted on
/dev/hd4          1048576    524288    524288   50% /
/dev/hd2         10485760   7340032   3145728   70% /usr
/dev/hd9var       4194304   2621440   1572864   63% /var
/dev/hd3          2097152    524288   1572864   25% /tmp
/dev/corelv      52428800  36700160  15728640   70% /usr/lpp/corebank
/dev/db2lv      209715200 146800640  62914560   70% /home/db2inst1
/dev/auditlv     10485760   5242880   5242880   50% /audit
EOF
    cat > "$R/etc/.sim_last" <<'EOF'
jbanks    pts/0        10.60.4.9         Jun 16 08:05   still logged in
svcbatch  pts/2        10.60.2.14        Jun 16 02:00 - 02:41  (00:41)
db2inst1  pts/1        aix-fin-batch01   Jun 16 01:00 - 05:30  (04:30)
contract1 pts/2        203.0.113.9       Jun 15 22:14 - 22:20  (00:06)
root      pts/0        10.60.4.9         Jun 15 18:22 - 19:10  (00:48)
reboot    ~            ~                 Jun 09 06:03

wtmp begins Jun  9 05:59
EOF
    cat > "$R/etc/.sim_setuid" <<'EOF'
/usr/bin/su
/usr/bin/passwd
/usr/bin/login
/usr/bin/sudo
/usr/sbin/sendmail
/usr/bin/rlogin
/usr/bin/rsh
/usr/lpp/corebank/bin/setid_helper
EOF
    cat > "$R/etc/.sim_setgid" <<'EOF'
/usr/bin/ipcs
/usr/sbin/lsps
/usr/bin/crontab
EOF
}

verify_os() {
    assert_report_matches 'Platform Family: AIX' 'AIX platform family reported'
    assert_report_matches 'Hardware Platform: 00F8A24C4C00' 'POWER machine id reported'
    # The AIX authentication summary parses per-user SYSTEM= stanzas.
    assert_report_matches 'SYSTEM = "LDAP' 'LDAP-backed authentication detected'
    assert_report_matches 'jbanks.*SYSTEM|SYSTEM.*LDAP or compat' 'per-user auth source captured'
    assert_report_matches 'Command: lslpp -L' 'fileset inventory labelled with its command'
    assert_report_matches 'bos\.rte\.security' 'AIX fileset inventory captured'
    assert_report_matches 'Command: lssrc -a' 'SRC subsystem listing labelled'
    assert_report_matches 'secldapclntd' 'LDAP client subsystem captured'
    assert_report_matches 'Command: netstat -an' 'network listing labelled'
    assert_report_matches 'contract1       ALL=\(ALL\) NOPASSWD: ALL' 'contractor sudo rule captured'
    assert_report_matches 'account_locked=true|account_locked = true' 'locked account status captured'
    assert_report_matches 'maxage = 13' 'AIX password aging policy captured'
    assert_report_matches 'Service account UID threshold: 100' 'AIX service-account cutoff applied'
    # On AIX the collector shows lssrc output for the startup section and lists
    # /etc/inittab as a source file rather than printing it inline, so the
    # evidence lands in raw_files/ instead of the report body.
    sim_check
    if [ -f "$E/raw_files/etc/inittab" ] && grep -q srcmstr "$E/raw_files/etc/inittab" 2>/dev/null; then
        sim_pass "/etc/inittab delivered as evidence"
    else
        sim_fail "/etc/inittab not delivered in raw_files/"
    fi

    # The regression this fixture exists to catch.
    sim_check
    if grep -q '^/etc/security/passwd$' "$SKIPPED" 2>/dev/null; then
        sim_pass "AIX /etc/security/passwd withheld from the package"
    else
        sim_fail "AIX /etc/security/passwd not recorded as skipped"
    fi
    sim_check
    if [ -f "$E/raw_files/etc/security/passwd" ]; then
        sim_fail "CREDENTIAL LEAK - /etc/security/passwd copied into raw_files/"
    else
        sim_pass "/etc/security/passwd absent from raw_files/"
    fi
    # The policy file next to it must still be collected, or the report is gutted.
    sim_check
    if [ -f "$E/raw_files/etc/security/user" ]; then
        sim_pass "/etc/security/user collected as evidence"
    else
        sim_fail "/etc/security/user missing from raw_files/ (over-blocked?)"
    fi
}

sim_main
