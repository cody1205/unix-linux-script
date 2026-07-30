# Multi-OS simulation tests

Repeatable regression tests that run the **unmodified collector** against four
simulated "lived-in" company servers and assert properties of the evidence
package it produces.

```sh
sudo sh tests/simulations/run-all.sh            # all platforms
sudo sh tests/simulations/run-all.sh aix hpux   # selected platforms
sudo sh tests/simulations/os_aix.sh             # one platform
```

Root is required (chroot and bind mounts). Everything the harness creates lives
under `SIM_WORK` (default `/tmp/sox-itgc-sim`); nothing outside it is modified.

| Platform | Fixture host | Identity / SSO model | Notable content |
| --- | --- | --- | --- |
| RHEL 8 | `rhel-fin-app01` | SSSD → LDAP + Kerberos | break-glass sudo, stale contractor rule, Oracle/Tomcat, TLS syslog |
| openSUSE Leap 15.6 | `suse-erp-db02` | Samba **winbind** → AD | sudo granted to AD groups, SAP + PostgreSQL, disabled leaver |
| AIX 7.2 | `aix-fin-batch01` | `SYSTEM=LDAP` via secldapclntd | stanza security DB, SRC subsystems, DB2, `.rhosts` trust |
| HP-UX 11i v3 | `hpux-ins-app01` | PAM + LDAP-UX | `/etc/default/passwd` policy, SD-UX, telnet/r-services listening |

The two Linux fixtures deliberately use **different** authentication mechanisms
so both code paths are exercised: one has `sssd.conf`, the other has none and
must be recognized through winbind instead.

## Fidelity: what these are and are not

Real **AIX** runs only on IBM POWER and real **HP-UX** only on PA-RISC/Itanium,
so neither can boot on x86 hardware at all. Each fixture is therefore a chroot
containing:

- a themed root filesystem (accounts, sudoers, auth, SSH, cron, logging,
  banners, an application tree) built to look like a server that has been in
  production for years, and
- command shims (`uname`, `rpm`/`lslpp`/`swlist`, `ss`/`netstat`,
  `systemctl`/`lssrc`, `getent`, `passwd`/`chage`/`lsuser`, `last`, `df`, and a
  themed setuid `find`) that make the collector believe it is on that OS.

The host's `/usr` is bind-mounted read-only to supply a working userland, and
`/usr/sbin` is shadowed by the shim directory, which the collector's fixed
`PATH` searches first.

**For RHEL and openSUSE this is high fidelity** — a real Linux kernel runs the
real Linux code path against real files. **For AIX and HP-UX it is a
file- and command-layer simulation**: it drives the collector's genuine AIX and
HP-UX branches (uname dispatch, `/etc/security/user`, `/etc/default/passwd`,
`/etc/pam.conf`, `lslpp`, `lssrc`, `lsuser`, `swlist`, service-account
thresholds) against realistic data, but it is not a real AIX or HP-UX kernel.
Anything depending on real kernel behaviour, real filesystem semantics, or true
vendor command output still needs a real host.

## What is asserted

Every platform is checked for (see `common.sh`):

- the collector exits 0 and produces a report, manifest, and archive
- `uname` dispatch is honoured, so platform-specific assertions are meaningful
- **no hash or private-key material anywhere in `raw_files/`**
- no `authorized_keys` copied
- every `COPIED|` manifest entry actually exists in `raw_files/` — the chain of
  custody never claims a file it did not deliver
- manifest paths are well formed (no double slashes)
- all 25 numbered sections render

Each fixture then adds platform-specific assertions (`verify_os`) covering its
identity source, package tooling, sudo rules, password policy, and startup
model — plus, for AIX and HP-UX, that credential stores are withheld **and**
that the policy files beside them (`/etc/security/user`,
`/etc/default/passwd`) are still collected, so a future fix cannot over-block
and silently gut the evidence.

## Why this harness exists

The AIX fixture found a real defect: AIX keeps password hashes in
`/etc/security/passwd`, not `/etc/shadow`, and the collector was copying that
file into `raw_files/` in full — hashes would have been shipped to the auditor.

Note that **an end-to-end test on a Linux runner could not have caught it**,
because the AIX branch only executes when `uname -s` is `AIX`. That is the gap
these fixtures close, and it is why `tests/test-sensitive-paths.sh` also exists
as a fast hermetic check of the same classification logic.

Both were verified to fail when that fix is reverted (the AIX fixture reports
three independent failures) and to pass when it is restored.

## Adding a platform

Copy an existing `os_*.sh` and set the header variables (`OS_KEY`, `OS_LABEL`,
`UNAME_*`, `NODENAME`, `APPDIR`, `BLOCKERS`), then define three functions:

- `write_os_shims` — OS-specific commands, written into `$RSHIMS`
- `write_os_files` — themed fixture files, written under `$R`
- `verify_os` — assertions using `assert_report_matches`, `sim_pass`,
  `sim_fail`, `sim_check`

`BLOCKERS` lists commands that must appear **absent** on that OS (HP-UX blocks
`getent` so the file-read fallback is exercised). End the script with
`sim_main`, and add the key to `ALL` in `run-all.sh`.

## Safety

The harness runs as root with the host's `/usr` bind-mounted inside the fixture,
so teardown is guarded three ways: it refuses any path outside `SIM_WORK`, it
unmounts everything first, and it refuses to delete if any mount is still
present underneath. If teardown ever reports an incomplete unmount, do not
delete the tree by hand until `/proc/mounts` is clear.
