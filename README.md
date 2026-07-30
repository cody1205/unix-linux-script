# unix-linux-script

SOX ITGC evidence collection for Unix-like systems.

`linux-unix-evidence-gathering-script.sh` performs a read-only collection of
operating-system control evidence (accounts, privileged access, authentication,
SSH, cron, logging, patching, time sync, file integrity), packages it into a
directory structure plus a `tar.gz` archive, and transfers ownership of the
output to the operator who invoked `sudo` so it can be sent on without root.

It is portable POSIX `sh` and targets Linux, AIX, Solaris/Illumos, HP-UX, and
BSD. It makes no configuration changes to the host.

## Usage

```sh
sudo sh linux-unix-evidence-gathering-script.sh
```

| Flag | Purpose |
| --- | --- |
| `--output-dir PATH` | Where the collection folder and archive are written. Prompts interactively if omitted. |
| `--app-dir PATH` | Include a recursive listing of an application install directory. Repeatable. |
| `--dry-run` | Non-root test run for pre-execution review. |
| `--help` | Usage. |

## Output

```
SOX-ITGC-AUDIT-LINUX-UNIX/
├── report/    SOX-ITGC-AUDIT-REPORT.txt   the narrative audit report
├── raw_files/                             copied non-sensitive source files
└── metadata/  MANIFEST.txt                chain of custody for every file used
            SENSITIVE_FILES_SKIPPED.txt    credential files deliberately withheld
```

Credential-bearing files (`/etc/shadow`, AIX `/etc/security/passwd`, SSH keys,
keytabs, LDAP bind secrets) are never printed or copied. The script records
their metadata and a safe summary instead, and logs them as
`SENSITIVE_METADATA_ONLY`.

## Impact on the target host

The script is read-only: it does not create, modify, delete, enable, disable,
restart, or reconfigure anything on the host. Everything else is effectively
instantaneous, but three sections walk the filesystem and carry a real runtime
cost. Each announces itself and reports its elapsed time on the operator's
terminal, and records start and end timestamps in the report and manifest.

| Section | Cost | Bounded how |
| --- | --- | --- |
| 10 — world-writable | seconds to minutes | pruned scope, `find -xdev`, output capped at 500 entries per category |
| 11 — SetUID/SetGID | seconds to minutes | pruned scope, `find -xdev` |
| 23 — application directory listing | **unbounded**; only runs when `--app-dir` is given | not capped and not `-xdev`; the operator chooses the roots |

Sections 10 and 11 are pruned to system binary, system configuration, and
application installation paths rather than scanning whole filesystems, and both
use `find -xdev` so they cannot descend into NFS or SAN mounts and place load on
a remote filer. Both state their scope and limits in the report, so a reviewer
can see the bound on the evidence rather than assuming the population is
complete.

Section 23 is the one to watch on a large estate. It is opt-in, but when a root
is supplied it recursively lists **every** file beneath it with no cap and
without stopping at filesystem boundaries, so a root that is network-mounted or
holds millions of files will be slow and will produce a correspondingly large
report. That is intentional — the operator named the directory and the listing is
the evidence — but it should be a considered choice rather than a surprise.

## Tests

```sh
sh tests/test-sensitive-paths.sh           # no root needed
sudo sh tests/test-no-credential-leak.sh   # runs a real collection
sudo sh tests/simulations/run-all.sh       # all four simulated platforms
```

- **`test-sensitive-paths.sh`** asserts the `is_sensitive_path()` classification
  table across Linux, AIX, Solaris, and HP-UX conventions. It is hermetic, so
  platform-specific hash stores are checked even on a Linux runner. It also
  asserts that policy files (AIX `/etc/security/user`, HP-UX
  `/etc/default/passwd`) stay collectable, guarding against over-blocking.
- **`test-no-credential-leak.sh`** plants sentinel credentials, runs a full
  collection as root, then fails if any sentinel or credential-shaped content
  reaches `raw_files/`, if a sensitive file read is not recorded, or if the
  manifest claims a `COPIED` file that is not present. It restores `/etc` on
  exit and is intended for ephemeral CI runners.

### Multi-OS simulation

`tests/simulations/` runs the collector against four themed "lived-in" servers —
RHEL 8 (SSSD/LDAP+Kerberos), openSUSE Leap 15.6 (AD via winbind), AIX 7.2
(`SYSTEM=LDAP`), and HP-UX 11i v3 (PAM + LDAP-UX) — and asserts what lands in
the evidence package. AIX and HP-UX cannot boot on x86, so those are
file- and command-layer simulations of their code paths; the two Linux fixtures
run for real. This is how the AIX password-hash leak was found. See
[`tests/simulations/README.md`](tests/simulations/README.md) for fidelity
caveats and how to add a platform.

CI (`.github/workflows/ci.yml`) runs both unit tests, all four simulations in
parallel, plus `sh`/`dash`/`bash` parse checks, `checkbashisms`, and advisory
ShellCheck on every push and pull request.
