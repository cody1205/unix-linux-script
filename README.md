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

Run it with `sh` rather than making it executable. The execute bit does not
survive email, FTP, or SharePoint, and naming the interpreter explicitly avoids
depending on the shebang being honoured — which matters on AIX and HP-UX, where
`/bin/sh` is not the shell a Linux user would expect. The file extension is
irrelevant to `sh`, so if a mail gateway rejects `.sh` you can send it as `.txt`
and the instruction is unchanged.

**[`CLIENT-INSTRUCTIONS.md`](CLIENT-INSTRUCTIONS.md) is the page to send to the
client's system administrator** — self-contained, covering what the script does
and does not do, how to verify it arrived intact, how to run it, how to recover
from Windows line endings, and what to send back.

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
            COLLECTION-LOG.txt             whether the collection itself worked
```

### Receiving and opening the package

Extract the archive **as your normal user account, not with sudo**. Extracting as
root makes `tar` restore the numeric user and group IDs recorded in the archive;
those come from the client system and mean nothing on yours, which is the usual
cause of an evidence package that will not open:

```sh
tar -xzf SOX-ITGC-AUDIT-LINUX-UNIX-<host>-<timestamp>.tar.gz
```

The package ships with `HOW-TO-READ-THIS-EVIDENCE.txt` at its top level covering
the same ground, so the guidance travels with the evidence rather than in a
separate document.

Permissions inside the package are deliberately not uniform:

- **`raw_files/` keeps the exact permissions each file had on the source system.**
  These are copies of the client's files and their modes are part of the
  evidence, so nothing rewrites them. One consequence: a source file readable
  only by its owner stays restrictive in the package, so a colleague opening it
  from a shared location may not be able to read every individual file. Take a
  copy and adjust the copy if that happens.
- **Everything else is normalised for handover** — the report, manifest,
  collection log, handling instructions, and all directories, at `0640` and
  `0750`. None of these existed on the client system, so their permissions are
  not evidence of anything. Directories are normalised throughout, including
  under `raw_files/`, because a directory that cannot be entered makes everything
  beneath it unreachable regardless of the files' own modes.

The whole package is owned by the operator who ran the collection. `MANIFEST.txt`
additionally records the permissions and ownership each file had on the source
system, which survives transfer even if filesystem metadata does not.

### Verify the package on receipt

Before anyone tests against a delivery, confirm the whole of it arrived. A
package can look complete — right folders, plausible file sizes — while being a
truncated delivery, and nothing in the files announces that.

```sh
sh tools/verify-package.sh SOX-ITGC-AUDIT-LINUX-UNIX-<host>-<timestamp>.tar.gz
```

It accepts either the archive or an extracted directory, is standalone POSIX
`sh`, and returns an exit code so it can gate an automated intake process:

| Exit | Meaning |
| --- | --- |
| `0` | Complete, and the collection reported no problems. |
| `1` | Complete, but the collection reported warnings. Usable — read them before relying on the affected sections. |
| `2` | Incomplete, truncated, or the collection reported errors. Request a fresh collection. |
| `3` | Could not be examined at all (missing, corrupt, not a package). |

It checks that the report reaches its execution summary and the log reaches its
verdict — both are written last, so their absence means the collection was
captured mid-write — that the manifest names no file the package lacks, and that
you can actually read what arrived.

`HOW-TO-READ-THIS-EVIDENCE.txt` inside every package carries a two-command
version of the same check, so a recipient without this repository can still tell
a complete delivery from a partial one.

### The collection log

The report says what the host is configured to do. `COLLECTION-LOG.txt` answers a
different question — *did this collection work, and is the evidence complete?* —
and is written for three readers at once: the auditor, the client's system
administrator, and an automated reader.

Each line is `timestamp | level | category | message`. `WARN` marks something
that limited the evidence; `ERROR` marks a step that failed. The file ends with a
summary block whose `RESULT` is one of:

| RESULT | Meaning |
| --- | --- |
| `COMPLETED_CLEAN` | Collection completed; nothing limited the evidence. |
| `COMPLETED_WITH_WARNINGS` | Completed, but some evidence was limited. Read the `WARN` lines before relying on the affected sections. |
| `COMPLETED_WITH_ERRORS` | A step failed; the package may be incomplete. |
| `FAILED` | Collection could not be completed; do not rely on the package. |

The distinction the log exists to draw: a file that is **absent** is normal, since
this script targets several Unix families and most hosts lack most of these paths.
A file that **exists but could not be read** is a genuine evidence gap. The report
renders both identically as "not available"; the log separates them, so a missing
`/etc/sudoers` is visible rather than buried among expected platform differences.

The log records paths and outcomes only — never file contents, credentials, or
command output — so it stays safe to forward to the client or paste into a ticket
even when the evidence package itself would not be. The operator also sees the
verdict on their terminal at the end of the run.

Credential-bearing files (`/etc/shadow`, AIX `/etc/security/passwd`, SSH keys,
keytabs, LDAP bind secrets) are never printed or copied. The script records
their metadata and a safe summary instead, logs them as
`SENSITIVE_METADATA_ONLY`, and lists them in `SENSITIVE_FILES_SKIPPED.txt`.

One credential store cannot be handled by path, because the file itself is
required evidence: **HP-UX without `pwconv`, and some older Solaris and
appliance builds, keep the password hash inline in field 2 of `/etc/passwd`.**
On such a host the script detects the hashes by content and delivers a
**redacted** copy — field 2 replaced with `<REDACTED-BY-COLLECTOR>`, every other
field reproduced exactly — so the account inventory survives intact and the
credentials do not leave the host. The substitution is stated in the file, in
the manifest as `COPIED_REDACTED`, in the skip list, and as a `WARN` in the
collection log, so a redacted value can never be mistaken for the host's real
configuration.

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
sh tests/test-inline-passwd-hashes.sh      # no root needed
sudo sh tests/test-no-credential-leak.sh   # runs a real collection
sudo sh tests/test-verify-package.sh       # the receipt verifier
sudo sh tests/simulations/run-all.sh       # all four simulated platforms
```

- **`test-sensitive-paths.sh`** asserts the `is_sensitive_path()` classification
  table across Linux, AIX, Solaris, and HP-UX conventions. It is hermetic, so
  platform-specific hash stores are checked even on a Linux runner. It also
  asserts that policy files (AIX `/etc/security/user`, HP-UX
  `/etc/default/passwd`) stay collectable, guarding against over-blocking.
- **`test-inline-passwd-hashes.sh`** covers the credential leak that a path
  table cannot catch. `/etc/passwd` must stay collectable — the account
  inventory is core evidence — but HP-UX without `pwconv` stores the crypt hash
  directly in field 2 of that file, so on such a host the collector would carry
  credentials out inside a file it is required to collect. The guard is a
  *content* check, and this asserts it against fixtures for each platform's
  conventions: DES, MD5, SHA-512, and yescrypt hashes must be detected, while
  `x`, `*`, `!`, `!!`, AIX `##user`, Solaris `NP`/`*LK*`, and NIS netgroup
  directives must not be mistaken for them.
- **`test-no-credential-leak.sh`** plants sentinel credentials, runs a full
  collection as root, then fails if any sentinel or credential-shaped content
  reaches `raw_files/`, if a sensitive file read is not recorded, or if the
  manifest claims a `COPIED` file that is not present. It restores `/etc` on
  exit and is intended for ephemeral CI runners.

- **`test-verify-package.sh`** produces a real package, then damages copies of it
  the way a delivery actually degrades — report cut short mid-write, log without
  its verdict, manifest naming files that never arrived, archive truncated in
  transfer — and requires `tools/verify-package.sh` to reject each with the right
  exit code. A checker that only passes on good input gives false assurance, so
  the failure cases are the point.

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
