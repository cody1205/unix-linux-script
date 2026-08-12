# SOX ITGC evidence collection for Unix and Linux

`linux-unix-evidence-gathering-script.sh` performs a read-only collection of
operating-system control evidence — accounts, privileged access, authentication,
SSH, cron, logging, patching, time sync, file integrity — packages it into a
directory structure plus a `tar.gz` archive, and hands ownership of the output
to the operator who invoked `sudo` so it can be sent on without root.

Portable POSIX `sh`. Targets Linux, AIX, Solaris/Illumos, HP-UX, and BSD. It
makes no configuration changes to the host.

**Sending this to a client?** [`CLIENT-INSTRUCTIONS.md`](CLIENT-INSTRUCTIONS.md)
is the page to send to their system administrator — self-contained, and written
to answer their questions rather than ours.

---

## The four claims this tool makes, and how each is proved

A tool that runs as root on a client's production server, and whose output
becomes audit evidence, is only as good as the guarantees it can demonstrate.
Each claim below is asserted by a test that fails the build.

| Claim | How it is proved | Test |
|---|---|---|
| **It changes nothing on the host** | Records mode, owner, size, mtime and ctime for ~100,000 paths before and after a real collection; requires zero difference | `test-host-not-modified.sh` |
| **Nothing is transmitted** | Static audit for network-capable commands, `strace` syscall trace showing zero `AF_INET` sockets, and a full run inside a network namespace with no interfaces at all | `test-no-network-egress.sh` |
| **No credentials leave the host** | Sentinel credentials planted and a real collection run against them; plus a content-based guard for hosts that store hashes in `/etc/passwd` | `test-no-credential-leak.sh`, `test-inline-passwd-hashes.sh` |
| **Every source is accounted for** | Every path the report cites must be recorded in the manifest, and every delivered file must be explained — in both directions | `test-evidence-chain.sh` |

Three further properties matter for evidence quality rather than safety:

| Property | Test |
|---|---|
| A messy client filesystem is genuinely examined, not silently skipped — spaces, quotes, unicode, symlink loops, unreadable and deeply nested directories | `test-hostile-filesystem.sh` |
| The verdict never overstates what was collected, under no root, a full disk, or interruption | `test-degraded-environment.sh` |
| Two collections of an unchanged host agree byte for byte | `test-determinism.sh` |

## Usage

```sh
sudo sh linux-unix-evidence-gathering-script.sh --output-dir /var/tmp/audit
```

Run it with `sh` rather than making it executable: the execute bit does not
survive email, FTP, or SharePoint, and naming the interpreter avoids depending
on the shebang being honoured — which matters on AIX and HP-UX, where `/bin/sh`
is not the shell a Linux user expects. The extension is irrelevant to `sh`, so a
mail gateway that blocks `.sh` can be worked around by sending `.txt` with no
change to the instruction.

| Flag | Purpose |
| --- | --- |
| `--output-dir PATH` | Where the collection folder and archive are written. Prompts interactively if omitted. |
| `--app-dir PATH` | Include a recursive listing of an application install directory. Repeatable. |
| `--dry-run` | Non-root test run for pre-execution review. |
| `--help` | Usage and exit codes. |

| Exit | Meaning |
| --- | --- |
| `0` | The package is usable — clean, or with warnings recorded in the log. |
| `1` | The package is not usable, or the arguments were invalid. |

Warnings are the normal outcome on a live system and do not indicate failure.

## Output

```
SOX-ITGC-AUDIT-LINUX-UNIX/
├── report/    SOX-ITGC-AUDIT-REPORT.txt   the narrative audit report
├── raw_files/                             copied non-sensitive source files
└── metadata/  MANIFEST.txt                chain of custody for every file used
            SENSITIVE_FILES_SKIPPED.txt    credential files deliberately withheld
            COLLECTION-LOG.txt             whether the collection itself worked
```

The report says what the host is **configured to do**. The collection log
answers a different question — *did this collection work, and is the evidence
complete?*

### Receiving and opening the package

Extract the archive **as your normal user account, not with sudo**. Extracting as
root makes `tar` restore the numeric UIDs and GIDs recorded in the archive; those
come from the client system and mean nothing on yours, which is the usual cause
of an evidence package that will not open:

```sh
tar -xzf SOX-ITGC-AUDIT-LINUX-UNIX-<host>-<timestamp>.tar.gz
```

`HOW-TO-READ-THIS-EVIDENCE.txt` ships at the top level of every package covering
the same ground, so the guidance travels with the evidence.

Permissions inside the package are deliberately **not** uniform:

- **`raw_files/` keeps the exact permissions each file had on the source
  system.** These are copies of the client's files and their modes are part of
  the evidence, so nothing rewrites them. One consequence: a source file readable
  only by its owner stays restrictive here, so a colleague opening the package
  from a shared location may not be able to read every individual file. Take a
  copy and adjust the copy.
- **Everything else is normalised for handover** — report, manifest, log,
  handling instructions, and all directories, at `0640` and `0750`. None of these
  existed on the client system, so their permissions are not evidence.
  Directories are normalised throughout, including under `raw_files/`, because a
  directory that cannot be entered makes everything beneath it unreachable.

`MANIFEST.txt` records the permissions and ownership each file had on the source
system, which survives transfer even when filesystem metadata does not.

### Verify the package on receipt

A package can look complete — right folders, plausible file sizes — while being a
truncated delivery, and nothing in the files announces that.

```sh
sh tools/verify-package.sh SOX-ITGC-AUDIT-LINUX-UNIX-<host>-<timestamp>.tar.gz
```

Accepts either the archive or an extracted directory, is standalone POSIX `sh`,
and returns an exit code so it can gate an automated intake process:

| Exit | Meaning |
| --- | --- |
| `0` | Complete, and the collection reported no problems. |
| `1` | Complete, but the collection reported warnings. Usable — read them first. |
| `2` | Incomplete, truncated, or the collection reported errors. Request a fresh collection. |
| `3` | Could not be examined at all (missing, corrupt, not a package). |

It checks that the report reaches its execution summary and the log reaches its
verdict — both written last, so their absence means the collection was captured
mid-write — that the manifest names no file the package lacks, and that you can
actually read what arrived.

`HOW-TO-READ-THIS-EVIDENCE.txt` carries a two-command version of the same check,
so a recipient without this repository can still tell a complete delivery from a
partial one.

### The collection log

Each line is `timestamp | level | category | message`. `WARN` marks something
that limited the evidence; `ERROR` marks a step that failed. The file ends with a
summary block whose `RESULT` is one of:

| RESULT | Meaning |
| --- | --- |
| `COMPLETED_CLEAN` | Collection completed; nothing limited the evidence. |
| `COMPLETED_WITH_WARNINGS` | Completed, but some evidence was limited. Read the `WARN` lines before relying on the affected sections. |
| `COMPLETED_WITH_ERRORS` | A step failed; the package may be incomplete. |
| `FAILED` | Collection could not be completed; do not rely on the package. |

The distinction the log exists to draw: a file that is **absent** is normal,
since this script targets several Unix families and most hosts lack most of these
paths. A file that **exists but could not be read** is a genuine evidence gap.
The report renders both as "not available"; the log separates them, so a missing
`/etc/sudoers` is visible rather than buried among expected platform differences.

The log records paths and outcomes only — never file contents, credentials, or
command output — so it stays safe to forward to the client or paste into a ticket
even when the evidence package would not be.

### Credential handling

Credential-bearing files (`/etc/shadow`, AIX `/etc/security/passwd`, SSH keys,
keytabs, LDAP bind secrets) are never printed or copied. The script records their
metadata and a safe summary, logs them as `SENSITIVE_METADATA_ONLY`, and lists
them in `SENSITIVE_FILES_SKIPPED.txt`.

One credential store cannot be handled by path, because the file itself is
required evidence: **HP-UX without `pwconv`, and some older Solaris and appliance
builds, keep the password hash inline in field 2 of `/etc/passwd`.** On such a
host the script detects the hashes by content and delivers a **redacted** copy —
field 2 replaced with `<REDACTED-BY-COLLECTOR>`, every other field reproduced
exactly — so the account inventory survives intact and the credentials do not
leave the host. The substitution is stated in the file itself, in the manifest as
`COPIED_REDACTED`, in the skip list, and as a `WARN`, so a redacted value can
never be mistaken for the host's real configuration.

## Impact on the target host

The script is read-only: it does not create, modify, delete, enable, disable,
restart, or reconfigure anything. Everything is effectively instantaneous except
three sections that walk the filesystem. Each announces itself and reports its
elapsed time on the operator's terminal, and records start and end timestamps in
the report and manifest.

| Section | Cost | Bounded how |
| --- | --- | --- |
| 10 — world-writable | seconds to minutes | pruned scope, `find -xdev`, output capped at 500 entries per category |
| 11 — SetUID/SetGID | seconds to minutes | pruned scope, `find -xdev` |
| 23 — application directory listing | **unbounded**; only runs when `--app-dir` is given | not capped and not `-xdev`; the operator chooses the roots |

Sections 10 and 11 are pruned to system binary, system configuration, and
application installation paths rather than scanning whole filesystems, and both
use `find -xdev` so they cannot descend into NFS or SAN mounts and place load on
a remote filer. Both state their scope and limits in the report, so a reviewer
sees the bound on the evidence rather than assuming the population is complete.

Section 23 is the one to watch on a large estate. It is opt-in, but when a root
is supplied it recursively lists **every** file beneath it with no cap and without
stopping at filesystem boundaries. That is intentional — the operator named the
directory and the listing is the evidence — but it should be a considered choice.

## Known limitations

Stated here rather than discovered during an engagement:

- **`find -xdev` under-reports by design.** A separately mounted subdirectory
  beneath a scanned path is not traversed. The trade is deliberate — it prevents
  load on client network storage — and the boundary is disclosed in the report.
- **Section 24 depends on name-service enumeration.** SSSD and winbind disable
  enumeration by default while still resolving accounts by name, so on a
  directory-joined host the interactive-user list may be local accounts only. The
  script detects this case, says so in the report, and raises a `WARN`.
- **AIX and HP-UX are exercised by simulation, not on real hardware.** Neither
  boots on x86. The simulations reproduce the file and command layer faithfully
  enough to have caught a real credential leak and a real account-modification
  bug, but **a dry run on client hardware before the engagement remains
  advisable.**
- **Section 23 is unbounded** when used. See the table above.

## Tests

```sh
# No root required
sh tests/test-sensitive-paths.sh
sh tests/test-inline-passwd-hashes.sh

# Require root; run a real collection
sudo sh tests/test-host-not-modified.sh
sudo sh tests/test-no-network-egress.sh
sudo sh tests/test-evidence-chain.sh
sudo sh tests/test-hostile-filesystem.sh
sudo sh tests/test-degraded-environment.sh
sudo sh tests/test-determinism.sh
sudo sh tests/test-no-credential-leak.sh
sudo sh tests/test-verify-package.sh
sudo sh tests/simulations/run-all.sh      # all four simulated platforms
```

A note on how these are written: several of them assert the **absence** of
something — no host modification, no network socket, no `passwd` invocation on
AIX. Asserting an absence is the only way to test that a dangerous thing did not
happen, because checking for a missing section in the output would pass equally
well if the dangerous thing had happened and merely failed. Where a test guards
something that matters, it has been verified to fail when the guard is removed;
a test that only ever passes provides false assurance.

- **`test-sensitive-paths.sh`** asserts the `is_sensitive_path()` classification
  table across Linux, AIX, Solaris, and HP-UX conventions. Hermetic, so
  platform-specific hash stores are checked on a Linux runner. It also asserts
  that policy files stay collectable, guarding against over-blocking.
- **`test-inline-passwd-hashes.sh`** covers the credential leak a path table
  cannot catch. Asserts detection of DES, MD5, SHA-512 and yescrypt hashes in
  `/etc/passwd`, and non-detection of `x`, `*`, `!`, AIX `##user`, Solaris
  `NP`/`*LK*`, and NIS directives — over-detection would needlessly redact
  evidence, so both directions are pinned.
- **`test-no-credential-leak.sh`** plants sentinel credentials, runs a full
  collection as root, then fails if any sentinel or credential-shaped content
  reaches `raw_files/`, if a sensitive read is not recorded, or if the manifest
  overclaims. Restores `/etc` on exit; intended for ephemeral CI runners.
- **`test-verify-package.sh`** produces a real package, then damages copies the
  way a delivery actually degrades — report cut short, log without its verdict,
  manifest naming files that never arrived, archive truncated — and requires the
  verifier to reject each with the right exit code.

### Multi-OS simulation

`tests/simulations/` runs the collector against four themed "lived-in" servers —
RHEL 8 (SSSD/LDAP+Kerberos), openSUSE Leap 15.6 (AD via winbind), AIX 7.2
(`SYSTEM=LDAP`), and HP-UX 11i v3 (PAM + LDAP-UX) — and asserts what lands in the
evidence package. AIX and HP-UX cannot boot on x86, so those are file- and
command-layer simulations of their code paths; the two Linux fixtures run for
real. This is how the AIX password-hash leak was found, and how the AIX
`passwd -s` account-modification bug was caught. See
[`tests/simulations/README.md`](tests/simulations/README.md) for fidelity caveats
and how to add a platform.

CI (`.github/workflows/ci.yml`) runs every test above on each push and pull
request, plus `sh`/`dash`/`bash` parse checks, `checkbashisms`, a carriage-return
guard, and advisory ShellCheck.
