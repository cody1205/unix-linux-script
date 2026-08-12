# Running the SOX ITGC evidence collection script

**For the system administrator who will run this script.**

This page is self-contained. It covers what the script does to your server, how
to satisfy yourself of that independently, how to run it, and what to send back.

---

## In one paragraph

You will be asked to run a single shell script, once, as root. It reads
operating-system configuration relevant to access control — accounts, groups,
`sudo` rules, SSH settings, scheduled jobs, logging, patching, time sync, file
permissions — writes what it read into an output directory you choose, and
exits. It changes nothing, installs nothing, and sends nothing anywhere. It
takes a few minutes and needs no maintenance window.

---

## What it does to your system

**Nothing.** It is read-only.

It does not create, modify, delete, enable, disable, restart, or reconfigure any
user, group, service, scheduled job, permission, package, network setting,
firewall rule, log, or authentication setting.

Every system command it runs is a query or status form — the same commands you
would type to look at the system. It never runs an administrative command in a
form that changes state.

| | |
|---|---|
| **Writes** | Only inside the `--output-dir` you choose, plus the archive in that same directory. Nothing in `/tmp`, nothing in any system path. |
| **Sends** | Nothing. No network connections, no sockets, no outbound anything. |
| **Reads** | OS configuration relevant to access control. No user data, no application data, no databases. |
| **Never collects** | Password hashes (`/etc/shadow`, AIX `/etc/security/passwd`), SSH private keys, Kerberos keytabs, LDAP bind secrets. |
| **Needs** | Root via `sudo`, a few hundred MB of free space, typically 1–10 minutes. |
| **Requires** | No reboot, no restart, no maintenance window, no installation. |

Two details worth knowing before you run it:

- **Credential files are deliberately excluded.** For these the script records
  permissions and ownership — evidence that they are *protected* — but never
  contents. Every file treated this way is listed in
  `metadata/SENSITIVE_FILES_SKIPPED.txt` in the output, so you can confirm
  exactly what was withheld.
- **Two sections walk the filesystem** and account for nearly all the runtime: a
  scan for world-writable files and one for SetUID/SetGID binaries. Both are
  limited to system and application directories rather than whole filesystems,
  and **both stop at filesystem boundaries**, so neither can descend into NFS or
  SAN mounts and put load on a remote filer. Each reports its own elapsed time
  on screen as it runs.

## Don't take that on trust — check it

Each of these was run against the script itself and produces what is described.

**See what it does, without root and without collecting anything privileged:**

```sh
sh linux-unix-evidence-gathering-script.sh --dry-run --output-dir /var/tmp/x
```

**Prove it opens no network socket.** This observes actual system calls rather
than trusting the source or this page:

```sh
strace -f -e trace=network \
  sh linux-unix-evidence-gathering-script.sh --dry-run --output-dir /var/tmp/x \
  2>&1 >/dev/null | grep AF_INET
```

Prints nothing. On AIX or Solaris use `truss -f -t so_socket` instead.

**See every file it can write to.** Each write target is a variable; this lists
them:

```sh
grep -nE "^[^#]*(>|>>)[[:space:]]*\"?\\\$" \
  linux-unix-evidence-gathering-script.sh | grep -oE '\$[A-Z_]+' | sort -u
```

Returns five names, all of them files inside the output directory you choose.

**Read it.** It is plain text and commented throughout, including the reasoning
behind each decision and an explicit statement of its limitations. The header
block is written for you specifically.

> **One thing that looks alarming and isn't:** grepping the script for `telnet`
> or `ftp` returns matches. Those are in a section that searches *your*
> `inetd`/`xinetd` configuration for those service names, because an enabled
> telnet or ftp service is an audit finding. That is the script reading your
> configuration in order to report on it. The `strace` check above is the
> reliable test, because it observes behaviour rather than vocabulary.

---

## Before you run it: confirm the file arrived intact

Compare the checksum against the value supplied separately with this document:

```sh
sha256sum linux-unix-evidence-gathering-script.sh
```

On AIX, Solaris or HP-UX use whichever exists:

```sh
csum -h SHA256 linux-unix-evidence-gathering-script.sh   # AIX
digest -a sha256 linux-unix-evidence-gathering-script.sh # Solaris
```

**If the checksums do not match, stop and request a fresh copy. Do not run it.**

## Run it

```sh
sudo sh linux-unix-evidence-gathering-script.sh --output-dir /var/tmp/audit
```

- Run it with `sh` as shown. It does not need to be marked executable, and
  invoking it this way avoids depending on the execute bit surviving transfer.
- **The file extension does not matter.** If it arrived as `.txt` because a mail
  gateway rejected `.sh`, run `sudo sh <filename>.txt` — behaviour is identical.
- Choose any `--output-dir` you prefer. If you omit it, the script asks.
- To include an application installation directory in the evidence, add
  `--app-dir /path/to/app`. Repeatable. Please include the directories named in
  the request that accompanied this document.

**You can stop it at any time with Ctrl-C.** It marks its own output as
incomplete so a partial collection cannot be mistaken for a finished one, and
exits. Nothing is left half-done, because nothing was being changed.

**Exit status**, if you are running it from a script:

| Code | Meaning |
|---|---|
| `0` | The package is usable. Either nothing limited the collection, or some evidence was limited and the log records what. |
| `1` | The package is not usable — a step failed, or the arguments were invalid. |

---

## If it fails with strange syntax errors

Errors like these mean the file picked up Windows line endings in transfer, not
that the script is broken:

```
linux-unix-evidence-gathering-script.sh: 2: : not found
linux-unix-evidence-gathering-script.sh: 40: readonly: PATH: bad variable name
syntax error near unexpected token
```

The give-away is an error naming a line that looks perfectly ordinary when you
open the file. Each line simply has an invisible carriage return on the end.

Repair it, then **verify the repaired copy before running it**:

```sh
tr -d '\r' < linux-unix-evidence-gathering-script.sh > collector.sh
sha256sum collector.sh
```

The checksum of `collector.sh` **must equal the value supplied with this
document**. Removing the carriage returns restores the file to exactly the bytes
that were sent, so a correct repair reproduces the original checksum precisely.

- **Match** — the file was only damaged by line-ending conversion. Run it:
  `sudo sh collector.sh --output-dir /var/tmp/audit`
- **No match** — something other than line endings changed in transfer. **Stop
  and request a fresh copy.**

Please mention the repair when you return the results.

---

## What it produces, and what to send back

Inside your chosen output directory:

```
SOX-ITGC-AUDIT-LINUX-UNIX/                            the evidence, as a folder
SOX-ITGC-AUDIT-LINUX-UNIX-<host>-<timestamp>.tar.gz   the same, archived
```

**Please return the `.tar.gz` archive.** It contains everything.

The archive is owned by the account that invoked `sudo`, so it can be copied,
emailed, or uploaded without further root access. Because it describes access
control on a production system, please transfer it over an encrypted channel and
treat it as confidential.

### Before sending — a five-second check

The script prints a verdict for its own run when it finishes:

```
================================================================
COLLECTION RESULT: COMPLETED_CLEAN
  errors: 0   warnings: 0
  The collection completed and nothing limited the evidence gathered.
  Full log: /var/tmp/audit/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt
================================================================
```

If it has scrolled away, read it back from the log — substituting the output
directory you actually chose:

```sh
OUTDIR=/var/tmp/audit        # the --output-dir you used
grep -E "^(FINAL_)?RESULT:" "$OUTDIR/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt"
```

| Result | What to do |
|---|---|
| `COMPLETED_CLEAN` | Everything collected. Send it. |
| `COMPLETED_WITH_WARNINGS` | **Normal, and not a problem.** Some evidence was limited — usually files that could not be read. Send it; we will review the warnings. |
| `COMPLETED_WITH_ERRORS` or `FAILED` | Something went wrong. Please send the archive anyway **and** tell us, so we can work out what happened. |

`COMPLETED_WITH_WARNINGS` is the common outcome on a real system. If
`FINAL_RESULT` is present it supersedes `RESULT`.

### What is in the package

`COLLECTION-LOG.txt` is worth a look before you send it. It records what the
script did, in plain language, and contains **no file contents, no credentials,
and no command output** — only paths and outcomes. It is safe to read, forward
internally, or attach to a change ticket even where the evidence package itself
would not be.

---

## Questions we are often asked

**Can we review the script first?** Yes, please do. It is plain text and
commented throughout. The header block is addressed to you and states its
limitations explicitly.

**Can we run it in a test environment first?** Yes. `--dry-run` also works
without root, on any host.

**Will it affect performance?** The two filesystem scans generate metadata I/O
for the minute or two they run. They are scoped to system and application paths
and do not cross into network-mounted storage. If you would prefer a maintenance
window that is fine — nothing about it is time-sensitive.

**Does it phone home or transmit anything?** No. It makes no network connections
and contains no command that could. Verify it with the `strace` check above.

**Could it lock accounts, expire passwords, or change a shell?** No. Where a
platform's account-status command has a dangerous form — AIX `passwd -s` changes
a login shell rather than showing status — the script selects the safe form
explicitly per platform and never invokes the other. This is enforced by an
automated test that fails the build if the unsafe command is ever called.

**What if it is interrupted, or the server reboots mid-run?** Nothing is left in
a partial state, because nothing is being changed. The output directory may hold
an incomplete collection, which the script marks as incomplete. Delete it and
re-run, or send it and tell us.

**Does it need internet access?** No. It has been tested running with no network
interfaces present at all.

**What if we are not comfortable with part of it?** Tell us which part. The
script is modular and we would rather scope a section out and document why than
have you run something you are not happy with.
