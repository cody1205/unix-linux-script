# Running the SOX ITGC evidence collection script

This page is written to be sent to the system administrator who will run the
script. It is deliberately self-contained: everything they need to decide whether
to run it, how to run it, and what to send back.

---

## What this is

A single shell script that reads operating-system configuration and packages it
for review as part of a SOX IT General Controls audit. It covers accounts and
group membership, privileged access and `sudo` rules, authentication
configuration, SSH settings, scheduled jobs, logging, patching, time
synchronisation, and file permissions.

## What it does to your system

**Nothing.** The script is read-only. It does not create, modify, delete,
enable, disable, restart, or reconfigure any user, group, service, job,
permission, package, network setting, or authentication setting.

The only files it writes are inside the output directory you choose, plus the
resulting archive in that same directory. It states this in its own output, and
the collection log it produces records the same guarantee for your records.

Two things worth knowing before you run it:

- **Credentials are never collected.** Password hash files (`/etc/shadow`, AIX
  `/etc/security/passwd`), SSH private keys, Kerberos keytabs, and LDAP bind
  secrets are deliberately excluded. The script records their permissions and
  ownership — evidence that they are protected — but never their contents. Files
  treated this way are listed in `metadata/SENSITIVE_FILES_SKIPPED.txt` so you
  can confirm it.
- **Two sections walk the filesystem** and take longer than the rest: a scan for
  world-writable files and a scan for SetUID/SetGID binaries. Both are limited to
  system and application directories rather than the whole filesystem, and both
  stop at filesystem boundaries so they cannot reach into NFS or SAN mounts. Each
  reports its own runtime on screen as it goes.

## What you need

- Root access, via `sudo`
- Somewhere with a few hundred megabytes free for the output
- Typically 1–10 minutes, depending on the size of `/usr` and any application
  directories included

---

## Before you run it: confirm the file arrived intact

Compare the checksum against the value supplied separately with this document:

```sh
sha256sum linux-unix-evidence-gathering-script.sh
```

On AIX, Solaris or HP-UX, use whichever of these exists:

```sh
csum -h SHA256 linux-unix-evidence-gathering-script.sh   # AIX
digest -a sha256 linux-unix-evidence-gathering-script.sh # Solaris
```

If the checksums do not match, stop and request a fresh copy. Do not run it.

## Run it

```sh
sudo sh linux-unix-evidence-gathering-script.sh --output-dir /var/tmp/audit
```

Notes:

- Run it with `sh` as shown. The file does not need to be marked executable, and
  invoking it this way avoids depending on the execute bit surviving transfer.
- The file extension does not matter. If it arrived as `.txt` because a mail
  gateway rejected `.sh`, run `sudo sh <filename>.txt` — it behaves identically.
- Choose any `--output-dir` you prefer. If you omit it, the script asks.
- To include an application installation directory in the evidence, add
  `--app-dir /path/to/app`. The flag can be repeated. Please include the
  directories named in the request that accompanied this document.

To review what it will do without root and without collecting anything
privileged:

```sh
sh linux-unix-evidence-gathering-script.sh --dry-run --output-dir /var/tmp/audit
sh linux-unix-evidence-gathering-script.sh --help
```

The script is plain text and can be read in full before it is run.

---

## If it fails with strange syntax errors

Errors like these usually mean the file picked up Windows line endings somewhere
in transfer, not that the script is broken:

```
linux-unix-evidence-gathering-script.sh: 2: : not found
linux-unix-evidence-gathering-script.sh: 40: readonly: PATH: bad variable name
syntax error near unexpected token
```

The give-away is an error that names a line which looks perfectly ordinary when
you open the file. Nothing is wrong with the script; each line simply has an
invisible carriage return on the end.

Repair it, then **verify the repaired copy before running it**:

```sh
tr -d '\r' < linux-unix-evidence-gathering-script.sh > collector.sh
sha256sum collector.sh
```

The checksum of `collector.sh` **must equal the value supplied with this
document**. Removing the carriage returns restores the file to exactly the bytes
that were sent, so a correct repair reproduces the original checksum precisely.

- **Checksums match** — the file is intact and was only damaged by line-ending
  conversion. Run it:

  ```sh
  sudo sh collector.sh --output-dir /var/tmp/audit
  ```

- **Checksums do not match** — something other than line endings changed in
  transfer. Stop, and request a fresh copy. Do not run it.

Please mention the repair when you return the results, so we can note it.

---

## What it produces, and what to send back

Inside your chosen output directory:

```
SOX-ITGC-AUDIT-LINUX-UNIX/          the evidence, as a folder
SOX-ITGC-AUDIT-LINUX-UNIX-<host>-<timestamp>.tar.gz   the same, archived
```

**Please return the `.tar.gz` archive.** It contains everything.

The archive is owned by the account that invoked `sudo`, so it can be copied,
emailed, or uploaded without further root access. Because it describes access
control on a production system, please transfer it over an encrypted channel and
treat it as confidential.

### Before sending, a 5-second check

The script prints a verdict for its own run when it finishes. It looks like this,
and includes the path to its full log:

```
================================================================
COLLECTION RESULT: COMPLETED_CLEAN
  errors: 0   warnings: 0
  The collection completed and nothing limited the evidence gathered.
  Full log: /var/tmp/audit/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt
================================================================
```

If that has scrolled away, read it back from the log. Substitute the output
directory you actually chose — the path below is only the example used in this
document:

```sh
OUTDIR=/var/tmp/audit        # the --output-dir you used
grep -E "^(FINAL_)?RESULT:" "$OUTDIR/SOX-ITGC-AUDIT-LINUX-UNIX/metadata/COLLECTION-LOG.txt"
```

| Result | Meaning |
| --- | --- |
| `COMPLETED_CLEAN` | Everything collected. Send it. |
| `COMPLETED_WITH_WARNINGS` | Normal. Some evidence was limited — usually files the script could not read. Send it; we will review the warnings. |
| `COMPLETED_WITH_ERRORS` or `FAILED` | Something went wrong. Please send the archive anyway **and** tell us, so we can work out what happened. |

`COMPLETED_WITH_WARNINGS` is the common outcome on a real system and is not a
problem. If `FINAL_RESULT` is present it supersedes `RESULT`.

---

## Questions we are likely to be asked

**Can we review the script before running it?** Yes, please do. It is plain text
and commented throughout, including the reasoning behind each decision.

**Can we run it in a test environment first?** Yes. `--dry-run` also works
without root, on any host.

**Will it affect performance?** The two filesystem scans generate metadata I/O
for the minute or two they run. They are scoped to system and application paths
and do not cross into network-mounted storage. If you would prefer to run it in a
maintenance window, that is fine — nothing about it is time-sensitive.

**Does it phone home or transmit anything?** No. It makes no network connections.
It writes to the output directory and nowhere else.

**What if we are not comfortable with part of it?** Tell us which part. The
script is modular and we would rather scope a section out and document why than
have you run something you are not happy with.
