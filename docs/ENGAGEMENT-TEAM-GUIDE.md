# Engagement team guide: from getting the script to receiving the evidence

**Who this is for.** You are on an engagement with a Linux or Unix server in
scope, you have never used this tool, and you do not work in Linux or Unix.
That is fine — this guide assumes nothing. The client's system administrator
does all the technical work on their server. Your job is to deliver the tool,
coordinate, and receive the evidence, and every step of that is written out
below, one at a time.

**The one rule that matters most: you never touch the client's server.**
Everything you do happens on your own laptop and over email. The only person
who runs anything on the client's system is the client's own administrator.

The whole process, at a glance:

1. Open a terminal on your laptop (the only technical part, and it is three
   commands)
2. Build the delivery bundle and write down two checksums
3. Email the bundle to the client with the introduction email
4. Email the checksum — separately
5. Give the client time to review, and field their questions
6. The client runs the script and sends you back an archive file
7. Check the archive arrived intact
8. Know what is inside it

Steps 1, 2, and 7 use a terminal. Everything else is email and coordination.

---

## Step 1 — Open a terminal

A terminal is a window where you type commands instead of clicking. You will
type a handful of commands, all given below word for word — copy and paste
them.

| Your laptop | How to open a terminal |
| --- | --- |
| Windows | Install **Git for Windows** (free, from git-scm.com — IT can install it if your laptop is locked down). Then open **Git Bash** from the Start menu. Do **not** use PowerShell or Command Prompt — they cannot run these commands. |
| Mac | Open **Terminal** (Applications → Utilities → Terminal). Nothing to install. |

When the guide says "in your terminal", it means this window.

**One habit that will save you:** copy commands exactly, including every space,
dot, and slash. Terminals do exactly what you type, and a close-enough command
is a different command.

---

## Step 2 — Get the script and build the delivery bundle

The script is never sent to a client as a bare file. It is packaged into a
single compressed **bundle** (`sox-itgc-collector-<version>.tar.gz`) that also
contains the client's instruction page. The bundle keeps the files intact in
transit and arrives ready to run — the reasons are in the README if you want
them, but you do not need them to proceed.

In your terminal, type these three commands, pressing Enter after each. The
first one copies the current version of the tool onto your laptop:

```sh
git clone https://github.com/cody1205/unix-linux-script.git
cd unix-linux-script
sh tools/make-release.sh v1.0
```

Use the version number the tool owner tells you is current — `v1.0` here is an
example.

**If you have done this before** on the same laptop, do not rebuild from your
old copy — it may be months stale. Type this instead:

```sh
cd unix-linux-script
git pull
sh tools/make-release.sh v1.0
```

When the build finishes it prints a block that starts `RELEASE BUNDLE BUILT`.
Three things in it matter to you:

1. **The file it built** — a path ending in
   `dist/sox-itgc-collector-v1.0.tar.gz`. That file is what you will email to
   the client.
2. **"SHA-256 of the bundle"** — a long string of letters and numbers. This is
   the bundle's **checksum**: a fingerprint of the file. If even one byte of
   the file changes in transit, the fingerprint changes completely, which is
   how the client will prove the file arrived exactly as you sent it.
3. **"SHA-256 of the collector inside it"** — a second fingerprint, for the
   script itself. You will use it in Step 8 to prove the evidence you receive
   was produced by this exact release.

**Copy both checksums into your engagement workpapers now**, labeled so you
can tell them apart. You will need the first one in Step 4 and the second in
Step 8.

If the build prints `FAIL` instead, it has refused to package something that
would not have worked on the client's server. Read which failure it is:

- **`contains carriage returns`** — the common one on a Windows laptop, and it
  is self-service. Windows and Unix mark the end of a line differently, and Git
  may have converted the file when it copied it to your machine. The message
  prints the three commands that fix it; run them and build again. Nothing is
  wrong with the script or your copy of it.
- **Anything else** — stop and contact the tool owner.

Either way the guard did its job: the build refuses to produce a bundle it
cannot stand behind, which is much better than a client discovering it.

---

## Step 3 — Send the introduction email

Open [`EMAIL-TEMPLATES.md`](EMAIL-TEMPLATES.md) in this same folder and use
**Template 1**. It is ready to send — fill in the square brackets, and attach:

1. **The bundle** you just built (`dist/sox-itgc-collector-v1.0.tar.gz`)
2. **The sample evidence package** — a real output from a lab system, so the
   client can see exactly what would come back from their own servers. The
   practice keeps a current one; ask the tool owner if you do not have it.

Send it to your client contact, asking them to route it to whoever
administers the in-scope server(s).

**Do not put the checksum in this email.** That is the whole point of the next
step.

Send this well ahead of fieldwork. The email asks the client's administrators
and security team to review the script before anything is scheduled, and that
review is what makes the eventual collection smooth — a client who has read
the script rarely objects to running it.

---

## Step 4 — Send the checksum email (separately)

Use **Template 2** from the same file. Paste in the **bundle** checksum — the
first of the two you saved in Step 2.

This must be a **separate email**, not a reply in the same thread as the
attachment, and never with the bundle attached. Here is why, because clients
ask: the checksum proves the file was not altered between you and them. If the
file and its fingerprint travel together, anyone who could tamper with one
could tamper with both, and the check proves nothing. Two separate messages
mean an attacker would have to intercept both. Reading the value over the
phone or sending it through the client's portal is even better, and the
template works for those too.

---

## Step 5 — The client reviews, and you field questions

Give the client's technical team time with the script. Most questions they ask
are already answered, in writing, in the `CLIENT-INSTRUCTIONS.md` inside the
bundle — it covers what the script does to their server (nothing — it is
read-only), how to independently verify that, how to trial it without root
privileges, and the fact that it can be stopped mid-run at any time. If a
question sounds technical, the honest and correct answer is: *"That's covered
in the instruction page inside the bundle — and if anything there doesn't
satisfy your team, tell us which part."*

Two situations to handle specifically:

- **"We're not comfortable with section X."** Do not negotiate this yourself
  and do not tell them to edit the script. Bring it to the tool owner — the
  script is modular, and the practice would rather formally scope a section
  out and document why than have a client run something under protest.
- **"The checksums don't match."** The client should not unpack or run
  anything. Rebuild the bundle (Step 2) and resend both emails. This is the
  process working, not failing.

Once their team is satisfied, agree a date for the collection. It needs no
maintenance window and takes a few minutes per server, so this is usually
easy to schedule.

---

## Step 6 — The client runs the script

You do nothing technical in this step. The client's administrator runs three
commands on each in-scope server (they are in both the introduction email and
their instruction page): verify the checksum, unpack the bundle, run the
script with `sudo`.

What to tell the client to send back: **the archive file** the script
produces, named like

```
SOX-ITGC-AUDIT-LINUX-UNIX-<servername>-<timestamp>.tar.gz
```

one per server, over an **encrypted channel** — the firm's secure file
transfer, or the client's own portal, but not plain email. The archive
describes access control on a production system and is treated as
confidential from the moment it exists.

The script prints a result when it finishes. If the administrator mentions
`COMPLETED_WITH_WARNINGS`, reassure them: that is the normal outcome on a real
system, and their instruction page says to send the archive anyway. Only
`COMPLETED_WITH_ERRORS` or `FAILED` means something actually went wrong — ask
them to send the archive regardless, plus a note of what they saw, and loop in
the tool owner.

---

## Step 7 — Check the archive arrived intact

An archive can survive delivery looking complete while actually being
truncated or damaged, and nothing about the file's appearance tells you. The
tool includes a checker that answers exactly this question, so run it before
anyone tests against the evidence.

Put the received archive somewhere on your laptop, then in your terminal
(from your `unix-linux-script` folder):

```sh
sh tools/verify-package.sh /path/to/SOX-ITGC-AUDIT-LINUX-UNIX-servername-timestamp.tar.gz
```

Replace the path with where you actually saved the file. (On Windows, the
easiest way to get a file's path right in Git Bash is to type
`sh tools/verify-package.sh ` — with the trailing space — and then drag the
archive file into the terminal window, which pastes its path.)

It prints its findings and ends with a verdict:

| What it reports | What it means | What you do |
| --- | --- | --- |
| Clean (exit code 0) | Complete, and the collection reported no problems. | Proceed. |
| Warnings (exit code 1) | Complete and usable, but some evidence was limited — usually files the script was not permitted to read. | Proceed, but read the WARN lines it points at before relying on the affected report sections. |
| Incomplete or errors (exit code 2) | The delivery is truncated or the collection itself reported errors. | Do not test against it. Ask the client to re-send the archive; if the same result repeats, ask them to re-run the collection, and loop in the tool owner. |
| Cannot examine (exit code 3) | The file is missing, unreadable, or not an evidence package — usually a wrong path or a damaged download. | Check the path you typed and re-download from the transfer platform, then run the check again. |

Run it once per server's archive.

---

## Step 8 — Know what is inside

Unpacking the archive (in your terminal: `tar xzf` followed by the archive
path, or any zip tool that opens `.tar.gz` files) gives one folder,
`SOX-ITGC-AUDIT-LINUX-UNIX`, with three things in it:

| | |
| --- | --- |
| `report/SOX-ITGC-AUDIT-REPORT.txt` | **Start here.** The narrative report, organized in numbered sections by ITGC area — accounts and privileged access, authentication policy, SSH, scheduled jobs, logging, patching, and so on. Written to be read by an auditor, not an administrator. |
| `raw_files/` | Copies of every readable, non-sensitive file the report drew on, in folders mirroring where they live on the server. When you need to see the underlying configuration behind a report statement, it is in here. |
| `metadata/` | The chain of custody. `MANIFEST.txt` accounts for every source consulted — copied, examined, absent, unreadable, or deliberately withheld. `SENSITIVE_FILES_SKIPPED.txt` lists every credential file the script refused to collect (it records that they are protected, never their contents). `COLLECTION-LOG.txt` records whether the run itself worked, in plain language, with a verdict at the end. |

**One tie-back worth doing in your workpapers:** the report records the
checksum of the script that produced it, labeled `Collector Script Checksum`.
It must equal the **second** checksum you saved in Step 2 ("SHA-256 of the
collector inside it"). If it matches, you have documented, end to end, that
this evidence was produced by the exact release your firm reviewed and sent.
If it does not match, the client ran some other copy of the script — the
evidence is not automatically bad, but find out what they ran before relying
on it, and tell the tool owner.

From here it is an ordinary evidence review: the report for the findings, the
raw files for support, and the manifest when you need to show completeness.

---

## If you get stuck

| Symptom | Where the answer is |
| --- | --- |
| The client's administrator reports strange syntax errors running the script | Their `CLIENT-INSTRUCTIONS.md`, section *"If it fails with strange syntax errors"*. It is a known file-transfer issue with a two-command repair — and it cannot happen if they unpacked the bundle, so first ask whether they ran a loose copy of the script instead. |
| The client wants a section of the script scoped out | Tool owner. Never improvise this. |
| The verifier reports the package incomplete twice in a row | Ask for a re-run of the collection; loop in the tool owner. |
| Anything about what the script does or why | `CLIENT-INSTRUCTIONS.md` in the bundle first, then the README in this repository, then the tool owner. |

"Tool owner" throughout means whoever your practice has designated as
responsible for this tool. Ask your engagement leadership if you do not know
who that is.
