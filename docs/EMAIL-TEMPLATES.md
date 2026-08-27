# Client email templates

Two templates the engagement team sends when delivering the collector to a
client: the introduction email that goes out ahead of fieldwork with the bundle
and sample package attached, and the separate checksum email that follows it.

They are kept here so the whole practice pulls from one source. Forwarded copies
of old emails drift — a stale filename, a section list that no longer matches
the script — and the client is then reviewing a description of a tool they were
not sent. If the script's behaviour changes in a way these templates describe
(what it collects, what it withholds, the run commands), update the templates in
the same pull request.

Square brackets mark the parts to fill in. Everything else is ready to send.

The bold lead-ins are optional — in a plain-text mail client they read as
ordinary sentences.

---

## Template 1 — Introduction email

Send ahead of fieldwork, before any evidence is requested. Attach:

1. the release bundle — `sox-itgc-collector-[version].tar.gz`, built with
   `sh tools/make-release.sh [version]`
2. a sample evidence package from a lab system, so the client can see exactly
   what would come back from their own servers

Do **not** include the checksum in this email — that is what Template 2 is for.

**Subject:** SOX ITGC audit — Linux/Unix evidence collection script for your
team's review

> As part of the SOX IT General Controls audit, we will be asking your team to
> run a data collection script on the in-scope Linux/Unix server(s). Evidence is
> not being requested at this time — I'm sharing the script now, ahead of
> fieldwork, so your system administrators and/or security team have time to
> review it and raise any concerns before we schedule the collection itself.
>
> **What it does to your servers: nothing.** The script is read-only. It does
> not create, modify, delete, restart, or reconfigure anything — no users,
> services, jobs, permissions, packages, or settings. It makes no network
> connections and transmits nothing; everything it gathers is written to a
> single output folder on the server, which your administrator reviews and
> returns to us. These aren't just assurances: the script is plain text and
> commented throughout, so your team can read every line, and the attached
> instructions include commands your administrators can run themselves to
> independently verify each claim.
>
> **What it collects.** Operating-system configuration relevant to access
> controls: accounts and privileged access, password and authentication
> settings, SSH configuration, scheduled jobs, logging, patching, time
> synchronization, and file permissions. It does not read user data,
> application data, or databases.
>
> **What it never collects.** Password hashes, SSH private keys, Kerberos
> keytabs, and similar credential material are deliberately excluded — the
> script records that those files are properly protected, never their contents.
> Every file withheld this way is listed in
> `metadata/SENSITIVE_FILES_SKIPPED.txt` in the output, so your team can
> confirm it.
>
> **The sample package is the fastest way to get comfortable.** The second
> attachment is a real, complete output from one of our lab systems — the exact
> folder structure, report, and file inventory your administrator would be
> sending back. Ten minutes with it will answer most questions about precisely
> what evidence is gathered from your server(s).
>
> **When we do collect,** it is three commands per server, typically a few
> minutes each, with no maintenance window, reboot, or installation required:
>
> ```
> sha256sum sox-itgc-collector-[version].tar.gz     # checksum sent separately
> tar xzf sox-itgc-collector-[version].tar.gz
> sudo ./linux-unix-evidence-gathering-script.sh --output-dir /var/tmp/audit
> ```
>
> I'll send the checksum in a separate email — verifying the file against a
> value that traveled separately is what makes the check meaningful. The bundle
> includes a detailed instruction page (CLIENT-INSTRUCTIONS.md) covering
> everything above in depth, plus answers to the questions administrators
> usually ask — including how to try the script first without root privileges
> (`--dry-run`) and the fact that it can be safely stopped mid-run at any time.
>
> If your team isn't comfortable with any section of the script, please let us
> know which. The script is modular — we would rather comment out a section and
> document why than have you run something you're not happy with.
>
> We're also happy to set up a call if that's easier than email. Otherwise,
> once your team has reviewed the script and is comfortable running it on the
> in-scope servers, we can coordinate timing for the collection.

---

## Template 2 — Checksum email

Send after Template 1, as a **separate email** — never as a reply in the same
thread as the attachment, and never with the bundle attached. The checksum to
paste is the value `tools/make-release.sh` prints as **"SHA-256 of the
bundle"** (the first of the two checksums in its output; the second is the
collector inside the bundle, which the evidence report uses for a different
purpose).

"Separate" should mean genuinely separate where practical: a distinct email is
the accepted baseline, and reading the value over the phone or sending it
through the client's portal is stronger still. The point of the split is that
anyone who could alter the bundle in transit would also have to intercept and
alter a second, independent message.

**Subject:** SOX ITGC collection script — verification checksum

> Hi [name],
>
> This is the checksum for the collection bundle sent in my earlier email
> ([date/subject]). It is sent separately on purpose: verifying the file
> against a value that traveled by a different route is what confirms the
> bundle wasn't altered in transit.
>
> **File:** `sox-itgc-collector-[version].tar.gz`
> **SHA-256:** `[paste checksum here]`
>
> Before extracting, your administrator should run:
>
> ```
> sha256sum sox-itgc-collector-[version].tar.gz
> ```
>
> If the output matches the value above, proceed per the instructions in the
> bundle. If it does not match, don't run the script — let us know and we'll
> resend.
>
> Thanks,
> [name]
