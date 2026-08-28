#!/bin/sh
# Build the delivery bundle that is sent to a client.
#
# WHAT THIS PRODUCES
# One tar.gz holding the collector at mode 0755 and the client instructions at
# 0644, plus the SHA-256 you send to the client separately.
#
# WHY A TARBALL RATHER THAN THE BARE FILES
# The execute bit only survives transports that store POSIX modes. Emailing the
# .sh directly, putting it on SharePoint, or serving it over HTTP all deliver it
# as 0644, which is why the instructions have always had to say "run it with sh".
# tar records the mode, so the client extracts a file that is already executable
# and can run ./linux-unix-evidence-gathering-script.sh with no chmod step.
#
# The bundle also gives the engagement ONE checksum covering both the script and
# the instructions, instead of two values to track, and a version number that can
# be cited in workpapers - which is what stops a stale copy circulating unnoticed.
#
# WHAT THIS DOES NOT DO
# It makes no network calls and publishes nothing. It writes the bundle to the
# output directory and stops. How the bundle reaches the client - secure file
# transfer, email, their own scp from a workstation - is a human step, and
# deliberately so: the client's server never needs to reach the internet.
#
# Usage:
#   sh tools/make-release.sh                 # version defaults to the date
#   sh tools/make-release.sh v1.0            # explicit version
#   sh tools/make-release.sh v1.0 /tmp/out   # explicit output directory

set -u

REPO_ROOT=`CDPATH= cd -- "\`dirname -- "$0"\`/.." && pwd`
VERSION=${1:-}
OUTDIR=${2:-"$REPO_ROOT/dist"}

if [ -z "$VERSION" ]; then
    VERSION=`date '+%Y%m%d' 2>/dev/null || echo undated`
fi

COLLECTOR="linux-unix-evidence-gathering-script.sh"
INSTRUCTIONS="CLIENT-INSTRUCTIONS.md"
BUNDLE="sox-itgc-collector-$VERSION.tar.gz"

for required in "$COLLECTOR" "$INSTRUCTIONS"; do
    if [ ! -f "$REPO_ROOT/$required" ]; then
        printf 'FAIL: %s not found in %s\n' "$required" "$REPO_ROOT" >&2
        exit 1
    fi
done

# Refuse to ship carriage returns.
#
# This check runs BEFORE the parse check, and the order is the whole point.
# Carriage returns also break "sh -n", so with the checks the other way round a
# CRLF-damaged file was reported as "does not parse" - a true statement that
# sends the operator hunting for a syntax error when the actual repair is one
# tr command. The more specific diagnosis has to win, or the message is worse
# than useless.
if grep -qU "`printf '\r'`" "$REPO_ROOT/$COLLECTOR" 2>/dev/null; then
    printf 'FAIL: %s contains carriage returns (CRLF line endings).\n' "$COLLECTOR" >&2
    printf '      A bundle built from it would fail on the client host with errors\n' >&2
    printf '      naming lines that look perfectly ordinary when opened.\n' >&2
    printf '\n' >&2
    printf '      IF YOU ARE ON WINDOWS, this is almost certainly the cause, and\n' >&2
    printf '      the repository itself is fine: Git for Windows defaults to\n' >&2
    printf '      core.autocrlf=true and rewrote the file when it checked it out.\n' >&2
    printf '      The durable fix is already in the repository - a .gitattributes\n' >&2
    printf '      that pins LF - so update and refresh this working copy:\n' >&2
    printf '\n' >&2
    printf '          git pull\n' >&2
    printf '          git rm --cached -r .\n' >&2
    printf '          git reset --hard\n' >&2
    printf '\n' >&2
    printf '      A fresh clone works too, and needs no Git settings changed.\n' >&2
    printf '\n' >&2
    printf '      IF YOU ARE NOT ON WINDOWS, the file was damaged in transfer.\n' >&2
    printf '      Repair it, then confirm it still matches its published checksum:\n' >&2
    printf '          tr -d "\\r" < %s > f && mv f %s\n' "$COLLECTOR" "$COLLECTOR" >&2
    exit 1
fi

# Refuse to ship a script that does not parse. A bundle is the last point at
# which a broken collector can be caught before it becomes a client's problem,
# and the cost of the check is a few milliseconds.
if ! sh -n "$REPO_ROOT/$COLLECTOR" 2>/dev/null; then
    printf 'FAIL: %s does not parse; refusing to build a release\n' "$COLLECTOR" >&2
    sh -n "$REPO_ROOT/$COLLECTOR" 2>&1 | sed 's/^/      /' >&2
    exit 1
fi

STAGE=`mktemp -d`
trap 'rm -rf "$STAGE"' EXIT INT TERM

cp "$REPO_ROOT/$COLLECTOR"    "$STAGE/$COLLECTOR"
cp "$REPO_ROOT/$INSTRUCTIONS" "$STAGE/$INSTRUCTIONS"

# The whole point of the bundle. Set explicitly rather than inherited, so the
# result does not depend on the umask of whoever runs this.
chmod 0755 "$STAGE/$COLLECTOR"
chmod 0644 "$STAGE/$INSTRUCTIONS"

mkdir -p "$OUTDIR" || { printf 'FAIL: cannot create %s\n' "$OUTDIR" >&2; exit 1; }

# Resolve the output directory to an absolute path.
#
# Both the build and the self-verification below run inside "cd" subshells, so a
# RELATIVE output directory would be resolved against the staging directory
# rather than against the directory the operator is standing in. The build then
# fails with a partial write and a tar error, which is a confusing way to learn
# that "sh tools/make-release.sh v1.0 mydir" is not supported.
#
# This is the same defect class as the relative-path bug found in
# tools/verify-package.sh: a path taken from the caller, used after a directory
# change, without being anchored first.
OUTDIR=`CDPATH= cd -- "$OUTDIR" && pwd` || {
    printf 'FAIL: cannot resolve output directory\n' >&2
    exit 1
}

# -C so the archive holds bare filenames rather than a staging path. The client
# extracts two files into the directory they are standing in, with no surprise
# nesting.
if ! ( cd "$STAGE" && tar czf "$OUTDIR/$BUNDLE" "$COLLECTOR" "$INSTRUCTIONS" ); then
    printf 'FAIL: could not create %s\n' "$OUTDIR/$BUNDLE" >&2
    exit 1
fi

# Verify the bundle rather than assume it. Extract it to a scratch directory and
# confirm the collector really did come back executable - if it did not, the
# client would have to chmod it and the reason for building a bundle is gone.
VERIFY="$STAGE/verify"
mkdir -p "$VERIFY"
if ! ( cd "$VERIFY" && tar xzf "$OUTDIR/$BUNDLE" ); then
    printf 'FAIL: the bundle just built could not be extracted\n' >&2
    exit 1
fi
if [ ! -x "$VERIFY/$COLLECTOR" ]; then
    printf 'FAIL: the collector is NOT executable after extraction; the bundle is useless\n' >&2
    exit 1
fi
if ! sh -n "$VERIFY/$COLLECTOR" 2>/dev/null; then
    printf 'FAIL: the extracted collector does not parse\n' >&2
    exit 1
fi

checksum_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        printf 'unavailable'
    fi
}

BUNDLE_SUM=`checksum_of "$OUTDIR/$BUNDLE"`
SCRIPT_SUM=`checksum_of "$REPO_ROOT/$COLLECTOR"`

printf '\n'
printf '================================================================\n'
printf 'RELEASE BUNDLE BUILT\n'
printf '================================================================\n'
printf '\n'
printf 'File:     %s\n' "$OUTDIR/$BUNDLE"
printf 'Version:  %s\n' "$VERSION"
printf 'Contents: %s (0755, executable on extraction)\n' "$COLLECTOR"
printf '          %s (0644)\n' "$INSTRUCTIONS"
printf '\n'
printf 'SHA-256 of the bundle:\n'
printf '  %s\n' "$BUNDLE_SUM"
printf '\n'
printf 'SHA-256 of the collector inside it:\n'
printf '  %s\n' "$SCRIPT_SUM"
printf '  (this is the value the report prints as "Collector Script Checksum",\n'
printf '   so a returned package can be tied back to this exact release)\n'
printf '\n'
printf 'Send to the client:\n'
printf '  1. the bundle above, by your usual secure file transfer\n'
printf '  2. the bundle SHA-256, SEPARATELY - a different email, or by phone.\n'
printf '     Sending both together proves nothing: anyone who could alter one\n'
printf '     in transit could alter the other.\n'
printf '\n'
printf 'What they run on their server:\n'
printf '  sha256sum %s\n' "$BUNDLE"
printf '  tar xzf %s\n' "$BUNDLE"
printf '  sudo ./%s --output-dir /var/tmp/audit\n' "$COLLECTOR"
printf '\n'
printf 'Their server needs no internet access at any point.\n'
printf '================================================================\n'
