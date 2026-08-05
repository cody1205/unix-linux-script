#!/bin/sh
# Verify a SOX ITGC evidence package on receipt.
#
# Run this before anyone starts testing against a package. It answers one
# question: did the whole of this evidence arrive, and did the collection that
# produced it actually work? A package can look complete - correct folders,
# plausible file sizes - while being a truncated or degraded delivery, and
# nothing in the files themselves announces that. This checks the few facts that
# distinguish the two.
#
# It is deliberately standalone: no dependency on the collector's repository,
# nothing beyond POSIX sh, grep, sed and tar. Copy it wherever it is useful.
#
# Usage:
#   sh verify-package.sh SOX-ITGC-AUDIT-LINUX-UNIX-host-timestamp.tar.gz
#   sh verify-package.sh /path/to/SOX-ITGC-AUDIT-LINUX-UNIX
#
# Exit codes, chosen so this can gate an automated intake process:
#   0  package is complete and the collection reported no problems
#   1  package is complete but the collection reported warnings - usable, but
#      read the WARN lines before relying on the affected report sections
#   2  package is incomplete, truncated, or the collection reported errors -
#      do not rely on it; request a fresh collection
#   3  the package could not be examined at all (missing, unreadable, not a
#      package)

set -u

PROGRAM_NAME=`basename "$0" 2>/dev/null || echo verify-package.sh`
PACKAGE_DIR_NAME=SOX-ITGC-AUDIT-LINUX-UNIX

usage() {
    printf 'Usage: sh %s <package.tar.gz | package-directory>\n' "$PROGRAM_NAME"
    printf '\n'
    printf 'Verifies that an evidence package arrived complete and that the\n'
    printf 'collection which produced it reported no problems.\n'
    printf '\n'
    printf 'Exit codes: 0 clean, 1 warnings, 2 incomplete or errors, 3 unreadable\n'
}

TARGET=${1:-}
case "$TARGET" in
    ''|-h|--help)
        usage
        [ -n "$TARGET" ] && exit 0
        exit 3
        ;;
esac

if [ ! -e "$TARGET" ]; then
    printf 'CANNOT VERIFY: %s does not exist\n' "$TARGET" >&2
    exit 3
fi

WORK=""
cleanup() {
    if [ -n "$WORK" ] && [ -d "$WORK" ]; then
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT INT TERM

# Resolve the target to a package directory, extracting an archive if needed.
# Extraction happens as the invoking user on purpose: running tar as root
# restores the numeric ownership recorded on the client's system, which is the
# usual reason a package appears unreadable.
ROOT_DIR=""
case "$TARGET" in
    *.tar.gz|*.tgz|*.tar)
        if [ "`id -u 2>/dev/null`" = "0" ]; then
            printf 'NOTE: running as root. Extracting an evidence package as root\n'
            printf '      restores the ownership recorded on the client system and is\n'
            printf '      the usual cause of an unreadable package. Prefer running\n'
            printf '      this as your normal user account.\n'
            printf '\n'
        fi
        WORK=`mktemp -d 2>/dev/null` || {
            printf 'CANNOT VERIFY: could not create a temporary directory\n' >&2
            exit 3
        }
        if ! ( cd "$WORK" && tar -xf "$TARGET" ) 2>/dev/null; then
            # Retry without assuming the archive is compressed.
            if ! ( cd "$WORK" && tar -xzf "$TARGET" ) 2>/dev/null; then
                printf 'CANNOT VERIFY: %s could not be extracted. It may be corrupt or\n' "$TARGET" >&2
                printf 'truncated in transfer.\n' >&2
                exit 3
            fi
        fi
        if [ -d "$WORK/$PACKAGE_DIR_NAME" ]; then
            ROOT_DIR="$WORK/$PACKAGE_DIR_NAME"
        else
            ROOT_DIR=$WORK
        fi
        ;;
    *)
        if [ ! -d "$TARGET" ]; then
            printf 'CANNOT VERIFY: %s is neither an archive nor a directory\n' "$TARGET" >&2
            exit 3
        fi
        # Accept either the package directory itself or its parent.
        if [ -d "$TARGET/$PACKAGE_DIR_NAME" ]; then
            ROOT_DIR="$TARGET/$PACKAGE_DIR_NAME"
        else
            ROOT_DIR=$TARGET
        fi
        ;;
esac

REPORT="$ROOT_DIR/report/SOX-ITGC-AUDIT-REPORT.txt"
LOG="$ROOT_DIR/metadata/COLLECTION-LOG.txt"
MANIFEST="$ROOT_DIR/metadata/MANIFEST.txt"

problems=0
warnings=0

report_problem() {
    printf '  PROBLEM   %s\n' "$1"
    problems=`expr "$problems" + 1`
}

report_warning() {
    printf '  WARNING   %s\n' "$1"
    warnings=`expr "$warnings" + 1`
}

report_ok() {
    printf '  ok        %s\n' "$1"
}

printf 'Verifying evidence package\n'
printf '%s\n' '=========================='
printf 'Package: %s\n' "$TARGET"
printf '\n'

# ---------------------------------------------------------------------------
printf 'Structure\n'

if [ -s "$REPORT" ]; then
    report_ok "audit report present"
else
    report_problem "audit report missing or empty (expected report/SOX-ITGC-AUDIT-REPORT.txt)"
fi

if [ -s "$MANIFEST" ]; then
    report_ok "manifest present"
else
    report_problem "manifest missing or empty (expected metadata/MANIFEST.txt)"
fi

if [ -s "$LOG" ]; then
    report_ok "collection log present"
else
    report_problem "collection log missing or empty (expected metadata/COLLECTION-LOG.txt)"
fi

if [ ! -s "$REPORT" ] || [ ! -s "$LOG" ]; then
    printf '\n'
    printf 'VERDICT: CANNOT RELY ON THIS PACKAGE\n'
    printf 'The package is missing files that every collection produces. Request a\n'
    printf 'fresh collection.\n'
    exit 2
fi

# ---------------------------------------------------------------------------
# Truncation. The report is written progressively and the execution summary is
# the last thing added to it, so a report without one was captured mid-write -
# which has happened, and produced packages that looked entirely normal.
printf '\n'
printf 'Completeness\n'

if grep -q 'Execution Summary' "$REPORT" 2>/dev/null; then
    report_ok "report reaches its execution summary (not truncated)"
else
    report_problem "report has no execution summary - it was truncated before the collection finished"
fi

# The log's summary block is likewise the last thing written to it.
if grep -q '^RESULT: ' "$LOG" 2>/dev/null; then
    report_ok "collection log reaches its summary (not truncated)"
else
    report_problem "collection log has no RESULT line - it was truncated before the collection finished"
fi

# Chain of custody: the manifest must not claim files the package does not
# contain. Only meaningful when raw_files/ is present.
if [ -s "$MANIFEST" ] && [ -d "$ROOT_DIR/raw_files" ]; then
    claimed=0
    absent=0
    while IFS= read -r manifest_line; do
        case "$manifest_line" in
            COPIED\|*) ;;
            *) continue ;;
        esac
        claimed_path=`printf '%s' "$manifest_line" | sed 's/^COPIED|//' | cut -d'|' -f1`
        claimed=`expr "$claimed" + 1`
        if [ ! -f "$ROOT_DIR/raw_files$claimed_path" ]; then
            absent=`expr "$absent" + 1`
        fi
    done < "$MANIFEST"

    if [ "$claimed" -eq 0 ]; then
        report_warning "manifest lists no collected files"
    elif [ "$absent" -eq 0 ]; then
        report_ok "all $claimed files named in the manifest are present"
    else
        report_problem "$absent of $claimed files named in the manifest are missing from the package"
    fi
fi

# ---------------------------------------------------------------------------
# The collection's own verdict. FINAL_RESULT appears only when the archive step
# ran and supersedes RESULT, because it accounts for the archive outcome.
printf '\n'
printf 'Collection verdict\n'

verdict=`sed -n 's/^FINAL_RESULT: //p' "$LOG" 2>/dev/null | tail -1`
verdict_source=FINAL_RESULT
if [ -z "$verdict" ]; then
    verdict=`sed -n 's/^RESULT: //p' "$LOG" 2>/dev/null | head -1`
    verdict_source=RESULT
fi

warn_lines=`grep -c ' | WARN  | ' "$LOG" 2>/dev/null`
[ -n "$warn_lines" ] || warn_lines=0
error_lines=`grep -c ' | ERROR | ' "$LOG" 2>/dev/null`
[ -n "$error_lines" ] || error_lines=0

printf '  %s: %s\n' "$verdict_source" "${verdict:-none found}"
printf '  log contains %s warning(s) and %s error(s)\n' "$warn_lines" "$error_lines"

case "$verdict" in
    COMPLETED_CLEAN)
        report_ok "the collection reported no problems"
        ;;
    COMPLETED_WITH_WARNINGS)
        report_warning "the collection reported warnings; some evidence was limited"
        ;;
    COMPLETED_WITH_ERRORS)
        report_problem "the collection reported errors; the package may be incomplete"
        ;;
    FAILED)
        report_problem "the collection failed; this package should not be relied upon"
        ;;
    *)
        report_problem "no recognised verdict in the collection log"
        ;;
esac

if [ "$warn_lines" -gt 0 ]; then
    printf '\n'
    printf '  Warnings recorded during collection:\n'
    grep ' | WARN  | ' "$LOG" 2>/dev/null | sed 's/^/    /' | head -20
    if [ "$warn_lines" -gt 20 ]; then
        printf '    ... and %s more; see the collection log\n' "`expr "$warn_lines" - 20`"
    fi
fi

if [ "$error_lines" -gt 0 ]; then
    printf '\n'
    printf '  Errors recorded during collection:\n'
    grep ' | ERROR | ' "$LOG" 2>/dev/null | sed 's/^/    /' | head -20
fi

# ---------------------------------------------------------------------------
# Readability, checked last because it is about this copy rather than the
# collection. Nothing above needs the raw files, so a package can verify as
# complete while still being awkward to open.
printf '\n'
printf 'Readability of this copy\n'

if [ -r "$REPORT" ]; then
    report_ok "you can read the report"
else
    report_problem "you cannot read the report; see HOW-TO-READ-THIS-EVIDENCE.txt"
fi

if [ -d "$ROOT_DIR/raw_files" ]; then
    # find -readable is a GNU extension and is absent on macOS and the BSDs,
    # which is where an auditor is as likely to run this as on Linux. A shell
    # test is portable and the file counts here are small.
    unreadable=`find "$ROOT_DIR/raw_files" -type f -print 2>/dev/null | while IFS= read -r _f; do
        [ -r "$_f" ] || printf '%s\n' "$_f"
    done | head -5`
    if [ -n "$unreadable" ]; then
        report_warning "some collected files are not readable by you:"
        printf '%s\n' "$unreadable" | sed 's/^/              /'
        printf '              Collected files keep the permissions they had on the\n'
        printf '              source system, so this can be expected. Take a copy and\n'
        printf '              adjust the copy if you need to read them.\n'
    else
        report_ok "collected files are readable by you"
    fi
fi

# ---------------------------------------------------------------------------
printf '\n'
printf '%s\n' '--------------------------------------------------------------'

if [ "$problems" -gt 0 ]; then
    printf 'VERDICT: CANNOT RELY ON THIS PACKAGE\n'
    printf '\n'
    printf '%s problem(s) found. The package is incomplete, truncated, or the\n' "$problems"
    printf 'collection that produced it did not finish correctly. Request a fresh\n'
    printf 'collection before testing against this evidence.\n'
    exit 2
fi

if [ "$warnings" -gt 0 ]; then
    printf 'VERDICT: USABLE, WITH CAVEATS\n'
    printf '\n'
    printf 'The package arrived complete, but the collection reported warnings.\n'
    printf 'Read them above before relying on the affected report sections: they\n'
    printf 'record evidence that was limited or unavailable, which is not the same\n'
    printf 'as evidence that a control was absent.\n'
    exit 1
fi

printf 'VERDICT: PACKAGE VERIFIED\n'
printf '\n'
printf 'The package arrived complete and the collection reported no problems.\n'
exit 0
