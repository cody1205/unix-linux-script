#!/bin/sh
# Run every OS simulation and summarize.
#
# Each fixture runs independently, so one failing platform does not mask the
# others. Exits non-zero if any platform failed, which is what CI gates on.
#
# Usage:
#   sudo sh tests/simulations/run-all.sh            # all platforms
#   sudo sh tests/simulations/run-all.sh aix hpux   # selected platforms
#
# Environment:
#   SIM_WORK   base working directory (default ${TMPDIR:-/tmp}/sox-itgc-sim)
#   COLLECTOR  path to the script under test
#   KEEP_ROOT  leave each chroot mounted for inspection

set -u

SIM_DIR=`CDPATH= cd -- "\`dirname -- "$0"\`" && pwd`
ALL="rhel opensuse aix hpux"
TARGETS=${*:-$ALL}

if [ "`id -u`" != "0" ]; then
    printf 'FAIL: must run as root (use: sudo sh %s)\n' "$0" >&2
    exit 1
fi

passed=""
failed=""

for os in $TARGETS; do
    script="$SIM_DIR/os_$os.sh"
    if [ ! -f "$script" ]; then
        printf 'FAIL: unknown platform "%s" (available: %s)\n' "$os" "$ALL" >&2
        failed="$failed $os"
        continue
    fi
    if sh "$script"; then
        passed="$passed $os"
    else
        failed="$failed $os"
    fi
done

printf '===============================================\n'
printf 'Simulation summary\n'
printf '===============================================\n'
[ -n "$passed" ] && printf 'PASS:%s\n' "$passed"
[ -n "$failed" ] && printf 'FAIL:%s\n' "$failed"

if [ -n "$failed" ]; then
    printf '\nOne or more platforms failed.\n'
    exit 1
fi
printf '\nAll platforms passed.\n'
exit 0
