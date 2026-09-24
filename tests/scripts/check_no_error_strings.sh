#!/bin/bash
# Verify PUBNUB_CFG_RES_STR=OFF eliminates the labels table.
set -euo pipefail

ARCHIVE="${1:-build/embedded/libpubnub.a}"
if [[ ! -f "$ARCHIVE" ]]; then
    echo "FAIL: archive not found: $ARCHIVE" >&2
    exit 1
fi

# Use POSIX nm (-P) for portability between BSD nm (macOS) and GNU nm (Linux).
if nm -P "$ARCHIVE" 2>/dev/null | \
   grep -E 'pn_(error|res)_(strings|labels|messages|table)' >&2; then
    echo "FAIL: error string table symbols found in embedded build" >&2
    exit 1
fi

# TODO(harden, owner=@sdk-arch): assert pubnub_res_str text size <= 64 B
# in OFF builds (just the empty-string return stub). Catches a future
# regression where heavy code accidentally lands outside the
# `#if PUBNUB_CFG_RES_STR` guard. Picked up in a follow-up alongside
# PR2 or PR3. Implementation sketch:
#   sz=$(size -A "$ARCHIVE" 2>/dev/null | awk '/error\.c\.o:/{flag=1;next} flag && /__text/{print $2; exit}')
#   if [[ -n "$sz" && "$sz" -gt 64 ]]; then
#       echo "FAIL: pubnub_res_str text size $sz B exceeds 64 B budget" >&2
#       exit 1
#   fi
# Note: size invocation differs between BSD and GNU; needs portability work.

exit 0
