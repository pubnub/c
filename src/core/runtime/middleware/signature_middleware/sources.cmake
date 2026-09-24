# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Source file list for PAM v3 signature middleware (gated by PUBNUB_ENABLE_PAM).

set(PN_MIDDLEWARE_SIGNATURE_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/../signature_middleware.c"
    "${CMAKE_CURRENT_LIST_DIR}/pn_signing_string.c"
)
