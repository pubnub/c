# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# TLS backend sources. Only one of these is compiled per build configuration.

set(PN_TRANSPORT_TLS_MBEDTLS_SOURCES "${CMAKE_CURRENT_LIST_DIR}/tls_mbedtls.c")
set(PN_TRANSPORT_TLS_OPENSSL_SOURCES "${CMAKE_CURRENT_LIST_DIR}/tls_openssl.c")
set(PN_TRANSPORT_TLS_NONE_SOURCES "${CMAKE_CURRENT_LIST_DIR}/tls_none.c")
