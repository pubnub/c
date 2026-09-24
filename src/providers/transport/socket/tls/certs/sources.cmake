# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Select the TLS CA certificate loader source.
#
# When PUBNUB_TLS_CA_CERT_FILE is set, generates a C source file at configure
# time that embeds the specified PEM file as a static const array. This
# replaces the platform-specific cert file, allowing callers to provide
# exactly the root CAs their endpoints use (reduces binary size).
#
# When not set, one of the platform-specific files is selected:
#   certs_linux.c, certs_macos.c, certs_windows.c, certs_esp.c,
#   certs_zephyr.c, certs_none.c
#
# Only one source file is compiled per build.

if(PUBNUB_TLS_CA_CERT_FILE)
    if(NOT EXISTS "${PUBNUB_TLS_CA_CERT_FILE}")
        message(
            FATAL_ERROR
            "[PubNub] PUBNUB_TLS_CA_CERT_FILE='${PUBNUB_TLS_CA_CERT_FILE}' does not exist."
        )
    endif()

    # Re-run CMake configure when the cert file is modified.
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${PUBNUB_TLS_CA_CERT_FILE}")

    # Read PEM lines (pure ASCII: base64 + header markers — no CMake metacharacters).
    file(STRINGS "${PUBNUB_TLS_CA_CERT_FILE}" _pn_cert_lines)

    # Build the generated C source content.
    set(_pn_cert_c "/* Copyright (c) PubNub Inc. */\n")
    string(APPEND _pn_cert_c "/* Auto-generated from PUBNUB_TLS_CA_CERT_FILE — do not edit. */\n")
    string(APPEND _pn_cert_c "/* Source: ${PUBNUB_TLS_CA_CERT_FILE} */\n")
    string(APPEND _pn_cert_c "\n")
    string(APPEND _pn_cert_c "#include \"tls/certs/pn_tls_cert_loader.h\"\n")
    string(APPEND _pn_cert_c "#include <mbedtls/x509_crt.h>\n")
    string(APPEND _pn_cert_c "\n")
    string(APPEND _pn_cert_c "/**\n")
    string(
        APPEND _pn_cert_c
        " * @brief Embedded CA bundle generated from PUBNUB_TLS_CA_CERT_FILE.\n"
    )
    string(APPEND _pn_cert_c " *\n")
    string(
        APPEND _pn_cert_c
        " * Compiled in at configure time. To update, change PUBNUB_TLS_CA_CERT_FILE\n"
    )
    string(
        APPEND _pn_cert_c
        " * and re-run CMake — the configure step re-reads the file automatically.\n"
    )
    string(APPEND _pn_cert_c " */\n")
    string(APPEND _pn_cert_c "static const char pn_custom_ca_bundle_pem[] =\n")
    foreach(_line IN LISTS _pn_cert_lines)
        string(APPEND _pn_cert_c "    \"${_line}\\n\"\n")
    endforeach()
    string(APPEND _pn_cert_c "    ;\n")
    string(APPEND _pn_cert_c "\n")
    string(APPEND _pn_cert_c "static int pn_tls_certs_custom(\n")
    string(APPEND _pn_cert_c "    void* ca_chain, void* ssl_conf, void* user_data)\n")
    string(APPEND _pn_cert_c "{\n")
    string(APPEND _pn_cert_c "    (void)ssl_conf;\n")
    string(APPEND _pn_cert_c "    (void)user_data;\n")
    string(APPEND _pn_cert_c "    return (0 > mbedtls_x509_crt_parse(\n")
    string(APPEND _pn_cert_c "                     (mbedtls_x509_crt*)ca_chain,\n")
    string(
        APPEND _pn_cert_c
        "                     (const unsigned char*)pn_custom_ca_bundle_pem,\n"
    )
    string(APPEND _pn_cert_c "                     sizeof(pn_custom_ca_bundle_pem))) ? -1 : 0;\n")
    string(APPEND _pn_cert_c "}\n")
    string(APPEND _pn_cert_c "\n")
    string(APPEND _pn_cert_c "/* NOLINTNEXTLINE(misc-use-internal-linkage) */\n")
    string(APPEND _pn_cert_c "pn_tls_system_cert_fn_t pn_tls_get_default_cert_loader(void)\n")
    string(APPEND _pn_cert_c "{\n")
    string(APPEND _pn_cert_c "    return pn_tls_certs_custom;\n")
    string(APPEND _pn_cert_c "}\n")

    set(_pn_cert_out "${CMAKE_CURRENT_BINARY_DIR}/pn_custom_ca_bundle.c")
    file(WRITE "${_pn_cert_out}" "${_pn_cert_c}")
    set(PN_TLS_CERT_LOADER_SOURCE "${_pn_cert_out}")
elseif(WIN32)
    set(PN_TLS_CERT_LOADER_SOURCE "${CMAKE_CURRENT_LIST_DIR}/certs_windows.c")
elseif(
    DEFINED BOARD
    OR ZEPHYR_TOOLCHAIN_VARIANT STREQUAL "zephyr"
    OR CMAKE_SYSTEM_NAME STREQUAL "zephyr"
)
    set(PN_TLS_CERT_LOADER_SOURCE "${CMAKE_CURRENT_LIST_DIR}/certs_zephyr.c")
elseif(DEFINED ENV{IDF_PATH} OR PUBNUB_PLATFORM STREQUAL "esp-idf")
    set(PN_TLS_CERT_LOADER_SOURCE "${CMAKE_CURRENT_LIST_DIR}/certs_esp.c")
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeRTOS" OR PUBNUB_PLATFORM STREQUAL "freertos")
    set(PN_TLS_CERT_LOADER_SOURCE "${CMAKE_CURRENT_LIST_DIR}/certs_none.c")
elseif(APPLE)
    set(PN_TLS_CERT_LOADER_SOURCE "${CMAKE_CURRENT_LIST_DIR}/certs_macos.c")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(PN_TLS_CERT_LOADER_SOURCE "${CMAKE_CURRENT_LIST_DIR}/certs_linux.c")
else()
    set(PN_TLS_CERT_LOADER_SOURCE "${CMAKE_CURRENT_LIST_DIR}/certs_none.c")
endif()
