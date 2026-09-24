# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Shim FindMbedTLS module for Zephyr builds.
#
# Zephyr provides mbedTLS through the zephyr_interface target. This
# file satisfies find_package(MbedTLS) used by the socket transport
# provider so it does not attempt to FetchContent a duplicate copy.

if(TARGET zephyr_interface)
    set(MbedTLS_FOUND TRUE)

    if(NOT TARGET MbedTLS::mbedtls)
        add_library(MbedTLS::mbedtls INTERFACE IMPORTED)
        set_target_properties(MbedTLS::mbedtls PROPERTIES INTERFACE_LINK_LIBRARIES zephyr_interface)
    endif()

    if(NOT TARGET MbedTLS::mbedcrypto)
        add_library(MbedTLS::mbedcrypto INTERFACE IMPORTED)
        set_target_properties(
            MbedTLS::mbedcrypto
            PROPERTIES INTERFACE_LINK_LIBRARIES zephyr_interface
        )
    endif()

    if(NOT TARGET MbedTLS::mbedx509)
        add_library(MbedTLS::mbedx509 INTERFACE IMPORTED)
        set_target_properties(
            MbedTLS::mbedx509
            PROPERTIES INTERFACE_LINK_LIBRARIES zephyr_interface
        )
    endif()
else()
    set(MbedTLS_FOUND FALSE)
endif()
