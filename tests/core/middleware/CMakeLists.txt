# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_core_middleware_units SOURCES middleware_units.c LIBS pubnub)

if(PUBNUB_ENABLE_PAM)
    pubnub_add_unit_test(
        test_core_pn_signing_string_units
        SOURCES signature_middleware/pn_signing_string_units.c
        LIBS pubnub
    )

    pubnub_add_unit_test(
        test_core_pn_base64url_units
        SOURCES signature_middleware/pn_base64url_units.c
        LIBS pubnub
    )
endif()

if(PUBNUB_ENABLE_RETRY)
    pubnub_add_unit_test(
        test_core_retry_middleware_units
        SOURCES retry_middleware_units.c
        LIBS pubnub
    )
endif()

if(PUBNUB_ENABLE_REQUEST_COMPRESSION)
    pubnub_add_unit_test(
        test_core_compression_middleware_units
        SOURCES test_compression_middleware.c
        LIBS pubnub
    )
    # The test uses zlib directly for decompression verification.
    # pn_core_middleware is an OBJECT library whose INTERFACE_INCLUDE_DIRECTORIES
    # do not propagate through $<TARGET_OBJECTS:...> to the pubnub aggregate, so
    # zlib must be linked to the test explicitly.
    if(TARGET ZLIB::ZLIB)
        target_link_libraries(test_core_compression_middleware_units PRIVATE ZLIB::ZLIB)
    elseif(TARGET zlibstatic)
        target_link_libraries(test_core_compression_middleware_units PRIVATE zlibstatic)
        get_target_property(_pn_zlib_incs pn_core_middleware INTERFACE_INCLUDE_DIRECTORIES)
        if(_pn_zlib_incs)
            target_include_directories(
                test_core_compression_middleware_units
                PRIVATE ${_pn_zlib_incs}
            )
        endif()
    endif()
endif()
