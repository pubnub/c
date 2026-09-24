# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

function(_pn_add_it_test name source)
    pubnub_add_integration_test(${name} SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
    target_link_libraries(${name} PRIVATE pn_test_helpers)
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../helpers")
    set_tests_properties(${name} PROPERTIES LABELS "integration" TIMEOUT 120)
endfunction()

# Tests that exercise subscribe long-polls, presence heartbeat cycles, or
# large message history batches need extra budget on slow networks.
function(_pn_add_it_test_slow name source)
    _pn_add_it_test(${name} ${source})
    set_tests_properties(${name} PROPERTIES TIMEOUT 300)
endfunction()

if(PUBNUB_ENABLE_TIME)
    _pn_add_it_test(test_it_time test_it_time.c)
endif()

if(PUBNUB_ENABLE_PUBLISH)
    _pn_add_it_test(test_it_publish test_it_publish.c)
    _pn_add_it_test(test_it_backpressure test_it_backpressure.c)
    _pn_add_it_test(test_it_error_handling test_it_error_handling.c)
endif()

if(PUBNUB_ENABLE_SIGNAL)
    _pn_add_it_test(test_it_signal test_it_signal.c)
endif()

if(PUBNUB_ENABLE_HISTORY)
    _pn_add_it_test_slow(test_it_history test_it_history.c)
endif()

if(PUBNUB_ENABLE_MESSAGE_ACTIONS)
    _pn_add_it_test(test_it_message_actions test_it_message_actions.c)
endif()

if(PUBNUB_ENABLE_SUBSCRIBE)
    _pn_add_it_test_slow(test_it_subscribe test_it_subscribe.c)
endif()

if(PUBNUB_ENABLE_SUBSCRIBE AND PUBNUB_ENABLE_PUBLISH)
    _pn_add_it_test_slow(test_it_subscribe_reconnect test_it_subscribe_reconnect.c)
endif()

if(PUBNUB_ENABLE_PRESENCE)
    _pn_add_it_test_slow(test_it_presence test_it_presence.c)
endif()

if(PUBNUB_ENABLE_CHANNEL_GROUPS)
    _pn_add_it_test(test_it_channel_groups test_it_channel_groups.c)
endif()

if(PUBNUB_ENABLE_APP_CONTEXT)
    _pn_add_it_test(test_it_app_context test_it_app_context.c)
endif()

if(PUBNUB_ENABLE_FILES)
    _pn_add_it_test(test_it_files test_it_files.c)
endif()

if(PUBNUB_ENABLE_CRYPTO)
    _pn_add_it_test_slow(test_it_crypto test_it_crypto.c)
endif()

if(PUBNUB_ENABLE_PAM)
    _pn_add_it_test(test_it_access test_it_access.c)
endif()

if(PUBNUB_ENABLE_PUSH_NOTIFICATIONS)
    _pn_add_it_test(test_it_push test_it_push.c)
endif()

if(PUBNUB_CFG_THREAD_SAFETY AND PUBNUB_ENABLE_PUBLISH)
    _pn_add_it_test(test_it_thread_safety test_it_thread_safety.c)
    target_include_directories(test_it_thread_safety PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")
    if(PUBNUB_ENABLE_HISTORY)
        target_compile_definitions(test_it_thread_safety PRIVATE IT_HAS_HISTORY=1)
    endif()
    if(PUBNUB_ENABLE_SUBSCRIBE)
        target_compile_definitions(test_it_thread_safety PRIVATE IT_HAS_SUBSCRIBE=1)
    endif()
endif()

if(PUBNUB_CFG_THREAD_SAFETY AND PUBNUB_ENABLE_PUBLISH)
    _pn_add_it_test(test_it_cancel_threading test_it_cancel_threading.c)
    target_include_directories(test_it_cancel_threading PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")

    _pn_add_it_test_slow(test_it_concurrent test_it_concurrent.c)
    target_include_directories(test_it_concurrent PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")

    # it_watchdog.h uses POSIX signal APIs (struct sigaction, sigaction(),
    # sigemptyset()), which require _POSIX_C_SOURCE on glibc with -std=c11.
    foreach(_pn_wd_test test_it_cancel_threading test_it_concurrent)
        target_compile_definitions(
            ${_pn_wd_test}
            PRIVATE
                $<$<NOT:$<PLATFORM_ID:Windows>>:_POSIX_C_SOURCE=200809L>
                $<$<NOT:$<PLATFORM_ID:Windows>>:_DEFAULT_SOURCE>
                $<$<PLATFORM_ID:Darwin>:_DARWIN_C_SOURCE>
        )
    endforeach()
endif()

if(PUBNUB_CFG_THREAD_SAFETY AND PUBNUB_ENABLE_SUBSCRIBE)
    _pn_add_it_test_slow(test_it_subscribe_threading test_it_subscribe_threading.c)
    target_include_directories(test_it_subscribe_threading PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")
    target_compile_definitions(
        test_it_subscribe_threading
        PRIVATE
            $<$<NOT:$<PLATFORM_ID:Windows>>:_POSIX_C_SOURCE=200809L>
            $<$<NOT:$<PLATFORM_ID:Windows>>:_DEFAULT_SOURCE>
            $<$<PLATFORM_ID:Darwin>:_DARWIN_C_SOURCE>
    )
endif()
