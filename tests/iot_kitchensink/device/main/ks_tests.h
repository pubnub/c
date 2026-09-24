/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef KS_TESTS_H
#define KS_TESTS_H

#include "ks_test_runner.h"

#include <stddef.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/* Each ks_tests_*.c file exports a test entry array and count. */

extern const ks_test_entry_t ks_time_tests[];
extern const size_t          ks_time_test_count;

extern const ks_test_entry_t ks_publish_tests[];
extern const size_t          ks_publish_test_count;

extern const ks_test_entry_t ks_subscribe_tests[];
extern const size_t          ks_subscribe_test_count;

extern const ks_test_entry_t ks_presence_tests[];
extern const size_t          ks_presence_test_count;

extern const ks_test_entry_t ks_history_tests[];
extern const size_t          ks_history_test_count;

extern const ks_test_entry_t ks_signal_tests[];
extern const size_t          ks_signal_test_count;

extern const ks_test_entry_t ks_message_actions_tests[];
extern const size_t          ks_message_actions_test_count;

extern const ks_test_entry_t ks_channel_groups_tests[];
extern const size_t          ks_channel_groups_test_count;

extern const ks_test_entry_t ks_app_context_tests[];
extern const size_t          ks_app_context_test_count;

extern const ks_test_entry_t ks_crypto_tests[];
extern const size_t          ks_crypto_test_count;

extern const ks_test_entry_t ks_files_tests[];
extern const size_t          ks_files_test_count;

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* KS_TESTS_H */
