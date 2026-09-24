/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#ifndef PUBNUB_XS_COMMON_H
#define PUBNUB_XS_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Result of a cross-SDK scenario execution. */
typedef struct xs_result {
    int  pass;        /**< 1 = pass, 0 = fail. */
    char detail[256]; /**< Human-readable detail string. */
} xs_result_t;

/** @brief CLI arguments parsed from command line. */
typedef struct xs_context {
    const char* sub_key;  /**< Subscribe key (@b required). */
    const char* pub_key;  /**< Publish key (@b required). */
    const char* channel;  /**< Test channel name (@b required). */
    const char* scenario; /**< Scenario name (@b required). */
    const char* cipher;   /**< Cipher key for crypto scenarios (nullable). */
    const char* uuid;     /**< UUID for metadata scenarios (nullable). */
    const char* content;  /**< Content string for publish/upload (nullable). */
    const char* output;   /**< Path to write JSON result (nullable = stdout). */
} xs_context_t;

/**
 * @brief Parse command-line arguments into xs_context_t.
 *
 * @param argc Argument count from main().
 * @param argv Argument vector from main().
 * @param ctx  Output context struct; all pointer fields are set to borrowed
 *             argv strings — do not free them.
 * @return 0 on success, non-zero if required args are missing.
 */
int xs_parse_args(int argc, char* argv[], xs_context_t* ctx);

/**
 * @brief Write xs_result_t as JSON to the output file or stdout.
 *
 * @param ctx    CLI context; uses @p ctx->output as the destination path
 *               when non-NULL.
 * @param result Scenario result to serialise.
 */
void xs_write_result(const xs_context_t* ctx, const xs_result_t* result);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_XS_COMMON_H */
