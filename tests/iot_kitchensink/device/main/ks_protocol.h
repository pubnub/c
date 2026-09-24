/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef KS_PROTOCOL_H
#define KS_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** Parsed companion message type. */
typedef enum ks_msg_type {
    KS_MSG_UNKNOWN = 0,
    KS_MSG_HANDSHAKE_ACK,
    KS_MSG_ACTION_DONE,
    KS_MSG_ACTION_FAIL,
    KS_MSG_READY
} ks_msg_type_t;

/** Parsed companion message. */
typedef struct ks_msg {
    ks_msg_type_t type;
    uint32_t      seq;
    uint8_t       pass;
    char          detail[128];
} ks_msg_t;

/**
 * @brief Return the fixed discovery channel name.
 *
 * The device publishes its handshake to this channel; the companion
 * subscribes to it at startup. Using a dash-only name avoids the
 * PubNub wildcard-depth restriction on dot-separated channel names.
 *
 * @param out     Output buffer.
 * @param out_len Size of @p out.
 */
void ks_protocol_handshake_channel(char* out, size_t out_len);

/**
 * @brief Build the control channel name for this run.
 *
 * Format: "iot-ks-{run_id}-control"
 *
 * @param run_id  8-char hex run identifier.
 * @param out     Output buffer.
 * @param out_len Size of @p out.
 */
void ks_protocol_ctrl_channel(const char* run_id, char* out, size_t out_len);

/**
 * @brief Build the result channel name for this run.
 *
 * Format: "iot-ks-{run_id}-result"
 *
 * @param run_id  8-char hex run identifier.
 * @param out     Output buffer.
 * @param out_len Size of @p out.
 */
void ks_protocol_result_channel(const char* run_id, char* out, size_t out_len);

/**
 * @brief Build a per-test channel name.
 *
 * Format: "iot-ks-{run_id}-{suffix}"
 *
 * @param run_id  8-char hex run identifier.
 * @param suffix  Test-specific suffix.
 * @param out     Output buffer.
 * @param out_len Size of @p out.
 */
void ks_protocol_test_channel(const char* run_id,
                              const char* suffix,
                              char*       out,
                              size_t      out_len);

/**
 * @brief Build a handshake JSON message.
 *
 * @param run_id    8-char hex run identifier.
 * @param device_id Device user ID string.
 * @return Pointer to an internal static buffer. Valid until the
 *         next call to any ks_protocol_*_msg function.
 */
const char* ks_protocol_handshake_msg(const char* run_id, const char* device_id);

/**
 * @brief Build an action request JSON message.
 *
 * @param test_id  Test name, e.g. "publish/string".
 * @param action   Action verb, e.g. "publish".
 * @param channel  Target channel for the action.
 * @param payload  JSON payload string (may be NULL).
 * @param seq      Sequence number for correlation.
 * @return Pointer to an internal static buffer. Valid until the
 *         next call to any ks_protocol_*_msg function.
 */
const char* ks_protocol_request_msg(const char* test_id,
                                    const char* action,
                                    const char* channel,
                                    const char* payload,
                                    uint32_t    seq);

/**
 * @brief Build a "done" summary JSON message.
 *
 * @param pass  Number of passed tests.
 * @param fail  Number of failed tests.
 * @param skip  Number of skipped tests.
 * @return Pointer to an internal static buffer. Valid until the
 *         next call to any ks_protocol_*_msg function.
 */
const char* ks_protocol_done_msg(uint32_t pass, uint32_t fail, uint32_t skip);

/**
 * @brief Parse a JSON message from the companion.
 *
 * Performs minimal string matching on the "type" field to
 * classify the message. Does not use the serialization provider.
 *
 * @param json  Raw JSON string.
 * @param len   Length of @p json.
 * @param out   Parsed message output.
 * @return 0 on success, -1 if the message could not be parsed.
 */
int ks_protocol_parse(const char* json, size_t len, ks_msg_t* out);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* KS_PROTOCOL_H */
