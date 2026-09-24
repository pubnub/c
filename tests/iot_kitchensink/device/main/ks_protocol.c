/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_protocol.h"

#include <stdio.h>
#include <string.h>

/** Shared static buffer for message building (single-use). */
static char s_msg_buf[1024];

/* Fixed discovery channel — device publishes handshake here; companion
 * subscribes to this channel at startup to learn the run_id. Using a
 * dash-only name avoids PubNub's wildcard-depth restriction (dots in
 * channel names trigger wildcard validation on keysets that have
 * Wildcard Subscribe enabled). */
#define KS_HANDSHAKE_CHANNEL "iot-ks-handshake"

void ks_protocol_handshake_channel(char* out, size_t out_len)
{
    snprintf(out, out_len, "%s", KS_HANDSHAKE_CHANNEL);
}

void ks_protocol_ctrl_channel(const char* run_id, char* out, size_t out_len)
{
    snprintf(out, out_len, "iot-ks-%s-control", run_id);
}

void ks_protocol_result_channel(const char* run_id, char* out, size_t out_len)
{
    snprintf(out, out_len, "iot-ks-%s-result", run_id);
}

void ks_protocol_test_channel(const char* run_id,
                              const char* suffix,
                              char*       out,
                              size_t      out_len)
{
    snprintf(out, out_len, "iot-ks-%s-%s", run_id, suffix);
}

const char* ks_protocol_handshake_msg(const char* run_id, const char* device_id)
{
    snprintf(s_msg_buf,
             sizeof(s_msg_buf),
             "{\"type\":\"handshake\","
             "\"run_id\":\"%s\","
             "\"device_id\":\"%s\"}",
             run_id,
             device_id);
    return s_msg_buf;
}

const char* ks_protocol_request_msg(const char* test_id,
                                    const char* action,
                                    const char* channel,
                                    const char* payload,
                                    uint32_t    seq)
{
    if (NULL != payload) {
        snprintf(s_msg_buf,
                 sizeof(s_msg_buf),
                 "{\"type\":\"request\","
                 "\"test\":\"%s\","
                 "\"action\":\"%s\","
                 "\"channel\":\"%s\","
                 "\"payload\":%s,"
                 "\"seq\":%u}",
                 test_id,
                 action,
                 channel,
                 payload,
                 (unsigned)seq);
    } else {
        snprintf(s_msg_buf,
                 sizeof(s_msg_buf),
                 "{\"type\":\"request\","
                 "\"test\":\"%s\","
                 "\"action\":\"%s\","
                 "\"channel\":\"%s\","
                 "\"seq\":%u}",
                 test_id,
                 action,
                 channel,
                 (unsigned)seq);
    }
    return s_msg_buf;
}

const char* ks_protocol_done_msg(uint32_t pass, uint32_t fail, uint32_t skip)
{
    snprintf(s_msg_buf,
             sizeof(s_msg_buf),
             "{\"type\":\"done\","
             "\"pass\":%u,"
             "\"fail\":%u,"
             "\"skip\":%u}",
             (unsigned)pass,
             (unsigned)fail,
             (unsigned)skip);
    return s_msg_buf;
}

/**
 * @brief Find a JSON string value for a given key (minimal parser).
 *
 * Searches for "key":"value" and copies the value into out.
 * Does not handle escaped quotes inside values.
 */
static int find_string_value(const char* json,
                             size_t      json_len,
                             const char* key,
                             char*       out,
                             size_t      out_len)
{
    char pattern[64] = {0};
    int  plen        = snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);

    if (plen <= 0 || (size_t)plen >= sizeof(pattern)) {
        return -1;
    }

    const char* found = NULL;
    size_t      i;
    for (i = 0; i + (size_t)plen <= json_len; i++) {
        if (0 == memcmp(json + i, pattern, (size_t)plen)) {
            found = json + i + plen;
            break;
        }
    }

    if (NULL == found) {
        return -1;
    }

    const char* end = memchr(found, '"', json_len - (size_t)(found - json));
    if (NULL == end) {
        return -1;
    }

    size_t vlen = (size_t)(end - found);
    if (vlen >= out_len) {
        vlen = out_len - 1;
    }
    memcpy(out, found, vlen);
    out[vlen] = '\0';
    return 0;
}

/**
 * @brief Find an unsigned integer value for a given key.
 *
 * Searches for "key":digits in the JSON string.
 */
static int find_uint_value(const char* json,
                           size_t      json_len,
                           const char* key,
                           uint32_t*   out)
{
    char pattern[64] = {0};
    int  plen        = snprintf(pattern, sizeof(pattern), "\"%s\":", key);

    if (plen <= 0 || (size_t)plen >= sizeof(pattern)) {
        return -1;
    }

    const char* found = NULL;
    size_t      i;
    for (i = 0; i + (size_t)plen <= json_len; i++) {
        if (0 == memcmp(json + i, pattern, (size_t)plen)) {
            found = json + i + plen;
            break;
        }
    }

    if (NULL == found) {
        return -1;
    }

    uint32_t val    = 0;
    size_t   digits = 0;
    while (found < json + json_len && *found >= '0' && *found <= '9' && digits < 10) {
        val = val * 10U + (uint32_t)(*found - '0');
        found++;
        digits++;
    }
    *out = val;
    return 0;
}

int ks_protocol_parse(const char* json, size_t len, ks_msg_t* out)
{
    char type_str[32] = {0};

    memset(out, 0, sizeof(*out));

    if (NULL == json || 0 == len) {
        return -1;
    }

    if (0 != find_string_value(json, len, "type", type_str, sizeof(type_str))) {
        return -1;
    }

    if (0 == strcmp(type_str, "handshake_ack")) {
        out->type = KS_MSG_HANDSHAKE_ACK;
    } else if (0 == strcmp(type_str, "action_done")) {
        out->type = KS_MSG_ACTION_DONE;
        out->pass = 1;
    } else if (0 == strcmp(type_str, "action_fail")) {
        out->type = KS_MSG_ACTION_FAIL;
        out->pass = 0;
    } else if (0 == strcmp(type_str, "ready")) {
        out->type = KS_MSG_READY;
    } else {
        out->type = KS_MSG_UNKNOWN;
    }

    (void)find_uint_value(json, len, "seq", &out->seq);
    (void)find_string_value(json, len, "detail", out->detail, sizeof(out->detail));

    return 0;
}
