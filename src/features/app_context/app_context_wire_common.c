/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "app_context_internal.h"

#include "core/pn_format.h"
#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

#if PUBNUB_ENABLE_APP_CONTEXT && PUBNUB_CFG_HTTP_SCRATCH_SIZE < 512
#pragma message(                                                              \
    "PubNub: app_context with full include parameters + pagination cursors"   \
    " requires at least 512 bytes of scratch (PUBNUB_CFG_HTTP_SCRATCH_SIZE);" \
    " set PUBNUB_CFG_HTTP_SCRATCH_SIZE >= 512 when enabling app_context on embedded targets")
#endif

/**
 * @brief Include-flag token lookup entry.
 */
typedef struct pn_include_token {
    uint32_t    flag;
    const char* token;
    size_t      token_len;
} pn_include_token_t;

/* Wire token strings for include flags (excluding TOTAL_COUNT). */
static const pn_include_token_t s_include_tokens[] = {
    {PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM,         "custom",         6 },
    {PUBNUB_APP_CONTEXT_INCLUDE_TYPE,           "type",           4 },
    {PUBNUB_APP_CONTEXT_INCLUDE_STATUS,         "status",         6 },
    {PUBNUB_APP_CONTEXT_INCLUDE_UUID,           "uuid",           4 },
    {PUBNUB_APP_CONTEXT_INCLUDE_UUID_CUSTOM,    "uuid.custom",    11},
    {PUBNUB_APP_CONTEXT_INCLUDE_UUID_TYPE,      "uuid.type",      9 },
    {PUBNUB_APP_CONTEXT_INCLUDE_UUID_STATUS,    "uuid.status",    11},
    {PUBNUB_APP_CONTEXT_INCLUDE_CHANNEL,        "channel",        7 },
    {PUBNUB_APP_CONTEXT_INCLUDE_CHANNEL_CUSTOM, "channel.custom", 14},
    {PUBNUB_APP_CONTEXT_INCLUDE_CHANNEL_TYPE,   "channel.type",   12},
    {PUBNUB_APP_CONTEXT_INCLUDE_CHANNEL_STATUS, "channel.status", 14},
};

#define PN_INCLUDE_TOKEN_COUNT \
    (sizeof(s_include_tokens) / sizeof(s_include_tokens[0]))

pubnub_res_t pn_app_context_add_include_param(pubnub_http_request_t* request,
                                              uint32_t include_mask)
{
    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Strip TOTAL_COUNT — it maps to the `count` param, not `include`. */
    uint32_t mask = include_mask & ~(uint32_t)PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;
    if (0 == mask) {
        return PUBNUB_OK;
    }

    /* Build comma-separated token string in scratch. Worst case is all
     * 11 tokens which is ~110 bytes + commas — fits in scratch. */
    unsigned int saved_scratch = request->scratch_used;
    char*        dst           = request->scratch + saved_scratch;
    size_t remaining = (size_t)PUBNUB_CFG_HTTP_SCRATCH_SIZE - saved_scratch;
    size_t written   = 0;
    size_t i;

    for (i = 0; i < PN_INCLUDE_TOKEN_COUNT; ++i) {
        if (0 == (mask & s_include_tokens[i].flag)) {
            continue;
        }
        size_t need = s_include_tokens[i].token_len;
        if (written > 0) {
            need += 1; /* comma */
        }
        if (written + need >= remaining) {
            return PUBNUB_ERR_BUFFER_TOO_SMALL;
        }
        if (written > 0) {
            dst[written] = ',';
            ++written;
        }
        memcpy(dst + written, s_include_tokens[i].token, s_include_tokens[i].token_len);
        written += s_include_tokens[i].token_len;
    }

    if (0 == written) {
        return PUBNUB_OK;
    }

    /* NUL-terminate for add_query_param. */
    if (written >= remaining) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }
    dst[written] = '\0';

    /* Commit scratch usage and build the view. */
    request->scratch_used = (unsigned int)(saved_scratch + written + 1);

    pubnub_string_view_t value = {.ptr = dst, .len = written};
    return pn_request_add_query_param_view(request, "include", value);
}

pubnub_res_t pn_app_context_add_if_match(pubnub_http_request_t* request,
                                         const char*            if_match)
{
    pubnub_string_view_t value;
    pubnub_kv_t*         h;
    pubnub_res_t         rc;
    size_t               i;

    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == if_match) {
        return PUBNUB_OK;
    }

    /* Reject CR/LF so a crafted ETag cannot inject extra headers. A
     * NUL terminates the C string, so no embedded NUL can survive this
     * scan into the header value. */
    for (i = 0; '\0' != if_match[i]; ++i) {
        if ('\r' == if_match[i] || '\n' == if_match[i]) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
    }

    if (request->header_count >= PUBNUB_CFG_HTTP_MAX_HEADERS) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    rc = pn_request_scratch_encode(request, if_match, &value, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    h            = &request->headers[request->header_count++];
    h->key.ptr   = "If-Match";
    h->key.len   = 8;
    h->value.ptr = value.ptr;
    h->value.len = value.len;

    return PUBNUB_OK;
}

pubnub_res_t pn_app_context_add_pagination_params(pubnub_http_request_t* request,
                                                  uint32_t    limit,
                                                  const char* start,
                                                  const char* end)
{
    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_res_t rc = PUBNUB_OK;

    if (0 != limit) {
        /* Format into a stack buffer; pn_request_add_query_param encodes
         * it into scratch and sets both tracking bits. */
        char limit_buf[12]; /* max uint32 is 10 digits + NUL */
        int len = pn_snprintf(limit_buf, sizeof(limit_buf), "%u", (unsigned)limit);
        if (len < 0 || (size_t)len >= sizeof(limit_buf)) {
            return PUBNUB_ERR_BUFFER_TOO_SMALL;
        }
        rc = pn_request_add_query_param(request, "limit", limit_buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (NULL != start) {
        rc = pn_request_add_query_param(request, "start", start, PN_ENCODE_FULL);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (NULL != end) {
        rc = pn_request_add_query_param(request, "end", end, PN_ENCODE_FULL);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_app_context_add_filter_param(pubnub_http_request_t* request,
                                             const char*            filter)
{
    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == filter) {
        return PUBNUB_OK;
    }
    return pn_request_add_query_param(request, "filter", filter, PN_ENCODE_FULL);
}

pubnub_res_t pn_app_context_add_sort_param(pubnub_http_request_t* request,
                                           const char*            sort)
{
    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == sort) {
        return PUBNUB_OK;
    }
    return pn_request_add_query_param(request, "sort", sort, PN_ENCODE_FULL);
}

pubnub_res_t pn_app_context_add_count_param(pubnub_http_request_t* request,
                                            uint32_t               include_mask)
{
    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (0 == (include_mask & PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT)) {
        return PUBNUB_OK;
    }
    return pn_request_add_query_param(request, "count", "true", PN_ENCODE_NONE);
}

pubnub_res_t pn_app_context_set_custom_field(pubnub_serialization_provider_t* serial,
                                             pubnub_json_value_t* obj,
                                             pubnub_json_value_t* custom_value,
                                             const char*          custom_raw,
                                             size_t custom_raw_len)
{
    if (NULL != custom_value) {
        pubnub_res_t rc =
            serial->object_set(serial, obj, "custom", 6, custom_value);
        if (PUBNUB_OK != rc) {
            serial->value_destroy(serial, custom_value);
        }
        return rc;
    }

    if (NULL != custom_raw) {
        if (NULL == serial->value_create_raw) {
            return PUBNUB_ERR_NOT_SUPPORTED;
        }
        size_t clen = (0 == custom_raw_len) ? strlen(custom_raw) : custom_raw_len;
        pubnub_json_value_t* val =
            serial->value_create_raw(serial, (const uint8_t*)custom_raw, clen);
        if (NULL == val) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        pubnub_res_t rc = serial->object_set(serial, obj, "custom", 6, val);
        if (PUBNUB_OK != rc) {
            serial->value_destroy(serial, val);
        }
        return rc;
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_app_context_response_validator(const uint8_t* body,
                                               size_t         body_len,
                                               int            http_status)
{
    if (http_status < 200 || http_status >= 300) {
        return PUBNUB_ERR_SERVER;
    }
    if (0 == body_len || NULL == body || '{' != body[0]) {
        return PUBNUB_ERR_SERVER;
    }
    return PUBNUB_OK;
}

pubnub_res_t pn_app_context_parse_page(pubnub_serialization_provider_t* serial,
                                       const pubnub_json_value_t*       tree,
                                       pubnub_app_context_page_t* out_page)
{
    if (NULL == serial || NULL == tree || NULL == out_page) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    memset(out_page, 0, sizeof(*out_page));

    /* Extract "data" array to determine item count. */
    pubnub_json_value_t* data_node = NULL;
    if (NULL != serial->object_get) {
        data_node = serial->object_get((pubnub_json_value_t*)tree, "data", 4);
    }
    if (NULL != data_node && NULL != serial->array_size) {
        out_page->count = (uint32_t)serial->array_size(data_node);
    }

    /* Extract "totalCount" (integer). */
    if (NULL != serial->object_get && NULL != serial->value_as_int) {
        pubnub_json_value_t* tc_node =
            serial->object_get((pubnub_json_value_t*)tree, "totalCount", 10);
        if (NULL != tc_node) {
            int val = 0;
            if (PUBNUB_OK == serial->value_as_int(tc_node, &val) && val >= 0) {
                out_page->total_count = (uint32_t)val;
            }
        }
    }

    /* Extract "next" cursor (string). */
    if (NULL != serial->object_get && NULL != serial->value_as_string) {
        pubnub_json_value_t* next_node =
            serial->object_get((pubnub_json_value_t*)tree, "next", 4);
        if (NULL != next_node) {
            size_t      slen = 0;
            const char* sptr = serial->value_as_string(next_node, &slen);
            if (NULL != sptr) {
                out_page->next.ptr = sptr;
                out_page->next.len = slen;
            }
        }
    }

    /* Extract "prev" cursor (string). */
    if (NULL != serial->object_get && NULL != serial->value_as_string) {
        pubnub_json_value_t* prev_node =
            serial->object_get((pubnub_json_value_t*)tree, "prev", 4);
        if (NULL != prev_node) {
            size_t      slen = 0;
            const char* sptr = serial->value_as_string(prev_node, &slen);
            if (NULL != sptr) {
                out_page->prev.ptr = sptr;
                out_page->prev.len = slen;
            }
        }
    }

    return PUBNUB_OK;
}

pubnub_json_value_t* pn_app_context_get_data_array(pubnub_serialization_provider_t* serial,
                                                   const pubnub_json_value_t* tree)
{
    if (NULL == serial || NULL == tree || NULL == serial->object_get
        || NULL == serial->value_type || NULL == serial->array_size
        || NULL == serial->array_get) {
        return NULL;
    }

    pubnub_json_value_t* node =
        serial->object_get((pubnub_json_value_t*)tree, "data", 4);
    if (NULL == node) {
        return NULL;
    }
    if (PUBNUB_JSON_ARRAY != serial->value_type(node)) {
        return NULL;
    }
    return node;
}

pubnub_json_value_t*
pn_app_context_get_data_object(pubnub_serialization_provider_t* serial,
                               const pubnub_json_value_t*       tree)
{
    if (NULL == serial || NULL == tree || NULL == serial->object_get
        || NULL == serial->value_type) {
        return NULL;
    }

    pubnub_json_value_t* node =
        serial->object_get((pubnub_json_value_t*)tree, "data", 4);
    if (NULL == node) {
        return NULL;
    }
    if (PUBNUB_JSON_OBJECT != serial->value_type(node)) {
        return NULL;
    }
    return node;
}

void pn_app_context_feature_state_cleanup(void* state,
                                          pubnub_allocator_provider_t* allocator)
{
    if (NULL == state || NULL == allocator) {
        return;
    }

    pn_app_context_state_t* s = (pn_app_context_state_t*)state;

    /* Free the parsed response wrapper (tree is slot-owned, NOT ours to
     * destroy). */
    if (NULL != s->parsed) {
        if (NULL != allocator->free) {
            PN_FREE(allocator, s->parsed);
        }
        s->parsed = NULL;
    }

    /* Free encoded path segment. */
    if (NULL != s->encoded_path_segment && NULL != allocator->free) {
        PN_FREE(allocator, s->encoded_path_segment);
        s->encoded_path_segment = NULL;
    }

    /* Release body buffer. */
    if (NULL != s->owned_body_buf.data && NULL != allocator->buf_release) {
        allocator->buf_release(allocator, &s->owned_body_buf);
    }

    /* Free state struct itself. */
    if (NULL != allocator->free) {
        PN_FREE(allocator, s);
    }
}
