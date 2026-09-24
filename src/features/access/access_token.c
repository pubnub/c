/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "access_internal.h"

#if !PUBNUB_ENABLE_PAM
#error "access_token.c requires PUBNUB_ENABLE_PAM=ON - this translation "  \
    "unit has no meaning without the PAM feature. Check the CMake feature " \
    "gating in src/features/CMakeLists.txt."
#endif

#include "core/core_internal.h"
#include "core/protocol_common/pn_base64.h"
#include "pubnub/capabilities.h"

#include <stddef.h>
#include <string.h>

/**
 * @brief Convert base64url-encoded data to standard base64 in-place.
 *
 * Replaces `-` with `+` and `_` with `/`, then pads with `=` to
 * reach a multiple-of-4 length. The buffer must have capacity for
 * up to 3 extra padding bytes beyond @p len.
 *
 * @param buf     Mutable buffer containing base64url characters.
 * @param len     Length of the base64url data (excluding NUL).
 * @param cap     Total buffer capacity.
 * @param out_len Receives the padded length on success.
 * @return PUBNUB_OK on success, PUBNUB_ERR_BUFFER_TOO_SMALL if
 *         padding would exceed capacity.
 */
static pubnub_res_t base64url_to_base64(char* buf, size_t len, size_t cap, size_t* out_len)
{
    size_t pad_needed = (4 - (len & 3)) & 3;
    size_t i;

    if (len + pad_needed >= cap) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < len; ++i) {
        if ('-' == buf[i]) {
            buf[i] = '+';
        } else if ('_' == buf[i]) {
            buf[i] = '/';
        }
    }

    for (i = 0; i < pad_needed; ++i) {
        buf[len + i] = '=';
    }
    *out_len      = len + pad_needed;
    buf[*out_len] = '\0';

    return PUBNUB_OK;
}

/**
 * @brief Count entries in a CBOR map, or 0 if not a map / NULL.
 */
static size_t count_map_entries(const pn_cbor_value_t* map)
{
    if (NULL == map || PN_CBOR_MAP != map->type) {
        return 0;
    }
    return map->data.map.count;
}

/**
 * @brief Extract a resource permission entry at a given index from
 *        a CBOR resource map (keys are names, values are bitmasks).
 */
static pubnub_parsed_token_resource_t
get_resource_at_index(const pn_cbor_value_t* resource_map, size_t index)
{
    const pubnub_parsed_token_resource_t empty = {0};

    if (NULL == resource_map || PN_CBOR_MAP != resource_map->type) {
        return empty;
    }
    if (index >= resource_map->data.map.count) {
        return empty;
    }

    const pn_cbor_map_entry_t* entry = &resource_map->data.map.entries[index];
    if (NULL == entry->key || NULL == entry->value) {
        return empty;
    }
    if (PN_CBOR_STRING != entry->key->type) {
        return empty;
    }
    if (PN_CBOR_UINT != entry->value->type) {
        return empty;
    }

    pubnub_parsed_token_resource_t result;
    result.name.ptr    = entry->key->data.string.ptr;
    result.name.len    = entry->key->data.string.len;
    result.permissions = (uint32_t)entry->value->data.uint_val;

    return result;
}

/**
 * @brief Navigate the CBOR tree to find a specific resource sub-map.
 *
 * Path: root -> @p section_key ("res" or "pat") -> @p type_key
 * ("chan", "grp", or "uuid").
 */
static const pn_cbor_value_t* get_resource_submap(const pn_cbor_value_t* root,
                                                  const char* section_key,
                                                  size_t      section_key_len,
                                                  const char* type_key,
                                                  size_t      type_key_len)
{
    if (NULL == root) {
        return NULL;
    }

    pn_cbor_value_t* section = pn_cbor_map_get(root, section_key, section_key_len);
    if (NULL == section || PN_CBOR_MAP != section->type) {
        return NULL;
    }

    return pn_cbor_map_get(section, type_key, type_key_len);
}

/**
 * @brief Accessor helper: retrieve a resource entry from the cached
 *        parsed token for a given section/type at @p index.
 */
static pubnub_parsed_token_resource_t token_accessor(pubnub_context_t* ctx,
                                                     size_t            index,
                                                     const char* section_key,
                                                     size_t section_key_len,
                                                     const char* type_key,
                                                     size_t      type_key_len)
{
    const pubnub_parsed_token_resource_t empty = {0};

    if (NULL == ctx) {
        return empty;
    }

    const pn_access_token_state_t* state =
        (const pn_access_token_state_t*)pn_context_feature_state(
            ctx, PUBNUB_FEATURE_PAM);
    if (NULL == state || NULL == state->parsed_tree) {
        return empty;
    }

    const pn_cbor_value_t* submap = get_resource_submap(
        state->parsed_tree, section_key, section_key_len, type_key, type_key_len);

    return get_resource_at_index(submap, index);
}

pubnub_res_t pn_access_parse_token_impl(const char*                  token,
                                        pubnub_allocator_provider_t* alloc,
                                        pn_access_token_state_t*     out)
{
    if (NULL == token || NULL == alloc || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    size_t token_len = strlen(token);
    if (0 == token_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /*
     * Allocate a working buffer for base64url -> base64 conversion.
     * Need token_len + up to 3 pad chars + NUL.
     */
    size_t work_cap = token_len + 4;
    char*  work_buf = (char*)PN_ALLOC(alloc, work_cap, 0);
    if (NULL == work_buf) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    memcpy(work_buf, token, token_len);
    work_buf[token_len] = '\0';

    /* Convert base64url to standard base64. */
    size_t b64_len = 0;
    pubnub_res_t rc = base64url_to_base64(work_buf, token_len, work_cap, &b64_len);
    if (PUBNUB_OK != rc) {
        PN_FREE(alloc, work_buf);
        return rc;
    }

    /* Decode base64 into binary. */
    size_t   decoded_max = pn_base64_decoded_max_len(b64_len);
    uint8_t* decoded_buf = (uint8_t*)PN_ALLOC(alloc, decoded_max, 0);
    if (NULL == decoded_buf) {
        PN_FREE(alloc, work_buf);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    size_t decoded_len = 0;
    rc = pn_base64_decode(work_buf, b64_len, decoded_buf, decoded_max, &decoded_len);

    /* work_buf no longer needed after base64 decode. */
    PN_FREE(alloc, work_buf);
    work_buf = NULL;

    if (PUBNUB_OK != rc) {
        PN_FREE(alloc, decoded_buf);
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Parse CBOR from the decoded bytes. */
    pn_cbor_value_t* root = pn_cbor_parse(decoded_buf, decoded_len, alloc);
    if (NULL == root) {
        PN_FREE(alloc, decoded_buf);
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PN_CBOR_MAP != root->type) {
        pn_cbor_cleanup(root, alloc);
        PN_FREE(alloc, decoded_buf);
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Extract scalar fields. */
    pn_cbor_value_t* v_node = pn_cbor_map_get(root, "v", 1);
    if (NULL != v_node && PN_CBOR_UINT == v_node->type) {
        out->result.version = (int32_t)v_node->data.uint_val;
    }

    pn_cbor_value_t* t_node = pn_cbor_map_get(root, "t", 1);
    if (NULL != t_node && PN_CBOR_UINT == t_node->type) {
        out->result.timestamp = t_node->data.uint_val;
    }

    pn_cbor_value_t* ttl_node = pn_cbor_map_get(root, "ttl", 3);
    if (NULL != ttl_node && PN_CBOR_UINT == ttl_node->type) {
        out->result.ttl = (uint32_t)ttl_node->data.uint_val;
    }

    pn_cbor_value_t* uuid_node = pn_cbor_map_get(root, "uuid", 4);
    if (NULL != uuid_node && PN_CBOR_STRING == uuid_node->type) {
        out->result.authorized_uuid.ptr = uuid_node->data.string.ptr;
        out->result.authorized_uuid.len = uuid_node->data.string.len;
    }

    /* Count resource entries. */
    pn_cbor_value_t* res_node = pn_cbor_map_get(root, "res", 3);
    if (NULL != res_node && PN_CBOR_MAP == res_node->type) {
        pn_cbor_value_t* chan = pn_cbor_map_get(res_node, "chan", 4);
        pn_cbor_value_t* grp  = pn_cbor_map_get(res_node, "grp", 3);
        pn_cbor_value_t* uuid = pn_cbor_map_get(res_node, "uuid", 4);

        out->result.channel_count = (uint32_t)count_map_entries(chan);
        out->result.group_count   = (uint32_t)count_map_entries(grp);
        out->result.uuid_count    = (uint32_t)count_map_entries(uuid);
    }

    /* Count pattern entries. */
    pn_cbor_value_t* pat_node = pn_cbor_map_get(root, "pat", 3);
    if (NULL != pat_node && PN_CBOR_MAP == pat_node->type) {
        pn_cbor_value_t* chan = pn_cbor_map_get(pat_node, "chan", 4);
        pn_cbor_value_t* grp  = pn_cbor_map_get(pat_node, "grp", 3);
        pn_cbor_value_t* uuid = pn_cbor_map_get(pat_node, "uuid", 4);

        out->result.channel_pattern_count = (uint32_t)count_map_entries(chan);
        out->result.group_pattern_count   = (uint32_t)count_map_entries(grp);
        out->result.uuid_pattern_count    = (uint32_t)count_map_entries(uuid);
    }

    /*
     * Transfer ownership: the decoded buffer must remain alive because
     * CBOR string/bytes nodes alias it. Store both in the output state.
     */
    out->parsed_tree = root;
    out->decoded_buf = decoded_buf;

    return PUBNUB_OK;
}

pubnub_res_t pubnub_parse_token(pubnub_context_t*                ctx,
                                const pubnub_parse_token_opts_t* opts,
                                pubnub_parsed_token_t*           out_result)
{
    if (NULL == ctx || NULL == opts || NULL == out_result) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == opts->token || '\0' == opts->token[0]) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    memset(out_result, 0, sizeof(*out_result));

    pubnub_allocator_provider_t* alloc = pn_context_allocator(ctx);
    if (NULL == alloc || NULL == alloc->alloc || NULL == alloc->free) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    /* Decode the token. */
    pn_access_token_state_t new_state;
    pubnub_res_t rc = pn_access_parse_token_impl(opts->token, alloc, &new_state);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Clean up any previously cached parse state. */
    pn_access_token_state_t* prev =
        (pn_access_token_state_t*)pn_context_feature_state(ctx, PUBNUB_FEATURE_PAM);
    if (NULL != prev) {
        pn_access_token_state_cleanup(prev, alloc);
    }

    /* Allocate new persistent state for caching. */
    pn_access_token_state_t* cached = (pn_access_token_state_t*)PN_ALLOC(
        alloc, sizeof(pn_access_token_state_t), 0);
    if (NULL == cached) {
        pn_cbor_cleanup(new_state.parsed_tree, alloc);
        PN_FREE(alloc, new_state.decoded_buf);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    memcpy(cached, &new_state, sizeof(*cached));

    /* Store in feature registry (replaces previous). */
    pn_context_set_feature_state(
        ctx, PUBNUB_FEATURE_PAM, cached, pn_access_token_state_cleanup);

    *out_result = cached->result;

    return PUBNUB_OK;
}

pubnub_parsed_token_resource_t pubnub_parsed_token_channel_at(pubnub_context_t* ctx,
                                                              size_t index)
{
    return token_accessor(ctx, index, "res", 3, "chan", 4);
}

pubnub_parsed_token_resource_t pubnub_parsed_token_group_at(pubnub_context_t* ctx,
                                                            size_t index)
{
    return token_accessor(ctx, index, "res", 3, "grp", 3);
}

pubnub_parsed_token_resource_t pubnub_parsed_token_uuid_at(pubnub_context_t* ctx,
                                                           size_t index)
{
    return token_accessor(ctx, index, "res", 3, "uuid", 4);
}

pubnub_parsed_token_resource_t
pubnub_parsed_token_channel_pattern_at(pubnub_context_t* ctx, size_t index)
{
    return token_accessor(ctx, index, "pat", 3, "chan", 4);
}

pubnub_parsed_token_resource_t
pubnub_parsed_token_group_pattern_at(pubnub_context_t* ctx, size_t index)
{
    return token_accessor(ctx, index, "pat", 3, "grp", 3);
}

pubnub_parsed_token_resource_t
pubnub_parsed_token_uuid_pattern_at(pubnub_context_t* ctx, size_t index)
{
    return token_accessor(ctx, index, "pat", 3, "uuid", 4);
}

void pn_access_token_state_cleanup(void* state, pubnub_allocator_provider_t* alloc)
{
    if (NULL == state || NULL == alloc) {
        return;
    }

    pn_access_token_state_t* s = (pn_access_token_state_t*)state;

    if (NULL != s->parsed_tree && NULL != alloc->free) {
        pn_cbor_cleanup(s->parsed_tree, alloc);
        s->parsed_tree = NULL;
    }

    /* Free the decoded bytes buffer that CBOR nodes alias. */
    if (NULL != s->decoded_buf && NULL != alloc->free) {
        PN_FREE(alloc, s->decoded_buf);
        s->decoded_buf = NULL;
    }

    if (NULL != alloc->free) {
        PN_FREE(alloc, s);
    }
}
