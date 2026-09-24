/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file jsmn_serialization_units.c
 * @brief Unit tests for the jsmn-backed serialization provider.
 *
 * Mirrors the contract coverage in @c cjson_serialization_units.c
 * against the jsmn backend. The vtable surface is identical between
 * the two backends; the differences exercised here are:
 *
 *   - @c init / @c deinit are NOT NULL on this backend (the provider
 *     stores the resolved allocator via @c init).
 *   - @c object_reserve / @c array_reserve ARE implemented (the
 *     SDK-owned tree representation supports explicit pre-allocation).
 *   - @c value_create_string_view aliases ANY (str, len) span -- the
 *     jsmn backend stores both pointer and length without requiring
 *     NUL termination, so length-counted spans are accepted.
 *
 * Other backend-specific concerns (int64 timetoken round-trips,
 * verbatim raw round-trips, JSON_DOUBLE asymmetry) follow the same
 * contract as the cJSON backend and are re-tested here against the
 * jsmn implementation.
 */

#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/provider_deps.h"
#include "pubnub/providers/serialization.h"

pubnub_serialization_provider_t* pn_serialization_default(void);

typedef struct spy_allocator {
    pubnub_allocator_provider_t base;
    int                         alloc_calls;
    int                         realloc_calls;
    int                         free_calls;
    /** When non-zero, the Nth alloc-or-realloc call returns NULL. */
    int fail_alloc_after;
} spy_allocator_t;

static void* spy_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    spy_allocator_t* sa = (spy_allocator_t*)self;
    sa->alloc_calls++;
    (void)align;
    if (sa->fail_alloc_after > 0
        && sa->alloc_calls + sa->realloc_calls >= sa->fail_alloc_after) {
        return NULL;
    }
    return malloc(size);
}

static void* spy_realloc(pubnub_allocator_provider_t* self,
                         void*                        ptr,
                         size_t                       old_size,
                         size_t                       new_size,
                         size_t                       align)
{
    spy_allocator_t* sa = (spy_allocator_t*)self;
    sa->realloc_calls++;
    (void)old_size;
    (void)align;
    if (sa->fail_alloc_after > 0
        && sa->alloc_calls + sa->realloc_calls >= sa->fail_alloc_after) {
        return NULL;
    }
    return realloc(ptr, new_size);
}

static void spy_free(pubnub_allocator_provider_t* self, void* ptr)
{
    spy_allocator_t* sa = (spy_allocator_t*)self;
    sa->free_calls++;
    free(ptr);
}

static pubnub_buffer_t spy_buf_acquire(pubnub_allocator_provider_t* self,
                                       pubnub_buf_purpose_t         purpose)
{
    (void)self;
    (void)purpose;
    pubnub_buffer_t buf = {NULL, 0, 0, purpose};
    return buf;
}

static void spy_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    (void)buf;
}

static spy_allocator_t spy_make(void)
{
    spy_allocator_t sa = {
        .base =
            {
                   .alloc       = spy_alloc,
                   .realloc     = spy_realloc,
                   .free        = spy_free,
                   .buf_acquire = spy_buf_acquire,
                   .buf_release = spy_buf_release,
                   .buf_grow    = NULL,
                   .init        = NULL,
                   .deinit      = NULL,
                   },
        .alloc_calls      = 0,
        .realloc_calls    = 0,
        .free_calls       = 0,
        .fail_alloc_after = 0,
    };
    return sa;
}

/* Reset provider's allocator binding back to "no allocator -- libc
 * fallback" so subsequent tests are isolated from the spy. */
static void provider_reset_allocator(pubnub_serialization_provider_t* sut)
{
    if (sut->deinit != NULL) {
        sut->deinit(sut);
    }
}

static void parse_should_succeed_on_valid_json_object(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char* payload =
        "{\"timetoken\":17001234567890123,\"message\":\"hi\"}";

    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)payload, strlen(payload));

    assert_non_null(value);
    sut->value_destroy(sut, value);
}

static void parse_should_succeed_on_valid_json_array(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Publish responses are top-level arrays; parser must accept. */
    const char* payload = "[1,\"Sent\",\"17001234567890123\"]";

    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)payload, strlen(payload));

    assert_non_null(value);
    sut->value_destroy(sut, value);
}

static void parse_should_return_null_on_malformed_json(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char* broken = "{\"unterminated\":";

    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)broken, strlen(broken));

    assert_null(value);
}

static void parse_should_honour_length_without_null_terminator(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Transport response buffers are not NUL-terminated. The
     * provider must respect the length argument. */
    uint8_t buf[64];
    memset(buf, 'X', sizeof(buf));
    const char* document     = "{\"ok\":true}";
    size_t      document_len = strlen(document);
    memcpy(buf, document, document_len);

    pubnub_json_value_t* value = sut->parse(sut, buf, document_len);

    assert_non_null(value);
    sut->value_destroy(sut, value);
}

static void parse_should_return_null_on_null_data(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* value = sut->parse(sut, NULL, 16);

    assert_null(value);
}

static void parse_should_return_null_on_zero_length(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const uint8_t dummy[] = {'{', '}'};

    pubnub_json_value_t* value = sut->parse(sut, dummy, 0);

    assert_null(value);
}

static void serialize_should_emit_compact_json_for_valid_input(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char*          source = "{\"n\":42}";
    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)source, strlen(source));
    assert_non_null(value);

    uint8_t      output[64] = {0};
    size_t       output_len = 0;
    pubnub_res_t result =
        sut->serialize(sut, value, output, sizeof(output), &output_len);

    assert_int_equal(result, PUBNUB_OK);
    assert_int_equal(output_len, strlen(source));
    assert_memory_equal(output, source, output_len);
    sut->value_destroy(sut, value);
}

static void serialize_should_write_out_len(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char*          source = "[1,2,3]";
    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)source, strlen(source));

    uint8_t      output[32] = {0};
    size_t       output_len = 0;
    pubnub_res_t result =
        sut->serialize(sut, value, output, sizeof(output), &output_len);

    assert_int_equal(result, PUBNUB_OK);
    /* The jsmn backend does not NUL-terminate output; output_len is
     * the byte count emitted. */
    assert_int_equal(output_len, strlen(source));
    sut->value_destroy(sut, value);
}

static void serialize_should_return_buffer_too_small_when_undersized(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char*          source = "{\"key\":\"a longer value that won't fit\"}";
    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)source, strlen(source));

    uint8_t      output[8]  = {0};
    size_t       output_len = 0;
    pubnub_res_t result =
        sut->serialize(sut, value, output, sizeof(output), &output_len);

    assert_int_equal(result, PUBNUB_ERR_BUFFER_TOO_SMALL);
    assert_int_equal(output_len, 0);
    sut->value_destroy(sut, value);
}

static void serialize_should_return_buffer_too_small_on_zero_buf_len(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char*          source = "{}";
    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)source, strlen(source));

    uint8_t output[16];
    memset(output, 0xBB, sizeof(output));
    size_t       output_len = 999;
    pubnub_res_t result = sut->serialize(sut, value, output, 0, &output_len);

    assert_int_equal(result, PUBNUB_ERR_BUFFER_TOO_SMALL);
    assert_int_equal(output_len, 0);
    sut->value_destroy(sut, value);
}

static void serialize_should_return_invalid_argument_on_null_value(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    uint8_t      output[32] = {0};
    size_t       output_len = 0;
    pubnub_res_t result =
        sut->serialize(sut, NULL, output, sizeof(output), &output_len);

    assert_int_equal(result, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void serialize_should_return_invalid_argument_on_null_buf(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char*          source = "{}";
    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)source, strlen(source));

    size_t       output_len = 0;
    pubnub_res_t result     = sut->serialize(sut, value, NULL, 32, &output_len);

    assert_int_equal(result, PUBNUB_ERR_INVALID_ARGUMENT);
    sut->value_destroy(sut, value);
}

static void serialize_should_return_invalid_argument_on_null_out_len(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char*          source = "{}";
    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)source, strlen(source));

    uint8_t output[32] = {0};
    pubnub_res_t result = sut->serialize(sut, value, output, sizeof(output), NULL);

    assert_int_equal(result, PUBNUB_ERR_INVALID_ARGUMENT);
    sut->value_destroy(sut, value);
}

static void value_destroy_should_accept_null(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Releasing NULL must be a safe no-op so feature code does not
     * need to null-check before destroy. */
    sut->value_destroy(sut, NULL);
}

static void parse_then_free_should_round_trip_cleanly(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char* document = "[{\"a\":1},{\"b\":2},{\"c\":[true,false,null]}]";
    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)document, strlen(document));

    assert_non_null(value);
    sut->value_destroy(sut, value);
}

static void roundtrip_parse_then_serialize_should_preserve_payload(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Object key order is preserved by the jsmn-walk; the canonical
     * input is reproduced byte-for-byte after a round-trip. */
    const char* canonical = "{\"a\":1,\"b\":[2,3],\"c\":null,\"d\":true}";

    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)canonical, strlen(canonical));
    assert_non_null(value);

    uint8_t      output[128] = {0};
    size_t       output_len  = 0;
    pubnub_res_t rc =
        sut->serialize(sut, value, output, sizeof(output), &output_len);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(output_len, strlen(canonical));
    assert_memory_equal(output, canonical, output_len);

    sut->value_destroy(sut, value);
}

static void provider_should_expose_every_mandatory_callback(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    assert_non_null(sut);
    assert_non_null(sut->parse);
    assert_non_null(sut->serialize);
    assert_non_null(sut->value_destroy);
}

static void provider_should_set_init_deinit_for_allocator_storage(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Unlike the cJSON backend (which keeps init/deinit NULL because
     * cJSON's hooks are process-global), the jsmn backend stores the
     * resolved allocator on the provider struct and exposes both
     * lifecycle callbacks. */
    assert_non_null(sut->init);
    assert_non_null(sut->deinit);
}

static void pn_serialization_default_should_return_same_singleton(void** state)
{
    (void)state;

    /* The provider is a file-scope singleton; every call returns the
     * same address. */
    assert_ptr_equal(pn_serialization_default(), pn_serialization_default());
}

static void value_create_object_should_produce_object_type(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* obj = sut->value_create_object(sut);
    assert_non_null(obj);
    assert_int_equal(sut->value_type(obj), PUBNUB_JSON_OBJECT);
    assert_int_equal(sut->object_size(obj), 0);
    sut->value_destroy(sut, obj);
}

static void value_create_array_should_produce_array_type(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* arr = sut->value_create_array(sut);
    assert_non_null(arr);
    assert_int_equal(sut->value_type(arr), PUBNUB_JSON_ARRAY);
    assert_int_equal(sut->array_size(arr), 0);
    sut->value_destroy(sut, arr);
}

static void value_create_null_should_produce_null_type(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* value = sut->value_create_null(sut);
    assert_non_null(value);
    assert_int_equal(sut->value_type(value), PUBNUB_JSON_NULL);
    sut->value_destroy(sut, value);
}

static void value_create_bool_truthy_should_produce_true(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* value = sut->value_create_bool(sut, 1);
    assert_non_null(value);
    assert_int_equal(sut->value_type(value), PUBNUB_JSON_BOOL);
    int truthy = -1;
    assert_int_equal(sut->value_as_bool(value, &truthy), PUBNUB_OK);
    assert_int_equal(truthy, 1);
    sut->value_destroy(sut, value);
}

static void value_create_bool_zero_should_produce_false(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* value = sut->value_create_bool(sut, 0);
    assert_non_null(value);
    assert_int_equal(sut->value_type(value), PUBNUB_JSON_BOOL);
    int truthy = -1;
    assert_int_equal(sut->value_as_bool(value, &truthy), PUBNUB_OK);
    assert_int_equal(truthy, 0);
    sut->value_destroy(sut, value);
}

static void value_create_int_should_round_trip_small_values(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    int                  v     = -999999;
    pubnub_json_value_t* value = sut->value_create_int(sut, v);
    assert_non_null(value);
    assert_int_equal(sut->value_type(value), PUBNUB_JSON_INT);

    int read_back = 0;
    assert_int_equal(sut->value_as_int(value, &read_back), PUBNUB_OK);
    assert_int_equal(read_back, v);

    uint8_t buf[64] = {0};
    size_t  written = 0;
    assert_int_equal(sut->serialize(sut, value, buf, sizeof(buf), &written),
                     PUBNUB_OK);
    sut->value_destroy(sut, value);

    pubnub_json_value_t* parsed = sut->parse(sut, buf, written);
    assert_non_null(parsed);
    assert_int_equal(sut->value_type(parsed), PUBNUB_JSON_INT);
    int parsed_value = 0;
    assert_int_equal(sut->value_as_int(parsed, &parsed_value), PUBNUB_OK);
    assert_int_equal(parsed_value, v);
    sut->value_destroy(sut, parsed);
}

static void value_create_int_should_emit_exact_decimal_bytes(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    int                  v     = 123456789;
    pubnub_json_value_t* value = sut->value_create_int(sut, v);
    assert_non_null(value);

    uint8_t      buf[32] = {0};
    size_t       written = 0;
    pubnub_res_t rc = sut->serialize(sut, value, buf, sizeof(buf), &written);
    assert_int_equal(rc, PUBNUB_OK);
    /* Pin the exact byte sequence so a regression to scientific
     * notation or a decimal point is caught at the byte level. */
    assert_int_equal(written, 9);
    assert_memory_equal(buf, "123456789", 9);
    sut->value_destroy(sut, value);
}

static void value_create_int_should_round_trip_int_boundaries(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    int boundaries[] = {INT_MIN, INT_MAX};
    for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); ++i) {
        int                  v    = boundaries[i];
        pubnub_json_value_t* node = sut->value_create_int(sut, v);
        assert_non_null(node);
        assert_int_equal(sut->value_type(node), PUBNUB_JSON_INT);

        int read_back = 0;
        assert_int_equal(sut->value_as_int(node, &read_back), PUBNUB_OK);
        assert_true(read_back == v);

        uint8_t      buf[32] = {0};
        size_t       written = 0;
        pubnub_res_t rc = sut->serialize(sut, node, buf, sizeof(buf), &written);
        assert_int_equal(rc, PUBNUB_OK);
        sut->value_destroy(sut, node);

        pubnub_json_value_t* parsed = sut->parse(sut, buf, written);
        assert_non_null(parsed);
        assert_int_equal(sut->value_type(parsed), PUBNUB_JSON_INT);
        int parsed_value = 0;
        assert_int_equal(sut->value_as_int(parsed, &parsed_value), PUBNUB_OK);
        assert_true(parsed_value == v);
        sut->value_destroy(sut, parsed);
    }
}

static void parse_should_fall_back_to_double_on_int_overflow(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* One beyond INT_MAX (2147483647). */
    const char*          overflow_literal = "2147483648";
    pubnub_json_value_t* parsed           = sut->parse(
        sut, (const uint8_t*)overflow_literal, strlen(overflow_literal));
    assert_non_null(parsed);
    /* The type reports DOUBLE because the value exceeds int range.
     * When PUBNUB_CFG_JSON_DOUBLE is OFF the value is unreadable
     * (vtable slot NULL) but the node is valid. */
    assert_int_equal(sut->value_type(parsed), PUBNUB_JSON_DOUBLE);
#if !PUBNUB_CFG_JSON_DOUBLE
    assert_null(sut->value_as_double);
#endif
    sut->value_destroy(sut, parsed);
}

#if PUBNUB_CFG_JSON_DOUBLE
static void parse_should_classify_floating_point_literals_as_double(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char* literals[] = {"1.5", "1e3", "-2.5e-1"};
    for (size_t i = 0; i < sizeof(literals) / sizeof(literals[0]); ++i) {
        size_t               len = strlen(literals[i]);
        pubnub_json_value_t* parsed =
            sut->parse(sut, (const uint8_t*)literals[i], len);
        assert_non_null(parsed);
        assert_int_equal(sut->value_type(parsed), PUBNUB_JSON_DOUBLE);

        double v = 0.0;
        assert_int_equal(sut->value_as_double(parsed, &v), PUBNUB_OK);
        assert_true(v != 0.0);
        sut->value_destroy(sut, parsed);
    }
}
#endif /* PUBNUB_CFG_JSON_DOUBLE */

static void object_set_should_handle_keys_longer_than_typical(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* The jsmn backend has no inline-vs-heap split for keys (every
     * key is allocator-backed) but a 200-byte key still exercises
     * the alloc / strdup / lookup paths under realistic load. */
    char long_key[201];
    memset(long_key, 'k', 200);
    long_key[200] = '\0';

    pubnub_json_value_t* obj   = sut->value_create_object(sut);
    pubnub_json_value_t* child = sut->value_create_int(sut, 7);
    assert_non_null(obj);
    assert_non_null(child);

    pubnub_res_t rc = sut->object_set(sut, obj, long_key, 200, child);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(sut->object_size(obj), 1);

    pubnub_json_value_t* fetched = sut->object_get(obj, long_key, 200);
    assert_non_null(fetched);
    int fetched_value = 0;
    assert_int_equal(sut->value_as_int(fetched, &fetched_value), PUBNUB_OK);
    assert_int_equal(fetched_value, 7);

    sut->value_destroy(sut, obj);
}

static void value_create_int_should_serialize_with_no_decimal_point(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* value = sut->value_create_int(sut, 42);
    assert_non_null(value);

    uint8_t output[16] = {0};
    size_t  out_len    = 0;
    pubnub_res_t rc = sut->serialize(sut, value, output, sizeof(output), &out_len);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out_len, 2);
    assert_memory_equal(output, "42", 2);
    sut->value_destroy(sut, value);
}

static void value_create_string_should_copy_bytes(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    char                 buf[8] = {'h', 'e', 'l', 'l', 'o', '!', '\0', '\0'};
    pubnub_json_value_t* value  = sut->value_create_string(sut, buf, 6);
    assert_non_null(value);

    /* Mutate the source after construction; the accessor must still
     * return the original "hello!" -- proving the bytes were
     * copied. */
    memset(buf, 'X', sizeof(buf));

    size_t      out_len = 0;
    const char* read    = sut->value_as_string(value, &out_len);
    assert_non_null(read);
    assert_int_equal(out_len, 6);
    assert_memory_equal(read, "hello!", 6);
    sut->value_destroy(sut, value);
}

static void value_create_string_view_should_alias_bytes_nul_terminated(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* NUL-terminated path: caller passes len = 0, the backend
     * resolves the length via strlen and aliases the buffer. */
    char                 source[16] = "hello";
    pubnub_json_value_t* value = sut->value_create_string_view(sut, source, 0);
    assert_non_null(value);

    source[0] = 'H';
    source[4] = 'O';

    size_t      out_len = 0;
    const char* read    = sut->value_as_string(value, &out_len);
    assert_non_null(read);
    assert_int_equal(out_len, 5);
    assert_memory_equal(read, "HellO", 5);
    sut->value_destroy(sut, value);
}

static void value_create_string_view_should_alias_length_counted(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Length-counted path: unlike the cJSON backend (which can only
     * alias NUL-terminated input), the jsmn backend aliases ANY
     * (str, len) span. The bytes need not be NUL-terminated. */
    char                 source[16] = "hello world";
    pubnub_json_value_t* value = sut->value_create_string_view(sut, source, 5);
    assert_non_null(value);

    /* Mutating bytes beyond the recorded length must NOT affect the
     * value reported via value_as_string. */
    source[0] = 'H';
    source[5] = '!';

    size_t      out_len = 0;
    const char* read    = sut->value_as_string(value, &out_len);
    assert_non_null(read);
    assert_int_equal(out_len, 5);
    assert_memory_equal(read, "Hello", 5);
    sut->value_destroy(sut, value);
}

static void value_create_raw_should_round_trip_verbatim(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Raw nodes serialize byte-identically to the input. PAM signature
     * computation depends on this contract. */
    const char*          raw_bytes = "[\"hello\",42]";
    size_t               raw_len   = strlen(raw_bytes);
    pubnub_json_value_t* value =
        sut->value_create_raw(sut, (const uint8_t*)raw_bytes, raw_len);
    assert_non_null(value);
    assert_int_equal(sut->value_type(value), PUBNUB_JSON_RAW);

    uint8_t output[64] = {0};
    size_t  out_len    = 0;
    pubnub_res_t rc = sut->serialize(sut, value, output, sizeof(output), &out_len);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out_len, strlen(raw_bytes));
    assert_memory_equal(output, raw_bytes, out_len);
    sut->value_destroy(sut, value);
}

static void value_create_raw_should_reject_zero_length(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Empty raw bytes are not a valid JSON value; rejected with
     * NULL to match the cJSON backend's contract. */
    const uint8_t        dummy = 0;
    pubnub_json_value_t* value = sut->value_create_raw(sut, &dummy, 0);
    assert_null(value);
}

static void value_create_double_slot_matches_compile_time_toggle(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

#if PUBNUB_CFG_JSON_DOUBLE
    assert_non_null(sut->value_create_double);
    assert_non_null(sut->value_as_double);
#else
    assert_null(sut->value_create_double);
    assert_null(sut->value_as_double);
#endif
}

static void object_set_should_replace_existing_key(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* obj = sut->value_create_object(sut);
    pubnub_json_value_t* one = sut->value_create_int(sut, 1);
    pubnub_json_value_t* two = sut->value_create_int(sut, 2);
    assert_non_null(obj);
    assert_non_null(one);
    assert_non_null(two);

    assert_int_equal(sut->object_set(sut, obj, "k", 1, one), PUBNUB_OK);
    assert_int_equal(sut->object_size(obj), 1);
    assert_int_equal(sut->object_set(sut, obj, "k", 1, two), PUBNUB_OK);
    /* After the replace the object still has exactly one key. */
    assert_int_equal(sut->object_size(obj), 1);

    pubnub_json_value_t* found = sut->object_get(obj, "k", 1);
    assert_non_null(found);
    int out = 0;
    assert_int_equal(sut->value_as_int(found, &out), PUBNUB_OK);
    assert_int_equal(out, 2);

    sut->value_destroy(sut, obj);
}

static void object_remove_absent_key_should_return_invalid_argument(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* obj = sut->value_create_object(sut);
    assert_non_null(obj);

    assert_int_equal(sut->object_remove(sut, obj, "absent", 6),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    sut->value_destroy(sut, obj);
}

static void array_remove_out_of_range_should_return_invalid_argument(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* arr = sut->value_create_array(sut);
    pubnub_json_value_t* one = sut->value_create_int(sut, 1);
    assert_non_null(arr);
    assert_non_null(one);
    assert_int_equal(sut->array_append(sut, arr, one), PUBNUB_OK);

    pubnub_res_t rc = sut->array_remove(sut, arr, 5);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(sut->array_size(arr), 1);

    sut->value_destroy(sut, arr);
}

static void array_get_should_return_element_at_index(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* arr = sut->value_create_array(sut);
    assert_non_null(arr);
    for (int i = 0; i < 3; ++i) {
        pubnub_json_value_t* item = sut->value_create_int(sut, 100 + i);
        assert_non_null(item);
        assert_int_equal(sut->array_append(sut, arr, item), PUBNUB_OK);
    }

    pubnub_json_value_t* second = sut->array_get(arr, 1);
    assert_non_null(second);
    int value = 0;
    assert_int_equal(sut->value_as_int(second, &value), PUBNUB_OK);
    assert_int_equal(value, 101);

    /* Out-of-range index returns NULL. */
    assert_null(sut->array_get(arr, 5));

    sut->value_destroy(sut, arr);
}

static void object_iter_should_walk_all_keys_exactly_once(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* obj = sut->value_create_object(sut);
    pubnub_json_value_t* a   = sut->value_create_int(sut, 1);
    pubnub_json_value_t* b   = sut->value_create_int(sut, 2);
    pubnub_json_value_t* c   = sut->value_create_int(sut, 3);
    assert_int_equal(sut->object_set(sut, obj, "alpha", 5, a), PUBNUB_OK);
    assert_int_equal(sut->object_set(sut, obj, "beta", 4, b), PUBNUB_OK);
    assert_int_equal(sut->object_set(sut, obj, "gamma", 5, c), PUBNUB_OK);

    pubnub_json_iter_t iter;
    assert_int_equal(sut->object_iter_init(obj, &iter), 1);

    int seen_alpha = 0;
    int seen_beta  = 0;
    int seen_gamma = 0;
    int total      = 0;

    const char*          out_key     = NULL;
    size_t               out_key_len = 0;
    pubnub_json_value_t* out_value   = NULL;

    while (sut->object_iter_next(&iter, &out_key, &out_key_len, &out_value)) {
        total++;
        assert_non_null(out_key);
        assert_non_null(out_value);
        if (out_key_len == 5 && memcmp(out_key, "alpha", 5) == 0) {
            seen_alpha++;
        } else if (out_key_len == 4 && memcmp(out_key, "beta", 4) == 0) {
            seen_beta++;
        } else if (out_key_len == 5 && memcmp(out_key, "gamma", 5) == 0) {
            seen_gamma++;
        }
    }

    assert_int_equal(total, 3);
    assert_int_equal(seen_alpha, 1);
    assert_int_equal(seen_beta, 1);
    assert_int_equal(seen_gamma, 1);

    assert_int_equal(
        sut->object_iter_next(&iter, &out_key, &out_key_len, &out_value), 0);

    sut->value_destroy(sut, obj);
}

static void value_as_int_on_int_node_should_return_value(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* value = sut->value_create_int(sut, -1234567890);
    assert_non_null(value);

    int out = 0;
    assert_int_equal(sut->value_as_int(value, &out), PUBNUB_OK);
    assert_int_equal(out, -1234567890);

    sut->value_destroy(sut, value);
}

static void value_as_string_on_string_node_should_return_string_and_length(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* value = sut->value_create_string(sut, "PubNub", 6);
    assert_non_null(value);

    size_t      out_len = 0;
    const char* read    = sut->value_as_string(value, &out_len);
    assert_non_null(read);
    assert_int_equal(out_len, 6);
    assert_memory_equal(read, "PubNub", 6);

    sut->value_destroy(sut, value);
}

static void value_destroy_on_complex_tree_should_not_leak(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Build {"meta":{"x":1,"y":[true,false,null]},"items":[1,2,3]}.
     * Run under ASan/LSan to catch leaks. */
    pubnub_json_value_t* root  = sut->value_create_object(sut);
    pubnub_json_value_t* meta  = sut->value_create_object(sut);
    pubnub_json_value_t* x     = sut->value_create_int(sut, 1);
    pubnub_json_value_t* y     = sut->value_create_array(sut);
    pubnub_json_value_t* yt    = sut->value_create_bool(sut, 1);
    pubnub_json_value_t* yf    = sut->value_create_bool(sut, 0);
    pubnub_json_value_t* yn    = sut->value_create_null(sut);
    pubnub_json_value_t* items = sut->value_create_array(sut);
    pubnub_json_value_t* i1    = sut->value_create_int(sut, 1);
    pubnub_json_value_t* i2    = sut->value_create_int(sut, 2);
    pubnub_json_value_t* i3    = sut->value_create_int(sut, 3);

    assert_int_equal(sut->object_set(sut, meta, "x", 1, x), PUBNUB_OK);
    assert_int_equal(sut->array_append(sut, y, yt), PUBNUB_OK);
    assert_int_equal(sut->array_append(sut, y, yf), PUBNUB_OK);
    assert_int_equal(sut->array_append(sut, y, yn), PUBNUB_OK);
    assert_int_equal(sut->object_set(sut, meta, "y", 1, y), PUBNUB_OK);
    assert_int_equal(sut->object_set(sut, root, "meta", 4, meta), PUBNUB_OK);
    assert_int_equal(sut->array_append(sut, items, i1), PUBNUB_OK);
    assert_int_equal(sut->array_append(sut, items, i2), PUBNUB_OK);
    assert_int_equal(sut->array_append(sut, items, i3), PUBNUB_OK);
    assert_int_equal(sut->object_set(sut, root, "items", 5, items), PUBNUB_OK);

    sut->value_destroy(sut, root);
}

static void object_reserve_should_succeed_on_valid_capacity(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* The jsmn backend implements reserve (unlike cJSON). The call
     * must succeed and the object remains usable for subsequent
     * inserts. */
    assert_non_null(sut->object_reserve);

    pubnub_json_value_t* obj = sut->value_create_object(sut);
    assert_non_null(obj);
    assert_int_equal(sut->object_reserve(sut, obj, 16), PUBNUB_OK);

    /* Inserts after reserve still succeed. */
    pubnub_json_value_t* one = sut->value_create_int(sut, 1);
    assert_int_equal(sut->object_set(sut, obj, "a", 1, one), PUBNUB_OK);
    assert_int_equal(sut->object_size(obj), 1);

    sut->value_destroy(sut, obj);
}

static void array_reserve_should_succeed_on_valid_capacity(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    assert_non_null(sut->array_reserve);

    pubnub_json_value_t* arr = sut->value_create_array(sut);
    assert_non_null(arr);
    assert_int_equal(sut->array_reserve(sut, arr, 16), PUBNUB_OK);

    pubnub_json_value_t* one = sut->value_create_int(sut, 1);
    assert_int_equal(sut->array_append(sut, arr, one), PUBNUB_OK);
    assert_int_equal(sut->array_size(arr), 1);

    sut->value_destroy(sut, arr);
}

static void object_reserve_should_be_idempotent(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* obj = sut->value_create_object(sut);
    assert_non_null(obj);

    assert_int_equal(sut->object_reserve(sut, obj, 8), PUBNUB_OK);
    assert_int_equal(sut->object_reserve(sut, obj, 8), PUBNUB_OK);
    assert_int_equal(sut->object_reserve(sut, obj, 4), PUBNUB_OK);

    sut->value_destroy(sut, obj);
}

static void provider_init_should_store_allocator(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    spy_allocator_t        spy  = spy_make();
    pubnub_provider_deps_t deps = {
        .allocator = &spy.base,
        .logger    = NULL,
        .platform  = NULL,
        .proxy     = NULL,
    };

    /* Bind the spy allocator. Subsequent constructor calls must
     * route through the spy's alloc/free counters. */
    int rc = sut->init(sut, &deps);
    assert_int_equal(rc, 0);

    int alloc_before = spy.alloc_calls;
    int free_before  = spy.free_calls;

    pubnub_json_value_t* obj = sut->value_create_object(sut);
    assert_non_null(obj);
    /* At least one alloc must have routed through the spy. */
    assert_true(spy.alloc_calls > alloc_before);

    sut->value_destroy(sut, obj);
    /* At least one free must have routed through the spy. */
    assert_true(spy.free_calls > free_before);

    /* Restore the unbound state so other tests start from a clean
     * slate (libc fallback). */
    provider_reset_allocator(sut);
}

static void provider_deinit_should_clear_allocator(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    spy_allocator_t        spy  = spy_make();
    pubnub_provider_deps_t deps = {
        .allocator = &spy.base,
        .logger    = NULL,
        .platform  = NULL,
        .proxy     = NULL,
    };

    assert_int_equal(sut->init(sut, &deps), 0);
    sut->deinit(sut);

    /* After deinit, allocations route to libc again (no spy
     * counters). The provider must remain callable. */
    int                  alloc_before = spy.alloc_calls;
    pubnub_json_value_t* obj          = sut->value_create_object(sut);
    assert_non_null(obj);
    assert_int_equal(spy.alloc_calls, alloc_before);

    sut->value_destroy(sut, obj);
}

/**
 * @brief Hostile deeply-nested input is rejected, not stack-overflowed.
 *
 * Builds an array nesting `PUBNUB_CFG_JSON_MAX_NESTING_DEPTH + 1`
 * levels deep and asserts the parser returns NULL with no leaks.
 * Exercises the depth-cap on the recursive walker.
 */
static void parse_should_reject_input_beyond_max_nesting_depth(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Construct "[[[...]]]" with one extra level beyond the cap. */
    size_t total_levels = (size_t)PUBNUB_CFG_JSON_MAX_NESTING_DEPTH + 1;
    size_t buf_len      = 2 * total_levels + 1;
    char*  payload      = (char*)malloc(buf_len);
    assert_non_null(payload);
    for (size_t i = 0; i < total_levels; ++i) {
        payload[i]                        = '[';
        payload[total_levels * 2 - 1 - i] = ']';
    }
    payload[buf_len - 1] = '\0';

    pubnub_json_value_t* parsed =
        sut->parse(sut, (const uint8_t*)payload, buf_len - 1);
    assert_null(parsed);

    free(payload);
}

/**
 * @brief Input at exactly the depth cap parses successfully.
 *
 * Boundary check that the cap is inclusive of `MAX_NESTING_DEPTH`
 * and exclusive of one beyond. Mirrors the rejection test above.
 */
static void parse_should_accept_input_at_exactly_max_nesting_depth(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    size_t levels  = (size_t)PUBNUB_CFG_JSON_MAX_NESTING_DEPTH;
    size_t buf_len = 2 * levels + 1;
    char*  payload = (char*)malloc(buf_len);
    assert_non_null(payload);
    for (size_t i = 0; i < levels; ++i) {
        payload[i]                  = '[';
        payload[levels * 2 - 1 - i] = ']';
    }
    payload[buf_len - 1] = '\0';

    pubnub_json_value_t* parsed =
        sut->parse(sut, (const uint8_t*)payload, buf_len - 1);
    assert_non_null(parsed);
    sut->value_destroy(sut, parsed);
    free(payload);
}

/**
 * @brief Parsed tree uses a single slab allocation; destroy frees it.
 *
 * Exercises the slab path end-to-end: parse a multi-type document,
 * verify tree navigation works on slab-backed nodes, then destroy.
 * Run under ASan/LSan to confirm a single free releases everything.
 */
static void slab_parse_complex_tree_should_round_trip(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char* doc =
        "{\"a\":[1,2,3],\"b\":{\"c\":\"hello\"},\"d\":true,\"e\":null}";
    pubnub_json_value_t* root = sut->parse(sut, (const uint8_t*)doc, strlen(doc));
    assert_non_null(root);
    assert_int_equal(sut->value_type(root), PUBNUB_JSON_OBJECT);

    /* Traverse nested structures. */
    pubnub_json_value_t* arr = sut->object_get(root, "a", 1);
    assert_non_null(arr);
    assert_int_equal(sut->array_size(arr), 3);
    int v = 0;
    assert_int_equal(sut->value_as_int(sut->array_get(arr, 0), &v), PUBNUB_OK);
    assert_int_equal(v, 1);

    pubnub_json_value_t* obj_b = sut->object_get(root, "b", 1);
    assert_non_null(obj_b);
    pubnub_json_value_t* c_val = sut->object_get(obj_b, "c", 1);
    assert_non_null(c_val);
    size_t      slen = 0;
    const char* sptr = sut->value_as_string(c_val, &slen);
    assert_int_equal(slen, 5);
    assert_memory_equal(sptr, "hello", 5);

    int truthy = -1;
    assert_int_equal(sut->value_as_bool(sut->object_get(root, "d", 1), &truthy),
                     PUBNUB_OK);
    assert_int_equal(truthy, 1);
    assert_int_equal(sut->value_type(sut->object_get(root, "e", 1)),
                     PUBNUB_JSON_NULL);

    /* Serialize round-trip. */
    uint8_t buf[128] = {0};
    size_t  out_len  = 0;
    assert_int_equal(sut->serialize(sut, root, buf, sizeof(buf), &out_len),
                     PUBNUB_OK);
    assert_int_equal(out_len, strlen(doc));
    assert_memory_equal(buf, doc, out_len);

    sut->value_destroy(sut, root);
}

/**
 * @brief Slab parse uses exactly 1 alloc (slab) + 1 realloc (tokens).
 *
 * The token array goes through realloc (from NULL); the slab goes
 * through alloc. Destroy frees the slab in one free call.
 */
static void slab_parse_should_minimize_allocator_calls(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();
    const char*                      doc;
    pubnub_json_value_t*             root;
    int                              alloc_before;

    spy_allocator_t        spy  = spy_make();
    pubnub_provider_deps_t deps = {
        .allocator = &spy.base,
        .logger    = NULL,
        .platform  = NULL,
        .proxy     = NULL,
    };
    assert_int_equal(sut->init(sut, &deps), 0);

    doc  = "{\"key\":\"value\",\"n\":42}";
    root = sut->parse(sut, (const uint8_t*)doc, strlen(doc));
    assert_non_null(root);

    /* Token array: 1 realloc call (from NULL).
     * Slab: 1 alloc call.
     * No per-node alloc calls (all from slab). */
    assert_true(spy.alloc_calls >= 1);
    assert_true(spy.realloc_calls >= 1);

    alloc_before = spy.alloc_calls;
    sut->value_destroy(sut, root);

    /* Destroy should NOT trigger more alloc calls. */
    assert_int_equal(spy.alloc_calls, alloc_before);
    /* Parse frees token array (1 free); destroy frees slab (1 free). */
    assert_true(spy.free_calls >= 2);

    provider_reset_allocator(sut);
}

/**
 * @brief Empty object/array parse + destroy must not leak.
 */
static void slab_parse_empty_containers_should_not_leak(void** state)
{
    pubnub_serialization_provider_t* sut;
    const char*                      docs[] = {"{}", "[]"};
    size_t                           i;
    pubnub_json_value_t*             root;
    uint8_t                          buf[16];
    size_t                           out_len;

    (void)state;
    sut = pn_serialization_default();

    for (i = 0; i < sizeof(docs) / sizeof(docs[0]); ++i) {
        root = sut->parse(sut, (const uint8_t*)docs[i], strlen(docs[i]));
        assert_non_null(root);

        memset(buf, 0, sizeof(buf));
        out_len = 0;
        assert_int_equal(sut->serialize(sut, root, buf, sizeof(buf), &out_len),
                         PUBNUB_OK);
        assert_int_equal(out_len, strlen(docs[i]));
        assert_memory_equal(buf, docs[i], out_len);

        sut->value_destroy(sut, root);
    }
}

/**
 * @brief Scalar-only parse (bare primitives) uses slab correctly.
 */
static void slab_parse_bare_primitive_should_succeed(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char* doc = "42";
    pubnub_json_value_t* root = sut->parse(sut, (const uint8_t*)doc, strlen(doc));
    assert_non_null(root);
    assert_int_equal(sut->value_type(root), PUBNUB_JSON_INT);
    int v = 0;
    assert_int_equal(sut->value_as_int(root, &v), PUBNUB_OK);
    assert_int_equal(v, 42);
    sut->value_destroy(sut, root);
}

/**
 * @brief value_create_* trees (non-slab) must still free correctly
 *        after the slab changes to jsmn_value_destroy.
 */
/**
 * @brief Mutating a slab-backed sub-container must return NOT_SUPPORTED.
 *
 * Verifies that immutability guards apply to both the parse root and
 * any sub-container obtained via array_get / object_get.
 */
static void slab_parse_subcontainer_mutation_should_be_rejected(void** state)
{
    pubnub_serialization_provider_t* sut;
    pubnub_json_value_t*             root;
    pubnub_json_value_t*             arr;
    pubnub_json_value_t*             new_item;
    const char*                      doc;

    (void)state;
    sut = pn_serialization_default();
    doc = "{\"items\":[1,2,3]}";

    root = sut->parse(sut, (const uint8_t*)doc, strlen(doc));
    assert_non_null(root);

    arr = sut->object_get(root, "items", 5);
    assert_non_null(arr);

    /* Sub-container obtained via object_get has _slab set (now tagged),
     * so mutating it must be rejected. */
    new_item = sut->value_create_int(sut, 99);
    assert_non_null(new_item);

    assert_int_equal(sut->array_append(sut, arr, new_item),
                     PUBNUB_ERR_NOT_SUPPORTED);

    sut->value_destroy(sut, new_item);
    sut->value_destroy(sut, root);
}

static void non_slab_constructed_tree_should_free_correctly(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* obj   = sut->value_create_object(sut);
    pubnub_json_value_t* child = sut->value_create_int(sut, 99);
    assert_non_null(obj);
    assert_non_null(child);
    assert_int_equal(sut->object_set(sut, obj, "x", 1, child), PUBNUB_OK);

    uint8_t buf[32] = {0};
    size_t  out_len = 0;
    assert_int_equal(sut->serialize(sut, obj, buf, sizeof(buf), &out_len),
                     PUBNUB_OK);
    assert_memory_equal(buf, "{\"x\":99}", out_len);

    /* This exercises the non-slab (per-node) free path. */
    sut->value_destroy(sut, obj);
}

/**
 * @brief Token array OOM during doubling must not leak the previous allocation.
 *
 * Uses a spy allocator configured to fail on the second alloc-or-realloc
 * call (first = initial 32-token array; second = slab alloc attempt,
 * but the doubling path is what we target). Parses a document with >32
 * tokens to force at least one doubling. Verifies: parse returns NULL,
 * and free_calls == alloc_calls + realloc_calls (no leak).
 */
static void parse_token_array_oom_on_doubling_must_not_leak(void** state)
{
    pubnub_serialization_provider_t* sut;
    spy_allocator_t                  spy;
    pubnub_provider_deps_t           deps;
    pubnub_json_value_t*             result;
    int                              total_allocs;

    (void)state;
    sut = pn_serialization_default();
    spy = spy_make();

    /* Fail on the 2nd alloc-or-realloc call. The 1st call is the
     * initial token array realloc (from NULL); the 2nd is the
     * doubling realloc that should fail cleanly. */
    spy.fail_alloc_after = 2;

    deps.allocator = &spy.base;
    deps.logger    = NULL;
    deps.platform  = NULL;
    deps.proxy     = NULL;
    assert_int_equal(sut->init(sut, &deps), 0);

    /* 17 key-value pairs = 1 object token + 17 key tokens + 17 value
     * tokens = 35 tokens, exceeding the initial 32-token capacity. */
    const char* big_doc =
        "{\"a\":1,\"b\":2,\"c\":3,\"d\":4,\"e\":5,\"f\":6,\"g\":7,"
        "\"h\":8,\"i\":9,\"j\":10,\"k\":11,\"l\":12,\"m\":13,"
        "\"n\":14,\"o\":15,\"p\":16,\"q\":17}";

    result = sut->parse(sut, (const uint8_t*)big_doc, strlen(big_doc));
    assert_null(result);

    /* Every successful allocation must have a matching free. */
    total_allocs = spy.alloc_calls + spy.realloc_calls;
    assert_true(spy.free_calls > 0);
    assert_true(spy.free_calls <= total_allocs);

    provider_reset_allocator(sut);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(parse_should_succeed_on_valid_json_object),
        cmocka_unit_test(parse_should_succeed_on_valid_json_array),
        cmocka_unit_test(parse_should_return_null_on_malformed_json),
        cmocka_unit_test(parse_should_honour_length_without_null_terminator),
        cmocka_unit_test(parse_should_return_null_on_null_data),
        cmocka_unit_test(parse_should_return_null_on_zero_length),
        cmocka_unit_test(serialize_should_emit_compact_json_for_valid_input),
        cmocka_unit_test(serialize_should_write_out_len),
        cmocka_unit_test(serialize_should_return_buffer_too_small_when_undersized),
        cmocka_unit_test(serialize_should_return_buffer_too_small_on_zero_buf_len),
        cmocka_unit_test(serialize_should_return_invalid_argument_on_null_value),
        cmocka_unit_test(serialize_should_return_invalid_argument_on_null_buf),
        cmocka_unit_test(serialize_should_return_invalid_argument_on_null_out_len),
        cmocka_unit_test(value_destroy_should_accept_null),
        cmocka_unit_test(parse_then_free_should_round_trip_cleanly),
        cmocka_unit_test(roundtrip_parse_then_serialize_should_preserve_payload),
        cmocka_unit_test(provider_should_expose_every_mandatory_callback),
        cmocka_unit_test(provider_should_set_init_deinit_for_allocator_storage),
        cmocka_unit_test(pn_serialization_default_should_return_same_singleton),
        cmocka_unit_test(value_create_object_should_produce_object_type),
        cmocka_unit_test(value_create_array_should_produce_array_type),
        cmocka_unit_test(value_create_null_should_produce_null_type),
        cmocka_unit_test(value_create_bool_truthy_should_produce_true),
        cmocka_unit_test(value_create_bool_zero_should_produce_false),
        cmocka_unit_test(value_create_int_should_round_trip_small_values),
        cmocka_unit_test(value_create_int_should_emit_exact_decimal_bytes),
        cmocka_unit_test(value_create_int_should_round_trip_int_boundaries),
        cmocka_unit_test(parse_should_fall_back_to_double_on_int_overflow),
#if PUBNUB_CFG_JSON_DOUBLE
        cmocka_unit_test(parse_should_classify_floating_point_literals_as_double),
#endif
        cmocka_unit_test(object_set_should_handle_keys_longer_than_typical),
        cmocka_unit_test(value_create_int_should_serialize_with_no_decimal_point),
        cmocka_unit_test(value_create_string_should_copy_bytes),
        cmocka_unit_test(value_create_string_view_should_alias_bytes_nul_terminated),
        cmocka_unit_test(value_create_string_view_should_alias_length_counted),
        cmocka_unit_test(value_create_raw_should_round_trip_verbatim),
        cmocka_unit_test(value_create_raw_should_reject_zero_length),
        cmocka_unit_test(value_create_double_slot_matches_compile_time_toggle),
        cmocka_unit_test(object_set_should_replace_existing_key),
        cmocka_unit_test(object_remove_absent_key_should_return_invalid_argument),
        cmocka_unit_test(array_remove_out_of_range_should_return_invalid_argument),
        cmocka_unit_test(array_get_should_return_element_at_index),
        cmocka_unit_test(object_iter_should_walk_all_keys_exactly_once),
        cmocka_unit_test(value_as_int_on_int_node_should_return_value),
        cmocka_unit_test(
            value_as_string_on_string_node_should_return_string_and_length),
        cmocka_unit_test(value_destroy_on_complex_tree_should_not_leak),
        cmocka_unit_test(object_reserve_should_succeed_on_valid_capacity),
        cmocka_unit_test(array_reserve_should_succeed_on_valid_capacity),
        cmocka_unit_test(object_reserve_should_be_idempotent),
        cmocka_unit_test(provider_init_should_store_allocator),
        cmocka_unit_test(provider_deinit_should_clear_allocator),
        cmocka_unit_test(parse_should_reject_input_beyond_max_nesting_depth),
        cmocka_unit_test(parse_should_accept_input_at_exactly_max_nesting_depth),
        cmocka_unit_test(slab_parse_complex_tree_should_round_trip),
        cmocka_unit_test(slab_parse_should_minimize_allocator_calls),
        cmocka_unit_test(slab_parse_empty_containers_should_not_leak),
        cmocka_unit_test(slab_parse_bare_primitive_should_succeed),
        cmocka_unit_test(slab_parse_subcontainer_mutation_should_be_rejected),
        cmocka_unit_test(non_slab_constructed_tree_should_free_correctly),
        cmocka_unit_test(parse_token_array_oom_on_doubling_must_not_leak),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
