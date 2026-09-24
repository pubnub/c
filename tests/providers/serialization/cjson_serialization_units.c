/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file cjson_serialization_units.c
 * @brief Unit tests for the cJSON-backed serialization provider.
 *
 * Covers the wire I/O entries (parse, serialize, value_destroy), the
 * vtable surface, and the constructor / mutator / accessor groups
 * defined in the serialization provider contract. Does not exercise cJSON's own parser
 * quality -- that is the library's responsibility. The focus is the
 * provider's shim: input handling, output shape, error mapping, no
 * leaks on happy + unhappy paths, plus the int64 and raw-node round
 * trips that the SDK's wire format depends on.
 */

#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/providers/serialization.h"

pubnub_serialization_provider_t* pn_serialization_default(void);

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

    /* Missing closing brace -- cJSON's parser must reject cleanly.
     * The provider contract is "NULL on parse error", not "propagate
     * a partial tree". */
    const char* broken = "{\"unterminated\":";

    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)broken, strlen(broken));

    assert_null(value);
}

static void parse_should_honour_length_without_null_terminator(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Transport layer fills response buffers without a trailing NUL.
     * The provider must use the length argument, not a strlen scan.
     * We place the valid document in a larger buffer padded with
     * garbage to prove the length is respected. */
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

    /* Defensive contract: passing NULL must not crash the provider. */
    pubnub_json_value_t* value = sut->parse(sut, NULL, 16);

    assert_null(value);
}

static void parse_should_return_null_on_zero_length(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const uint8_t dummy[] = {'{', '}'};

    /* Zero length is treated as a parse failure per the header
     * contract -- an empty document is not a valid JSON value. */
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
    /* Compact form is the same byte-for-byte as the source for this
     * simple input -- the parser does not reorder keys and the
     * printer omits whitespace. */
    assert_int_equal(output_len, strlen(source));
    assert_memory_equal(output, source, output_len);
    sut->value_destroy(sut, value);
}

static void serialize_should_write_out_len_equal_to_strlen(void** state)
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
    /* output_len excludes the trailing NUL that cJSON writes; callers
     * can rely on it to size downstream copies without adding 1. */
    assert_int_equal(output_len, strlen((const char*)output));
    sut->value_destroy(sut, value);
}

static void serialize_should_return_buffer_too_small_when_undersized(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char*          source = "{\"key\":\"a longer value that won't fit\"}";
    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)source, strlen(source));

    /* 8 bytes is far too small for the compact output.
     * Provider must fail cleanly rather than write past the buffer. */
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

    /* Explicit `buf_len == 0` exercises the early-out branch that
     * precedes the cJSON call. Must report BUFFER_TOO_SMALL and
     * leave output_len at 0 -- matching every other failure path
     * so callers only need a single "ignore the buffer" rule. */
    uint8_t output[16];
    memset(output, 0xBB, sizeof(output));
    size_t       output_len = 999;
    pubnub_res_t result = sut->serialize(sut, value, output, 0, &output_len);

    assert_int_equal(result, PUBNUB_ERR_BUFFER_TOO_SMALL);
    assert_int_equal(output_len, 0);
    sut->value_destroy(sut, value);
}

static void serialize_should_reject_buf_len_equal_to_output_len(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char*          source = "{\"a\":1,\"b\":2,\"c\":3}";
    pubnub_json_value_t* value =
        sut->parse(sut, (const uint8_t*)source, strlen(source));

    /* Measure the exact output length with a generous buffer. */
    uint8_t      large[128]   = {0};
    size_t       required_len = 0;
    pubnub_res_t large_rc =
        sut->serialize(sut, value, large, sizeof(large), &required_len);
    assert_int_equal(large_rc, PUBNUB_OK);
    assert_true(required_len > 0);

    /* Shrink to exactly the output length -- no room for the
     * trailing NUL the printer needs. The provider must report
     * BUFFER_TOO_SMALL rather than silently overwriting the byte
     * past the buffer end. */
    uint8_t tight[64];
    memset(tight, 0xCC, sizeof(tight));
    size_t       tight_len = 123;
    pubnub_res_t tight_rc =
        sut->serialize(sut, value, tight, required_len, &tight_len);
    assert_int_equal(tight_rc, PUBNUB_ERR_BUFFER_TOO_SMALL);
    assert_int_equal(tight_len, 0);

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

    /* cJSON_Delete documents NULL as a no-op; the provider inherits
     * that safety so feature code does not need to null-check before
     * releasing an already-released tree. */
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

static void provider_should_leave_init_deinit_null(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* init / deinit are optional per the provider header contract.
     * They stay NULL on this branch because cJSON's memory hooks are
     * global state and do not fit the per-context provider model
     * without cross-context interference. */
    assert_null(sut->init);
    assert_null(sut->deinit);
}

static void pn_serialization_default_should_return_same_singleton(void** state)
{
    (void)state;

    /* The provider is stateless; every call returns the same
     * address. Contexts share the instance without coordination. */
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

    int                  v     = 42;
    pubnub_json_value_t* value = sut->value_create_int(sut, v);
    assert_non_null(value);
    assert_int_equal(sut->value_type(value), PUBNUB_JSON_INT);

    int read_back = 0;
    assert_int_equal(sut->value_as_int(value, &read_back), PUBNUB_OK);
    assert_int_equal(read_back, v);

    /* Wire round-trip: serialize, parse, read. */
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

/**
 * @brief Byte-level emit assertion for integer values.
 *
 * cJSON's print_number uses the `%d` integer format when the double
 * value equals `(double)item->valueint` (where valueint is an `int`).
 */
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
    assert_int_equal(written, 9);
    assert_memory_equal(buf, "123456789", 9);
    sut->value_destroy(sut, value);
}

/**
 * @brief Boundary regression: INT_MAX and INT_MIN round-trip.
 *
 * cJSON uses `%d` format when `(double)item->valueint == d`. INT_MAX
 * and INT_MIN exercise both the positive and negative edges and must
 * round-trip exactly through serialize/parse.
 */
static void value_create_int_should_round_trip_int_boundaries(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    int boundaries[] = {INT_MAX, INT_MIN};
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

/**
 * @brief Integer literals beyond INT_MAX classify as DOUBLE.
 *
 * cJSON parses all numbers as double. A value beyond INT_MAX cannot
 * satisfy the exact-integer check in value_type(), so it reports as
 * PUBNUB_JSON_DOUBLE.
 */
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
     * When PUBNUB_CFG_JSON_DOUBLE is OFF, the value is unreadable
     * (vtable slot NULL) but the node is valid. */
    assert_int_equal(sut->value_type(parsed), PUBNUB_JSON_DOUBLE);
#if !PUBNUB_CFG_JSON_DOUBLE
    assert_null(sut->value_as_double);
#endif
    sut->value_destroy(sut, parsed);
}

#if PUBNUB_CFG_JSON_DOUBLE
/**
 * @brief Fractional floating-point literals parse to PUBNUB_JSON_DOUBLE.
 *
 * Only truly fractional values classify as DOUBLE — values like `1e3`
 * (= 1000.0) are exact integers and classify as INT. Use `1.5` and
 * `-2.5e-1` to exercise the DOUBLE path.
 */
static void parse_should_classify_floating_point_literals_as_double(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char* literals[] = {"1.5", "-2.5e-1"};
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

/**
 * @brief Object key longer than the inline scratch exercises the heap path.
 *
 * The provider's `nul_terminate_key` helper uses a 128-byte stack
 * buffer for typical keys and falls back to allocator-backed heap
 * for longer ones. This test forces the heap branch and ensures the
 * malloc/free path is leak-free under ASan.
 */
static void object_set_should_handle_keys_longer_than_stack_scratch(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Construct a 200-byte key: well past the 128-byte inline buf. */
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
    /* "42" with no decimal point and no scientific notation. */
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

    /* Mutate the source after construction. The accessor must still
     * return the original "hello!" -- proving cJSON copied the bytes. */
    memset(buf, 'X', sizeof(buf));

    size_t      out_len = 0;
    const char* read    = sut->value_as_string(value, &out_len);
    assert_non_null(read);
    assert_int_equal(out_len, 6);
    assert_memory_equal(read, "hello!", 6);
    sut->value_destroy(sut, value);
}

static void value_create_string_view_should_alias_bytes(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* The view variant aliases caller-owned bytes that must stay
     * alive for the tree's lifetime. The cJSON backend can only
     * alias NUL-terminated input (cJSON_CreateStringReference stores
     * the pointer directly and reads to the terminator on print), so
     * the caller signals "NUL-terminated, please alias" by passing
     * @c len = 0. We then mutate the *interior* bytes (keeping the
     * NUL in place) and verify the accessor reflects the change --
     * proving no copy was made. */
    char                 source[16] = "hello";
    pubnub_json_value_t* value = sut->value_create_string_view(sut, source, 0);
    assert_non_null(value);

    source[0] = 'H';
    source[4] = 'O';
    /* source is still "HellO\0" -- 5 chars + NUL. */

    size_t      out_len = 0;
    const char* read    = sut->value_as_string(value, &out_len);
    assert_non_null(read);
    assert_int_equal(out_len, 5);
    assert_memory_equal(read, "HellO", 5);
    sut->value_destroy(sut, value);
}

/**
 * @brief Length-counted spans cannot be aliased on the cJSON backend.
 *
 * When @p len != 0, the provider must reject the call
 * with NULL rather than reading @c str[len] (which would be a one-byte
 * out-of-bounds read on a non-NUL-terminated span). Callers are
 * expected to fall back to @c value_create_string for length-counted
 * input on this backend.
 */
static void value_create_string_view_should_reject_length_counted(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    const char*          source = "hello world";
    pubnub_json_value_t* value  = sut->value_create_string_view(sut, source, 5);
    assert_null(value);
}

static void value_create_raw_should_round_trip_verbatim(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Raw nodes must serialize byte-identically to the input. PAM
     * signature computation depends on this contract. */
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

static void value_create_double_slot_matches_compile_time_toggle(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* The vtable contract: when PUBNUB_CFG_JSON_DOUBLE is 0 the
     * value_create_double / value_as_double slots are NULL; when 1
     * they are populated. Pin the invariant either way so a future
     * configuration flip is caught immediately. */
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
    /* After the replace, the object still has exactly one key. */
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

    /* Per ADR / vtable contract: removing a key that is not present
     * is reported as INVALID_ARGUMENT, not a silent success. */
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

    /* Index 5 in a 1-element array is out of range. */
    pubnub_res_t rc = sut->array_remove(sut, arr, 5);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(sut->array_size(arr), 1);

    sut->value_destroy(sut, arr);
}

/**
 * @brief array_get retrieves the N-th element by zero-based index.
 *
 * Pure cJSON_GetArrayItem passthrough, but covers the vtable surface
 * so a future regression in the wrapper (off-by-one, NULL on empty)
 * is caught before it reaches feature-level tests.
 */
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

    /* Out-of-range index returns NULL rather than an undefined slot. */
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

    /* Subsequent next() returns 0 (exhausted). */
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
     * Run under ASan/LSan to catch leaks; without sanitizers this
     * test still pins that the construction path succeeds. */
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

    /* Single destroy call walks the entire tree; no orphan nodes. */
    sut->value_destroy(sut, root);
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
        cmocka_unit_test(serialize_should_write_out_len_equal_to_strlen),
        cmocka_unit_test(serialize_should_return_buffer_too_small_when_undersized),
        cmocka_unit_test(serialize_should_return_buffer_too_small_on_zero_buf_len),
        cmocka_unit_test(serialize_should_reject_buf_len_equal_to_output_len),
        cmocka_unit_test(serialize_should_return_invalid_argument_on_null_value),
        cmocka_unit_test(serialize_should_return_invalid_argument_on_null_buf),
        cmocka_unit_test(serialize_should_return_invalid_argument_on_null_out_len),
        cmocka_unit_test(value_destroy_should_accept_null),
        cmocka_unit_test(parse_then_free_should_round_trip_cleanly),
        cmocka_unit_test(roundtrip_parse_then_serialize_should_preserve_payload),
        cmocka_unit_test(provider_should_expose_every_mandatory_callback),
        cmocka_unit_test(provider_should_leave_init_deinit_null),
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
        cmocka_unit_test(object_set_should_handle_keys_longer_than_stack_scratch),
        cmocka_unit_test(value_create_int_should_serialize_with_no_decimal_point),
        cmocka_unit_test(value_create_string_should_copy_bytes),
        cmocka_unit_test(value_create_string_view_should_alias_bytes),
        cmocka_unit_test(value_create_string_view_should_reject_length_counted),
        cmocka_unit_test(value_create_raw_should_round_trip_verbatim),
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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
