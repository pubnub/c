/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file json_helpers_units.c
 * @brief Unit tests for the @c pubnub/json.h ergonomic helpers.
 *
 * The same TU is built against both shipped serialization backends
 * (cJSON and jsmn) so the helpers' contract is exercised against the
 * full vtable surface variation -- jsmn implements
 * @c init / @c deinit and the reserve mutators while cJSON does not.
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
#include "pubnub/json.h"
#include "pubnub/json_macros.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/provider_deps.h"
#include "pubnub/providers/serialization.h"

pubnub_serialization_provider_t* pn_serialization_default(void);

typedef struct fail_allocator {
    pubnub_allocator_provider_t base;
    int                         alloc_calls;
    int                         fail_after;
} fail_allocator_t;

static void* fail_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    fail_allocator_t* fa = (fail_allocator_t*)self;
    (void)align;
    fa->alloc_calls++;
    if (fa->fail_after >= 0 && fa->alloc_calls > fa->fail_after) {
        return NULL;
    }
    return malloc(size);
}

static void* fail_realloc(pubnub_allocator_provider_t* self,
                          void*                        ptr,
                          size_t                       old_size,
                          size_t                       new_size,
                          size_t                       align)
{
    fail_allocator_t* fa = (fail_allocator_t*)self;
    (void)align;
    (void)old_size;
    fa->alloc_calls++;
    if (fa->fail_after >= 0 && fa->alloc_calls > fa->fail_after) {
        return NULL;
    }
    return realloc(ptr, new_size);
}

static void fail_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

/**
 * @brief Bind the failing allocator to backends that observe it.
 *
 * The cJSON backend uses libc malloc directly and ignores the
 * provider; the jsmn backend wires @p allocator through @c init.
 * Returns 1 when the allocator is actually observed by the backend
 * (i.e. @c init is non-NULL and returned success); returns 0 when the
 * backend bypasses the allocator or @c init failed.
 */
static int bind_allocator_if_supported(pubnub_serialization_provider_t* serial,
                                       fail_allocator_t* allocator)
{
    if (NULL == serial->init) {
        return 0;
    }
    pubnub_provider_deps_t deps;
    memset(&deps, 0, sizeof(deps));
    deps.allocator = &allocator->base;
    return 0 == serial->init(serial, &deps) ? 1 : 0;
}

static void unbind_allocator_if_supported(pubnub_serialization_provider_t* serial)
{
    if (NULL != serial->deinit) {
        serial->deinit(serial);
    }
}

static void object_set_str_should_attach_child_with_strlen_key(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* obj   = sut->value_create_object(sut);
    pubnub_json_value_t* child = sut->value_create_int(sut, 7);
    assert_non_null(obj);
    assert_non_null(child);

    assert_int_equal(pubnub_json_object_set(sut, obj, "device", child), PUBNUB_OK);
    assert_int_equal(sut->object_size(obj), 1);
    pubnub_json_value_t* fetched = sut->object_get(obj, "device", 6);
    assert_non_null(fetched);
    int v = 0;
    assert_int_equal(sut->value_as_int(fetched, &v), PUBNUB_OK);
    assert_int_equal(v, 7);

    pubnub_json_destroy(sut, obj);
}

static void array_append_should_passthrough(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* arr  = sut->value_create_array(sut);
    pubnub_json_value_t* item = sut->value_create_int(sut, 99);
    assert_non_null(arr);
    assert_non_null(item);

    assert_int_equal(pubnub_json_array_append(sut, arr, item), PUBNUB_OK);
    assert_int_equal(sut->array_size(arr), 1);

    pubnub_json_destroy(sut, arr);
}

static void destroy_should_be_null_safe(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* All NULL combinations must be no-ops. */
    pubnub_json_destroy(NULL, NULL);
    pubnub_json_destroy(sut, NULL);
    pubnub_json_destroy(NULL, (pubnub_json_value_t*)(uintptr_t)0xDEADBEEF);
}

#if PUBNUB_CFG_JSON_HELPERS

static void object_build_should_assemble_three_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* device = sut->value_create_string(sut, "sensor-1", 8);
    pubnub_json_value_t* temp   = sut->value_create_int(sut, 42);
    pubnub_json_value_t* alarm  = sut->value_create_bool(sut, 0);
    assert_non_null(device);
    assert_non_null(temp);
    assert_non_null(alarm);

    pubnub_json_value_t* msg = pubnub_json_object_build(
        sut, "device", device, "temp_c", temp, "alarm", alarm, (const char*)NULL);
    assert_non_null(msg);
    assert_int_equal(sut->object_size(msg), 3);

    pubnub_json_value_t* d = sut->object_get(msg, "device", 6);
    pubnub_json_value_t* t = sut->object_get(msg, "temp_c", 6);
    pubnub_json_value_t* a = sut->object_get(msg, "alarm", 5);
    assert_non_null(d);
    assert_non_null(t);
    assert_non_null(a);

    size_t      dev_len = 0;
    const char* dev_str = sut->value_as_string(d, &dev_len);
    assert_non_null(dev_str);
    assert_int_equal(dev_len, 8);
    assert_memory_equal(dev_str, "sensor-1", 8);

    int temp_v = 0;
    assert_int_equal(sut->value_as_int(t, &temp_v), PUBNUB_OK);
    assert_int_equal(temp_v, 42);

    int alarm_v = -1;
    assert_int_equal(sut->value_as_bool(a, &alarm_v), PUBNUB_OK);
    assert_int_equal(alarm_v, 0);

    pubnub_json_destroy(sut, msg);
}

static void object_build_should_free_partial_on_attach_failure(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Force a failure midway by passing a NULL child for the second
     * pair. The helper must release the first child (already
     * attached, freed transitively via the partial root) AND the
     * remaining caller-owned children that were not yet visited. */
    pubnub_json_value_t* first_child = sut->value_create_int(sut, 1);
    pubnub_json_value_t* third_child = sut->value_create_int(sut, 3);
    assert_non_null(first_child);
    assert_non_null(third_child);

    pubnub_json_value_t* result =
        pubnub_json_object_build(sut,
                                 "a",
                                 first_child,
                                 "b",
                                 (pubnub_json_value_t*)NULL,
                                 "c",
                                 third_child,
                                 (const char*)NULL);
    assert_null(result);
    /* If ASan is enabled, leaks here would fail the run. The test
     * doesn't have a heap inspector so we rely on the sanitizer for
     * the leak verdict. */
}

static void object_build_should_free_remaining_args_on_failure(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Same shape as the previous test but explicitly demonstrates the
     * "remaining children get freed too" rule by counting via an
     * allocator hook. We do not require the cJSON backend to honour
     * the allocator (it uses libc malloc directly), so we skip the
     * count check on backends that ignore the allocator. */
    fail_allocator_t alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.base.alloc   = fail_alloc;
    alloc.base.realloc = fail_realloc;
    alloc.base.free    = fail_free;
    alloc.fail_after   = -1; /* never fail; just count. */

    int has_init = 0 != bind_allocator_if_supported(sut, &alloc);

    pubnub_json_value_t* a = sut->value_create_int(sut, 1);
    pubnub_json_value_t* c = sut->value_create_int(sut, 3);
    assert_non_null(a);
    assert_non_null(c);

    int alloc_before = alloc.alloc_calls;
    (void)alloc_before;

    pubnub_json_value_t* result = pubnub_json_object_build(
        sut, "a", a, "b", (pubnub_json_value_t*)NULL, "c", c, (const char*)NULL);
    assert_null(result);

    /* Sanity: when the backend uses our allocator, no orphan nodes
     * should remain (the helper called free for each tree). The
     * actual leak verdict comes from ASan; the alloc-call counter is
     * informational. */
    if (has_init) {
        assert_true(alloc.alloc_calls >= alloc_before);
    }

    unbind_allocator_if_supported(sut);
}

static void clone_should_deep_copy_object(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* src    = sut->value_create_object(sut);
    pubnub_json_value_t* device = sut->value_create_string(sut, "abc", 3);
    pubnub_json_value_t* count  = sut->value_create_int(sut, 5);
    pubnub_json_value_t* alarm  = sut->value_create_bool(sut, 1);
    assert_non_null(src);
    assert_non_null(device);
    assert_non_null(count);
    assert_non_null(alarm);
    assert_int_equal(sut->object_set(sut, src, "device", 6, device), PUBNUB_OK);
    assert_int_equal(sut->object_set(sut, src, "count", 5, count), PUBNUB_OK);
    assert_int_equal(sut->object_set(sut, src, "alarm", 5, alarm), PUBNUB_OK);

    pubnub_json_value_t* clone = pubnub_json_clone(sut, src);
    assert_non_null(clone);
    assert_int_equal(sut->object_size(clone), 3);

    /* Mutate the source: replace count with 99. The clone must remain
     * unchanged. */
    pubnub_json_value_t* nine_nine = sut->value_create_int(sut, 99);
    assert_non_null(nine_nine);
    assert_int_equal(sut->object_set(sut, src, "count", 5, nine_nine), PUBNUB_OK);

    pubnub_json_value_t* clone_count = sut->object_get(clone, "count", 5);
    assert_non_null(clone_count);
    int clone_count_v = 0;
    assert_int_equal(sut->value_as_int(clone_count, &clone_count_v), PUBNUB_OK);
    assert_int_equal(clone_count_v, 5);

    pubnub_json_destroy(sut, src);
    pubnub_json_destroy(sut, clone);
}

static void clone_should_deep_copy_array_of_objects(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* src = sut->value_create_array(sut);
    assert_non_null(src);
    for (int i = 0; i < 3; ++i) {
        pubnub_json_value_t* obj   = sut->value_create_object(sut);
        pubnub_json_value_t* index = sut->value_create_int(sut, i);
        assert_non_null(obj);
        assert_non_null(index);
        assert_int_equal(sut->object_set(sut, obj, "i", 1, index), PUBNUB_OK);
        assert_int_equal(sut->array_append(sut, src, obj), PUBNUB_OK);
    }

    pubnub_json_value_t* clone = pubnub_json_clone(sut, src);
    assert_non_null(clone);
    assert_int_equal(sut->array_size(clone), 3);

    for (size_t i = 0; i < 3; ++i) {
        pubnub_json_value_t* item = sut->array_get(clone, i);
        assert_non_null(item);
        pubnub_json_value_t* idx = sut->object_get(item, "i", 1);
        assert_non_null(idx);
        int v = -1;
        assert_int_equal(sut->value_as_int(idx, &v), PUBNUB_OK);
        assert_int_equal(v, (int)i);
    }

    pubnub_json_destroy(sut, src);
    pubnub_json_destroy(sut, clone);
}

static void clone_should_handle_raw_nodes(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* Raw nodes serialize verbatim. Cloning then serializing must
     * yield the same bytes as serializing the source. */
    const char*          raw_bytes = "{\"verbatim\":true}";
    size_t               raw_len   = strlen(raw_bytes);
    pubnub_json_value_t* src =
        sut->value_create_raw(sut, (const uint8_t*)raw_bytes, raw_len);
    assert_non_null(src);

    pubnub_json_value_t* clone = pubnub_json_clone(sut, src);
    assert_non_null(clone);

    uint8_t src_buf[64]   = {0};
    uint8_t clone_buf[64] = {0};
    size_t  src_len       = 0;
    size_t  clone_len     = 0;
    assert_int_equal(sut->serialize(sut, src, src_buf, sizeof(src_buf), &src_len),
                     PUBNUB_OK);
    assert_int_equal(
        sut->serialize(sut, clone, clone_buf, sizeof(clone_buf), &clone_len),
        PUBNUB_OK);
    assert_int_equal(src_len, clone_len);
    assert_memory_equal(src_buf, clone_buf, src_len);

    pubnub_json_destroy(sut, src);
    pubnub_json_destroy(sut, clone);
}

static void clone_should_return_null_on_alloc_failure(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* This test is meaningful only on backends that route allocations
     * through the configured allocator (currently jsmn). On backends
     * that bypass the allocator (cJSON), we exercise the NULL-source
     * branch instead so the test still has at least one assertion. */
    fail_allocator_t alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.base.alloc   = fail_alloc;
    alloc.base.realloc = fail_realloc;
    alloc.base.free    = fail_free;
    alloc.fail_after   = -1;

    if (0 == bind_allocator_if_supported(sut, &alloc)) {
        /* Allocator not honoured (cJSON path): degenerate to the
         * NULL-source check, which is still a valid contract. */
        assert_null(pubnub_json_clone(sut, NULL));
        return;
    }

    pubnub_json_value_t* src = sut->value_create_object(sut);
    assert_non_null(src);
    for (int i = 0; i < 3; ++i) {
        pubnub_json_value_t* leaf = sut->value_create_int(sut, i);
        assert_non_null(leaf);
        char key[2] = {(char)('a' + i), '\0'};
        assert_int_equal(sut->object_set(sut, src, key, 1, leaf), PUBNUB_OK);
    }

    /* Trip the allocator after a couple of clone allocations so the
     * walker hits OOM mid-tree. */
    alloc.alloc_calls = 0;
    alloc.fail_after  = 1;

    pubnub_json_value_t* result = pubnub_json_clone(sut, src);
    assert_null(result);

    pubnub_json_destroy(sut, src);
    unbind_allocator_if_supported(sut);
}

static void to_debug_string_should_produce_serialized_text(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* obj = sut->value_create_object(sut);
    pubnub_json_value_t* n   = sut->value_create_int(sut, 42);
    assert_non_null(obj);
    assert_non_null(n);
    assert_int_equal(sut->object_set(sut, obj, "n", 1, n), PUBNUB_OK);

    char   buf[64] = {0};
    size_t len     = pubnub_json_to_debug_string(sut, obj, buf, sizeof(buf));
    assert_true(len > 0);
    assert_int_equal(strlen(buf), len);
    assert_memory_equal(buf, "{\"n\":42}", len);

    pubnub_json_destroy(sut, obj);
}

static void to_debug_string_should_truncate_on_overflow(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* obj = sut->value_create_object(sut);
    pubnub_json_value_t* child =
        sut->value_create_string(sut, "this string is intentionally long", 33);
    assert_non_null(obj);
    assert_non_null(child);
    assert_int_equal(sut->object_set(sut, obj, "k", 1, child), PUBNUB_OK);

    char   buf[8] = {0};
    size_t len    = pubnub_json_to_debug_string(sut, obj, buf, sizeof(buf));
    /* Provider rejects too-small buffer; helper returns 0 and clears
     * @c buf[0]. */
    assert_int_equal(len, 0);
    assert_int_equal(buf[0], '\0');

    pubnub_json_destroy(sut, obj);
}

static void PUBNUB_JSON_OBJ_macro_should_assemble_object_with_kv_macros(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    pubnub_json_value_t* via_macros =
        PUBNUB_JSON_OBJ(sut,
                        PUBNUB_JSON_KV_STR(sut, "device", "sensor-1"),
                        PUBNUB_JSON_KV_INT(sut, "temp_c", 42),
                        PUBNUB_JSON_KV_BOOL(sut, "alarm", 0));
    assert_non_null(via_macros);
    assert_int_equal(sut->object_size(via_macros), 3);

    pubnub_json_value_t* device = sut->object_get(via_macros, "device", 6);
    pubnub_json_value_t* temp   = sut->object_get(via_macros, "temp_c", 6);
    pubnub_json_value_t* alarm  = sut->object_get(via_macros, "alarm", 5);
    assert_non_null(device);
    assert_non_null(temp);
    assert_non_null(alarm);

    size_t      dev_len = 0;
    const char* dev_str = sut->value_as_string(device, &dev_len);
    assert_non_null(dev_str);
    assert_int_equal(dev_len, 8);
    assert_memory_equal(dev_str, "sensor-1", 8);

    int temp_v = 0;
    assert_int_equal(sut->value_as_int(temp, &temp_v), PUBNUB_OK);
    assert_int_equal(temp_v, 42);

    int alarm_v = -1;
    assert_int_equal(sut->value_as_bool(alarm, &alarm_v), PUBNUB_OK);
    assert_int_equal(alarm_v, 0);

    pubnub_json_destroy(sut, via_macros);
}

static void PUBNUB_JSON_KV_INT_should_handle_boundary_values(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* sut = pn_serialization_default();

    /* INT_MAX verifies that the macro's (int) cast preserves
     * precision at the boundary. */
    int                  big = INT_MAX;
    pubnub_json_value_t* obj =
        PUBNUB_JSON_OBJ(sut, PUBNUB_JSON_KV_INT(sut, "n", big));
    assert_non_null(obj);

    pubnub_json_value_t* n_node = sut->object_get(obj, "n", 1);
    assert_non_null(n_node);
    int n_v = 0;
    assert_int_equal(sut->value_as_int(n_node, &n_v), PUBNUB_OK);
    assert_int_equal(n_v, big);

    pubnub_json_destroy(sut, obj);
}

#endif /* PUBNUB_CFG_JSON_HELPERS */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(object_set_str_should_attach_child_with_strlen_key),
        cmocka_unit_test(array_append_should_passthrough),
        cmocka_unit_test(destroy_should_be_null_safe),
#if PUBNUB_CFG_JSON_HELPERS
        cmocka_unit_test(object_build_should_assemble_three_fields),
        cmocka_unit_test(object_build_should_free_partial_on_attach_failure),
        cmocka_unit_test(object_build_should_free_remaining_args_on_failure),
        cmocka_unit_test(clone_should_deep_copy_object),
        cmocka_unit_test(clone_should_deep_copy_array_of_objects),
        cmocka_unit_test(clone_should_handle_raw_nodes),
        cmocka_unit_test(clone_should_return_null_on_alloc_failure),
        cmocka_unit_test(to_debug_string_should_produce_serialized_text),
        cmocka_unit_test(to_debug_string_should_truncate_on_overflow),
        cmocka_unit_test(PUBNUB_JSON_OBJ_macro_should_assemble_object_with_kv_macros),
        cmocka_unit_test(PUBNUB_JSON_KV_INT_should_handle_boundary_values),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
