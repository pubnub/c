/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file publish_value_units.c
 * @brief Unit tests for the value-tree path in `pubnub_publish`
 *        (Borrowed ownership contract).
 *
 * The value-tree path serializes the user's value tree during the
 * call but does NOT destroy it -- trees are Borrowed and the caller
 * retains ownership. These tests exercise that contract through the
 * synchronous validation-failure paths: building real trees, passing
 * them to `pubnub_publish` with a NULL ctx, and verifying that the
 * caller can still safely destroy the trees after the call returns.
 *
 * Wire-layer coverage (path builder, query helpers, response parser,
 * validator) lives in @c publish_units.c -- those helpers are shared
 * between both publish paths.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/features/publish.h"
#include "pubnub/providers/serialization.h"

/* Provided by the linked serialization provider. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

/* Borrowed contract for value-tree fields:
 * the entry point does NOT consume the caller's trees. The caller
 * retains ownership and must destroy them after the call. */

static void publish_value_caller_owns_message_after_validation_failure(void** state)
{
    (void)state;
    /* NULL ctx triggers the very first validation failure inside
     * `pubnub_publish`. The tree remains caller-owned -- we destroy
     * it ourselves. Under ASan a double-free would crash and a leak
     * would be detected. */
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);
    assert_non_null(serial->value_create_string);
    assert_non_null(serial->value_destroy);

    pubnub_json_value_t* msg = serial->value_create_string(serial, "hello", 5);
    assert_non_null(msg);

    /* No ctx -- pure validation failure. */
    pubnub_publish_opts_t opts = {
        .channel       = "ch",
        .message_value = msg,
    };
    pubnub_future_t fut = pubnub_publish(NULL, &opts);

    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
    /* Caller owns the tree -- destroy it. */
    serial->value_destroy(serial, msg);
}

static void publish_value_caller_owns_meta_after_validation_failure(void** state)
{
    (void)state;
    /* Same as the message-side contract but for opts.meta_value. */
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_json_value_t* msg  = serial->value_create_string(serial, "x", 1);
    pubnub_json_value_t* meta = serial->value_create_object(serial);
    assert_non_null(msg);
    assert_non_null(meta);

    pubnub_publish_opts_t opts = {
        .channel       = "ch",
        .message_value = msg,
        .meta_value    = meta,
    };
    /* NULL ctx triggers validation failure -- trees remain
     * caller-owned. */
    pubnub_future_t fut = pubnub_publish(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);

    /* Caller destroys both trees. */
    serial->value_destroy(serial, msg);
    serial->value_destroy(serial, meta);
}

/* value_create_raw migration bridge: callers with existing
 * JSON-formatted strings wrap the bytes via value_create_raw. The
 * cJSON backend implements raw verbatim emission. We cannot
 * dispatch through the full pipeline without a context, so this
 * test verifies (a) the constructor produces a valid node, and
 * (b) the caller retains ownership after the SDK validation failure.
 * Byte-equality on the wire is covered by the cJSON provider's
 * own value_create_raw_should_emit_verbatim test. */

static void publish_value_caller_owns_raw_after_validation_failure(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial->value_create_raw);

    const char           raw_json[] = "{\"hello\":\"world\"}";
    pubnub_json_value_t* raw        = serial->value_create_raw(
        serial, (const uint8_t*)raw_json, sizeof(raw_json) - 1);
    assert_non_null(raw);

    pubnub_publish_opts_t opts = {
        .channel       = "ch",
        .message_value = raw,
    };
    /* NULL ctx -> validation failure -> caller still owns raw. */
    pubnub_future_t fut = pubnub_publish(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);

    /* Caller destroys. */
    serial->value_destroy(serial, raw);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(publish_value_caller_owns_message_after_validation_failure),
        cmocka_unit_test(publish_value_caller_owns_meta_after_validation_failure),
        cmocka_unit_test(publish_value_caller_owns_raw_after_validation_failure),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
