/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/app_context.h"
#include "pubnub/future.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/types.h"

#include "features/app_context/app_context_internal.h"

extern pubnub_serialization_provider_t* pn_serialization_default(void);

#define BODY_CAP 1024

#define NOT_FOUND (-1)

/* Real-provider helpers. */

typedef struct body_fixture {
    uint8_t         storage[BODY_CAP];
    pubnub_buffer_t buf;
} body_fixture_t;

static void body_init(body_fixture_t* fx)
{
    memset(fx, 0, sizeof(*fx));
    fx->buf.data    = fx->storage;
    fx->buf.cap     = sizeof(fx->storage);
    fx->buf.purpose = PUBNUB_BUF_OBJ;
}

static int node_type(pubnub_serialization_provider_t* serial,
                     pubnub_json_value_t*             obj,
                     const char*                      key)
{
    pubnub_json_value_t* node = serial->object_get(obj, key, strlen(key));

    if (NULL == node) {
        return NOT_FOUND;
    }
    return (int)serial->value_type(node);
}

static void assert_string_node(pubnub_serialization_provider_t* serial,
                               pubnub_json_value_t*             obj,
                               const char*                      key,
                               const char*                      expected)
{
    pubnub_json_value_t* node = serial->object_get(obj, key, strlen(key));
    size_t               len  = 0;
    const char*          str;

    assert_non_null(node);
    assert_int_equal(PUBNUB_JSON_STRING, serial->value_type(node));
    str = serial->value_as_string(node, &len);
    assert_non_null(str);
    assert_int_equal(strlen(expected), len);
    assert_memory_equal(str, expected, len);
}

static pubnub_json_value_t* parse_body(pubnub_serialization_provider_t* serial,
                                       const body_fixture_t*            fx)
{
    pubnub_json_value_t* tree = serial->parse(serial, fx->buf.data, fx->buf.len);

    assert_non_null(tree);
    return tree;
}

static void assert_body_contains(const body_fixture_t* fx, const char* needle)
{
    char text[BODY_CAP + 1];

    memcpy(text, fx->buf.data, fx->buf.len);
    text[fx->buf.len] = '\0';
    assert_non_null(strstr(text, needle));
}

/* UUID metadata body. */

enum {
    UUID_NAME,
    UUID_EXTERNAL_ID,
    UUID_PROFILE_URL,
    UUID_EMAIL,
    UUID_TYPE,
    UUID_STATUS,
    UUID_FIELD_COUNT
};

static const char* const k_uuid_keys[UUID_FIELD_COUNT] = {
    "name",
    "externalId",
    "profileUrl",
    "email",
    "type",
    "status",
};

static void uuid_set_field(pubnub_set_uuid_metadata_opts_t* opts,
                           int                              field,
                           const char*                      value)
{
    switch (field) {
    case UUID_NAME: opts->name = value; break;
    case UUID_EXTERNAL_ID: opts->external_id = value; break;
    case UUID_PROFILE_URL: opts->profile_url = value; break;
    case UUID_EMAIL: opts->email = value; break;
    case UUID_TYPE: opts->type = value; break;
    default: opts->status = value; break;
    }
}

static void uuid_clear_marker_in_each_string_field_encodes_null(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    int                              field;
    int                              other;

    (void)state;
    for (field = 0; field < UUID_FIELD_COUNT; ++field) {
        pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
        body_fixture_t       fx;
        pubnub_json_value_t* tree;

        body_init(&fx);
        uuid_set_field(&opts, field, PUBNUB_CLEAR_VALUE);

        assert_int_equal(
            PUBNUB_OK, pn_uuid_metadata_build_body(serial, NULL, &opts, &fx.buf));
        tree = parse_body(serial, &fx);

        assert_int_equal(PUBNUB_JSON_NULL,
                         node_type(serial, tree, k_uuid_keys[field]));
        /* A cleared field must not drag any other field into the body. */
        for (other = 0; other < UUID_FIELD_COUNT; ++other) {
            if (other != field) {
                assert_int_equal(NOT_FOUND,
                                 node_type(serial, tree, k_uuid_keys[other]));
            }
        }
        assert_int_equal(NOT_FOUND, node_type(serial, tree, "custom"));
        serial->value_destroy(serial, tree);
    }
}

static void uuid_clear_marker_in_custom_encodes_null(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_set_uuid_metadata_opts_t  opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    body_fixture_t                   fx;
    pubnub_json_value_t*             tree;

    (void)state;
    body_init(&fx);
    opts.custom = PUBNUB_CLEAR_VALUE;

    assert_int_equal(PUBNUB_OK,
                     pn_uuid_metadata_build_body(serial, NULL, &opts, &fx.buf));
    assert_body_contains(&fx, "\"custom\":null");
    tree = parse_body(serial, &fx);
    assert_int_equal(PUBNUB_JSON_NULL, node_type(serial, tree, "custom"));
    serial->value_destroy(serial, tree);
}

static void uuid_clear_marker_in_custom_ignores_custom_len(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_set_uuid_metadata_opts_t  opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    body_fixture_t                   fx;

    (void)state;
    body_init(&fx);
    opts.custom     = PUBNUB_CLEAR_VALUE;
    opts.custom_len = 4096;

    assert_int_equal(PUBNUB_OK,
                     pn_uuid_metadata_build_body(serial, NULL, &opts, &fx.buf));
    assert_body_contains(&fx, "\"custom\":null");
}

static void uuid_null_omits_empty_stays_empty_normal_unchanged(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_set_uuid_metadata_opts_t  opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    body_fixture_t                   fx;
    pubnub_json_value_t*             tree;

    (void)state;
    body_init(&fx);
    opts.name  = "";
    opts.email = "x";

    assert_int_equal(PUBNUB_OK,
                     pn_uuid_metadata_build_body(serial, NULL, &opts, &fx.buf));
    tree = parse_body(serial, &fx);

    assert_string_node(serial, tree, "name", "");
    assert_string_node(serial, tree, "email", "x");
    assert_int_equal(NOT_FOUND, node_type(serial, tree, "externalId"));
    assert_int_equal(NOT_FOUND, node_type(serial, tree, "profileUrl"));
    assert_int_equal(NOT_FOUND, node_type(serial, tree, "type"));
    assert_int_equal(NOT_FOUND, node_type(serial, tree, "status"));
    assert_int_equal(NOT_FOUND, node_type(serial, tree, "custom"));
    serial->value_destroy(serial, tree);
}

static void uuid_mixed_clear_set_and_omitted_fields(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_set_uuid_metadata_opts_t  opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    body_fixture_t                   fx;
    pubnub_json_value_t*             tree;

    (void)state;
    body_init(&fx);
    opts.name   = PUBNUB_CLEAR_VALUE;
    opts.email  = "x";
    opts.type   = "";
    opts.status = PUBNUB_CLEAR_VALUE;
    opts.custom = "{\"k\":1}";

    assert_int_equal(PUBNUB_OK,
                     pn_uuid_metadata_build_body(serial, NULL, &opts, &fx.buf));
    assert_body_contains(&fx, "\"name\":null");
    assert_body_contains(&fx, "\"email\":\"x\"");
    assert_body_contains(&fx, "\"type\":\"\"");
    assert_body_contains(&fx, "\"status\":null");
    assert_body_contains(&fx, "\"custom\":{\"k\":1}");

    tree = parse_body(serial, &fx);
    assert_int_equal(NOT_FOUND, node_type(serial, tree, "externalId"));
    assert_int_equal(NOT_FOUND, node_type(serial, tree, "profileUrl"));
    serial->value_destroy(serial, tree);
}

static void uuid_marker_lookalike_is_an_ordinary_string(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_set_uuid_metadata_opts_t  opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    body_fixture_t                   fx;
    pubnub_json_value_t*             tree;
    char                             impostor[] = "\0PN_CLEAR_VALUE";

    (void)state;
    body_init(&fx);
    /* Identity is by address: same bytes elsewhere read as "" (leading NUL). */
    opts.name = impostor;

    assert_int_equal(PUBNUB_OK,
                     pn_uuid_metadata_build_body(serial, NULL, &opts, &fx.buf));
    tree = parse_body(serial, &fx);
    assert_string_node(serial, tree, "name", "");
    serial->value_destroy(serial, tree);
}

static void uuid_custom_value_wins_over_clear_marker_in_custom(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_set_uuid_metadata_opts_t  opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    body_fixture_t                   fx;
    pubnub_json_value_t*             tree;
    const char*                      json = "{\"a\":1}";

    (void)state;
    body_init(&fx);
    opts.custom_value = serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(opts.custom_value);
    opts.custom = PUBNUB_CLEAR_VALUE;

    assert_int_equal(PUBNUB_OK,
                     pn_uuid_metadata_build_body(serial, NULL, &opts, &fx.buf));
    tree = parse_body(serial, &fx);
    assert_int_equal(PUBNUB_JSON_OBJECT, node_type(serial, tree, "custom"));
    serial->value_destroy(serial, tree);
}

/* Channel metadata body. */

enum { CH_NAME, CH_DESCRIPTION, CH_TYPE, CH_STATUS, CH_FIELD_COUNT };

static const char* const k_channel_keys[CH_FIELD_COUNT] = {
    "name",
    "description",
    "type",
    "status",
};

static void channel_set_field(pubnub_set_channel_metadata_opts_t* opts,
                              int                                 field,
                              const char*                         value)
{
    switch (field) {
    case CH_NAME: opts->name = value; break;
    case CH_DESCRIPTION: opts->description = value; break;
    case CH_TYPE: opts->type = value; break;
    default: opts->status = value; break;
    }
}

static void channel_clear_marker_in_each_string_field_encodes_null(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    int                              field;
    int                              other;

    (void)state;
    for (field = 0; field < CH_FIELD_COUNT; ++field) {
        pubnub_set_channel_metadata_opts_t opts =
            PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
        body_fixture_t       fx;
        pubnub_json_value_t* tree;

        body_init(&fx);
        channel_set_field(&opts, field, PUBNUB_CLEAR_VALUE);

        assert_int_equal(
            PUBNUB_OK, pn_channel_metadata_build_body(serial, NULL, &opts, &fx.buf));
        tree = parse_body(serial, &fx);

        assert_int_equal(PUBNUB_JSON_NULL,
                         node_type(serial, tree, k_channel_keys[field]));
        for (other = 0; other < CH_FIELD_COUNT; ++other) {
            if (other != field) {
                assert_int_equal(NOT_FOUND,
                                 node_type(serial, tree, k_channel_keys[other]));
            }
        }
        assert_int_equal(NOT_FOUND, node_type(serial, tree, "custom"));
        serial->value_destroy(serial, tree);
    }
}

static void channel_clear_marker_in_custom_ignores_custom_len(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    body_fixture_t fx;

    (void)state;
    body_init(&fx);
    opts.custom     = PUBNUB_CLEAR_VALUE;
    opts.custom_len = 77;

    assert_int_equal(
        PUBNUB_OK, pn_channel_metadata_build_body(serial, NULL, &opts, &fx.buf));
    assert_body_contains(&fx, "\"custom\":null");
}

static void channel_null_omits_empty_stays_empty_normal_unchanged(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    body_fixture_t       fx;
    pubnub_json_value_t* tree;

    (void)state;
    body_init(&fx);
    opts.description = "";
    opts.name        = "General";

    assert_int_equal(
        PUBNUB_OK, pn_channel_metadata_build_body(serial, NULL, &opts, &fx.buf));
    tree = parse_body(serial, &fx);

    assert_string_node(serial, tree, "description", "");
    assert_string_node(serial, tree, "name", "General");
    assert_int_equal(NOT_FOUND, node_type(serial, tree, "type"));
    assert_int_equal(NOT_FOUND, node_type(serial, tree, "status"));
    assert_int_equal(NOT_FOUND, node_type(serial, tree, "custom"));
    serial->value_destroy(serial, tree);
}

static void channel_mixed_clear_set_and_omitted_fields(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    body_fixture_t fx;

    (void)state;
    body_init(&fx);
    opts.description = PUBNUB_CLEAR_VALUE;
    opts.name        = "n";
    opts.custom      = PUBNUB_CLEAR_VALUE;

    assert_int_equal(
        PUBNUB_OK, pn_channel_metadata_build_body(serial, NULL, &opts, &fx.buf));
    assert_body_contains(&fx, "\"description\":null");
    assert_body_contains(&fx, "\"name\":\"n\"");
    assert_body_contains(&fx, "\"custom\":null");
}

static void channel_marker_lookalike_is_an_ordinary_string(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    body_fixture_t       fx;
    pubnub_json_value_t* tree;
    char                 impostor[] = "\0PN_CLEAR_VALUE";

    (void)state;
    body_init(&fx);
    opts.description = impostor;

    assert_int_equal(
        PUBNUB_OK, pn_channel_metadata_build_body(serial, NULL, &opts, &fx.buf));
    tree = parse_body(serial, &fx);
    assert_string_node(serial, tree, "description", "");
    serial->value_destroy(serial, tree);
}

/* Membership and member set items. */

static pubnub_json_value_t* first_set_item(pubnub_serialization_provider_t* serial,
                                           pubnub_json_value_t* root)
{
    pubnub_json_value_t* arr = serial->object_get(root, "set", 3);

    assert_non_null(arr);
    assert_int_equal(1, serial->array_size(arr));
    return serial->array_get(arr, 0);
}

static void membership_clear_marker_in_each_field_encodes_null(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_membership_input_t        items[3];
    body_fixture_t                   fx;
    pubnub_json_value_t*             tree;
    pubnub_json_value_t*             item;
    int                              i;

    (void)state;
    memset(items, 0, sizeof(items));
    items[0].channel_id = "c";
    items[0].status     = PUBNUB_CLEAR_VALUE;
    items[1].channel_id = "c";
    items[1].type       = PUBNUB_CLEAR_VALUE;
    items[2].channel_id = "c";
    items[2].custom     = PUBNUB_CLEAR_VALUE;
    items[2].custom_len = 123;

    for (i = 0; i < 3; ++i) {
        body_init(&fx);
        assert_int_equal(PUBNUB_OK,
                         pn_memberships_build_body(
                             serial, NULL, &items[i], 1, NULL, 0, &fx.buf));
        tree = parse_body(serial, &fx);
        item = first_set_item(serial, tree);

        assert_int_equal(0 == i ? PUBNUB_JSON_NULL : NOT_FOUND,
                         node_type(serial, item, "status"));
        assert_int_equal(1 == i ? PUBNUB_JSON_NULL : NOT_FOUND,
                         node_type(serial, item, "type"));
        assert_int_equal(2 == i ? PUBNUB_JSON_NULL : NOT_FOUND,
                         node_type(serial, item, "custom"));
        assert_int_equal(PUBNUB_JSON_OBJECT, node_type(serial, item, "channel"));
        serial->value_destroy(serial, tree);
    }
}

static void member_clear_marker_in_each_field_encodes_null(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_member_input_t            items[3];
    body_fixture_t                   fx;
    pubnub_json_value_t*             tree;
    pubnub_json_value_t*             item;
    int                              i;

    (void)state;
    memset(items, 0, sizeof(items));
    items[0].uuid_id = "u";
    items[0].status  = PUBNUB_CLEAR_VALUE;
    items[1].uuid_id = "u";
    items[1].type    = PUBNUB_CLEAR_VALUE;
    items[2].uuid_id = "u";
    items[2].custom  = PUBNUB_CLEAR_VALUE;

    for (i = 0; i < 3; ++i) {
        body_init(&fx);
        assert_int_equal(
            PUBNUB_OK,
            pn_members_build_body(serial, NULL, &items[i], 1, NULL, 0, &fx.buf));
        tree = parse_body(serial, &fx);
        item = first_set_item(serial, tree);

        assert_int_equal(0 == i ? PUBNUB_JSON_NULL : NOT_FOUND,
                         node_type(serial, item, "status"));
        assert_int_equal(1 == i ? PUBNUB_JSON_NULL : NOT_FOUND,
                         node_type(serial, item, "type"));
        assert_int_equal(2 == i ? PUBNUB_JSON_NULL : NOT_FOUND,
                         node_type(serial, item, "custom"));
        assert_int_equal(PUBNUB_JSON_OBJECT, node_type(serial, item, "uuid"));
        serial->value_destroy(serial, tree);
    }
}

static void membership_null_omits_empty_stays_empty_mixed_and_lookalike(void** state)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_membership_input_t        items[1];
    body_fixture_t                   fx;
    pubnub_json_value_t*             tree;
    pubnub_json_value_t*             item;
    char                             impostor[] = "\0PN_CLEAR_VALUE";

    (void)state;

    /* status cleared, type empty, custom omitted. */
    memset(items, 0, sizeof(items));
    items[0].channel_id = "c";
    items[0].status     = PUBNUB_CLEAR_VALUE;
    items[0].type       = "";
    body_init(&fx);
    assert_int_equal(
        PUBNUB_OK,
        pn_memberships_build_body(serial, NULL, items, 1, NULL, 0, &fx.buf));
    tree = parse_body(serial, &fx);
    item = first_set_item(serial, tree);
    assert_int_equal(PUBNUB_JSON_NULL, node_type(serial, item, "status"));
    assert_string_node(serial, item, "type", "");
    assert_int_equal(NOT_FOUND, node_type(serial, item, "custom"));
    serial->value_destroy(serial, tree);

    /* Look-alike buffer encodes as an ordinary (empty) string. */
    memset(items, 0, sizeof(items));
    items[0].channel_id = "c";
    items[0].status     = impostor;
    items[0].type       = "t";
    body_init(&fx);
    assert_int_equal(
        PUBNUB_OK,
        pn_memberships_build_body(serial, NULL, items, 1, NULL, 0, &fx.buf));
    tree = parse_body(serial, &fx);
    item = first_set_item(serial, tree);
    assert_string_node(serial, item, "status", "");
    assert_string_node(serial, item, "type", "t");
    serial->value_destroy(serial, tree);
}

/* Counting mock serializer. */

enum { KIND_NULL = 1, KIND_STRING = 2, KIND_RAW = 3, KIND_TREE = 4 };

typedef struct mock_val {
    int    kind;
    size_t len;
} mock_val_t;

typedef struct mock_serial {
    pubnub_serialization_provider_t base;
    int                             fail_null;
    int                             fail_string;
    int                             fail_raw;
    int                             fail_set;
    int                             null_calls;
    int                             string_calls;
    int                             raw_calls;
    int                             set_calls;
    int                             created;
    int                             destroyed;
    int                             consumed;
    int                             last_set_kind;
    size_t                          last_len;
} mock_serial_t;

static mock_val_t* mock_new(mock_serial_t* m, int kind, size_t len)
{
    mock_val_t* v = (mock_val_t*)malloc(sizeof(*v));

    assert_non_null(v);
    v->kind = kind;
    v->len  = len;
    ++m->created;
    return v;
}

static pubnub_json_value_t* mock_create_null(pubnub_serialization_provider_t* self)
{
    mock_serial_t* m = (mock_serial_t*)self;

    ++m->null_calls;
    if (m->fail_null) {
        return NULL;
    }
    return (pubnub_json_value_t*)mock_new(m, KIND_NULL, 0);
}

static pubnub_json_value_t* mock_create_string(pubnub_serialization_provider_t* self,
                                               const char* str,
                                               size_t      len)
{
    mock_serial_t* m = (mock_serial_t*)self;

    (void)str;
    ++m->string_calls;
    if (m->fail_string) {
        return NULL;
    }
    return (pubnub_json_value_t*)mock_new(m, KIND_STRING, len);
}

static pubnub_json_value_t* mock_create_raw(pubnub_serialization_provider_t* self,
                                            const uint8_t* bytes,
                                            size_t         len)
{
    mock_serial_t* m = (mock_serial_t*)self;

    (void)bytes;
    ++m->raw_calls;
    m->last_len = len;
    if (m->fail_raw) {
        return NULL;
    }
    return (pubnub_json_value_t*)mock_new(m, KIND_RAW, len);
}

static pubnub_res_t mock_object_set(pubnub_serialization_provider_t* self,
                                    pubnub_json_value_t*             obj,
                                    const char*                      key,
                                    size_t                           key_len,
                                    pubnub_json_value_t*             child)
{
    mock_serial_t* m = (mock_serial_t*)self;
    mock_val_t*    v = (mock_val_t*)child;

    (void)obj;
    (void)key;
    (void)key_len;
    ++m->set_calls;
    if (m->fail_set) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    /* Success transfers ownership; the mock releases it right away. */
    m->last_set_kind = v->kind;
    ++m->consumed;
    free(v);
    return PUBNUB_OK;
}

static void mock_value_destroy(pubnub_serialization_provider_t* self,
                               pubnub_json_value_t*             value)
{
    mock_serial_t* m = (mock_serial_t*)self;

    ++m->destroyed;
    free(value);
}

static void mock_init(mock_serial_t* m, int has_null, int has_raw)
{
    memset(m, 0, sizeof(*m));
    m->base.value_create_string = mock_create_string;
    m->base.object_set          = mock_object_set;
    m->base.value_destroy       = mock_value_destroy;
    m->base.value_create_null   = has_null ? mock_create_null : NULL;
    m->base.value_create_raw    = has_raw ? mock_create_raw : NULL;
}

static int mock_live(const mock_serial_t* m)
{
    return m->created - m->destroyed - m->consumed;
}

/* pn_app_context_set_string_field. */

static void string_field_marker_creates_null(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 1, 1);
    assert_int_equal(PUBNUB_OK,
                     pn_app_context_set_string_field(
                         &m.base, NULL, "name", 4, PUBNUB_CLEAR_VALUE));
    assert_int_equal(1, m.null_calls);
    assert_int_equal(0, m.string_calls);
    assert_int_equal(KIND_NULL, m.last_set_kind);
    assert_int_equal(0, mock_live(&m));
}

static void string_field_plain_string_creates_string(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 1, 1);
    assert_int_equal(
        PUBNUB_OK, pn_app_context_set_string_field(&m.base, NULL, "name", 4, "abc"));
    assert_int_equal(0, m.null_calls);
    assert_int_equal(1, m.string_calls);
    assert_int_equal(KIND_STRING, m.last_set_kind);
    assert_int_equal(0, mock_live(&m));
}

static void string_field_empty_string_is_not_a_clear(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 1, 1);
    assert_int_equal(
        PUBNUB_OK, pn_app_context_set_string_field(&m.base, NULL, "name", 4, ""));
    assert_int_equal(0, m.null_calls);
    assert_int_equal(1, m.string_calls);
    assert_int_equal(0, mock_live(&m));
}

static void string_field_null_creation_failure_is_oom(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 1, 1);
    m.fail_null = 1;
    assert_int_equal(PUBNUB_ERR_OUT_OF_MEMORY,
                     pn_app_context_set_string_field(
                         &m.base, NULL, "name", 4, PUBNUB_CLEAR_VALUE));
    assert_int_equal(0, m.set_calls);
    assert_int_equal(0, mock_live(&m));
}

static void string_field_string_creation_failure_is_oom(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 1, 1);
    m.fail_string = 1;
    assert_int_equal(
        PUBNUB_ERR_OUT_OF_MEMORY,
        pn_app_context_set_string_field(&m.base, NULL, "name", 4, "abc"));
    assert_int_equal(0, m.set_calls);
    assert_int_equal(0, mock_live(&m));
}

static void string_field_object_set_failure_destroys_value_once(void** state)
{
    mock_serial_t m;

    (void)state;

    mock_init(&m, 1, 1);
    m.fail_set = 1;
    assert_int_equal(PUBNUB_ERR_OUT_OF_MEMORY,
                     pn_app_context_set_string_field(
                         &m.base, NULL, "name", 4, PUBNUB_CLEAR_VALUE));
    assert_int_equal(1, m.created);
    assert_int_equal(1, m.destroyed);
    assert_int_equal(0, mock_live(&m));

    mock_init(&m, 1, 1);
    m.fail_set = 1;
    assert_int_equal(
        PUBNUB_ERR_OUT_OF_MEMORY,
        pn_app_context_set_string_field(&m.base, NULL, "name", 4, "abc"));
    assert_int_equal(1, m.created);
    assert_int_equal(1, m.destroyed);
    assert_int_equal(0, mock_live(&m));
}

static void string_field_marker_without_null_support_is_not_supported(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 0, 1);
    assert_int_equal(PUBNUB_ERR_NOT_SUPPORTED,
                     pn_app_context_set_string_field(
                         &m.base, NULL, "name", 4, PUBNUB_CLEAR_VALUE));
    assert_int_equal(0, m.created);
    assert_int_equal(0, m.set_calls);
    assert_int_equal(0, m.string_calls);
}

static void string_field_plain_string_works_without_null_support(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 0, 1);
    assert_int_equal(
        PUBNUB_OK, pn_app_context_set_string_field(&m.base, NULL, "name", 4, "abc"));
    assert_int_equal(KIND_STRING, m.last_set_kind);
    assert_int_equal(0, mock_live(&m));
}

static void string_field_lookalike_is_a_string_not_a_clear(void** state)
{
    mock_serial_t m;
    char          impostor[] = "\0PN_CLEAR_VALUE";

    (void)state;
    mock_init(&m, 0, 1);
    /* Even without null support the look-alike must not be rejected. */
    assert_int_equal(
        PUBNUB_OK,
        pn_app_context_set_string_field(&m.base, NULL, "name", 4, impostor));
    assert_int_equal(KIND_STRING, m.last_set_kind);
    assert_int_equal(0, m.null_calls);
}

/* pn_app_context_set_custom_field. */

static void custom_field_capability_matrix(void** state)
{
    int               has_null;
    int               has_raw;
    int               use_marker;
    static const char raw_json[] = "{\"a\":1}";

    (void)state;
    for (has_null = 0; has_null <= 1; ++has_null) {
        for (has_raw = 0; has_raw <= 1; ++has_raw) {
            for (use_marker = 0; use_marker <= 1; ++use_marker) {
                mock_serial_t m;
                const char* input = use_marker ? PUBNUB_CLEAR_VALUE : raw_json;
                /* Marker needs only null; non-clear raw needs only raw. */
                int          supported = use_marker ? has_null : has_raw;
                pubnub_res_t rc;

                mock_init(&m, has_null, has_raw);
                rc = pn_app_context_set_custom_field(
                    &m.base, NULL, NULL, input, sizeof(raw_json) - 1);

                if (supported) {
                    assert_int_equal(PUBNUB_OK, rc);
                    assert_int_equal(use_marker ? KIND_NULL : KIND_RAW,
                                     m.last_set_kind);
                    assert_int_equal(use_marker ? 1 : 0, m.null_calls);
                    assert_int_equal(use_marker ? 0 : 1, m.raw_calls);
                } else {
                    assert_int_equal(PUBNUB_ERR_NOT_SUPPORTED, rc);
                    assert_int_equal(0, m.created);
                    assert_int_equal(0, m.set_calls);
                }
                assert_int_equal(0, mock_live(&m));
            }
        }
    }
}

static void custom_field_marker_ignores_length(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 1, 0);
    assert_int_equal(PUBNUB_OK,
                     pn_app_context_set_custom_field(
                         &m.base, NULL, NULL, PUBNUB_CLEAR_VALUE, 9999));
    assert_int_equal(KIND_NULL, m.last_set_kind);
    assert_int_equal(0, m.raw_calls);
}

static void custom_field_raw_length_zero_uses_strlen_else_explicit(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 1, 1);
    assert_int_equal(
        PUBNUB_OK,
        pn_app_context_set_custom_field(&m.base, NULL, NULL, "{\"a\":1}", 0));
    assert_int_equal(7, (int)m.last_len);

    assert_int_equal(
        PUBNUB_OK,
        pn_app_context_set_custom_field(&m.base, NULL, NULL, "{\"a\":1}", 3));
    assert_int_equal(3, (int)m.last_len);
}

static void custom_field_lookalike_is_raw_not_a_clear(void** state)
{
    mock_serial_t m;
    char          impostor[] = "\0PN_CLEAR_VALUE";

    (void)state;
    mock_init(&m, 1, 1);
    assert_int_equal(
        PUBNUB_OK,
        pn_app_context_set_custom_field(&m.base, NULL, NULL, impostor, 5));
    assert_int_equal(0, m.null_calls);
    assert_int_equal(1, m.raw_calls);
    assert_int_equal(5, (int)m.last_len);
}

static void custom_field_creation_failures_are_oom(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 1, 1);
    m.fail_null = 1;
    assert_int_equal(PUBNUB_ERR_OUT_OF_MEMORY,
                     pn_app_context_set_custom_field(
                         &m.base, NULL, NULL, PUBNUB_CLEAR_VALUE, 0));
    assert_int_equal(0, mock_live(&m));

    mock_init(&m, 1, 1);
    m.fail_raw = 1;
    assert_int_equal(PUBNUB_ERR_OUT_OF_MEMORY,
                     pn_app_context_set_custom_field(&m.base, NULL, NULL, "{}", 2));
    assert_int_equal(0, mock_live(&m));
}

static void custom_field_object_set_failure_destroys_value_once(void** state)
{
    mock_serial_t m;

    (void)state;

    mock_init(&m, 1, 1);
    m.fail_set = 1;
    assert_int_equal(PUBNUB_ERR_OUT_OF_MEMORY,
                     pn_app_context_set_custom_field(
                         &m.base, NULL, NULL, PUBNUB_CLEAR_VALUE, 0));
    assert_int_equal(1, m.destroyed);
    assert_int_equal(0, mock_live(&m));

    mock_init(&m, 1, 1);
    m.fail_set = 1;
    assert_int_equal(PUBNUB_ERR_OUT_OF_MEMORY,
                     pn_app_context_set_custom_field(&m.base, NULL, NULL, "{}", 2));
    assert_int_equal(1, m.destroyed);
    assert_int_equal(0, mock_live(&m));
}

static void custom_field_tree_path_takes_precedence_and_is_unchanged(void** state)
{
    mock_serial_t m;
    mock_val_t*   tree;

    (void)state;

    /* Tree wins over a clear marker; no null/raw node is created. */
    mock_init(&m, 1, 1);
    tree = mock_new(&m, KIND_TREE, 0);
    assert_int_equal(
        PUBNUB_OK,
        pn_app_context_set_custom_field(
            &m.base, NULL, (pubnub_json_value_t*)tree, PUBNUB_CLEAR_VALUE, 0));
    assert_int_equal(KIND_TREE, m.last_set_kind);
    assert_int_equal(0, m.null_calls);
    assert_int_equal(0, m.raw_calls);
    assert_int_equal(0, mock_live(&m));

    /* Tree works even when the serializer lacks null and raw support. */
    mock_init(&m, 0, 0);
    tree = mock_new(&m, KIND_TREE, 0);
    assert_int_equal(PUBNUB_OK,
                     pn_app_context_set_custom_field(
                         &m.base, NULL, (pubnub_json_value_t*)tree, NULL, 0));
    assert_int_equal(0, mock_live(&m));

    /* A failed attach destroys the tree exactly once. */
    mock_init(&m, 1, 1);
    m.fail_set = 1;
    tree       = mock_new(&m, KIND_TREE, 0);
    assert_int_equal(PUBNUB_ERR_OUT_OF_MEMORY,
                     pn_app_context_set_custom_field(
                         &m.base, NULL, (pubnub_json_value_t*)tree, NULL, 0));
    assert_int_equal(1, m.destroyed);
    assert_int_equal(0, mock_live(&m));
}

static void custom_field_absent_is_a_noop(void** state)
{
    mock_serial_t m;

    (void)state;
    mock_init(&m, 0, 0);
    assert_int_equal(
        PUBNUB_OK, pn_app_context_set_custom_field(&m.base, NULL, NULL, NULL, 0));
    assert_int_equal(0, m.created);
    assert_int_equal(0, m.set_calls);
}

/* Builder error propagation with a serializer that cannot encode null. */

static pubnub_json_value_t* mock_create_object(pubnub_serialization_provider_t* self)
{
    return (pubnub_json_value_t*)mock_new((mock_serial_t*)self, KIND_TREE, 0);
}

static pubnub_res_t mock_serialize(pubnub_serialization_provider_t* self,
                                   const pubnub_json_value_t*       value,
                                   uint8_t*                         buf,
                                   size_t                           buf_len,
                                   size_t*                          out_len)
{
    (void)self;
    (void)value;
    (void)buf;
    (void)buf_len;
    (void)out_len;
    return PUBNUB_OK;
}

static void builder_propagates_not_supported_and_frees_object(void** state)
{
    mock_serial_t                   m;
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    uint8_t                         storage[64];
    pubnub_buffer_t                 body = {
                        .data = storage, .len = 0, .cap = sizeof(storage), .purpose = PUBNUB_BUF_OBJ};

    (void)state;
    mock_init(&m, 0, 1);
    m.base.value_create_object = mock_create_object;
    m.base.serialize           = mock_serialize;
    opts.name                  = PUBNUB_CLEAR_VALUE;

    assert_int_equal(PUBNUB_ERR_NOT_SUPPORTED,
                     pn_uuid_metadata_build_body(&m.base, NULL, &opts, &body));
    /* Only the root object was created, and it was released. */
    assert_int_equal(1, m.created);
    assert_int_equal(1, m.destroyed);
    assert_int_equal(0, mock_live(&m));
}

/* End-to-end through the public API. */

#define MAX_CAPTURES 4

typedef struct send_capture {
    pubnub_http_request_t*  request;
    pubnub_http_response_t* response;
} send_capture_t;

static int            s_send_count;
static send_capture_t s_captures[MAX_CAPTURES];
static int            s_fake_handle_storage[MAX_CAPTURES];

static pubnub_transport_handle_t* e2e_send(pubnub_transport_provider_t* self,
                                           pubnub_http_request_t*       request,
                                           pubnub_http_response_t* response)
{
    (void)self;
    if (s_send_count >= MAX_CAPTURES) {
        return NULL;
    }
    s_captures[s_send_count].request  = request;
    s_captures[s_send_count].response = response;
    s_send_count++;
    return (pubnub_transport_handle_t*)&s_fake_handle_storage[s_send_count - 1];
}

static int e2e_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void e2e_cancel(pubnub_transport_provider_t* self,
                       pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
}

static pubnub_transport_provider_t s_e2e_transport = {
    .send   = e2e_send,
    .poll   = e2e_poll,
    .cancel = e2e_cancel,
};

static pubnub_context_t* e2e_create(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();

    s_send_count = 0;
    memset(s_captures, 0, sizeof(s_captures));
    cfg.subscribe_key = "sub-test";
    cfg.user_id       = "tester";
    cfg.transport     = &s_e2e_transport;
    return pubnub_create(&cfg);
}

/* Copy the captured PATCH body, then finish and release the request. */
static void e2e_capture_and_finish(pubnub_context_t* ctx,
                                   pubnub_future_t   fut,
                                   char*             out,
                                   size_t            out_cap)
{
    static const uint8_t    k_reply[] = "{\"status\":200,\"data\":{}}";
    pubnub_http_request_t*  req;
    pubnub_http_response_t* resp;

    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);
    req  = s_captures[0].request;
    resp = s_captures[0].response;
    assert_int_equal(PUBNUB_HTTP_PATCH, req->method);
    assert_non_null(req->body);
    assert_true(req->body_len < out_cap);
    memcpy(out, req->body, req->body_len);
    out[req->body_len] = '\0';

    resp->body        = k_reply;
    resp->body_len    = sizeof(k_reply) - 1;
    resp->status_code = 200;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
    (void)pubnub_process(ctx);
    pubnub_future_release(fut);
}

static void public_set_uuid_metadata_sends_null_for_cleared_name(void** state)
{
    pubnub_context_t*               ctx  = e2e_create();
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_future_t                 fut;
    char                            body[BODY_CAP];

    (void)state;
    assert_non_null(ctx);
    opts.name  = PUBNUB_CLEAR_VALUE;
    opts.email = "x";

    fut = pubnub_set_uuid_metadata(ctx, &opts);
    e2e_capture_and_finish(ctx, fut, body, sizeof(body));

    assert_non_null(strstr(body, "\"name\":null"));
    assert_non_null(strstr(body, "\"email\":\"x\""));
    pubnub_destroy(ctx);
}

static void public_set_channel_metadata_sends_null_for_cleared_fields(void** state)
{
    pubnub_context_t* ctx = e2e_create();
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_future_t fut;
    char            body[BODY_CAP];

    (void)state;
    assert_non_null(ctx);
    opts.channel     = "ch";
    opts.description = PUBNUB_CLEAR_VALUE;
    opts.custom      = PUBNUB_CLEAR_VALUE;
    opts.custom_len  = 50;
    opts.name        = "General";

    fut = pubnub_set_channel_metadata(ctx, &opts);
    e2e_capture_and_finish(ctx, fut, body, sizeof(body));

    assert_non_null(strstr(body, "\"description\":null"));
    assert_non_null(strstr(body, "\"custom\":null"));
    assert_non_null(strstr(body, "\"name\":\"General\""));
    pubnub_destroy(ctx);
}

static void public_set_memberships_sends_null_for_cleared_status(void** state)
{
    pubnub_context_t*             ctx  = e2e_create();
    pubnub_set_memberships_opts_t opts = PUBNUB_SET_MEMBERSHIPS_OPTS_INIT;
    pubnub_membership_input_t     item;
    pubnub_future_t               fut;
    char                          body[BODY_CAP];

    (void)state;
    assert_non_null(ctx);
    memset(&item, 0, sizeof(item));
    item.channel_id = "c1";
    item.status     = PUBNUB_CLEAR_VALUE;
    item.type       = "t";
    opts.set        = &item;
    opts.set_count  = 1;

    fut = pubnub_set_memberships(ctx, &opts);
    e2e_capture_and_finish(ctx, fut, body, sizeof(body));

    assert_non_null(strstr(body, "\"status\":null"));
    assert_non_null(strstr(body, "\"type\":\"t\""));
    pubnub_destroy(ctx);
}

static void public_set_channel_members_sends_null_for_cleared_status(void** state)
{
    pubnub_context_t* ctx = e2e_create();
    pubnub_set_channel_members_opts_t opts = PUBNUB_SET_CHANNEL_MEMBERS_OPTS_INIT;
    pubnub_member_input_t item;
    pubnub_future_t       fut;
    char                  body[BODY_CAP];

    (void)state;
    assert_non_null(ctx);
    memset(&item, 0, sizeof(item));
    item.uuid_id   = "u1";
    item.status    = PUBNUB_CLEAR_VALUE;
    item.custom    = PUBNUB_CLEAR_VALUE;
    opts.channel   = "ch";
    opts.set       = &item;
    opts.set_count = 1;

    fut = pubnub_set_channel_members(ctx, &opts);
    e2e_capture_and_finish(ctx, fut, body, sizeof(body));

    assert_non_null(strstr(body, "\"status\":null"));
    assert_non_null(strstr(body, "\"custom\":null"));
    pubnub_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(uuid_clear_marker_in_each_string_field_encodes_null),
        cmocka_unit_test(uuid_clear_marker_in_custom_encodes_null),
        cmocka_unit_test(uuid_clear_marker_in_custom_ignores_custom_len),
        cmocka_unit_test(uuid_null_omits_empty_stays_empty_normal_unchanged),
        cmocka_unit_test(uuid_mixed_clear_set_and_omitted_fields),
        cmocka_unit_test(uuid_marker_lookalike_is_an_ordinary_string),
        cmocka_unit_test(uuid_custom_value_wins_over_clear_marker_in_custom),
        cmocka_unit_test(channel_clear_marker_in_each_string_field_encodes_null),
        cmocka_unit_test(channel_clear_marker_in_custom_ignores_custom_len),
        cmocka_unit_test(channel_null_omits_empty_stays_empty_normal_unchanged),
        cmocka_unit_test(channel_mixed_clear_set_and_omitted_fields),
        cmocka_unit_test(channel_marker_lookalike_is_an_ordinary_string),
        cmocka_unit_test(membership_clear_marker_in_each_field_encodes_null),
        cmocka_unit_test(member_clear_marker_in_each_field_encodes_null),
        cmocka_unit_test(membership_null_omits_empty_stays_empty_mixed_and_lookalike),
        cmocka_unit_test(string_field_marker_creates_null),
        cmocka_unit_test(string_field_plain_string_creates_string),
        cmocka_unit_test(string_field_empty_string_is_not_a_clear),
        cmocka_unit_test(string_field_null_creation_failure_is_oom),
        cmocka_unit_test(string_field_string_creation_failure_is_oom),
        cmocka_unit_test(string_field_object_set_failure_destroys_value_once),
        cmocka_unit_test(string_field_marker_without_null_support_is_not_supported),
        cmocka_unit_test(string_field_plain_string_works_without_null_support),
        cmocka_unit_test(string_field_lookalike_is_a_string_not_a_clear),
        cmocka_unit_test(custom_field_capability_matrix),
        cmocka_unit_test(custom_field_marker_ignores_length),
        cmocka_unit_test(custom_field_raw_length_zero_uses_strlen_else_explicit),
        cmocka_unit_test(custom_field_lookalike_is_raw_not_a_clear),
        cmocka_unit_test(custom_field_creation_failures_are_oom),
        cmocka_unit_test(custom_field_object_set_failure_destroys_value_once),
        cmocka_unit_test(custom_field_tree_path_takes_precedence_and_is_unchanged),
        cmocka_unit_test(custom_field_absent_is_a_noop),
        cmocka_unit_test(builder_propagates_not_supported_and_frees_object),
        cmocka_unit_test(public_set_uuid_metadata_sends_null_for_cleared_name),
        cmocka_unit_test(public_set_channel_metadata_sends_null_for_cleared_fields),
        cmocka_unit_test(public_set_memberships_sends_null_for_cleared_status),
        cmocka_unit_test(public_set_channel_members_sends_null_for_cleared_status),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
