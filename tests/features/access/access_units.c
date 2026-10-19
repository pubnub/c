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

#include "pubnub/features/access.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

/* Internal declarations shared with the feature implementation. */
#include "features/access/access_internal.h"

/* Provided by the linked cJSON serialization provider. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

/* Real malloc/free-backed allocator for tests that need genuine
 * alloc/free semantics (revoke path URL encoding). */
static void* test_allocator_alloc(pubnub_allocator_provider_t* self,
                                  size_t                       size,
                                  size_t                       align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void test_allocator_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t s_test_allocator = {
    .alloc       = test_allocator_alloc,
    .realloc     = NULL,
    .free        = test_allocator_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

#define OOM_PROXY_MAX_LIVE 64
#define OOM_PROXY_NEVER    (-1L)

/* Serialization proxy that injects failures into node creation and
 * object_set, and tracks ownership of every unattached node so leaks and
 * double destroys are detected independently of the sanitizer. */
typedef struct oom_proxy {
    pubnub_serialization_provider_t  base;
    pubnub_serialization_provider_t* real;
    long                             calls;
    long                             fail_from;
    const char*                      fail_key;
    pubnub_res_t                     set_error;
    int                              injected;
    pubnub_json_value_t*             live[OOM_PROXY_MAX_LIVE];
    size_t                           live_count;
    int                              bad_ownership;
} oom_proxy_t;

static void oom_proxy_track(oom_proxy_t* p, pubnub_json_value_t* node)
{
    if (p->live_count < OOM_PROXY_MAX_LIVE) {
        p->live[p->live_count++] = node;
    }
}

static int oom_proxy_untrack(oom_proxy_t* p, const pubnub_json_value_t* node)
{
    size_t i;

    for (i = 0; i < p->live_count; ++i) {
        if (p->live[i] == node) {
            p->live[i] = p->live[--p->live_count];
            return 1;
        }
    }
    return 0;
}

static int oom_proxy_should_fail(oom_proxy_t* p)
{
    long call = p->calls++;

    if (OOM_PROXY_NEVER != p->fail_from && call >= p->fail_from) {
        p->injected = 1;
        return 1;
    }
    return 0;
}

static pubnub_json_value_t* oom_proxy_create_object(pubnub_serialization_provider_t* self)
{
    oom_proxy_t*         p = (oom_proxy_t*)self;
    pubnub_json_value_t* node;

    if (oom_proxy_should_fail(p)) {
        return NULL;
    }
    node = p->real->value_create_object(p->real);
    if (NULL != node) {
        oom_proxy_track(p, node);
    }
    return node;
}

static pubnub_json_value_t* oom_proxy_create_int(pubnub_serialization_provider_t* self,
                                                 int value)
{
    oom_proxy_t*         p = (oom_proxy_t*)self;
    pubnub_json_value_t* node;

    if (oom_proxy_should_fail(p)) {
        return NULL;
    }
    node = p->real->value_create_int(p->real, value);
    if (NULL != node) {
        oom_proxy_track(p, node);
    }
    return node;
}

static pubnub_json_value_t* oom_proxy_create_string(pubnub_serialization_provider_t* self,
                                                    const char* str,
                                                    size_t      len)
{
    oom_proxy_t*         p = (oom_proxy_t*)self;
    pubnub_json_value_t* node;

    if (oom_proxy_should_fail(p)) {
        return NULL;
    }
    node = p->real->value_create_string(p->real, str, len);
    if (NULL != node) {
        oom_proxy_track(p, node);
    }
    return node;
}

static pubnub_res_t oom_proxy_object_set(pubnub_serialization_provider_t* self,
                                         pubnub_json_value_t*             obj,
                                         const char*                      key,
                                         size_t               key_len,
                                         pubnub_json_value_t* value)
{
    oom_proxy_t* p = (oom_proxy_t*)self;
    pubnub_res_t rc;

    if (NULL != p->fail_key && strlen(p->fail_key) == key_len
        && 0 == memcmp(p->fail_key, key, key_len)) {
        p->injected = 1;
        return p->set_error;
    }
    if (oom_proxy_should_fail(p)) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    rc = p->real->object_set(p->real, obj, key, key_len, value);
    if (PUBNUB_OK == rc && 0 == oom_proxy_untrack(p, value)) {
        p->bad_ownership++;
    }
    return rc;
}

static void oom_proxy_value_destroy(pubnub_serialization_provider_t* self,
                                    pubnub_json_value_t*             value)
{
    oom_proxy_t* p = (oom_proxy_t*)self;

    if (NULL == value) {
        return;
    }
    if (0 == oom_proxy_untrack(p, value)) {
        /* Double destroy, or destroy of a node a parent already owns. */
        p->bad_ownership++;
        return;
    }
    p->real->value_destroy(p->real, value);
}

static pubnub_res_t oom_proxy_serialize(pubnub_serialization_provider_t* self,
                                        const pubnub_json_value_t*       root,
                                        uint8_t*                         buf,
                                        size_t                           cap,
                                        size_t* out_len)
{
    oom_proxy_t* p = (oom_proxy_t*)self;
    return p->real->serialize(p->real, root, buf, cap, out_len);
}

static void oom_proxy_init(oom_proxy_t* p)
{
    memset(p, 0, sizeof(*p));
    p->real                     = pn_serialization_default();
    p->base                     = *p->real;
    p->base.value_create_object = oom_proxy_create_object;
    p->base.value_create_int    = oom_proxy_create_int;
    p->base.value_create_string = oom_proxy_create_string;
    p->base.object_set          = oom_proxy_object_set;
    p->base.value_destroy       = oom_proxy_value_destroy;
    p->base.serialize           = oom_proxy_serialize;
    p->fail_from                = OOM_PROXY_NEVER;
    p->set_error                = PUBNUB_ERR_OUT_OF_MEMORY;
}

static void oom_proxy_rearm(oom_proxy_t* p, long fail_from)
{
    p->calls         = 0;
    p->fail_from     = fail_from;
    p->fail_key      = NULL;
    p->injected      = 0;
    p->live_count    = 0;
    p->bad_ownership = 0;
}

/* Build the body, parse it back and return the "permissions" node. */
static const pubnub_json_value_t*
build_permissions(pubnub_serialization_provider_t* serial,
                  const pubnub_grant_token_opts_t* opts,
                  uint8_t*                         buf,
                  size_t                           cap,
                  pubnub_json_value_t**            out_tree)
{
    size_t out_len = 0;
    pubnub_res_t rc = pn_access_grant_build_body(serial, opts, buf, cap, &out_len);

    assert_int_equal(rc, PUBNUB_OK);
    *out_tree = serial->parse(serial, buf, out_len);
    assert_non_null(*out_tree);
    return serial->object_get(*out_tree, "permissions", 11);
}

static void expect_int_member(pubnub_serialization_provider_t* serial,
                              const pubnub_json_value_t*       obj,
                              const char*                      key,
                              int                              expected)
{
    const pubnub_json_value_t* node = serial->object_get(obj, key, strlen(key));
    int                        val  = -1;

    assert_non_null(node);
    assert_int_equal(serial->value_as_int(node, &val), PUBNUB_OK);
    assert_int_equal(val, expected);
}

/* ------------------------------------------------------------------ */
/* Tests: grant path builder                                           */
/* ------------------------------------------------------------------ */

static void test_grant_build_path_success(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pubnub_res_t rc = pn_access_grant_build_path(&request, "my-sub-key");

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.path_segment_count, 4);
    assert_memory_equal(request.path_segments[0].ptr, "v3", 2);
    assert_int_equal(request.path_segments[0].len, 2);
    assert_memory_equal(request.path_segments[1].ptr, "pam", 3);
    assert_int_equal(request.path_segments[1].len, 3);
    assert_memory_equal(request.path_segments[2].ptr, "my-sub-key", 10);
    assert_int_equal(request.path_segments[2].len, 10);
    assert_memory_equal(request.path_segments[3].ptr, "grant", 5);
    assert_int_equal(request.path_segments[3].len, 5);
}

static void test_grant_build_path_null_request(void** state)
{
    (void)state;
    pubnub_res_t rc = pn_access_grant_build_path(NULL, "key");
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void test_grant_build_path_null_key(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pubnub_res_t rc = pn_access_grant_build_path(&request, NULL);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ------------------------------------------------------------------ */
/* Tests: grant body builder                                           */
/* ------------------------------------------------------------------ */

static void test_grant_build_body_single_channel(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    pubnub_access_resource_permission_t ch_perms[] = {
        {"ch1", PUBNUB_ACCESS_READ | PUBNUB_ACCESS_WRITE},
    };
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 60;
    opts.channels                  = ch_perms;
    opts.channel_count             = 1;

    uint8_t buf[2048];
    size_t  out_len = 0;

    pubnub_res_t rc =
        pn_access_grant_build_body(serial, &opts, buf, sizeof(buf), &out_len);
    assert_int_equal(rc, PUBNUB_OK);
    assert_true(out_len > 0);

    /* Parse the serialized body back and verify structure. */
    pubnub_json_value_t* tree = serial->parse(serial, buf, out_len);
    assert_non_null(tree);
    assert_int_equal(serial->value_type(tree), PUBNUB_JSON_OBJECT);

    /* Verify TTL. */
    const pubnub_json_value_t* ttl_node = serial->object_get(tree, "ttl", 3);
    assert_non_null(ttl_node);
    int ttl_val = 0;
    assert_int_equal(serial->value_as_int(ttl_node, &ttl_val), PUBNUB_OK);
    assert_int_equal(ttl_val, 60);

    /* Navigate to permissions.resources.channels.ch1 */
    const pubnub_json_value_t* perms_node =
        serial->object_get(tree, "permissions", 11);
    assert_non_null(perms_node);

    const pubnub_json_value_t* resources_node =
        serial->object_get(perms_node, "resources", 9);
    assert_non_null(resources_node);

    const pubnub_json_value_t* channels_node =
        serial->object_get(resources_node, "channels", 8);
    assert_non_null(channels_node);

    const pubnub_json_value_t* ch1_node =
        serial->object_get(channels_node, "ch1", 3);
    assert_non_null(ch1_node);
    int perm_val = 0;
    assert_int_equal(serial->value_as_int(ch1_node, &perm_val), PUBNUB_OK);
    assert_int_equal(perm_val, 3); /* READ | WRITE */

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_multiple_resource_types(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    pubnub_access_resource_permission_t ch_perms[] = {
        {"channel-a", PUBNUB_ACCESS_READ},
    };
    pubnub_access_resource_permission_t grp_perms[] = {
        {"group-1", PUBNUB_ACCESS_MANAGE},
    };
    pubnub_access_resource_permission_t uuid_perms[] = {
        {"user-x", PUBNUB_ACCESS_GET | PUBNUB_ACCESS_UPDATE},
    };

    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 120;
    opts.channels                  = ch_perms;
    opts.channel_count             = 1;
    opts.groups                    = grp_perms;
    opts.group_count               = 1;
    opts.uuids                     = uuid_perms;
    opts.uuid_count                = 1;

    uint8_t buf[4096];
    size_t  out_len = 0;

    pubnub_res_t rc =
        pn_access_grant_build_body(serial, &opts, buf, sizeof(buf), &out_len);
    assert_int_equal(rc, PUBNUB_OK);

    pubnub_json_value_t* tree = serial->parse(serial, buf, out_len);
    assert_non_null(tree);

    const pubnub_json_value_t* perms_node =
        serial->object_get(tree, "permissions", 11);
    assert_non_null(perms_node);
    const pubnub_json_value_t* resources =
        serial->object_get(perms_node, "resources", 9);
    assert_non_null(resources);

    /* channels.channel-a == 1 (READ) */
    const pubnub_json_value_t* ch_obj =
        serial->object_get(resources, "channels", 8);
    assert_non_null(ch_obj);
    const pubnub_json_value_t* ch_a = serial->object_get(ch_obj, "channel-a", 9);
    assert_non_null(ch_a);
    int val = 0;
    serial->value_as_int(ch_a, &val);
    assert_int_equal(val, 1);

    /* groups.group-1 == 4 (MANAGE) */
    const pubnub_json_value_t* grp_obj = serial->object_get(resources, "groups", 6);
    assert_non_null(grp_obj);
    const pubnub_json_value_t* grp1 = serial->object_get(grp_obj, "group-1", 7);
    assert_non_null(grp1);
    serial->value_as_int(grp1, &val);
    assert_int_equal(val, 4);

    /* uuids.user-x == 96 (GET|UPDATE = 32|64) */
    const pubnub_json_value_t* uuid_obj = serial->object_get(resources, "uuids", 5);
    assert_non_null(uuid_obj);
    const pubnub_json_value_t* ux = serial->object_get(uuid_obj, "user-x", 6);
    assert_non_null(ux);
    serial->value_as_int(ux, &val);
    assert_int_equal(val, 96);

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_patterns(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    pubnub_access_resource_permission_t pat[] = {
        {"^chat\\..*$", PUBNUB_ACCESS_READ | PUBNUB_ACCESS_WRITE},
    };

    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 30;
    opts.channel_patterns          = pat;
    opts.channel_pattern_count     = 1;

    uint8_t buf[2048];
    size_t  out_len = 0;

    pubnub_res_t rc =
        pn_access_grant_build_body(serial, &opts, buf, sizeof(buf), &out_len);
    assert_int_equal(rc, PUBNUB_OK);

    pubnub_json_value_t* tree = serial->parse(serial, buf, out_len);
    assert_non_null(tree);

    const pubnub_json_value_t* perms_node =
        serial->object_get(tree, "permissions", 11);
    assert_non_null(perms_node);
    const pubnub_json_value_t* patterns =
        serial->object_get(perms_node, "patterns", 8);
    assert_non_null(patterns);

    const pubnub_json_value_t* ch_pat = serial->object_get(patterns, "channels", 8);
    assert_non_null(ch_pat);
    const pubnub_json_value_t* regex_node =
        serial->object_get(ch_pat, "^chat\\..*$", 10);
    assert_non_null(regex_node);
    int val = 0;
    serial->value_as_int(regex_node, &val);
    assert_int_equal(val, 3); /* READ | WRITE */

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_with_authorized_uuid(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    pubnub_access_resource_permission_t ch_perms[] = {
        {"ch", PUBNUB_ACCESS_READ},
    };
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 15;
    opts.channels                  = ch_perms;
    opts.channel_count             = 1;
    opts.authorized_uuid           = "user-abc";

    uint8_t buf[2048];
    size_t  out_len = 0;

    pubnub_res_t rc =
        pn_access_grant_build_body(serial, &opts, buf, sizeof(buf), &out_len);
    assert_int_equal(rc, PUBNUB_OK);

    pubnub_json_value_t* tree = serial->parse(serial, buf, out_len);
    assert_non_null(tree);

    const pubnub_json_value_t* perms_node =
        serial->object_get(tree, "permissions", 11);
    assert_non_null(perms_node);
    const pubnub_json_value_t* uuid_node =
        serial->object_get(perms_node, "uuid", 4);
    assert_non_null(uuid_node);

    size_t      str_len = 0;
    const char* str_val = serial->value_as_string(uuid_node, &str_len);
    assert_non_null(str_val);
    assert_int_equal(str_len, 8);
    assert_memory_equal(str_val, "user-abc", 8);

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_with_meta(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    pubnub_access_resource_permission_t ch_perms[] = {
        {"ch", PUBNUB_ACCESS_READ},
    };
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 10;
    opts.channels                  = ch_perms;
    opts.channel_count             = 1;
    opts.meta                      = "{\"team\":\"alpha\"}";

    uint8_t buf[2048];
    size_t  out_len = 0;

    pubnub_res_t rc =
        pn_access_grant_build_body(serial, &opts, buf, sizeof(buf), &out_len);
    assert_int_equal(rc, PUBNUB_OK);

    pubnub_json_value_t* tree = serial->parse(serial, buf, out_len);
    assert_non_null(tree);

    const pubnub_json_value_t* perms_node =
        serial->object_get(tree, "permissions", 11);
    assert_non_null(perms_node);
    const pubnub_json_value_t* meta_node =
        serial->object_get(perms_node, "meta", 4);
    assert_non_null(meta_node);
    assert_int_equal(serial->value_type(meta_node), PUBNUB_JSON_OBJECT);

    const pubnub_json_value_t* team_node = serial->object_get(meta_node, "team", 4);
    assert_non_null(team_node);
    size_t      tl = 0;
    const char* tv = serial->value_as_string(team_node, &tl);
    assert_non_null(tv);
    assert_int_equal(tl, 5);
    assert_memory_equal(tv, "alpha", 5);

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_null_serial(void** state)
{
    (void)state;
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 60;

    uint8_t buf[64];
    size_t  out_len = 0;

    pubnub_res_t rc =
        pn_access_grant_build_body(NULL, &opts, buf, sizeof(buf), &out_len);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void test_grant_build_body_null_opts(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    uint8_t buf[64];
    size_t  out_len = 0;

    pubnub_res_t rc =
        pn_access_grant_build_body(serial, NULL, buf, sizeof(buf), &out_len);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void test_grant_build_body_buffer_too_small(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    pubnub_access_resource_permission_t ch_perms[] = {
        {"channel-with-long-name", PUBNUB_ACCESS_READ},
    };
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 60;
    opts.channels                  = ch_perms;
    opts.channel_count             = 1;

    /* Tiny buffer that cannot hold the serialized JSON. */
    uint8_t buf[4];
    size_t  out_len = 0;

    pubnub_res_t rc =
        pn_access_grant_build_body(serial, &opts, buf, sizeof(buf), &out_len);
    assert_int_not_equal(rc, PUBNUB_OK);
}

static void test_grant_build_body_category_only(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_grant_token_opts_t        opts   = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    uint8_t                          buf[1024];
    pubnub_json_value_t*             tree  = NULL;
    const pubnub_json_value_t*       perms = NULL;
    const pubnub_json_value_t*       cats  = NULL;

    opts.ttl                           = 60;
    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;

    perms = build_permissions(serial, &opts, buf, sizeof(buf), &tree);
    assert_non_null(perms);
    assert_true(serial->object_size(perms) > 0);
    assert_null(serial->object_get(perms, "resources", 9));
    assert_null(serial->object_get(perms, "patterns", 8));

    cats = serial->object_get(perms, "categories", 10);
    assert_non_null(cats);
    assert_int_equal(serial->value_type(cats), PUBNUB_JSON_OBJECT);
    assert_int_equal(serial->object_size(cats), 2);
    expect_int_member(serial, cats, "channels", 32);
    expect_int_member(serial, cats, "uuids", 32);

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_category_channels_only(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_grant_token_opts_t        opts   = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    uint8_t                          buf[1024];
    pubnub_json_value_t*             tree  = NULL;
    const pubnub_json_value_t*       perms = NULL;
    const pubnub_json_value_t*       cats  = NULL;

    opts.ttl                           = 60;
    opts.channels_category_permissions = PUBNUB_ACCESS_GET;

    perms = build_permissions(serial, &opts, buf, sizeof(buf), &tree);
    assert_non_null(perms);
    cats = serial->object_get(perms, "categories", 10);
    assert_non_null(cats);
    assert_int_equal(serial->object_size(cats), 1);
    expect_int_member(serial, cats, "channels", 32);
    assert_null(serial->object_get(cats, "uuids", 5));

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_category_uuids_only(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_grant_token_opts_t        opts   = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    uint8_t                          buf[1024];
    pubnub_json_value_t*             tree  = NULL;
    const pubnub_json_value_t*       perms = NULL;
    const pubnub_json_value_t*       cats  = NULL;

    opts.ttl                        = 60;
    opts.uuids_category_permissions = PUBNUB_ACCESS_GET;

    perms = build_permissions(serial, &opts, buf, sizeof(buf), &tree);
    assert_non_null(perms);
    cats = serial->object_get(perms, "categories", 10);
    assert_non_null(cats);
    assert_int_equal(serial->object_size(cats), 1);
    expect_int_member(serial, cats, "uuids", 32);
    assert_null(serial->object_get(cats, "channels", 8));

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_category_with_resources_and_patterns(void** state)
{
    (void)state;
    pubnub_serialization_provider_t*    serial     = pn_serialization_default();
    pubnub_access_resource_permission_t ch_perms[] = {
        {"ch1", PUBNUB_ACCESS_READ},
    };
    pubnub_access_resource_permission_t uuid_pat[] = {
        {"^user-.*$", PUBNUB_ACCESS_GET | PUBNUB_ACCESS_UPDATE},
    };
    pubnub_grant_token_opts_t  opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    uint8_t                    buf[2048];
    pubnub_json_value_t*       tree      = NULL;
    const pubnub_json_value_t* perms     = NULL;
    const pubnub_json_value_t* resources = NULL;
    const pubnub_json_value_t* patterns  = NULL;
    const pubnub_json_value_t* cats      = NULL;
    const pubnub_json_value_t* node      = NULL;

    opts.ttl                           = 60;
    opts.channels                      = ch_perms;
    opts.channel_count                 = 1;
    opts.uuid_patterns                 = uuid_pat;
    opts.uuid_pattern_count            = 1;
    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;

    perms = build_permissions(serial, &opts, buf, sizeof(buf), &tree);
    assert_non_null(perms);

    resources = serial->object_get(perms, "resources", 9);
    assert_non_null(resources);
    node = serial->object_get(resources, "channels", 8);
    assert_non_null(node);
    expect_int_member(serial, node, "ch1", 1);
    assert_null(serial->object_get(resources, "categories", 10));

    patterns = serial->object_get(perms, "patterns", 8);
    assert_non_null(patterns);
    node = serial->object_get(patterns, "uuids", 5);
    assert_non_null(node);
    expect_int_member(serial, node, "^user-.*$", 96);
    assert_null(serial->object_get(patterns, "categories", 10));

    cats = serial->object_get(perms, "categories", 10);
    assert_non_null(cats);
    expect_int_member(serial, cats, "channels", 32);
    expect_int_member(serial, cats, "uuids", 32);

    serial->value_destroy(serial, tree);
}

static void
test_grant_build_body_resources_only_omits_patterns_and_categories(void** state)
{
    (void)state;
    pubnub_serialization_provider_t*    serial     = pn_serialization_default();
    pubnub_access_resource_permission_t ch_perms[] = {
        {"ch1", PUBNUB_ACCESS_READ},
    };
    pubnub_grant_token_opts_t  opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    uint8_t                    buf[1024];
    pubnub_json_value_t*       tree  = NULL;
    const pubnub_json_value_t* perms = NULL;

    opts.ttl           = 60;
    opts.channels      = ch_perms;
    opts.channel_count = 1;

    perms = build_permissions(serial, &opts, buf, sizeof(buf), &tree);
    assert_non_null(perms);
    assert_null(serial->object_get(perms, "categories", 10));
    assert_non_null(serial->object_get(perms, "resources", 9));
    assert_null(serial->object_get(perms, "patterns", 8));

    serial->value_destroy(serial, tree);
}

static void
test_grant_build_body_patterns_only_omits_resources_and_categories(void** state)
{
    (void)state;
    pubnub_serialization_provider_t*    serial = pn_serialization_default();
    pubnub_access_resource_permission_t pat[]  = {
        {"^chat\\..*$", PUBNUB_ACCESS_READ},
    };
    pubnub_grant_token_opts_t  opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    uint8_t                    buf[1024];
    pubnub_json_value_t*       tree  = NULL;
    const pubnub_json_value_t* perms = NULL;

    opts.ttl                   = 60;
    opts.channel_patterns      = pat;
    opts.channel_pattern_count = 1;

    perms = build_permissions(serial, &opts, buf, sizeof(buf), &tree);
    assert_non_null(perms);
    assert_null(serial->object_get(perms, "resources", 9));
    assert_non_null(serial->object_get(perms, "patterns", 8));
    assert_null(serial->object_get(perms, "categories", 10));

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_resources_and_patterns_omits_categories(void** state)
{
    (void)state;
    pubnub_serialization_provider_t*    serial     = pn_serialization_default();
    pubnub_access_resource_permission_t ch_perms[] = {
        {"ch1", PUBNUB_ACCESS_READ},
    };
    pubnub_access_resource_permission_t ch_pat[] = {
        {"^chat\\..*$", PUBNUB_ACCESS_READ},
    };
    pubnub_grant_token_opts_t  opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    uint8_t                    buf[1024];
    pubnub_json_value_t*       tree  = NULL;
    const pubnub_json_value_t* perms = NULL;

    opts.ttl                   = 60;
    opts.channels              = ch_perms;
    opts.channel_count         = 1;
    opts.channel_patterns      = ch_pat;
    opts.channel_pattern_count = 1;

    perms = build_permissions(serial, &opts, buf, sizeof(buf), &tree);
    assert_non_null(perms);
    assert_non_null(serial->object_get(perms, "resources", 9));
    assert_non_null(serial->object_get(perms, "patterns", 8));
    assert_null(serial->object_get(perms, "categories", 10));

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_non_get_category_bits_not_emitted(void** state)
{
    (void)state;
    pubnub_serialization_provider_t*    serial     = pn_serialization_default();
    pubnub_access_resource_permission_t ch_perms[] = {
        {"ch1", PUBNUB_ACCESS_READ},
    };
    pubnub_grant_token_opts_t  opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    uint8_t                    buf[1024];
    pubnub_json_value_t*       tree  = NULL;
    const pubnub_json_value_t* perms = NULL;

    opts.ttl                           = 60;
    opts.channels                      = ch_perms;
    opts.channel_count                 = 1;
    opts.channels_category_permissions = PUBNUB_ACCESS_READ;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_UPDATE;

    perms = build_permissions(serial, &opts, buf, sizeof(buf), &tree);
    assert_non_null(perms);
    assert_null(serial->object_get(perms, "categories", 10));

    serial->value_destroy(serial, tree);
}

static void test_grant_build_body_category_buffer_boundary(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_grant_token_opts_t        opts   = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    uint8_t                          storage[512];
    uint8_t                          reference[512];
    size_t                           full_len = 0;
    size_t                           min_cap  = 0;
    size_t                           cap;
    size_t                           i;

    opts.ttl                           = 60;
    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;

    assert_int_equal(pn_access_grant_build_body(
                         serial, &opts, reference, sizeof(reference), &full_len),
                     PUBNUB_OK);
    assert_true(full_len > 0);
    assert_true(full_len < sizeof(reference) - 8U);

    for (cap = 1; cap <= full_len + 64U; ++cap) {
        size_t       out_len = 0;
        pubnub_res_t rc;

        memset(storage, 0xA5, sizeof(storage));
        rc = pn_access_grant_build_body(serial, &opts, storage, cap, &out_len);

        /* Nothing past the advertised capacity may ever be touched. */
        for (i = cap; i < sizeof(storage); ++i) {
            assert_int_equal(storage[i], 0xA5);
        }
        if (PUBNUB_OK == rc) {
            if (0 == min_cap) {
                min_cap = cap;
            }
            assert_int_equal(out_len, full_len);
            assert_memory_equal(storage, reference, full_len);
        } else {
            /* Once a capacity works, every larger one must too. */
            assert_int_equal(rc, PUBNUB_ERR_BUFFER_TOO_SMALL);
            assert_int_equal(0, min_cap);
        }
    }

    /* The serialized length is reachable; some providers need a few
     * bytes of terminator slack beyond it. */
    assert_true(min_cap >= full_len);
    assert_true(min_cap <= full_len + 64U);
}

static void run_oom_sweep(oom_proxy_t* proxy, const pubnub_grant_token_opts_t* opts)
{
    uint8_t buf[2048];
    long    k;
    long    injections = 0;

    for (k = 0; k < 200; ++k) {
        size_t       out_len = 0;
        pubnub_res_t rc;

        oom_proxy_rearm(proxy, k);
        rc = pn_access_grant_build_body(
            &proxy->base, opts, buf, sizeof(buf), &out_len);

        assert_int_equal(proxy->bad_ownership, 0);
        assert_int_equal(proxy->live_count, 0);
        if (0 == proxy->injected) {
            assert_int_equal(rc, PUBNUB_OK);
            break;
        }
        ++injections;
        assert_int_equal(rc, PUBNUB_ERR_OUT_OF_MEMORY);
    }
    /* Sweep must have exercised a meaningful number of failure points
     * and must have terminated by reaching the success case. */
    assert_true(injections >= 6);
    assert_true(k < 200);
}

static void test_grant_build_body_category_only_oom_every_index(void** state)
{
    (void)state;
    oom_proxy_t               proxy;
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;

    oom_proxy_init(&proxy);
    opts.ttl                           = 60;
    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;

    run_oom_sweep(&proxy, &opts);
}

static void test_grant_build_body_combined_oom_every_index(void** state)
{
    (void)state;
    oom_proxy_t                         proxy;
    pubnub_access_resource_permission_t ch_perms[] = {
        {"ch1", PUBNUB_ACCESS_READ},
    };
    pubnub_access_resource_permission_t uuid_pat[] = {
        {"^u.*$", PUBNUB_ACCESS_GET},
    };
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;

    oom_proxy_init(&proxy);
    opts.ttl                           = 60;
    opts.channels                      = ch_perms;
    opts.channel_count                 = 1;
    opts.uuid_patterns                 = uuid_pat;
    opts.uuid_pattern_count            = 1;
    opts.authorized_uuid               = "owner";
    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;

    run_oom_sweep(&proxy, &opts);
}

static void test_grant_build_body_category_set_failure_code_propagates(void** state)
{
    (void)state;
    static const char* const  keys[] = {"channels", "uuids", "categories"};
    oom_proxy_t               proxy;
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    uint8_t                   buf[1024];
    size_t                    i;

    oom_proxy_init(&proxy);
    opts.ttl                           = 60;
    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;

    /* A failure that is not out-of-memory must surface as itself. */
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        size_t       out_len = 0;
        pubnub_res_t rc;

        oom_proxy_rearm(&proxy, OOM_PROXY_NEVER);
        proxy.fail_key  = keys[i];
        proxy.set_error = PUBNUB_ERR_SERIALIZATION;

        rc = pn_access_grant_build_body(
            &proxy.base, &opts, buf, sizeof(buf), &out_len);

        assert_int_equal(proxy.injected, 1);
        assert_int_equal(rc, PUBNUB_ERR_SERIALIZATION);
        assert_int_equal(proxy.bad_ownership, 0);
        assert_int_equal(proxy.live_count, 0);
    }
}

/* ------------------------------------------------------------------ */
/* Tests: revoke path builder                                          */
/* ------------------------------------------------------------------ */

static void test_revoke_build_path_success(void** state)
{
    (void)state;
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;
    char*                        encoded   = NULL;

    pubnub_res_t rc = pn_access_revoke_build_path(
        &request, allocator, "sub-c-key", "simpletoken", &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.path_segment_count, 5);
    assert_memory_equal(request.path_segments[0].ptr, "v3", 2);
    assert_memory_equal(request.path_segments[1].ptr, "pam", 3);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "grant", 5);
    assert_non_null(encoded);
    /* The encoded token is the 5th segment. */
    assert_non_null(request.path_segments[4].ptr);
    assert_true(request.path_segments[4].len > 0);

    allocator->free(allocator, encoded);
}

static void test_revoke_build_path_encodes_special_chars(void** state)
{
    (void)state;
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;
    char*                        encoded   = NULL;

    /* Token with characters that need percent-encoding. */
    pubnub_res_t rc = pn_access_revoke_build_path(
        &request, allocator, "sub-key", "tok/en+val=", &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(encoded);
    /* Slash, plus, and equals should be percent-encoded. */
    assert_non_null(strstr(encoded, "%2F") != NULL ? strstr(encoded, "%2F")
                                                   : strstr(encoded, "%2f"));
    assert_non_null(strstr(encoded, "%2B") != NULL ? strstr(encoded, "%2B")
                                                   : strstr(encoded, "%2b"));
    assert_non_null(strstr(encoded, "%3D") != NULL ? strstr(encoded, "%3D")
                                                   : strstr(encoded, "%3d"));

    allocator->free(allocator, encoded);
}

static void test_revoke_build_path_null_token(void** state)
{
    (void)state;
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;
    char*                        encoded   = NULL;

    pubnub_res_t rc =
        pn_access_revoke_build_path(&request, allocator, "sub-key", NULL, &encoded);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_null(encoded);
}

static void test_revoke_build_path_null_subscribe_key(void** state)
{
    (void)state;
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;
    char*                        encoded   = NULL;

    pubnub_res_t rc =
        pn_access_revoke_build_path(&request, allocator, NULL, "token", &encoded);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void test_revoke_build_path_null_request(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* allocator = &s_test_allocator;
    char*                        encoded   = NULL;

    pubnub_res_t rc =
        pn_access_revoke_build_path(NULL, allocator, "sub-key", "token", &encoded);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ------------------------------------------------------------------ */
/* Tests: response validator                                           */
/* ------------------------------------------------------------------ */

static void test_validator_http_200(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"data\":{\"token\":\"abc\"}}";
    pubnub_res_t  rc =
        pn_access_grant_response_validator(body, sizeof(body) - 1, 200);
    assert_int_equal(rc, PUBNUB_OK);
}

static void test_validator_http_201(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"data\":{\"token\":\"abc\"}}";
    pubnub_res_t  rc =
        pn_access_grant_response_validator(body, sizeof(body) - 1, 201);
    assert_int_equal(rc, PUBNUB_OK);
}

static void test_validator_http_403(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"error\":\"forbidden\"}";
    pubnub_res_t  rc =
        pn_access_grant_response_validator(body, sizeof(body) - 1, 403);
    assert_int_equal(rc, PUBNUB_ERR_SERVER);
}

static void test_validator_http_400(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"error\":\"bad request\"}";
    pubnub_res_t  rc =
        pn_access_grant_response_validator(body, sizeof(body) - 1, 400);
    assert_int_equal(rc, PUBNUB_ERR_SERVER);
}

static void test_validator_http_500(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"error\":\"internal\"}";
    pubnub_res_t  rc =
        pn_access_grant_response_validator(body, sizeof(body) - 1, 500);
    assert_int_equal(rc, PUBNUB_ERR_SERVER);
}

/* ------------------------------------------------------------------ */
/* Tests: response parser                                              */
/* ------------------------------------------------------------------ */

static pubnub_json_value_t* parse_body(pubnub_serialization_provider_t* serial,
                                       const char*                      body)
{
    return serial->parse(serial, (const uint8_t*)body, strlen(body));
}

static void test_parse_response_valid(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      body = "{\"data\":{\"token\":\"abc123\"}}";
    pubnub_json_value_t*             tree = parse_body(serial, body);
    assert_non_null(tree);

    pn_access_grant_parsed_t out = {0};
    pubnub_res_t rc = pn_access_grant_parse_response(serial, tree, &out);
    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(out.token.ptr);
    assert_int_equal(out.token.len, 6);
    assert_memory_equal(out.token.ptr, "abc123", 6);

    serial->value_destroy(serial, tree);
}

static void test_parse_response_missing_data(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      body   = "{\"error\":\"something\"}";
    pubnub_json_value_t*             tree   = parse_body(serial, body);
    assert_non_null(tree);

    pn_access_grant_parsed_t out = {0};
    pubnub_res_t rc = pn_access_grant_parse_response(serial, tree, &out);
    assert_int_equal(rc, PUBNUB_ERR_SERIALIZATION);
    assert_null(out.token.ptr);

    serial->value_destroy(serial, tree);
}

static void test_parse_response_missing_token(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      body   = "{\"data\":{\"message\":\"ok\"}}";
    pubnub_json_value_t*             tree   = parse_body(serial, body);
    assert_non_null(tree);

    pn_access_grant_parsed_t out = {0};
    pubnub_res_t rc = pn_access_grant_parse_response(serial, tree, &out);
    assert_int_equal(rc, PUBNUB_ERR_SERIALIZATION);
    assert_null(out.token.ptr);

    serial->value_destroy(serial, tree);
}

static void test_parse_response_non_object_root(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      body   = "[1,2,3]";
    pubnub_json_value_t*             tree   = parse_body(serial, body);
    assert_non_null(tree);

    pn_access_grant_parsed_t out = {0};
    pubnub_res_t rc = pn_access_grant_parse_response(serial, tree, &out);
    assert_int_equal(rc, PUBNUB_ERR_SERIALIZATION);

    serial->value_destroy(serial, tree);
}

static void test_parse_response_null_out(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      body   = "{\"data\":{\"token\":\"x\"}}";
    pubnub_json_value_t*             tree   = parse_body(serial, body);
    assert_non_null(tree);

    pubnub_res_t rc = pn_access_grant_parse_response(serial, tree, NULL);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);

    serial->value_destroy(serial, tree);
}

static void test_parse_response_null_serial(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      body   = "{\"data\":{\"token\":\"x\"}}";
    pubnub_json_value_t*             tree   = parse_body(serial, body);
    assert_non_null(tree);

    pn_access_grant_parsed_t out = {0};
    pubnub_res_t rc = pn_access_grant_parse_response(NULL, tree, &out);
    assert_int_equal(rc, PUBNUB_ERR_SERIALIZATION);

    serial->value_destroy(serial, tree);
}

static void test_parse_response_null_tree(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    pn_access_grant_parsed_t out = {0};
    pubnub_res_t rc = pn_access_grant_parse_response(serial, NULL, &out);
    assert_int_equal(rc, PUBNUB_ERR_SERIALIZATION);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* Grant path builder */
        cmocka_unit_test(test_grant_build_path_success),
        cmocka_unit_test(test_grant_build_path_null_request),
        cmocka_unit_test(test_grant_build_path_null_key),
        /* Grant body builder */
        cmocka_unit_test(test_grant_build_body_single_channel),
        cmocka_unit_test(test_grant_build_body_multiple_resource_types),
        cmocka_unit_test(test_grant_build_body_patterns),
        cmocka_unit_test(test_grant_build_body_with_authorized_uuid),
        cmocka_unit_test(test_grant_build_body_with_meta),
        cmocka_unit_test(test_grant_build_body_null_serial),
        cmocka_unit_test(test_grant_build_body_null_opts),
        cmocka_unit_test(test_grant_build_body_buffer_too_small),
        cmocka_unit_test(test_grant_build_body_category_only),
        cmocka_unit_test(test_grant_build_body_category_channels_only),
        cmocka_unit_test(test_grant_build_body_category_uuids_only),
        cmocka_unit_test(test_grant_build_body_category_with_resources_and_patterns),
        cmocka_unit_test(
            test_grant_build_body_resources_only_omits_patterns_and_categories),
        cmocka_unit_test(
            test_grant_build_body_patterns_only_omits_resources_and_categories),
        cmocka_unit_test(test_grant_build_body_resources_and_patterns_omits_categories),
        cmocka_unit_test(test_grant_build_body_non_get_category_bits_not_emitted),
        cmocka_unit_test(test_grant_build_body_category_buffer_boundary),
        cmocka_unit_test(test_grant_build_body_category_only_oom_every_index),
        cmocka_unit_test(test_grant_build_body_combined_oom_every_index),
        cmocka_unit_test(test_grant_build_body_category_set_failure_code_propagates),
        /* Revoke path builder */
        cmocka_unit_test(test_revoke_build_path_success),
        cmocka_unit_test(test_revoke_build_path_encodes_special_chars),
        cmocka_unit_test(test_revoke_build_path_null_token),
        cmocka_unit_test(test_revoke_build_path_null_subscribe_key),
        cmocka_unit_test(test_revoke_build_path_null_request),
        /* Response validator */
        cmocka_unit_test(test_validator_http_200),
        cmocka_unit_test(test_validator_http_201),
        cmocka_unit_test(test_validator_http_403),
        cmocka_unit_test(test_validator_http_400),
        cmocka_unit_test(test_validator_http_500),
        /* Response parser */
        cmocka_unit_test(test_parse_response_valid),
        cmocka_unit_test(test_parse_response_missing_data),
        cmocka_unit_test(test_parse_response_missing_token),
        cmocka_unit_test(test_parse_response_non_object_root),
        cmocka_unit_test(test_parse_response_null_out),
        cmocka_unit_test(test_parse_response_null_serial),
        cmocka_unit_test(test_parse_response_null_tree),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
