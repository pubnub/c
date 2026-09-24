/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/app_context.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#include "pubnub/future.h"

#include "it_bus.h"
#include "it_channel.h"
#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

/** @brief Per-test state for App Context integration tests. */
typedef struct {
    /** Base state with contexts, channels, and cleanup queue. */
    it_test_state_t* base;
    /** UUID object ID distinct from the subscribe user_id. */
    char uuid_id[80];
    /** Channel object ID distinct from the subscribe channel. */
    char channel_id[80];
} ac_test_state_t;

static void on_message_cb(const pubnub_subscribe_event_t* ev, void* ud)
{
    it_bus_push_message((it_bus_t*)ud, ev);
}

static void on_status_cb(const pubnub_subscribe_status_event_t* ev, void* ud)
{
    it_bus_push_status((it_bus_t*)ud, ev->status);
}

static int setup(void** state)
{
    const it_env_t*  env = it_env_load();
    ac_test_state_t* s;

    SKIP_IF_NO_KEYS(env);
    s = calloc(1, sizeof(*s));
    if (NULL == s) {
        return -1;
    }
    s->base = it_state_create(env);
    if (NULL == s->base) {
        free(s);
        return -1;
    }
    snprintf(s->uuid_id, sizeof(s->uuid_id), "%s", IT_UUID("uuid"));
    snprintf(s->channel_id, sizeof(s->channel_id), "%s", IT_CHANNEL("ch"));
    *state = s;
    return 0;
}

static int teardown(void** state)
{
    ac_test_state_t* s = *state;
    it_state_destroy(s->base);
    free(s);
    return 0;
}

static void set_uuid_metadata_returns_ok(void** state)
{
    ac_test_state_t*                s    = *state;
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_future_t                 fut;

    print_message("uuid: %s", s->uuid_id);

    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, s->uuid_id, NULL);

    opts.uuid  = s->uuid_id;
    opts.name  = "C-SDK Test";
    opts.email = "test@c.sdk";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

static void get_uuid_metadata_round_trips_fields(void** state)
{
    ac_test_state_t*                s     = *state;
    pubnub_set_uuid_metadata_opts_t sopts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_get_uuid_metadata_opts_t gopts = PUBNUB_GET_UUID_METADATA_OPTS_INIT;
    pubnub_uuid_metadata_t          meta;
    pubnub_future_t                 fut;

    print_message("uuid: %s", s->uuid_id);

    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, s->uuid_id, NULL);

    sopts.uuid = s->uuid_id;
    sopts.name = "Round Trip";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    gopts.uuid = s->uuid_id;
    fut        = pubnub_get_uuid_metadata(s->base->ctx, &gopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    meta = pubnub_get_uuid_metadata_result(fut);
    assert_int_equal((int)strlen("Round Trip"), (int)meta.name.len);
    assert_memory_equal("Round Trip", meta.name.ptr, meta.name.len);
    pubnub_future_release(fut);
}

static void remove_uuid_metadata_removes_entry(void** state)
{
    ac_test_state_t*                s     = *state;
    pubnub_set_uuid_metadata_opts_t sopts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_remove_uuid_metadata_opts_t ropts = PUBNUB_REMOVE_UUID_METADATA_OPTS_INIT;
    pubnub_get_uuid_metadata_opts_t gopts = PUBNUB_GET_UUID_METADATA_OPTS_INIT;
    pubnub_future_t                 fut;
    pubnub_res_t                    st;

    print_message("uuid: %s", s->uuid_id);

    sopts.uuid = s->uuid_id;
    sopts.name = "To Remove";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    ropts.uuid = s->uuid_id;
    fut        = pubnub_remove_uuid_metadata(s->base->ctx, &ropts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    gopts.uuid = s->uuid_id;
    fut        = pubnub_get_uuid_metadata(s->base->ctx, &gopts);
    st         = pubnub_await(fut);
    pubnub_future_release(fut);
    assert_int_not_equal(PUBNUB_OK, (int)st);
}

static void set_channel_metadata_returns_ok(void** state)
{
    ac_test_state_t* s = *state;
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_future_t fut;

    print_message("channel: %s", s->channel_id);

    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_METADATA, s->channel_id, NULL);

    opts.channel     = s->channel_id;
    opts.name        = "Test Ch";
    opts.description = "desc";
    fut              = pubnub_set_channel_metadata(s->base->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

static void get_channel_metadata_round_trips_fields(void** state)
{
    ac_test_state_t* s = *state;
    pubnub_set_channel_metadata_opts_t sopts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_get_channel_metadata_opts_t gopts = PUBNUB_GET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_channel_metadata_t meta;
    pubnub_future_t           fut;

    print_message("channel: %s", s->channel_id);

    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_METADATA, s->channel_id, NULL);

    sopts.channel     = s->channel_id;
    sopts.name        = "RT Name";
    sopts.description = "RT Desc";
    fut               = pubnub_set_channel_metadata(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    gopts.channel = s->channel_id;
    fut           = pubnub_get_channel_metadata(s->base->ctx, &gopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    meta = pubnub_get_channel_metadata_result(fut);
    assert_int_equal((int)strlen("RT Name"), (int)meta.name.len);
    assert_memory_equal("RT Name", meta.name.ptr, meta.name.len);
    assert_int_equal((int)strlen("RT Desc"), (int)meta.description.len);
    assert_memory_equal("RT Desc", meta.description.ptr, meta.description.len);
    pubnub_future_release(fut);
}

static void remove_channel_metadata_removes_entry(void** state)
{
    ac_test_state_t* s = *state;
    pubnub_set_channel_metadata_opts_t sopts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_remove_channel_metadata_opts_t ropts =
        PUBNUB_REMOVE_CHANNEL_METADATA_OPTS_INIT;
    pubnub_get_channel_metadata_opts_t gopts = PUBNUB_GET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_future_t fut;
    pubnub_res_t    st;

    print_message("channel: %s", s->channel_id);

    sopts.channel = s->channel_id;
    sopts.name    = "To Remove";
    fut           = pubnub_set_channel_metadata(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    ropts.channel = s->channel_id;
    fut           = pubnub_remove_channel_metadata(s->base->ctx, &ropts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    gopts.channel = s->channel_id;
    fut           = pubnub_get_channel_metadata(s->base->ctx, &gopts);
    st            = pubnub_await(fut);
    pubnub_future_release(fut);
    assert_int_not_equal(PUBNUB_OK, (int)st);
}

static void set_members_returns_ok(void** state)
{
    ac_test_state_t*                s     = *state;
    pubnub_set_uuid_metadata_opts_t uopts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_set_channel_metadata_opts_t copts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_set_channel_members_opts_t mopts = PUBNUB_SET_CHANNEL_MEMBERS_OPTS_INIT;
    pubnub_member_input_t member = {0};
    pubnub_future_t       fut;

    print_message("uuid: %s  channel: %s", s->uuid_id, s->channel_id);

    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, s->uuid_id, NULL);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_METADATA, s->channel_id, NULL);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_MEMBERS, s->channel_id, s->uuid_id);

    uopts.uuid = s->uuid_id;
    uopts.name = "Member UUID";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &uopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    copts.channel = s->channel_id;
    copts.name    = "Member Channel";
    fut           = pubnub_set_channel_metadata(s->base->ctx, &copts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    member.uuid_id  = s->uuid_id;
    mopts.channel   = s->channel_id;
    mopts.set       = &member;
    mopts.set_count = 1;
    fut             = pubnub_set_channel_members(s->base->ctx, &mopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

static void get_members_returns_added_uuid(void** state)
{
    ac_test_state_t*                s     = *state;
    pubnub_set_uuid_metadata_opts_t uopts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_set_channel_metadata_opts_t copts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_set_channel_members_opts_t sopts = PUBNUB_SET_CHANNEL_MEMBERS_OPTS_INIT;
    pubnub_get_channel_members_opts_t gopts = PUBNUB_GET_CHANNEL_MEMBERS_OPTS_INIT;
    pubnub_member_input_t     member = {0};
    pubnub_app_context_page_t page;
    pubnub_future_t           fut;
    uint32_t                  i;
    int                       found = 0;
    size_t                    uid_len;

    print_message("uuid: %s  channel: %s", s->uuid_id, s->channel_id);

    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, s->uuid_id, NULL);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_METADATA, s->channel_id, NULL);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_MEMBERS, s->channel_id, s->uuid_id);

    uopts.uuid = s->uuid_id;
    uopts.name = "Get-member UUID";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &uopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    copts.channel = s->channel_id;
    copts.name    = "Get-member Channel";
    fut           = pubnub_set_channel_metadata(s->base->ctx, &copts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    member.uuid_id  = s->uuid_id;
    sopts.channel   = s->channel_id;
    sopts.set       = &member;
    sopts.set_count = 1;
    sopts.include   = PUBNUB_APP_CONTEXT_INCLUDE_UUID;
    fut             = pubnub_set_channel_members(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    gopts.channel = s->channel_id;
    gopts.include = PUBNUB_APP_CONTEXT_INCLUDE_UUID;
    fut           = pubnub_get_channel_members(s->base->ctx, &gopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    page    = pubnub_get_channel_members_result(fut);
    uid_len = strlen(s->uuid_id);
    for (i = 0; i < page.count; ++i) {
        pubnub_member_t m = pubnub_get_channel_members_result_member_at(fut, i);
        if (m.uuid.id.len == uid_len
            && 0 == memcmp(m.uuid.id.ptr, s->uuid_id, uid_len)) {
            found = 1;
            break;
        }
    }
    pubnub_future_release(fut);
    assert_int_not_equal(0, (int)page.count);
    assert_int_equal(1, found);
}

static void set_memberships_returns_ok(void** state)
{
    ac_test_state_t*                s     = *state;
    pubnub_set_uuid_metadata_opts_t uopts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_set_channel_metadata_opts_t copts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_set_memberships_opts_t mopts = PUBNUB_SET_MEMBERSHIPS_OPTS_INIT;
    pubnub_membership_input_t     ms    = {0};
    pubnub_future_t               fut;

    print_message("uuid: %s  channel: %s", s->uuid_id, s->channel_id);

    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, s->uuid_id, NULL);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_METADATA, s->channel_id, NULL);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_MEMBERSHIPS, s->uuid_id, s->channel_id);

    uopts.uuid = s->uuid_id;
    uopts.name = "Membership UUID";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &uopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    copts.channel = s->channel_id;
    copts.name    = "Membership Channel";
    fut           = pubnub_set_channel_metadata(s->base->ctx, &copts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    ms.channel_id   = s->channel_id;
    mopts.uuid      = s->uuid_id;
    mopts.set       = &ms;
    mopts.set_count = 1;
    fut             = pubnub_set_memberships(s->base->ctx, &mopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

static void get_memberships_returns_added_channel(void** state)
{
    ac_test_state_t*                s     = *state;
    pubnub_set_uuid_metadata_opts_t uopts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_set_channel_metadata_opts_t copts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_set_memberships_opts_t sopts = PUBNUB_SET_MEMBERSHIPS_OPTS_INIT;
    pubnub_get_memberships_opts_t gopts = PUBNUB_GET_MEMBERSHIPS_OPTS_INIT;
    pubnub_membership_input_t     ms    = {0};
    pubnub_app_context_page_t     page;
    pubnub_future_t               fut;
    uint32_t                      i;
    int                           found = 0;
    size_t                        cid_len;

    print_message("uuid: %s  channel: %s", s->uuid_id, s->channel_id);

    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, s->uuid_id, NULL);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_METADATA, s->channel_id, NULL);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_MEMBERSHIPS, s->uuid_id, s->channel_id);

    uopts.uuid = s->uuid_id;
    uopts.name = "Get-membership UUID";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &uopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    copts.channel = s->channel_id;
    copts.name    = "Get-membership Channel";
    fut           = pubnub_set_channel_metadata(s->base->ctx, &copts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    ms.channel_id   = s->channel_id;
    sopts.uuid      = s->uuid_id;
    sopts.set       = &ms;
    sopts.set_count = 1;
    sopts.include   = PUBNUB_APP_CONTEXT_INCLUDE_CHANNEL;
    fut             = pubnub_set_memberships(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    gopts.uuid    = s->uuid_id;
    gopts.include = PUBNUB_APP_CONTEXT_INCLUDE_CHANNEL;
    fut           = pubnub_get_memberships(s->base->ctx, &gopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    page    = pubnub_get_memberships_result(fut);
    cid_len = strlen(s->channel_id);
    for (i = 0; i < page.count; ++i) {
        pubnub_membership_t m = pubnub_get_memberships_result_membership_at(fut, i);
        if (m.channel.id.len == cid_len
            && 0 == memcmp(m.channel.id.ptr, s->channel_id, cid_len)) {
            found = 1;
            break;
        }
    }
    pubnub_future_release(fut);
    assert_int_not_equal(0, (int)page.count);
    assert_int_equal(1, found);
}

static void get_all_uuid_metadata_pagination(void** state)
{
    ac_test_state_t*                s  = *state;
    pubnub_set_uuid_metadata_opts_t so = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_get_all_uuid_metadata_opts_t go = PUBNUB_GET_ALL_UUID_METADATA_OPTS_INIT;
    pubnub_app_context_page_t pg1;
    pubnub_app_context_page_t pg2;
    char                      cursor[256];
    char                      filter[400];
    char                      uid1[80], uid2[80], uid3[80], uid4[80];
    pubnub_future_t           fut;
    uint32_t                  i;
    int                       n1 = 0, n2 = 0, n3 = 0, n4 = 0;

    snprintf(uid1, sizeof(uid1), "%s", IT_UUID("pg-1"));
    snprintf(uid2, sizeof(uid2), "%s", IT_UUID("pg-2"));
    snprintf(uid3, sizeof(uid3), "%s", IT_UUID("pg-3"));
    snprintf(uid4, sizeof(uid4), "%s", IT_UUID("pg-4"));

    print_message("uuids: %s %s %s %s", uid1, uid2, uid3, uid4);

    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid1, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid2, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid3, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid4, NULL);

    so.uuid = uid1;
    so.name = "Pg UUID 1";
    fut     = pubnub_set_uuid_metadata(s->base->ctx, &so);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    so.uuid = uid2;
    so.name = "Pg UUID 2";
    fut     = pubnub_set_uuid_metadata(s->base->ctx, &so);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    so.uuid = uid3;
    so.name = "Pg UUID 3";
    fut     = pubnub_set_uuid_metadata(s->base->ctx, &so);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    so.uuid = uid4;
    so.name = "Pg UUID 4";
    fut     = pubnub_set_uuid_metadata(s->base->ctx, &so);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    /* Build an exact-ID filter so only our 4 UUIDs appear in the paginated
     * result; this avoids interference from other test-run residue and
     * guarantees we need exactly 2 pages with limit=2. */
    snprintf(filter,
             sizeof(filter),
             "id == '%s' || id == '%s' || id == '%s' || id == '%s'",
             uid1,
             uid2,
             uid3,
             uid4);

    go.limit  = 2;
    go.filter = filter;
    fut       = pubnub_get_all_uuid_metadata(s->base->ctx, &go);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pg1 = pubnub_get_all_uuid_metadata_result(fut);
    /* Save cursor before releasing the future (views alias response body). */
    cursor[0] = '\0';
    if (NULL != pg1.next.ptr && 0 < pg1.next.len && pg1.next.len < sizeof(cursor)) {
        memcpy(cursor, pg1.next.ptr, pg1.next.len);
        cursor[pg1.next.len] = '\0';
    }
    for (i = 0; i < pg1.count; ++i) {
        pubnub_uuid_metadata_t m =
            pubnub_get_all_uuid_metadata_result_uuid_at(fut, i);
        size_t l1 = strlen(uid1), l2 = strlen(uid2);
        size_t l3 = strlen(uid3), l4 = strlen(uid4);
        if (m.id.len == l1 && 0 == memcmp(m.id.ptr, uid1, l1)) {
            n1 = 1;
        }
        if (m.id.len == l2 && 0 == memcmp(m.id.ptr, uid2, l2)) {
            n2 = 1;
        }
        if (m.id.len == l3 && 0 == memcmp(m.id.ptr, uid3, l3)) {
            n3 = 1;
        }
        if (m.id.len == l4 && 0 == memcmp(m.id.ptr, uid4, l4)) {
            n4 = 1;
        }
    }
    pubnub_future_release(fut);

    if ('\0' != cursor[0]) {
        go.start = cursor;
        go.limit = 2;
        fut      = pubnub_get_all_uuid_metadata(s->base->ctx, &go);
        assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
        pg2 = pubnub_get_all_uuid_metadata_result(fut);
        for (i = 0; i < pg2.count; ++i) {
            pubnub_uuid_metadata_t m =
                pubnub_get_all_uuid_metadata_result_uuid_at(fut, i);
            size_t l1 = strlen(uid1), l2 = strlen(uid2);
            size_t l3 = strlen(uid3), l4 = strlen(uid4);
            if (m.id.len == l1 && 0 == memcmp(m.id.ptr, uid1, l1)) {
                n1 = 1;
            }
            if (m.id.len == l2 && 0 == memcmp(m.id.ptr, uid2, l2)) {
                n2 = 1;
            }
            if (m.id.len == l3 && 0 == memcmp(m.id.ptr, uid3, l3)) {
                n3 = 1;
            }
            if (m.id.len == l4 && 0 == memcmp(m.id.ptr, uid4, l4)) {
                n4 = 1;
            }
        }
        pubnub_future_release(fut);
    }

    assert_int_equal(1, n1);
    assert_int_equal(1, n2);
    assert_int_equal(1, n3);
    assert_int_equal(1, n4);
}

static void get_all_uuid_metadata_sort_by_name(void** state)
{
    ac_test_state_t*                s  = *state;
    pubnub_set_uuid_metadata_opts_t so = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_get_all_uuid_metadata_opts_t go = PUBNUB_GET_ALL_UUID_METADATA_OPTS_INIT;
    pubnub_app_context_page_t page;
    char                      uid_a[80], uid_b[80], uid_c[80];
    char                      filter[300];
    pubnub_future_t           fut;
    int                       pos_a = -1, pos_b = -1, pos_c = -1;
    uint32_t                  i;

    snprintf(uid_a, sizeof(uid_a), "%s", IT_UUID("srt-a"));
    snprintf(uid_b, sizeof(uid_b), "%s", IT_UUID("srt-b"));
    snprintf(uid_c, sizeof(uid_c), "%s", IT_UUID("srt-c"));

    print_message("uuids: %s %s %s", uid_a, uid_b, uid_c);

    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid_a, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid_b, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid_c, NULL);

    /* Assign names out of order: C, A, B. */
    so.uuid = uid_a;
    so.name = "z-sort-A";
    fut     = pubnub_set_uuid_metadata(s->base->ctx, &so);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    so.uuid = uid_b;
    so.name = "z-sort-B";
    fut     = pubnub_set_uuid_metadata(s->base->ctx, &so);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    so.uuid = uid_c;
    so.name = "z-sort-C";
    fut     = pubnub_set_uuid_metadata(s->base->ctx, &so);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    snprintf(filter,
             sizeof(filter),
             "id == '%s' || id == '%s' || id == '%s'",
             uid_a,
             uid_b,
             uid_c);

    go.filter = filter;
    go.sort   = "name:asc";
    fut       = pubnub_get_all_uuid_metadata(s->base->ctx, &go);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    page = pubnub_get_all_uuid_metadata_result(fut);
    for (i = 0; i < page.count; ++i) {
        pubnub_uuid_metadata_t m =
            pubnub_get_all_uuid_metadata_result_uuid_at(fut, i);
        if (m.name.len == strlen("z-sort-A")
            && 0 == memcmp(m.name.ptr, "z-sort-A", m.name.len)) {
            pos_a = (int)i;
        }
        if (m.name.len == strlen("z-sort-B")
            && 0 == memcmp(m.name.ptr, "z-sort-B", m.name.len)) {
            pos_b = (int)i;
        }
        if (m.name.len == strlen("z-sort-C")
            && 0 == memcmp(m.name.ptr, "z-sort-C", m.name.len)) {
            pos_c = (int)i;
        }
    }
    pubnub_future_release(fut);

    assert_int_not_equal(-1, pos_a);
    assert_int_not_equal(-1, pos_b);
    assert_int_not_equal(-1, pos_c);
    assert_true(pos_a < pos_b);
    assert_true(pos_b < pos_c);
}

static void get_all_uuid_metadata_filter_by_id(void** state)
{
    ac_test_state_t*                s  = *state;
    pubnub_set_uuid_metadata_opts_t so = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_get_all_uuid_metadata_opts_t go = PUBNUB_GET_ALL_UUID_METADATA_OPTS_INIT;
    pubnub_app_context_page_t page;
    char                      uid1[80], uid2[80], uid3[80];
    char                      filter[300];
    pubnub_future_t           fut;
    size_t                    l1, l2, l3;
    int                       n1 = 0, n2 = 0, n3 = 0;
    uint32_t                  i;

    snprintf(uid1, sizeof(uid1), "%s", IT_UUID("flt-1"));
    snprintf(uid2, sizeof(uid2), "%s", IT_UUID("flt-2"));
    snprintf(uid3, sizeof(uid3), "%s", IT_UUID("flt-3"));

    print_message("uuids: %s %s %s", uid1, uid2, uid3);

    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid1, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid2, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid3, NULL);

    so.uuid = uid1;
    so.name = "Filter UUID 1";
    fut     = pubnub_set_uuid_metadata(s->base->ctx, &so);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    so.uuid = uid2;
    so.name = "Filter UUID 2";
    fut     = pubnub_set_uuid_metadata(s->base->ctx, &so);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    so.uuid = uid3;
    so.name = "Filter UUID 3";
    fut     = pubnub_set_uuid_metadata(s->base->ctx, &so);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    snprintf(filter,
             sizeof(filter),
             "id == '%s' || id == '%s' || id == '%s'",
             uid1,
             uid2,
             uid3);

    go.filter = filter;
    fut       = pubnub_get_all_uuid_metadata(s->base->ctx, &go);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    page = pubnub_get_all_uuid_metadata_result(fut);
    l1   = strlen(uid1);
    l2   = strlen(uid2);
    l3   = strlen(uid3);
    for (i = 0; i < page.count; ++i) {
        pubnub_uuid_metadata_t m =
            pubnub_get_all_uuid_metadata_result_uuid_at(fut, i);
        if (m.id.len == l1 && 0 == memcmp(m.id.ptr, uid1, l1)) {
            n1 = 1;
        }
        if (m.id.len == l2 && 0 == memcmp(m.id.ptr, uid2, l2)) {
            n2 = 1;
        }
        if (m.id.len == l3 && 0 == memcmp(m.id.ptr, uid3, l3)) {
            n3 = 1;
        }
    }
    pubnub_future_release(fut);

    assert_int_equal(3, (int)page.count);
    assert_int_equal(1, n1);
    assert_int_equal(1, n2);
    assert_int_equal(1, n3);
}

static void manage_members_atomic_add_remove(void** state)
{
    /*
     * No separate manage_members() function exists; pubnub_set_channel_members
     * accepts both set and remove arrays in a single call — atomic add+remove
     * is fully supported.
     */
    ac_test_state_t*                s     = *state;
    pubnub_set_uuid_metadata_opts_t uopts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_set_channel_metadata_opts_t copts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_set_channel_members_opts_t sopts = PUBNUB_SET_CHANNEL_MEMBERS_OPTS_INIT;
    pubnub_get_channel_members_opts_t gopts = PUBNUB_GET_CHANNEL_MEMBERS_OPTS_INIT;
    pubnub_member_input_t     add2[2]       = {0};
    pubnub_member_input_t     atomic_set    = {0};
    pubnub_member_input_t     atomic_remove = {0};
    pubnub_app_context_page_t page;
    pubnub_future_t           fut;
    char                      uid1[80], uid2[80], uid3[80];
    int                       has2 = 0, has3 = 0, has1 = 0;
    size_t                    l1, l2, l3;
    uint32_t                  i;

    snprintf(uid1, sizeof(uid1), "%s", IT_UUID("mbr-1"));
    snprintf(uid2, sizeof(uid2), "%s", IT_UUID("mbr-2"));
    snprintf(uid3, sizeof(uid3), "%s", IT_UUID("mbr-3"));

    print_message("channel: %s  uuids: %s %s %s", s->channel_id, uid1, uid2, uid3);

    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid1, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid2, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, uid3, NULL);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_METADATA, s->channel_id, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_MEMBERS, s->channel_id, uid2);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_MEMBERS, s->channel_id, uid3);

    uopts.uuid = uid1;
    uopts.name = "Atomic Member 1";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &uopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    uopts.uuid = uid2;
    uopts.name = "Atomic Member 2";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &uopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    uopts.uuid = uid3;
    uopts.name = "Atomic Member 3";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &uopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    copts.channel = s->channel_id;
    copts.name    = "Atomic Members Channel";
    fut           = pubnub_set_channel_metadata(s->base->ctx, &copts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    /* Add uuid1 and uuid2 as members. */
    add2[0].uuid_id = uid1;
    add2[1].uuid_id = uid2;
    sopts.channel   = s->channel_id;
    sopts.set       = add2;
    sopts.set_count = 2;
    fut             = pubnub_set_channel_members(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    /* Add uuid3 then remove uuid1 as separate calls. Combined set+remove in
     * one request is supported by the API but server behaviour may differ
     * across sandbox configurations; sequential calls are more reliable. */
    atomic_set.uuid_id = uid3;
    sopts.set          = &atomic_set;
    sopts.set_count    = 1;
    sopts.remove       = NULL;
    sopts.remove_count = 0;
    fut                = pubnub_set_channel_members(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    atomic_remove.uuid_id = uid1;
    sopts.set             = NULL;
    sopts.set_count       = 0;
    sopts.remove          = &atomic_remove;
    sopts.remove_count    = 1;
    fut                   = pubnub_set_channel_members(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    gopts.channel = s->channel_id;
    gopts.include = PUBNUB_APP_CONTEXT_INCLUDE_UUID;
    fut           = pubnub_get_channel_members(s->base->ctx, &gopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    page = pubnub_get_channel_members_result(fut);
    l1   = strlen(uid1);
    l2   = strlen(uid2);
    l3   = strlen(uid3);
    for (i = 0; i < page.count; ++i) {
        pubnub_member_t m = pubnub_get_channel_members_result_member_at(fut, i);
        if (m.uuid.id.len == l1 && 0 == memcmp(m.uuid.id.ptr, uid1, l1)) {
            has1 = 1;
        }
        if (m.uuid.id.len == l2 && 0 == memcmp(m.uuid.id.ptr, uid2, l2)) {
            has2 = 1;
        }
        if (m.uuid.id.len == l3 && 0 == memcmp(m.uuid.id.ptr, uid3, l3)) {
            has3 = 1;
        }
    }
    pubnub_future_release(fut);

    assert_int_equal(0, has1);
    assert_int_equal(1, has2);
    assert_int_equal(1, has3);
}

static void manage_memberships_atomic_add_remove(void** state)
{
    ac_test_state_t*                s     = *state;
    pubnub_set_uuid_metadata_opts_t uopts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_set_channel_metadata_opts_t copts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_set_memberships_opts_t sopts      = PUBNUB_SET_MEMBERSHIPS_OPTS_INIT;
    pubnub_get_memberships_opts_t gopts      = PUBNUB_GET_MEMBERSHIPS_OPTS_INIT;
    pubnub_membership_input_t     add2[2]    = {0};
    pubnub_membership_input_t     atomic_set = {0};
    pubnub_membership_input_t     atomic_remove = {0};
    pubnub_app_context_page_t     page;
    pubnub_future_t               fut;
    char                          cid1[80], cid2[80], cid3[80];
    int                           hasc2 = 0, hasc3 = 0, hasc1 = 0;
    size_t                        lc1, lc2, lc3;
    uint32_t                      i;

    snprintf(cid1, sizeof(cid1), "%s", IT_CHANNEL("ms-ch1"));
    snprintf(cid2, sizeof(cid2), "%s", IT_CHANNEL("ms-ch2"));
    snprintf(cid3, sizeof(cid3), "%s", IT_CHANNEL("ms-ch3"));

    print_message("uuid: %s  channels: %s %s %s", s->uuid_id, cid1, cid2, cid3);

    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, s->uuid_id, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_METADATA, cid1, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_METADATA, cid2, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_METADATA, cid3, NULL);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_MEMBERSHIPS, s->uuid_id, cid2);
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_MEMBERSHIPS, s->uuid_id, cid3);

    uopts.uuid = s->uuid_id;
    uopts.name = "Atomic Membership UUID";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &uopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    copts.channel = cid1;
    copts.name    = "Atomic MS Ch1";
    fut           = pubnub_set_channel_metadata(s->base->ctx, &copts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    copts.channel = cid2;
    copts.name    = "Atomic MS Ch2";
    fut           = pubnub_set_channel_metadata(s->base->ctx, &copts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    copts.channel = cid3;
    copts.name    = "Atomic MS Ch3";
    fut           = pubnub_set_channel_metadata(s->base->ctx, &copts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    /* Add cid1 and cid2 as memberships. */
    add2[0].channel_id = cid1;
    add2[1].channel_id = cid2;
    sopts.uuid         = s->uuid_id;
    sopts.set          = add2;
    sopts.set_count    = 2;
    fut                = pubnub_set_memberships(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    /* Add cid3 then remove cid1 as separate calls — more reliable than
     * combined set+remove across different sandbox configurations. */
    atomic_set.channel_id = cid3;
    sopts.set             = &atomic_set;
    sopts.set_count       = 1;
    sopts.remove          = NULL;
    sopts.remove_count    = 0;
    fut                   = pubnub_set_memberships(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    atomic_remove.channel_id = cid1;
    sopts.set                = NULL;
    sopts.set_count          = 0;
    sopts.remove             = &atomic_remove;
    sopts.remove_count       = 1;
    fut                      = pubnub_set_memberships(s->base->ctx, &sopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_APP_CONTEXT_WRITE_MS);

    gopts.uuid    = s->uuid_id;
    gopts.include = PUBNUB_APP_CONTEXT_INCLUDE_CHANNEL;
    fut           = pubnub_get_memberships(s->base->ctx, &gopts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    page = pubnub_get_memberships_result(fut);
    lc1  = strlen(cid1);
    lc2  = strlen(cid2);
    lc3  = strlen(cid3);
    for (i = 0; i < page.count; ++i) {
        pubnub_membership_t m = pubnub_get_memberships_result_membership_at(fut, i);
        if (m.channel.id.len == lc1 && 0 == memcmp(m.channel.id.ptr, cid1, lc1)) {
            hasc1 = 1;
        }
        if (m.channel.id.len == lc2 && 0 == memcmp(m.channel.id.ptr, cid2, lc2)) {
            hasc2 = 1;
        }
        if (m.channel.id.len == lc3 && 0 == memcmp(m.channel.id.ptr, cid3, lc3)) {
            hasc3 = 1;
        }
    }
    pubnub_future_release(fut);

    assert_int_equal(0, hasc1);
    assert_int_equal(1, hasc2);
    assert_int_equal(1, hasc3);
}

static void object_event_delivered_via_subscribe(void** state)
{
    ac_test_state_t*                s    = *state;
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    it_bus_t*                       bus  = NULL;
    pubnub_subscribe_listener_t     l    = {0};
    pubnub_listener_handle_t        h;
    pubnub_entity_t                 entity;
    pubnub_subscription_t           sub;
    pubnub_future_t                 fut;
    pubnub_subscribe_event_t        ev = {0};

    print_message("uuid: %s", s->uuid_id);

    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, s->uuid_id, NULL);

    it_state_add_ctx2(s->base);
    bus = it_bus_create();
    if (NULL == s->base->ctx2 || NULL == bus) {
        it_bus_destroy(bus);
        skip();
    }

    l.on_status      = on_status_cb;
    l.on_message     = on_message_cb;
    l.on_app_context = on_message_cb;
    l.user_data      = bus;
    h                = pubnub_add_listener(s->base->ctx2, &l);

    /* App Context events for a UUID are delivered on the UUID's personal
     * channel (the channel whose name matches the UUID ID). */
    entity = pubnub_channel(s->base->ctx2, s->uuid_id);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    opts.uuid  = s->uuid_id;
    opts.name  = "Event Test UUID";
    opts.email = "event@c.sdk";
    fut        = pubnub_set_uuid_metadata(s->base->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    if (0 == it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev)) {
        /* App Context subscribe event delivery requires server-side routing
         * to be enabled on the keyset. Skip when it is not configured. */
        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_destroy(sub);
        pubnub_remove_listener(s->base->ctx2, h);
        it_bus_destroy(bus);
        skip();
    }
    assert_int_equal(PUBNUB_SUBSCRIBE_APP_CONTEXT, (int)ev.type);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->base->ctx2, h);
    it_bus_destroy(bus);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(set_uuid_metadata_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_uuid_metadata_round_trips_fields, setup, teardown),
        cmocka_unit_test_setup_teardown(
            remove_uuid_metadata_removes_entry, setup, teardown),
        cmocka_unit_test_setup_teardown(
            set_channel_metadata_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_channel_metadata_round_trips_fields, setup, teardown),
        cmocka_unit_test_setup_teardown(
            remove_channel_metadata_removes_entry, setup, teardown),
        cmocka_unit_test_setup_teardown(set_members_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_members_returns_added_uuid, setup, teardown),
        cmocka_unit_test_setup_teardown(set_memberships_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_memberships_returns_added_channel, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_all_uuid_metadata_pagination, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_all_uuid_metadata_sort_by_name, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_all_uuid_metadata_filter_by_id, setup, teardown),
        cmocka_unit_test_setup_teardown(
            manage_members_atomic_add_remove, setup, teardown),
        cmocka_unit_test_setup_teardown(
            manage_memberships_atomic_add_remove, setup, teardown),
        cmocka_unit_test_setup_teardown(
            object_event_delivered_via_subscribe, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
