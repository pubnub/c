/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include <cmocka.h>

#include "pubnub/config.h"
#include "pn_logger_manager.h"

/* Capture helper — records last entry received. */
static const pubnub_log_entry_t* s_last_entry = NULL;
static uint64_t                  s_last_ts    = 0u;
static char                      s_last_ctx_buf[16];
static const char*               s_last_ctx = NULL;
static pubnub_log_level_t        s_last_min = PUBNUB_LOG_LEVEL_NONE;

static void capture_log(struct pubnub_logger_provider* self,
                        const pubnub_log_entry_t*      entry)
{
    (void)self;
    s_last_entry = entry;
    s_last_ts    = entry->timestamp_ms;
    if (NULL != entry->context_id) {
        size_t len = strlen(entry->context_id);
        if (len >= sizeof(s_last_ctx_buf)) {
            len = sizeof(s_last_ctx_buf) - 1;
        }
        memcpy(s_last_ctx_buf, entry->context_id, len);
        s_last_ctx_buf[len] = '\0';
        s_last_ctx          = s_last_ctx_buf;
    } else {
        s_last_ctx_buf[0] = '\0';
        s_last_ctx        = NULL;
    }
    s_last_min = entry->minimum_level;
}

static pubnub_logger_provider_t s_capture = {capture_log, NULL};

/* Reset all capture globals before each test that depends on them.
 * Prevents state left by earlier tests from affecting assertions. */
static int reset_capture_globals(void** state)
{
    (void)state;
    s_last_entry      = NULL;
    s_last_ts         = 0u;
    s_last_min        = PUBNUB_LOG_LEVEL_NONE;
    s_last_ctx        = NULL;
    s_last_ctx_buf[0] = '\0';
    return 0;
}

/* Call the manager log() vtable entry directly, bypassing the
 * PUBNUB_LOG_TEXT compile-time level guard (PUBNUB_CFG_LOG_LEVEL_COMPILED
 * is 0x00 in the embedded profile, which would silently drop all calls
 * through the macro and cause every dispatch assertion to fail). */
static void emit_direct(pubnub_logger_provider_t* prov,
                        pubnub_log_level_t        level,
                        const char*               msg)
{
    pubnub_log_entry_text_t entry_ = {0};
    entry_.base.type               = PUBNUB_LOG_ENTRY_TEXT;
    entry_.base.level              = level;
    entry_.base.file               = __FILE__;
    entry_.base.line               = __LINE__;
    entry_.message                 = msg;
    if (NULL != prov && NULL != prov->log) {
        prov->log(prov, (const pubnub_log_entry_t*)&entry_);
    }
}

static void emit_warning_direct(pubnub_logger_provider_t* prov, const char* msg)
{
    emit_direct(prov, PUBNUB_LOG_LEVEL_WARNING, msg);
}

/* Stub platform — returns fixed timestamp 42000. */
static uint64_t stub_monotonic_ms(struct pubnub_platform_provider* self)
{
    (void)self;
    return 42000u;
}

static uint64_t stub_wall_clock_ms(struct pubnub_platform_provider* self)
{
    (void)self;
    return 42000u;
}

static pubnub_platform_provider_t s_platform;

static void setup_platform(void** state)
{
    (void)state;
    memset(&s_platform, 0, sizeof(s_platform));
    s_platform.monotonic_ms  = stub_monotonic_ms;
    s_platform.wall_clock_ms = stub_wall_clock_ms;
}

static void mgr_wire_context_id_is_instance_based(void** state)
{
    (void)state;
    pn_logger_manager_t mux;
    pn_logger_manager_init(&mux);
    pn_logger_manager_wire(&mux, NULL);
    /* Address-based hash produces 8 hex chars and is non-zero
     * (the manager is a stack variable, never at address 0). */
    assert_int_equal((int)strlen(mux.context_id), 8);
    assert_string_not_equal(mux.context_id, "00000000");
}

static void mgr_log_stamps_context_id(void** state)
{
    (void)state;
    setup_platform(state);
    pn_logger_manager_t mux;
    pn_logger_manager_init(&mux);
    pn_logger_manager_wire(&mux, &s_platform);
    pn_logger_manager_add(&mux, &s_capture);

    emit_warning_direct(&mux.base, "test");

    assert_non_null(s_last_entry);
    assert_non_null(s_last_ctx);
    assert_int_equal((int)strlen(s_last_ctx), 8);
}

static void mgr_log_stamps_timestamp_from_platform(void** state)
{
    (void)state;
    setup_platform(state);
    pn_logger_manager_t mux;
    pn_logger_manager_init(&mux);
    pn_logger_manager_wire(&mux, &s_platform);
    pn_logger_manager_add(&mux, &s_capture);

    emit_warning_direct(&mux.base, "ts");

    assert_int_equal((int)s_last_ts, 42000);
}

static void mgr_log_stamps_zero_ts_without_platform(void** state)
{
    (void)state;
    pn_logger_manager_t mux;
    pn_logger_manager_init(&mux);
    pn_logger_manager_wire(&mux, NULL);
    pn_logger_manager_add(&mux, &s_capture);

    s_last_ts = 99u;
    emit_warning_direct(&mux.base, "no-ts");

    assert_int_equal((int)s_last_ts, 0);
}

static void mgr_set_level_updates_min_level_on_entries(void** state)
{
    (void)state;
    pn_logger_manager_t mux;
    pn_logger_manager_init(&mux);
    pn_logger_manager_wire(&mux, NULL);
    pn_logger_manager_add(&mux, &s_capture);
    mux.base.set_level(&mux.base, PUBNUB_LOG_LEVEL_WARNING);

    s_last_min = PUBNUB_LOG_LEVEL_NONE;
    emit_warning_direct(&mux.base, "w");

    assert_int_equal((int)s_last_min, (int)PUBNUB_LOG_LEVEL_WARNING);
}

static void mgr_add_beyond_capacity_returns_error(void** state)
{
    (void)state;
    pn_logger_manager_t mux;
    pn_logger_manager_init(&mux);
    pn_logger_manager_wire(&mux, NULL);

    int i;
    for (i = 0; i < PUBNUB_CFG_MAX_LOGGERS; ++i) {
        assert_int_equal((int)pn_logger_manager_add(&mux, &s_capture),
                         (int)PUBNUB_OK);
    }
    assert_int_equal((int)pn_logger_manager_add(&mux, &s_capture),
                     (int)PUBNUB_ERR_QUEUE_FULL);
}

static void mgr_set_level_filters_below_threshold(void** state)
{
    (void)state;
    pn_logger_manager_t mux;
    pn_logger_manager_init(&mux);
    pn_logger_manager_wire(&mux, NULL);
    pn_logger_manager_add(&mux, &s_capture);
    mux.base.set_level(&mux.base, PUBNUB_LOG_LEVEL_WARNING);

    /* DEBUG < WARNING: must be dropped */
    s_last_entry = NULL;
    emit_direct(&mux.base, PUBNUB_LOG_LEVEL_DEBUG, "below");
    assert_null(s_last_entry);

    /* WARNING >= WARNING: must pass */
    s_last_entry = NULL;
    emit_direct(&mux.base, PUBNUB_LOG_LEVEL_WARNING, "at-threshold");
    assert_non_null(s_last_entry);

    /* ERROR > WARNING: must pass */
    s_last_entry = NULL;
    emit_direct(&mux.base, PUBNUB_LOG_LEVEL_ERROR, "above");
    assert_non_null(s_last_entry);
}

/* Spy that records the last set_level call. */
static pubnub_log_level_t s_set_level_received = PUBNUB_LOG_LEVEL_NONE;

static void spy_set_level(struct pubnub_logger_provider* self, pubnub_log_level_t lvl)
{
    (void)self;
    s_set_level_received = lvl;
}

static pubnub_logger_provider_t s_spy = {NULL, spy_set_level};

static void mgr_add_syncs_min_level_to_new_child(void** state)
{
    (void)state;
    pn_logger_manager_t mux;
    pn_logger_manager_init(&mux);
    pn_logger_manager_wire(&mux, NULL);
    mux.base.set_level(&mux.base, PUBNUB_LOG_LEVEL_WARNING);

    s_set_level_received = PUBNUB_LOG_LEVEL_NONE;
    pn_logger_manager_add(&mux, &s_spy);
    assert_int_equal((int)s_set_level_received, (int)PUBNUB_LOG_LEVEL_WARNING);
}

static void test_log_value_factories(void** state)
{
    (void)state;

    /* null */
    pubnub_log_value_t v = pubnub_log_value_null();
    assert_int_equal(PUBNUB_LOG_VALUE_NULL, pubnub_log_value_type(&v));

    /* bool */
    v = pubnub_log_value_bool(1);
    assert_int_equal(PUBNUB_LOG_VALUE_BOOL, pubnub_log_value_type(&v));
    assert_int_equal(1, pubnub_log_value_get_bool(&v));

    /* number */
    v = pubnub_log_value_number((int64_t)42);
    assert_int_equal(PUBNUB_LOG_VALUE_NUMBER, pubnub_log_value_type(&v));
    assert_int_equal(42, (int)pubnub_log_value_get_number(&v));

    /* string (NUL-terminated) */
    v = pubnub_log_value_string("hello");
    assert_int_equal(PUBNUB_LOG_VALUE_STRING, pubnub_log_value_type(&v));
    size_t      len = 99;
    const char* ptr = pubnub_log_value_get_string(&v, &len);
    assert_non_null(ptr);
    assert_string_equal("hello", ptr);
    assert_int_equal(0, (int)len); /* len=0 signals NUL-terminated */

    /* string_n */
    v   = pubnub_log_value_string_n("world", 3);
    len = 99;
    ptr = pubnub_log_value_get_string(&v, &len);
    assert_non_null(ptr);
    assert_int_equal(3, (int)len);
}

static void test_log_value_inspection_null_safety(void** state)
{
    (void)state;
    assert_int_equal(PUBNUB_LOG_VALUE_NULL, (int)pubnub_log_value_type(NULL));
    assert_int_equal(0, pubnub_log_value_get_bool(NULL));
    assert_int_equal(0, (int)pubnub_log_value_get_number(NULL));
    assert_null(pubnub_log_value_get_string(NULL, NULL));
    assert_null(pubnub_log_value_first(NULL));
    assert_null(pubnub_log_value_key(NULL));
    assert_null(pubnub_log_value_next(NULL));
}

static void test_log_value_array_and_map(void** state)
{
    (void)state;

    /* array */
    pubnub_log_value_t arr = pubnub_log_value_array_init();
    assert_int_equal(PUBNUB_LOG_VALUE_ARRAY, pubnub_log_value_type(&arr));
    assert_null(pubnub_log_value_first(&arr));

    pubnub_log_value_t n1 = pubnub_log_value_number(10);
    pubnub_log_value_t n2 = pubnub_log_value_number(20);
    pubnub_log_value_array_append_node(&arr, &n1);
    pubnub_log_value_array_append_node(&arr, &n2);

    const pubnub_log_value_t* it = pubnub_log_value_first(&arr);
    assert_non_null(it);
    assert_int_equal(10, (int)pubnub_log_value_get_number(it));
    it = pubnub_log_value_next(it);
    assert_non_null(it);
    assert_int_equal(20, (int)pubnub_log_value_get_number(it));
    assert_null(pubnub_log_value_next(it));

    /* map */
    pubnub_log_value_t* map = pubnub_log_value_map_init();
    assert_null(map);

    pubnub_log_value_t v_name = pubnub_log_value_string("alice");
    pubnub_log_value_t e_name =
        (pubnub_log_value_t)PUBNUB_LOG_MAP_ENTRY("name", &v_name, NULL);
    pubnub_log_value_map_set_entry(&map, &e_name);

    assert_non_null(map);
    assert_string_equal("name", pubnub_log_value_key(map));
    assert_null(pubnub_log_value_next(map));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(mgr_wire_context_id_is_instance_based),
        cmocka_unit_test_setup(mgr_log_stamps_context_id, reset_capture_globals),
        cmocka_unit_test_setup(mgr_log_stamps_timestamp_from_platform,
                               reset_capture_globals),
        cmocka_unit_test_setup(mgr_log_stamps_zero_ts_without_platform,
                               reset_capture_globals),
        cmocka_unit_test_setup(mgr_set_level_updates_min_level_on_entries,
                               reset_capture_globals),
        cmocka_unit_test(mgr_add_beyond_capacity_returns_error),
        cmocka_unit_test(mgr_set_level_filters_below_threshold),
        cmocka_unit_test(mgr_add_syncs_min_level_to_new_child),
        cmocka_unit_test(test_log_value_factories),
        cmocka_unit_test(test_log_value_inspection_null_safety),
        cmocka_unit_test(test_log_value_array_and_map),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
