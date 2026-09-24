/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file logger_stdout_units.c
 * @brief Unit tests for pubnub_logger_stdout_t.
 *
 * Tests verify init, vtable wiring, that log() does not crash for all
 * entry types, and — on POSIX hosts — that a full ERROR entry is emitted
 * to a single, correctly-ordered, newline-terminated stream (regression
 * guard against the split stdout/stderr defect).
 */

/* dup/dup2/fileno require POSIX visibility under strict -std=c99/c11. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
/* NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp,readability-identifier-naming) */
#define _POSIX_C_SOURCE 200112L
#endif

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "pubnub/config.h"
#include "logger_stdout_internal.h"

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#define PN_HAVE_STDOUT_CAPTURE 1
#include <unistd.h>
#else
#define PN_HAVE_STDOUT_CAPTURE 0
#endif

static void stdout_init_sets_vtable(void** state)
{
    (void)state;
    pubnub_logger_stdout_t logger;
    pubnub_logger_stdout_init(&logger);

    assert_non_null(logger.base.log);
    assert_non_null(logger.base.set_level);
}

static void stdout_init_null_is_safe(void** state)
{
    (void)state;
    pubnub_logger_stdout_init(NULL); /* must not crash */
}

static void stdout_log_text_does_not_crash(void** state)
{
    (void)state;
    pubnub_logger_stdout_t logger;
    pubnub_logger_stdout_init(&logger);

    pubnub_log_entry_text_t entry = {0};
    entry.base.type               = PUBNUB_LOG_ENTRY_TEXT;
    entry.base.level              = PUBNUB_LOG_LEVEL_DEBUG;
    entry.base.file               = "test.c";
    entry.base.line               = 1;
    entry.base.context_id         = "aabbccdd";
    entry.base.timestamp_ms       = 0u;
    entry.base.minimum_level      = PUBNUB_LOG_LEVEL_DEBUG;
    entry.message                 = "hello test";

    logger.base.log(&logger.base, (const pubnub_log_entry_t*)&entry);

    assert_non_null(logger.base.log);
}

static void stdout_log_error_does_not_crash(void** state)
{
    (void)state;
    pubnub_logger_stdout_t logger;
    pubnub_logger_stdout_init(&logger);

    pubnub_log_entry_error_t entry = {0};
    entry.base.type                = PUBNUB_LOG_ENTRY_ERROR;
    entry.base.level               = PUBNUB_LOG_LEVEL_ERROR;
    entry.base.context_id          = "aabbccdd";
    entry.base.timestamp_ms        = 1000u;
    entry.base.minimum_level       = PUBNUB_LOG_LEVEL_DEBUG;
    entry.error_code               = 42;
    entry.error_message            = "something failed";

    logger.base.log(&logger.base, (const pubnub_log_entry_t*)&entry);

    assert_non_null(logger.base.log);
}

static void stdout_log_net_req_does_not_crash(void** state)
{
    (void)state;
    pubnub_logger_stdout_t logger;
    pubnub_logger_stdout_init(&logger);

    pubnub_log_entry_net_request_t entry = {0};
    entry.base.type                      = PUBNUB_LOG_ENTRY_NET_REQ;
    entry.base.level                     = PUBNUB_LOG_LEVEL_DEBUG;
    entry.base.context_id                = "aabbccdd";
    entry.base.timestamp_ms              = 2000u;
    entry.base.minimum_level             = PUBNUB_LOG_LEVEL_DEBUG;
    entry.method                         = "GET";
    entry.url = "https://ps.pndsn.com/v2/publish/key/key/0/ch/0/msg";

    logger.base.log(&logger.base, (const pubnub_log_entry_t*)&entry);

    assert_non_null(logger.base.log);
}

static void stdout_log_net_resp_does_not_crash(void** state)
{
    (void)state;
    pubnub_logger_stdout_t logger;
    pubnub_logger_stdout_init(&logger);

    pubnub_log_entry_net_response_t entry = {0};
    entry.base.type                       = PUBNUB_LOG_ENTRY_NET_RESP;
    entry.base.level                      = PUBNUB_LOG_LEVEL_DEBUG;
    entry.base.context_id                 = "aabbccdd";
    entry.base.timestamp_ms               = 3000u;
    entry.base.minimum_level              = PUBNUB_LOG_LEVEL_DEBUG;
    entry.status_code                     = 200;
    entry.url = "https://ps.pndsn.com/v2/publish/key/key/0/ch/0/msg";

    logger.base.log(&logger.base, (const pubnub_log_entry_t*)&entry);

    assert_non_null(logger.base.log);
}

static void stdout_set_level_does_not_crash(void** state)
{
    (void)state;
    pubnub_logger_stdout_t logger;
    pubnub_logger_stdout_init(&logger);
    logger.base.set_level(&logger.base, PUBNUB_LOG_LEVEL_WARNING);

    assert_non_null(logger.base.set_level);
}

#if PN_HAVE_STDOUT_CAPTURE

/**
 * @brief Redirect/restore state for capturing stdout and stderr into
 *        temporary files during a single log emission.
 */
typedef struct {
    FILE* out_tmp;   /**< Temp file receiving redirected stdout. */
    FILE* err_tmp;   /**< Temp file receiving redirected stderr. */
    int   saved_out; /**< dup() of the original stdout fd. */
    int   saved_err; /**< dup() of the original stderr fd. */
} pn_capture_t;

/**
 * @brief Begin capturing stdout and stderr into temporary files.
 *
 * On failure nothing remains redirected: any partially acquired
 * resources are released before returning.
 *
 * @param cap Capture state to initialize.
 * @retval 0  Redirection is active; the caller must pair with
 *            pn_capture_end().
 * @retval -1 Setup failed (unsupported host); no redirection is active.
 */
static int pn_capture_begin(pn_capture_t* cap)
{
    cap->out_tmp   = NULL;
    cap->err_tmp   = NULL;
    cap->saved_out = -1;
    cap->saved_err = -1;

    cap->out_tmp = tmpfile();
    cap->err_tmp = tmpfile();
    if (NULL == cap->out_tmp || NULL == cap->err_tmp) {
        goto fail;
    }

    (void)fflush(stdout);
    (void)fflush(stderr);

    cap->saved_out = dup(fileno(stdout));
    cap->saved_err = dup(fileno(stderr));
    if (0 > cap->saved_out || 0 > cap->saved_err) {
        goto fail;
    }

    if (0 > dup2(fileno(cap->out_tmp), fileno(stdout))) {
        goto fail;
    }
    if (0 > dup2(fileno(cap->err_tmp), fileno(stderr))) {
        (void)dup2(cap->saved_out, fileno(stdout));
        goto fail;
    }
    return 0;

fail:
    if (0 <= cap->saved_out) {
        (void)close(cap->saved_out);
    }
    if (0 <= cap->saved_err) {
        (void)close(cap->saved_err);
    }
    if (NULL != cap->out_tmp) {
        (void)fclose(cap->out_tmp);
    }
    if (NULL != cap->err_tmp) {
        (void)fclose(cap->err_tmp);
    }
    return -1;
}

/**
 * @brief Restore stdout/stderr and read back the captured bytes.
 *
 * Restoration happens before any bytes are read so that subsequent
 * cmocka assertions print to the real terminal, not the temp files.
 *
 * @param cap     Active capture state from pn_capture_begin().
 * @param out_buf Destination for captured stdout (NUL-terminated).
 * @param out_cap Size of @p out_buf in bytes (must be >= 1).
 * @param err_buf Destination for captured stderr (NUL-terminated).
 * @param err_cap Size of @p err_buf in bytes (must be >= 1).
 */
static void pn_capture_end(pn_capture_t* cap,
                           char*         out_buf,
                           size_t        out_cap,
                           char*         err_buf,
                           size_t        err_cap)
{
    size_t n;

    (void)fflush(stdout);
    (void)fflush(stderr);
    (void)dup2(cap->saved_out, fileno(stdout));
    (void)dup2(cap->saved_err, fileno(stderr));
    (void)close(cap->saved_out);
    (void)close(cap->saved_err);

    (void)fseek(cap->out_tmp, 0L, SEEK_SET);
    n          = fread(out_buf, 1u, out_cap - 1u, cap->out_tmp);
    out_buf[n] = '\0';
    (void)fclose(cap->out_tmp);

    (void)fseek(cap->err_tmp, 0L, SEEK_SET);
    n          = fread(err_buf, 1u, err_cap - 1u, cap->err_tmp);
    err_buf[n] = '\0';
    (void)fclose(cap->err_tmp);
}

static void stdout_log_error_single_ordered_stream(void** state)
{
    (void)state;
    pubnub_logger_stdout_t logger;
    pn_capture_t           cap;
    char                   out_buf[1024];
    char                   err_buf[256];
    const char*            level_pos;
    const char*            body_pos;
    const char*            code_pos;
    size_t                 out_len;

    pubnub_logger_stdout_init(&logger);

    pubnub_log_entry_error_t entry = {0};
    entry.base.type                = PUBNUB_LOG_ENTRY_ERROR;
    entry.base.level               = PUBNUB_LOG_LEVEL_ERROR;
    entry.base.context_id          = "aabbccdd";
    entry.base.timestamp_ms        = 1000u;
    entry.base.minimum_level       = PUBNUB_LOG_LEVEL_DEBUG;
    entry.error_code               = 42;
    entry.error_message            = "something failed";

    if (0 != pn_capture_begin(&cap)) {
        skip();
    }
    logger.base.log(&logger.base, (const pubnub_log_entry_t*)&entry);
    pn_capture_end(&cap, out_buf, sizeof(out_buf), err_buf, sizeof(err_buf));

    /* The whole entry goes to a single stream: nothing on stderr. */
    assert_int_equal(0, (int)strlen(err_buf));

    out_len = strlen(out_buf);
    assert_true(out_len > 0u);
    /* Entry is newline-terminated — no dangling unterminated prefix. */
    assert_int_equal('\n', out_buf[out_len - 1u]);

    level_pos = strstr(out_buf, "ERROR ");
    body_pos  = strstr(out_buf, "Error: something failed");
    code_pos  = strstr(out_buf, "Code: 42");
    assert_non_null(level_pos);
    assert_non_null(body_pos);
    assert_non_null(code_pos);

    /* Prefix/header BEFORE body BEFORE code line. */
    assert_true(level_pos < body_pos);
    assert_true(body_pos < code_pos);
}

static void stdout_log_error_zero_code_null_message(void** state)
{
    (void)state;
    pubnub_logger_stdout_t logger;
    pn_capture_t           cap;
    char                   out_buf[1024];
    char                   err_buf[256];
    size_t                 out_len;

    pubnub_logger_stdout_init(&logger);

    pubnub_log_entry_error_t entry = {0};
    entry.base.type                = PUBNUB_LOG_ENTRY_ERROR;
    entry.base.level               = PUBNUB_LOG_LEVEL_ERROR;
    entry.base.context_id          = "aabbccdd";
    entry.base.timestamp_ms        = 0u;
    entry.base.minimum_level       = PUBNUB_LOG_LEVEL_DEBUG;
    entry.error_code               = 0;    /* suppresses the Code line */
    entry.error_message            = NULL; /* falls back to "(no message)" */

    if (0 != pn_capture_begin(&cap)) {
        skip();
    }
    logger.base.log(&logger.base, (const pubnub_log_entry_t*)&entry);
    pn_capture_end(&cap, out_buf, sizeof(out_buf), err_buf, sizeof(err_buf));

    assert_int_equal(0, (int)strlen(err_buf));

    out_len = strlen(out_buf);
    assert_true(out_len > 0u);
    assert_int_equal('\n', out_buf[out_len - 1u]);

    assert_non_null(strstr(out_buf, "Error: (no message)"));
    /* error_code == 0 must suppress the Code line entirely. */
    assert_null(strstr(out_buf, "Code:"));
}

#endif /* PN_HAVE_STDOUT_CAPTURE */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(stdout_init_sets_vtable),
        cmocka_unit_test(stdout_init_null_is_safe),
        cmocka_unit_test(stdout_log_text_does_not_crash),
        cmocka_unit_test(stdout_log_error_does_not_crash),
        cmocka_unit_test(stdout_log_net_req_does_not_crash),
        cmocka_unit_test(stdout_log_net_resp_does_not_crash),
        cmocka_unit_test(stdout_set_level_does_not_crash),
#if PN_HAVE_STDOUT_CAPTURE
        cmocka_unit_test(stdout_log_error_single_ordered_stream),
        cmocka_unit_test(stdout_log_error_zero_code_null_message),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
