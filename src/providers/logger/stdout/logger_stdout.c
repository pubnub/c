/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/* gmtime_r requires POSIX.1-2001; define before any system header. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
/* NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp,readability-identifier-naming) */
#define _POSIX_C_SOURCE 200112L
#endif

#include "logger_stdout_internal.h"
#include "pubnub/error.h"
#include "pubnub/providers/logger_types.h"

#include "pn_format.h"

#include <stdint.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#endif

/* Platform output adapter: printk on Zephyr (no picolibc needed),
 * standard stdio elsewhere.
 * Use (...) rather than (fmt, ...) to avoid the ISO C99 "at least one
 * argument for '...'" constraint — single-string calls like
 * PN_STDOUT("text") are valid with the variadic-only form. */
#if defined(__ZEPHYR__)
#include <zephyr/sys/printk.h>
#define PN_STDOUT(...) printk(__VA_ARGS__)
#define PN_FLUSH()     ((void)0)
#else
#include <stdio.h>
#define PN_STDOUT(...) (void)printf(__VA_ARGS__)
#define PN_FLUSH()     (void)fflush(stdout)
#endif

#define PN_STDOUT_MAX_DEPTH   10
#define PN_STDOUT_INDENT_SIZE 256

static void stdout_write_timestamp_(uint64_t timestamp_ms)
{
    if (0U == timestamp_ms) {
        PN_STDOUT("0000-00-00T00:00:00.000Z ");
        return;
    }

    const time_t   sec  = (time_t)(timestamp_ms / 1000U);
    const uint32_t msec = (uint32_t)(timestamp_ms % 1000U);
    struct tm      tm_utc;
    int            ok = 0;

#if defined(_WIN32)
    ok = (0 == gmtime_s(&tm_utc, &sec));
#elif defined(__unix__) || defined(__APPLE__) || defined(ESP_PLATFORM) \
    || defined(__ZEPHYR__)
    ok = (NULL != gmtime_r(&sec, &tm_utc));
#else
    {
        const struct tm* ptm = gmtime(&sec);
        if (NULL != ptm) {
            tm_utc = *ptm;
            ok     = 1;
        }
    }
#endif

    if (!ok) {
        PN_STDOUT("0000-00-00T00:00:00.000Z ");
        return;
    }

    char buf[20];
    if (0 == strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_utc)) {
        PN_STDOUT("0000-00-00T00:00:00.000Z ");
        return;
    }
    PN_STDOUT("%s.%03uZ ", buf, (unsigned)msec);
}

static void stdout_write_level_(pubnub_log_level_t level)
{
    switch (level) {
    case PUBNUB_LOG_LEVEL_TRACE: PN_STDOUT("TRACE "); break;
    case PUBNUB_LOG_LEVEL_DEBUG: PN_STDOUT("DEBUG "); break;
    case PUBNUB_LOG_LEVEL_INFO: PN_STDOUT("INFO  "); break;
    case PUBNUB_LOG_LEVEL_WARNING: PN_STDOUT("WARN  "); break;
    case PUBNUB_LOG_LEVEL_ERROR: PN_STDOUT("ERROR "); break;
    case PUBNUB_LOG_LEVEL_NONE: /* fall through */
    default: PN_STDOUT("NONE  "); break;
    }
}

static void stdout_write_prefix_(const pubnub_log_entry_t* e)
{
    stdout_write_timestamp_(e->timestamp_ms);
    PN_STDOUT("PubNub-%s ", (NULL != e->context_id) ? e->context_id : "00000000");
    stdout_write_level_(e->level);
    if (NULL != e->file) {
        PN_STDOUT("%s:%d ", e->file, e->line);
    }
}

/**
 * Iterative value-tree printer using an explicit stack.
 * Avoids recursion (misc-no-recursion clang-tidy rule) while
 * supporting nested structures up to PN_STDOUT_MAX_DEPTH.
 */

/** Frame types for the iterative printer stack. */
typedef enum {
    PN_FRAME_VALUE,
    PN_FRAME_ARRAY_ITER,
    PN_FRAME_MAP_ITER
} pn_frame_type_t;

/** Explicit stack frame for the iterative value-tree printer. */
typedef struct {
    const pubnub_log_value_t* node;
    pn_frame_type_t           type;
    int                       depth;
    char                      indent[PN_STDOUT_INDENT_SIZE];
} pn_print_frame_t;

/* NOLINTNEXTLINE(readability-function-size) */
static void stdout_print_value_(const pubnub_log_value_t* root)
{
    pn_print_frame_t stack[PN_STDOUT_MAX_DEPTH + 1];
    int              sp = 0;

    if (NULL == root) {
        PN_STDOUT("null\n");
        return;
    }

    /* Push root frame. */
    stack[0].type      = PN_FRAME_VALUE;
    stack[0].node      = root;
    stack[0].depth     = 0;
    stack[0].indent[0] = '\0';
    sp                 = 1;

    while (sp > 0) {
        pn_print_frame_t frame = stack[--sp];

        if (frame.depth > PN_STDOUT_MAX_DEPTH) {
            PN_STDOUT("%s...\n", frame.indent);
            continue;
        }

        if (PN_FRAME_ARRAY_ITER == frame.type) {
            /* Iterate remaining array elements. */
            const pubnub_log_value_t* el = frame.node;
            while (NULL != el) {
                /* Push remaining siblings back. */
                if (NULL != el->next && sp < PN_STDOUT_MAX_DEPTH + 1) {
                    stack[sp].type  = PN_FRAME_ARRAY_ITER;
                    stack[sp].node  = el->next;
                    stack[sp].depth = frame.depth;
                    pn_snprintf(
                        stack[sp].indent, PN_STDOUT_INDENT_SIZE, "%s", frame.indent);
                    sp++;
                }
                /* Push this element as a value frame. */
                if (sp < PN_STDOUT_MAX_DEPTH + 1) {
                    char child_indent[PN_STDOUT_INDENT_SIZE];
                    pn_snprintf(
                        child_indent, PN_STDOUT_INDENT_SIZE, "%s  - ", frame.indent);
                    stack[sp].type  = PN_FRAME_VALUE;
                    stack[sp].node  = el;
                    stack[sp].depth = frame.depth + 1;
                    pn_snprintf(
                        stack[sp].indent, PN_STDOUT_INDENT_SIZE, "%s", child_indent);
                    sp++;
                }
                break;
            }
            continue;
        }

        if (PN_FRAME_MAP_ITER == frame.type) {
            /* Iterate remaining map entries. */
            const pubnub_log_value_t* node = frame.node;
            while (NULL != node && NULL != node->data.map_val.key) {
                /* Push remaining siblings back. */
                if (NULL != node->next && sp < PN_STDOUT_MAX_DEPTH + 1) {
                    stack[sp].type  = PN_FRAME_MAP_ITER;
                    stack[sp].node  = node->next;
                    stack[sp].depth = frame.depth;
                    pn_snprintf(
                        stack[sp].indent, PN_STDOUT_INDENT_SIZE, "%s", frame.indent);
                    sp++;
                }
                /* Push the value with key prefix. */
                if (NULL != node->data.map_val.value
                    && sp < PN_STDOUT_MAX_DEPTH + 1) {
                    char kv_indent[PN_STDOUT_INDENT_SIZE];
                    pn_snprintf(kv_indent,
                                PN_STDOUT_INDENT_SIZE,
                                "%s%s: ",
                                frame.indent,
                                node->data.map_val.key);
                    stack[sp].type  = PN_FRAME_VALUE;
                    stack[sp].node  = node->data.map_val.value;
                    stack[sp].depth = frame.depth + 1;
                    pn_snprintf(
                        stack[sp].indent, PN_STDOUT_INDENT_SIZE, "%s", kv_indent);
                    sp++;
                } else if (NULL == node->data.map_val.value) {
                    PN_STDOUT("%s%s: null\n", frame.indent, node->data.map_val.key);
                }
                break;
            }
            continue;
        }

        /* PN_FRAME_VALUE: print the value itself. */
        if (NULL == frame.node) {
            PN_STDOUT("%snull\n", frame.indent);
            continue;
        }

        switch (frame.node->type) {
        case PUBNUB_LOG_VALUE_NULL: PN_STDOUT("%snull\n", frame.indent); break;
        case PUBNUB_LOG_VALUE_BOOL:
            PN_STDOUT("%s%s\n",
                      frame.indent,
                      frame.node->data.bool_val ? "true" : "false");
            break;
        case PUBNUB_LOG_VALUE_NUMBER: {
            /* Avoid %lld — not portable on Zephyr printk or the minimal
             * formatter without CONFIG_CBPRINTF_COMPLETE. Split into
             * billions + remainder so only %u is needed. */
            long long          v   = (long long)frame.node->data.number_val;
            int                neg = v < 0;
            unsigned long long uv =
                neg ? (unsigned long long)(-v) : (unsigned long long)v;
            unsigned int hi = (unsigned int)(uv / 1000000000ULL);
            unsigned int lo = (unsigned int)(uv % 1000000000ULL);
            if (0 != hi) {
                PN_STDOUT(neg ? "%s-%u%09u\n" : "%s%u%09u\n", frame.indent, hi, lo);
            } else {
                PN_STDOUT(neg ? "%s-%u\n" : "%s%u\n", frame.indent, lo);
            }
            break;
        }
        case PUBNUB_LOG_VALUE_STRING: {
            const char* s   = frame.node->data.string_val.ptr;
            size_t      len = frame.node->data.string_val.len;
            if (NULL != s) {
                if (len > 0) {
                    PN_STDOUT("%s%.*s\n", frame.indent, (int)len, s);
                } else {
                    PN_STDOUT("%s%s\n", frame.indent, s);
                }
            } else {
                PN_STDOUT("%s(null string)\n", frame.indent);
            }
            break;
        }
        case PUBNUB_LOG_VALUE_ARRAY: {
            const pubnub_log_value_t* head = frame.node->data.array_val.head;
            if (NULL == head) {
                PN_STDOUT("%s[]\n", frame.indent);
            } else if (sp < PN_STDOUT_MAX_DEPTH + 1) {
                stack[sp].type  = PN_FRAME_ARRAY_ITER;
                stack[sp].node  = head;
                stack[sp].depth = frame.depth;
                pn_snprintf(
                    stack[sp].indent, PN_STDOUT_INDENT_SIZE, "%s", frame.indent);
                sp++;
            }
            break;
        }
        case PUBNUB_LOG_VALUE_MAP: {
            if (NULL == frame.node->data.map_val.key) {
                PN_STDOUT("%s{}\n", frame.indent);
            } else if (sp < PN_STDOUT_MAX_DEPTH + 1) {
                char map_indent[PN_STDOUT_INDENT_SIZE];
                pn_snprintf(map_indent, PN_STDOUT_INDENT_SIZE, "%s  ", frame.indent);
                stack[sp].type  = PN_FRAME_MAP_ITER;
                stack[sp].node  = frame.node;
                stack[sp].depth = frame.depth;
                pn_snprintf(stack[sp].indent, PN_STDOUT_INDENT_SIZE, "%s", map_indent);
                sp++;
            }
            break;
        }
        default: PN_STDOUT("%s(unknown)\n", frame.indent); break;
        }
    }
}

static int stdout_is_text_content_type_(const char* ct)
{
    static const char* const markers[] = {"json",
                                          "javascript",
                                          "xml",
                                          "html",
                                          "text",
                                          "application/x-www-form-urlencoded",
                                          NULL};
    int                      i;
    if (NULL == ct) {
        return 0;
    }
    for (i = 0; NULL != markers[i]; ++i) {
        if (NULL != strstr(ct, markers[i])) {
            return 1;
        }
    }
    return 0;
}

static int stdout_should_show_body_(const pubnub_log_value_t* headers)
{
    const pubnub_log_value_t* node;
    if (NULL == headers) {
        return 0;
    }
    for (node = headers; NULL != node; node = node->next) {
        if (NULL == node->data.map_val.key) {
            continue;
        }
        if (0 == strcmp(node->data.map_val.key, "Content-Type")
            || 0 == strcmp(node->data.map_val.key, "content-type")) {
            const pubnub_log_value_t* v = node->data.map_val.value;
            if (NULL != v && PUBNUB_LOG_VALUE_STRING == v->type) {
                return stdout_is_text_content_type_(v->data.string_val.ptr);
            }
        }
    }
    return 0;
}

static void stdout_print_text_(const pubnub_log_entry_text_t* e)
{
    stdout_write_prefix_(&e->base);
    PN_STDOUT("%s\n", NULL != e->message ? e->message : "(null)");
    PN_FLUSH();
}

static void stdout_print_object_(const pubnub_log_entry_object_t* e)
{
    stdout_write_prefix_(&e->base);
    if (NULL != e->label) {
        PN_STDOUT("%s\n", e->label);
    }
    if (NULL == e->data) {
        PN_STDOUT("(null)\n");
    } else {
        stdout_print_value_(e->data);
    }
    PN_FLUSH();
}

static void stdout_print_error_(const pubnub_log_entry_error_t* e)
{
    stdout_write_prefix_(&e->base);
    PN_STDOUT("Error: %s\n",
              NULL != e->error_message ? e->error_message : "(no message)");
    if (0 != e->error_code) {
        PN_STDOUT("  Code: %d\n", e->error_code);
    }
    PN_FLUSH();
}

static void stdout_print_net_req_(const pubnub_log_entry_net_request_t* e)
{
    const int show_full = (!e->canceled && !e->failed)
                       && (e->base.minimum_level <= PUBNUB_LOG_LEVEL_TRACE);

    stdout_write_prefix_(&e->base);

    if (e->canceled) {
        PN_STDOUT("Canceled HTTP request (slot %u)", (unsigned)e->slot_id);
    } else if (e->failed) {
        const char* res_str = pubnub_res_str(e->result);
        if (NULL != res_str && '\0' != res_str[0]) {
            PN_STDOUT("Failed HTTP request (slot %u) (%d: %s)",
                      (unsigned)e->slot_id,
                      (int)e->result,
                      res_str);
        } else {
            PN_STDOUT("Failed HTTP request (slot %u) (%d)",
                      (unsigned)e->slot_id,
                      (int)e->result);
        }
    } else {
        PN_STDOUT("Sending HTTP request (slot %u)", (unsigned)e->slot_id);
    }
    PN_STDOUT(":\n");
    PN_STDOUT("  Method: %s\n", NULL != e->method ? e->method : "?");
    PN_STDOUT("  URL:    %s\n", NULL != e->url ? e->url : "?");

    if (show_full && NULL != e->headers) {
        const pubnub_log_value_t* node = e->headers;
        PN_STDOUT("  Headers:\n");
        while (NULL != node && NULL != node->data.map_val.key) {
            const pubnub_log_value_t* v       = node->data.map_val.value;
            const char*               val     = "";
            int                       val_len = 0;
            if (NULL != v && PUBNUB_LOG_VALUE_STRING == v->type) {
                val = (NULL != v->data.string_val.ptr) ? v->data.string_val.ptr
                                                       : "";
                val_len = (int)v->data.string_val.len;
            }
            PN_STDOUT("    - %s: %.*s\n", node->data.map_val.key, val_len, val);
            node = node->next;
        }
    }

    if (show_full && NULL != e->body && e->body_len > 0
        && stdout_should_show_body_(e->headers)) {
        PN_STDOUT("  Body:\n    %.*s\n", (int)e->body_len, (const char*)e->body);
    }
    PN_FLUSH();
}

static void stdout_print_net_resp_(const pubnub_log_entry_net_response_t* e)
{
    const int show_full = (e->base.minimum_level <= PUBNUB_LOG_LEVEL_TRACE);

    stdout_write_prefix_(&e->base);
    PN_STDOUT("Received HTTP response:\n");
    PN_STDOUT("  Status: %d\n", e->status_code);
    if (NULL != e->url) {
        PN_STDOUT("  URL:    %s\n", e->url);
    }

    if (show_full && NULL != e->headers) {
        const pubnub_log_value_t* node = e->headers;
        PN_STDOUT("  Headers:\n");
        while (NULL != node && NULL != node->data.map_val.key) {
            const pubnub_log_value_t* v       = node->data.map_val.value;
            const char*               val     = "";
            int                       val_len = 0;
            if (NULL != v && PUBNUB_LOG_VALUE_STRING == v->type) {
                val = (NULL != v->data.string_val.ptr) ? v->data.string_val.ptr
                                                       : "";
                val_len = (int)v->data.string_val.len;
            }
            PN_STDOUT("    - %s: %.*s\n", node->data.map_val.key, val_len, val);
            node = node->next;
        }
    }

    /* Show body at DEBUG with 256-byte truncation; at TRACE show full
     * body when Content-Type is text-like. */
    if (NULL != e->body && e->body_len > 0) {
        if (show_full && stdout_should_show_body_(e->headers)) {
            PN_STDOUT("  Body:\n    %.*s\n", (int)e->body_len, (const char*)e->body);
        } else {
            const int limit = (e->body_len > 256) ? 256 : (int)e->body_len;
            PN_STDOUT("  Body (%u B):\n    %.*s",
                      (unsigned int)e->body_len,
                      limit,
                      (const char*)e->body);
            if (e->body_len > 256) {
                PN_STDOUT("...");
            }
            PN_STDOUT("\n");
        }
    }
    PN_FLUSH();
}

static void stdout_log_(struct pubnub_logger_provider* self,
                        const pubnub_log_entry_t*      entry)
{
    (void)self;

    if (NULL == entry) {
        return;
    }

    switch (entry->type) {
    case PUBNUB_LOG_ENTRY_TEXT:
        stdout_print_text_((const pubnub_log_entry_text_t*)entry);
        break;
    case PUBNUB_LOG_ENTRY_OBJECT:
        stdout_print_object_((const pubnub_log_entry_object_t*)entry);
        break;
    case PUBNUB_LOG_ENTRY_ERROR:
        stdout_print_error_((const pubnub_log_entry_error_t*)entry);
        break;
    case PUBNUB_LOG_ENTRY_NET_REQ:
        stdout_print_net_req_((const pubnub_log_entry_net_request_t*)entry);
        break;
    case PUBNUB_LOG_ENTRY_NET_RESP:
        stdout_print_net_resp_((const pubnub_log_entry_net_response_t*)entry);
        break;
    default:
        PN_STDOUT("(unknown log entry type %d)\n", (int)entry->type);
        PN_FLUSH();
        break;
    }
}

static void stdout_set_level_(struct pubnub_logger_provider* self,
                              pubnub_log_level_t             min_level)
{
    (void)self;
    (void)min_level;
    /* No per-instance level filtering — the mux handles it. */
}

void pubnub_logger_stdout_init(pubnub_logger_stdout_t* logger)
{
    if (NULL == logger) {
        return;
    }
    memset(logger, 0, sizeof(*logger));
    logger->base.log       = stdout_log_;
    logger->base.set_level = stdout_set_level_;
}

pubnub_logger_provider_t* pn_logger_default(void)
{
    static pubnub_logger_stdout_t s_stdout_logger;
    static int                    s_initialized = 0;

    if (!s_initialized) {
        pubnub_logger_stdout_init(&s_stdout_logger);
        s_initialized = 1;
    }
    return &s_stdout_logger.base;
}
