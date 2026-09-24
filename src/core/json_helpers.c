/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file json_helpers.c
 * @brief Ergonomic JSON helpers (thin vtable call-throughs).
 *
 * Gated helpers (PUBNUB_CFG_JSON_HELPERS) include a recursive clone
 * walker - only compiled on hosted profiles where stack depth is
 * not a concern.
 */

#include "pubnub/json.h"

#include "core_internal.h"
#include "pubnub/error.h"
#include "pubnub/providers/serialization.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

pubnub_res_t pubnub_json_object_set(pubnub_serialization_provider_t* serial,
                                    pubnub_json_value_t*             obj,
                                    const char*                      key,
                                    pubnub_json_value_t*             child)
{
    if (NULL == serial || NULL == obj || NULL == key || NULL == child) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == serial->object_set) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return serial->object_set(serial, obj, key, strlen(key), child);
}

pubnub_res_t pubnub_json_array_append(pubnub_serialization_provider_t* serial,
                                      pubnub_json_value_t*             arr,
                                      pubnub_json_value_t*             item)
{
    if (NULL == serial || NULL == arr || NULL == item) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == serial->array_append) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return serial->array_append(serial, arr, item);
}

void pubnub_json_destroy(pubnub_serialization_provider_t* serial,
                         pubnub_json_value_t*             value)
{
    if (NULL == serial || NULL == value) {
        return;
    }
    if (NULL == serial->value_destroy) {
        return;
    }
    serial->value_destroy(serial, value);
}

#if PUBNUB_CFG_JSON_HELPERS

/**
 * @brief Drain remaining (key, child) pairs from @p ap and free each
 *        child via @p serial.
 *
 * Used by @ref pubnub_json_object_build to honour the "every variadic
 * child reference is invalidated by the call regardless of outcome"
 * contract: when an attach fails midway, the unvisited children in the
 * variadic list are still caller-owned and must be released so users
 * never have to track which arguments were consumed.
 *
 * The function consumes @p ap as a side effect; callers should not
 * read further pairs from it after return.
 */
static void pn_json_drain_va_children(
    pubnub_serialization_provider_t* serial,
    va_list ap) // NOLINT(readability-non-const-parameter) va_arg mutates ap
{
    for (;;) {
        const char* key = va_arg(ap, const char*);
        if (NULL == key) {
            return;
        }
        pubnub_json_value_t* child = va_arg(ap, pubnub_json_value_t*);
        pubnub_json_destroy(serial, child);
    }
}

pubnub_json_value_t* pubnub_json_object_build(pubnub_serialization_provider_t* serial,
                                              ...)
{
    if (NULL == serial || NULL == serial->value_create_object
        || NULL == serial->object_set || NULL == serial->value_destroy) {
        /* Drain caller's variadic children before returning so the
         * "all references invalidated on failure" contract holds even
         * when the provider is misconfigured. */
        va_list ap;
        va_start(ap, serial);
        if (NULL != serial) {
            pn_json_drain_va_children(serial, ap);
        }
        va_end(ap);
        return NULL;
    }

    pubnub_json_value_t* obj = serial->value_create_object(serial);
    if (NULL == obj) {
        va_list ap;
        va_start(ap, serial);
        pn_json_drain_va_children(serial, ap);
        va_end(ap);
        return NULL;
    }

    va_list ap;
    va_start(ap, serial);
    for (;;) {
        const char* key = va_arg(ap, const char*);
        if (NULL == key) {
            break;
        }
        pubnub_json_value_t* child = va_arg(ap, pubnub_json_value_t*);
        if (NULL == child) {
            /* Constructor for this slot already failed; the prior
             * children are owned by @p obj, the remaining children
             * are still in the variadic list and we must drain them. */
            pn_json_drain_va_children(serial, ap);
            va_end(ap);
            serial->value_destroy(serial, obj);
            return NULL;
        }
        pubnub_res_t rc = serial->object_set(serial, obj, key, strlen(key), child);
        if (PUBNUB_OK != rc) {
            /* Attach failed: @p child is still caller-owned per the
             * vtable contract. Free it explicitly, then drain the
             * rest. */
            serial->value_destroy(serial, child);
            pn_json_drain_va_children(serial, ap);
            va_end(ap);
            serial->value_destroy(serial, obj);
            return NULL;
        }
    }
    va_end(ap);
    return obj;
}

/**
 * @brief Recursively clone @p src into a fresh tree owned by @p serial.
 *
 * Returns NULL on any allocation failure encountered during the walk;
 * the caller of the top-level @ref pubnub_json_clone is responsible
 * for releasing the partial result via @c value_destroy.
 */
// NOLINTNEXTLINE(misc-no-recursion,readability-function-size)
static pubnub_json_value_t* pn_json_clone_walk(pubnub_serialization_provider_t* serial,
                                               const pubnub_json_value_t* src)
{
    if (NULL == src || NULL == serial->value_type) {
        return NULL;
    }

    pubnub_json_type_t type = serial->value_type(src);
    switch (type) {
    case PUBNUB_JSON_NULL:
        if (NULL == serial->value_create_null) {
            return NULL;
        }
        return serial->value_create_null(serial);

    case PUBNUB_JSON_BOOL: {
        if (NULL == serial->value_as_bool || NULL == serial->value_create_bool) {
            return NULL;
        }
        int truthy = 0;
        if (PUBNUB_OK != serial->value_as_bool(src, &truthy)) {
            return NULL;
        }
        return serial->value_create_bool(serial, truthy);
    }

    case PUBNUB_JSON_INT: {
        if (NULL == serial->value_as_int || NULL == serial->value_create_int) {
            return NULL;
        }
        int v = 0;
        if (PUBNUB_OK != serial->value_as_int(src, &v)) {
            return NULL;
        }
        return serial->value_create_int(serial, v);
    }

    case PUBNUB_JSON_DOUBLE:
        if (PUBNUB_CFG_JSON_DOUBLE && NULL != serial->value_as_double
            && NULL != serial->value_create_double) {
            double v = 0.0;
            if (PUBNUB_OK != serial->value_as_double(src, &v)) {
                return NULL;
            }
            return serial->value_create_double(serial, v);
        }
        /* Defensive fallback: when JSON_DOUBLE is compiled out the
         * accessor slot is NULL and the value is unreadable. Emit a
         * null so the clone remains structurally valid. */
        if (NULL == serial->value_create_null) {
            return NULL;
        }
        return serial->value_create_null(serial);

    case PUBNUB_JSON_STRING: {
        if (NULL == serial->value_as_string || NULL == serial->value_create_string) {
            return NULL;
        }
        size_t      len = 0;
        const char* str = serial->value_as_string(src, &len);
        if (NULL == str) {
            return NULL;
        }
        return serial->value_create_string(serial, str, len);
    }

    case PUBNUB_JSON_RAW: {
        /* Raw nodes report bytes via value_as_string in both shipped
         * backends. Rebuild via value_create_raw so the clone is also
         * a verbatim node. */
        if (NULL == serial->value_as_string || NULL == serial->value_create_raw) {
            return NULL;
        }
        size_t      len = 0;
        const char* str = serial->value_as_string(src, &len);
        if (NULL == str || 0 == len) {
            return NULL;
        }
        return serial->value_create_raw(serial, (const uint8_t*)str, len);
    }

    case PUBNUB_JSON_ARRAY: {
        pubnub_json_value_t*     arr  = NULL;
        pubnub_json_array_iter_t iter = {0};
        pubnub_json_value_t*     elem = NULL;

        if (NULL == serial->value_create_array || NULL == serial->array_iter_init
            || NULL == serial->array_iter_next || NULL == serial->array_append) {
            return NULL;
        }
        arr = serial->value_create_array(serial);
        if (NULL == arr) {
            return NULL;
        }
        if (0 == serial->array_iter_init(src, &iter)) {
            return arr; /* empty array */
        }
        while (serial->array_iter_next(&iter, &elem)) {
            if (NULL == elem) {
                serial->value_destroy(serial, arr);
                return NULL;
            }
            pubnub_json_value_t* clone = pn_json_clone_walk(serial, elem);
            if (NULL == clone) {
                serial->value_destroy(serial, arr);
                return NULL;
            }
            if (PUBNUB_OK != serial->array_append(serial, arr, clone)) {
                serial->value_destroy(serial, clone);
                serial->value_destroy(serial, arr);
                return NULL;
            }
        }
        return arr;
    }

    case PUBNUB_JSON_OBJECT: {
        if (NULL == serial->value_create_object || NULL == serial->object_iter_init
            || NULL == serial->object_iter_next || NULL == serial->object_set) {
            return NULL;
        }
        pubnub_json_value_t* obj = serial->value_create_object(serial);
        if (NULL == obj) {
            return NULL;
        }
        pubnub_json_iter_t iter;
        if (0 == serial->object_iter_init(src, &iter)) {
            return obj; /* empty object */
        }
        const char*          key     = NULL;
        size_t               key_len = 0;
        pubnub_json_value_t* value   = NULL;
        while (serial->object_iter_next(&iter, &key, &key_len, &value)) {
            if (NULL == value) {
                serial->value_destroy(serial, obj);
                return NULL;
            }
            pubnub_json_value_t* clone = pn_json_clone_walk(serial, value);
            if (NULL == clone) {
                serial->value_destroy(serial, obj);
                return NULL;
            }
            if (PUBNUB_OK != serial->object_set(serial, obj, key, key_len, clone)) {
                serial->value_destroy(serial, clone);
                serial->value_destroy(serial, obj);
                return NULL;
            }
        }
        return obj;
    }

    default: return NULL;
    }
}

pubnub_json_value_t* pubnub_json_clone(pubnub_serialization_provider_t* serial,
                                       const pubnub_json_value_t*       src)
{
    if (NULL == serial || NULL == src) {
        return NULL;
    }
    return pn_json_clone_walk(serial, src);
}

size_t pubnub_json_to_debug_string(pubnub_serialization_provider_t* serial,
                                   const pubnub_json_value_t*       value,
                                   char*                            buf,
                                   size_t                           cap)
{
    if (NULL != buf && cap >= 1) {
        buf[0] = '\0';
    }
    if (NULL == serial || NULL == serial->serialize || NULL == value
        || NULL == buf || cap < 2) {
        return 0;
    }
    size_t       written = 0;
    pubnub_res_t rc =
        serial->serialize(serial, value, (uint8_t*)buf, cap - 1, &written);
    if (PUBNUB_OK != rc) {
        buf[0] = '\0';
        return 0;
    }
    if (written >= cap) {
        /* Defensive: provider should have rejected a too-small buf
         * but if it claimed to write past the reserved NUL slot we
         * truncate explicitly. */
        written = cap - 1;
    }
    buf[written] = '\0';
    return written;
}

#endif /* PUBNUB_CFG_JSON_HELPERS */

pubnub_json_value_t* pn_json_array_cursor_get(pubnub_serialization_provider_t* serial,
                                              const pubnub_json_value_t* arr,
                                              size_t                     index,
                                              pubnub_json_array_iter_t* iter_cache,
                                              size_t*  iter_pos,
                                              uint8_t* iter_valid)
{
    pubnub_json_value_t* elem = NULL;

    if (NULL == serial || NULL == arr || NULL == iter_cache || NULL == iter_pos
        || NULL == iter_valid) {
        return NULL;
    }

    /* Backends without iteration support fall back to indexed access. */
    if (NULL == serial->array_iter_init || NULL == serial->array_iter_next) {
        if (NULL == serial->array_get) {
            return NULL;
        }
        return serial->array_get(arr, index);
    }

    /* Restart on first use or when the request walks backwards. */
    if (0 == *iter_valid || index < *iter_pos) {
        *iter_valid = (uint8_t)(0 != serial->array_iter_init(arr, iter_cache));
        *iter_pos   = 0;
    }

    /* Advance until the next step yields the requested element. */
    while (0 != *iter_valid && *iter_pos <= index) {
        if (0 == serial->array_iter_next(iter_cache, &elem)) {
            *iter_valid = 0;
            elem        = NULL;
            break;
        }
        (*iter_pos)++;
        if (*iter_pos == index + 1) {
            break;
        }
    }

    return (0 != *iter_valid) ? elem : NULL;
}
