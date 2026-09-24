/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/config.h"

#if PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0

#include "pubnub/providers/logger.h"

#include "pn_format.h"

#include <stdarg.h>

void pn_log_variadic_(pubnub_logger_provider_t* prov,
                      pubnub_log_level_t        level,
                      const char*               file,
                      int                       line,
                      const char*               fmt,
                      ...)
{
    char                    buf[PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE];
    va_list                 args;
    pubnub_log_entry_text_t entry = {0};

    va_start(args, fmt);
    pn_vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    buf[sizeof(buf) - 1] = '\0';

    entry.base.type  = PUBNUB_LOG_ENTRY_TEXT;
    entry.base.level = level;
    entry.base.file  = file;
    entry.base.line  = line;
    entry.message    = buf;

    prov->log(prov, (const pubnub_log_entry_t*)&entry);
}

#endif /* PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0 */

/* Suppress ISO C "empty translation unit" diagnostic when variadic logging is
 * compiled out. */
typedef int pn_log_variadic_empty_tu_t;
