/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_PROXY_WPAD_H
#define PN_PROXY_WPAD_H

#include "proxy_interface.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Resolve proxy settings via OS auto-discovery (WPAD/PAC).
 *
 * Queries the operating system for proxy settings applicable to the
 * given target URL. On success, populates the output config with host
 * and port. On failure or "direct connection", sets out->host to NULL.
 *
 * This is a BLOCKING call (OS API may perform network I/O to fetch a
 * PAC file). Call during transport init, not during tick loops.
 *
 * @param target_url  URL to query proxy for (e.g. "https://ps.pndsn.com").
 *                    Must be NUL-terminated. NULL causes immediate failure.
 * @param out         Output proxy config. Caller-allocated, zeroed on entry
 *                    by this function. String fields point to internal static
 *                    storage valid until pn_proxy_wpad_free is called.
 * @return 0 on success (out populated; out->host may still be NULL meaning
 *         "direct connection"), -1 on error (out zeroed).
 */
int pn_proxy_wpad_resolve(const char* target_url, pn_proxy_config_t* out);

/**
 * @brief Free resources allocated by pn_proxy_wpad_resolve.
 *
 * Zeroes the static host buffer and clears the config struct.
 * Safe to call with NULL config (no-op).
 *
 * @param config Config previously populated by pn_proxy_wpad_resolve.
 */
void pn_proxy_wpad_free(pn_proxy_config_t* config);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PROXY_WPAD_H */
