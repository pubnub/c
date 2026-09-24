/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pn_signing_string.h
 * @brief PubNub PAM v2/v3 canonical signing-string builder.
 *
 * Internal-only helper; not installed as a public header. Produces
 * the byte sequence that HMAC-SHA256 must sign to obtain a valid
 * PAMv3 `signature=v2.<base64url>` query parameter.
 *
 * Canonical format (PAMv3, matches c-core legacy pn_gen_pam_v3_sign):
 *
 *     METHOD LF PUBLISH_KEY LF PATH LF QUERY LF BODY
 *
 * where LF is U+000A (`\n`). BODY is the raw request body for POST
 * and PATCH, empty bytes for GET and DELETE. Either way, the final
 * LF between QUERY and BODY is always present (so no-body requests
 * end with a trailing LF).
 *
 * The PATH is the URL path segments joined with `/` and prefixed with
 * a leading `/` (for example `/publish/pk/sk/0/channel/0/msg`). The
 * QUERY is every key=value pair joined with `&` in the order they
 * appear in `request->query_params`. The caller is responsible for
 * pre-sorting query params alphabetically when deterministic output
 * is required (signing matches the exact query string the transport
 * will emit).
 *
 * Values in `query_params` are assumed to be URL-encoded already; the
 * builder copies them verbatim so the canonical string matches the
 * bytes the transport puts on the wire after `?`.
 */

#ifndef PN_SIGNING_STRING_H
#define PN_SIGNING_STRING_H

#include "pubnub/error.h"
#include "pubnub/providers/transport_types.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Compute the number of bytes the canonical signing string
 *        will occupy for @p request / @p publish_key.
 *
 * The returned value does NOT include a NUL terminator - the
 * canonical string is a raw byte sequence that may contain any
 * binary body content.
 *
 * Returns 0 on invalid arguments so callers can treat 0 as an error
 * sentinel without mixing it with PUBNUB_OK semantics.
 *
 * PAM compatibility: for /publish requests, the method is internally
 * normalized to GET before sizing (PAM has a known bug where it does
 * not canonicalize the POST body on that endpoint). Callers don't
 * pass a method at all; the function reads @c request->method and
 * applies the workaround when needed.
 *
 * @param request      Request whose method, path, and query contribute
 *                     to the canonical string (borrowed).
 * @param publish_key  Publisher key (borrowed, null-terminated).
 * @return Size in bytes, or 0 on invalid arguments.
 */
size_t pn_signing_string_len(const pubnub_http_request_t* request,
                             const char*                  publish_key);

/**
 * @brief Build the canonical signing string into @p output.
 *
 * On success writes exactly `pn_signing_string_len(...)`
 * bytes into @p output and stores that count in @p out_len. Does
 * NOT NUL-terminate (body content may be arbitrary binary).
 *
 * PAM compatibility: same /publish method-normalization as
 * pn_signing_string_len() - see that function's doc.
 *
 * @param request      Request contributing method, path, and query.
 * @param publish_key  Publisher key (borrowed, null-terminated).
 * @param output       Destination buffer.
 * @param out_cap      Capacity of @p output.
 * @param out_len      On success, set to bytes written.
 * @return `PUBNUB_OK` on success, an error code if a required pointer
 *         is NULL or @p out_cap is insufficient.
 */
pubnub_res_t pn_signing_string_build(const pubnub_http_request_t* request,
                                     const char*                  publish_key,
                                     uint8_t*                     output,
                                     size_t                       out_cap,
                                     size_t*                      out_len);

/**
 * @brief Return the canonical uppercase HTTP method verb.
 *
 * @param method HTTP method.
 * @return Null-terminated string literal, never NULL. Returns the
 *         string `"UNKNOWN"` for unrecognized enum values so that a
 *         signing attempt with a broken enum is immediately visible
 *         in logs without crashing.
 */
const char* pn_signing_method_verb(pubnub_http_method_t method);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_SIGNING_STRING_H */
