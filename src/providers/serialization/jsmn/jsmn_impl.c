/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file jsmn_impl.c
 * @brief Single-translation-unit jsmn definitions.
 *
 * jsmn is a single-header library (fetched via FetchContent) whose
 * implementation is inlined into the translation unit that omits
 * @c JSMN_HEADER. This file is that translation unit; it exists to
 * isolate jsmn's third-party code from the SDK's strict project
 * warning policy.
 *
 * The provider source `serialization_jsmn.c` includes the same header
 * with @c JSMN_HEADER defined, picking up only the prototypes and
 * type declarations. The build wires the two compilation units into
 * the same static library with file-level warning suppressions
 * applied to this file only (see `CMakeLists.txt`).
 */

/* No JSMN_STRICT: see the rationale at the top of
 * `serialization_jsmn.c`. Bare top-level primitives must parse so
 * the int64-round-trip tests pass; non-strict mode is acceptable
 * because the SDK's own walker classifies primitive tokens. */

#include <jsmn.h>
