/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief Minimal CBOR decoder for PubNub access tokens.
 *
 * Handles only the subset required by the PubNub token format:
 * unsigned integers (type 0), byte strings (type 2), text strings
 * (type 3), and maps (type 5). All other CBOR major types are
 * rejected.
 *
 * Guarantees:
 * - No recursion (iterative parser with explicit stack).
 * - Bounded nesting depth (PN_CBOR_MAX_DEPTH).
 * - Bounded input size (PN_CBOR_MAX_INPUT bytes).
 * - String/bytes pointers alias the original input buffer.
 * - Only map entry arrays require allocation.
 */

#ifndef PN_CBOR_H
#define PN_CBOR_H

#include "pubnub/providers/allocator.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** Maximum nesting depth for CBOR maps. */
#define PN_CBOR_MAX_DEPTH 5

/** Maximum input size in bytes (PubNub tokens never exceed this). */
#define PN_CBOR_MAX_INPUT 4096

/**
 * @brief CBOR value type discriminator.
 *
 * Values match CBOR major type numbers for the supported subset.
 */
typedef enum pn_cbor_type {
    /** Unsigned integer (major type 0). */
    PN_CBOR_UINT = 0,
    /** Byte string (major type 2). */
    PN_CBOR_BYTES = 2,
    /** UTF-8 text string (major type 3). */
    PN_CBOR_STRING = 3,
    /** Map of key-value pairs (major type 5). */
    PN_CBOR_MAP = 5,
    /** Sentinel for invalid/uninitialized values. */
    PN_CBOR_INVALID = 0xFF
} pn_cbor_type_t;

typedef struct pn_cbor_value pn_cbor_value_t;

/**
 * @brief Single key-value entry within a CBOR map.
 */
typedef struct pn_cbor_map_entry {
    /** Key node (typically PN_CBOR_STRING). */
    pn_cbor_value_t* key;
    /** Value node (any supported type). */
    pn_cbor_value_t* value;
} pn_cbor_map_entry_t;

/**
 * @brief Parsed CBOR value node.
 *
 * Forms a tree: map nodes contain arrays of entries, each entry
 * pointing to child value nodes. Leaf nodes (uint, bytes, string)
 * have no children. String and bytes pointers alias the original
 * input buffer and remain valid only while the input is alive.
 */
struct pn_cbor_value {
    /** Type discriminator. */
    pn_cbor_type_t type;

    /** Type-specific payload. */
    union {
        /** PN_CBOR_UINT: 64-bit unsigned value. */
        uint64_t uint_val;

        /** PN_CBOR_BYTES: pointer into input buffer + length. */
        struct {
            const uint8_t* ptr;
            size_t         len;
        } bytes;

        /** PN_CBOR_STRING: pointer into input buffer + length. */
        struct {
            const char* ptr;
            size_t      len;
        } string;

        /** PN_CBOR_MAP: allocated entry array + count. */
        struct {
            pn_cbor_map_entry_t* entries;
            size_t               count;
        } map;
    } data;
};

/**
 * @brief Parse CBOR bytes into a value tree.
 *
 * Decodes a complete CBOR item from @p input. Only the PubNub token
 * CBOR subset is supported (uint, bytes, string, map). Rejects
 * inputs larger than PN_CBOR_MAX_INPUT bytes and nesting deeper
 * than PN_CBOR_MAX_DEPTH levels.
 *
 * @param input     Raw CBOR bytes (borrowed; must remain valid while
 *                  the returned tree is in use).
 * @param input_len Length of @p input in bytes.
 * @param alloc     Allocator for tree nodes and map entry arrays.
 * @return Root value node on success, or NULL on any parse error.
 *         Call @ref pn_cbor_cleanup to free the returned tree.
 */
pn_cbor_value_t* pn_cbor_parse(const uint8_t*               input,
                               size_t                       input_len,
                               pubnub_allocator_provider_t* alloc);

/**
 * @brief Look up a key in a map node by byte content.
 *
 * Performs a linear scan of the map's entries. Matches both text
 * string keys (major type 3) and byte string keys (major type 2)
 * since PubNub tokens encode keys as byte strings for compactness.
 * Keys are compared by exact length + byte content match.
 *
 * @param map     Map node to search (must be PN_CBOR_MAP or NULL).
 * @param key     Key bytes to find (not required to be NUL-terminated).
 * @param key_len Length of @p key in bytes.
 * @return Pointer to the value node if found, or NULL if @p map is
 *         not a map or the key is absent.
 */
pn_cbor_value_t* pn_cbor_map_get(const pn_cbor_value_t* map,
                                 const char*            key,
                                 size_t                 key_len);

/**
 * @brief Free the entire parsed CBOR tree.
 *
 * Releases all allocator-owned memory (nodes and map entry arrays).
 * Safe to call with NULL arguments.
 *
 * @param root  Root node returned by @ref pn_cbor_parse (or NULL).
 * @param alloc Allocator used during parsing (or NULL).
 */
void pn_cbor_cleanup(pn_cbor_value_t* root, pubnub_allocator_provider_t* alloc);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_CBOR_H */
