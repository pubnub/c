/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file serialization_jsmn.c
 * @brief jsmn-backed serialization provider.
 *
 * The `jsmn` provider is the embedded-friendly JSON serialization
 * backend, paired with either the stdlib or arena-based allocator
 * without code change. It wraps jsmn v1.1.0 (MIT-licensed; fetched via
 * FetchContent, no local patches) behind the
 * `pubnub_serialization_provider_t` vtable.
 *
 * @par Parse strategy
 *
 * jsmn is a tokenize-only library: a call to @c jsmn_parse populates
 * an array of @c jsmntok_t records with `(type, start, end, size)`
 * fields that index into the original input buffer. The provider runs
 * a two-step parse:
 *
 *   1. Tokenize into an allocator-owned `jsmntok_t` array, doubling
 *      capacity on @c JSMN_ERROR_NOMEM up to a hard ceiling
 *      (@ref PN_JSMN_MAX_TOKEN_DOUBLINGS) so that pathological inputs
 *      cannot exhaust memory unboundedly.
 *   2. Walk the token array linearly and materialize a tree of
 *      @ref pn_jsv_node_t nodes. Each token's source bytes are COPIED
 *      into allocator-backed storage; the resulting tree is independent
 *      of the input buffer's lifetime.
 *
 * @par RX buffer lifetime invariant
 *
 * The jsmn backend MAY adopt a future zero-copy parse strategy in which
 * string nodes alias spans inside the response RX buffer rather than
 * copying. That optimization is correct only if the request slot's
 * release sequence runs `feature_state_cleanup` (which destroys the
 * tree) BEFORE @c buf_release(RX). The invariant is documented in
 * `src/core/runtime/request_pool.c`.
 *
 * Currently the backend COPIES strings on parse (via @ref pn_jsv_dup_str),
 * keeping the implementation safe regardless of caller buffer lifetime.
 *
 * @par Integer precision
 *
 * jsmn does not interpret primitive tokens - numbers, booleans, and
 * `null` arrive as a span of source bytes. The provider classifies
 * each primitive: a literal containing no `.`, `e`, or `E` is parsed
 * via @c strtol with an explicit INT_MIN/INT_MAX range check. Values
 * that overflow @c int are classified as DOUBLE (same behaviour as
 * cJSON). PubNub timetokens (17-digit decimals) are always strings
 * in the wire format and do not flow through the integer path.
 *
 * @par Verbatim raw nodes
 *
 * `value_create_raw` produces a @c PN_JSV_RAW node whose bytes are
 * emitted unchanged on @c serialize via @c memcpy. This provides the
 * byte-stable round-trip contract that PAM signature computation
 * depends on.
 *
 * @par Allocator wiring
 *
 * Every node, pair, string, and token-array element flows through the
 * `pubnub_allocator_provider_t` vtable supplied via @ref init. When
 * the provider is used without an explicit @c init call (e.g. an
 * integrator that configures the SDK before its allocator is ready),
 * the backend falls back to libc `malloc` / `realloc` / `free` so the
 * vtable remains callable.
 *
 * @par Per-context vs singleton
 *
 * The provider struct embeds the vtable as its first member and
 * carries the resolved allocator plus an init reference count. A
 * static singleton is returned from @ref pn_serialization_default and
 * may be shared by multiple concurrently-live contexts.
 *
 * @ref init captures the allocator on the first call (@c ref_count
 * transition 0 -> 1) and increments the count on every call. @ref
 * deinit decrements the count and clears the allocator only when it
 * reaches zero. This keeps a second context's serialization working
 * after the first context deinits - the earlier singleton design
 * NULLed the allocator on the first deinit and corrupted any surviving
 * context.
 *
 * If a later context supplies a different allocator instance than the
 * first, the mismatch is logged at WARNING level and the
 * first-registered allocator is retained. On embedded profiles all
 * contexts share one allocator instance, so the mismatch path is a
 * misconfiguration guard rather than a supported mode. The future
 * `pubnub_init`-style API will let callers compose per-context
 * provider instances when strict per-context isolation is needed.
 *
 * @par PUBNUB_CFG_JSON_DOUBLE asymmetry
 *
 * When @c PUBNUB_CFG_JSON_DOUBLE is 0 the @c value_create_double
 * and @c value_as_double vtable slots are NULL. The parser still
 * classifies floating-point literals as @ref PUBNUB_JSON_DOUBLE so
 * inbound payloads carrying doubles do not mis-parse, but the value
 * is unreadable through the vtable - the node can be carried,
 * serialized verbatim, and freed.
 */

#include "pubnub/providers/serialization.h"

#include "pubnub/pubnub_compat.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/logger.h"

#include "pn_format.h"
#include "pn_json_unescape.h"

/* JSMN_HEADER pulls in only the prototypes from jsmn.h - the
 * implementation lives in jsmn_impl.c so vendored-code warnings stay
 * isolated to that translation unit.
 *
 * JSMN_STRICT is intentionally NOT defined: under strict mode, jsmn
 * rejects bare top-level primitives ("42", "1.5", etc.) because they
 * lack a closing delimiter, which our int64-timetoken round-trip
 * tests rely on. Non-strict mode treats every unquoted token as a
 * primitive; classification (number / boolean / null) happens in our
 * own walker via @ref pn_jsmn_make_primitive, so the lax mode does
 * not weaken the contract observed at the SDK layer. */
#define JSMN_HEADER
#include <jsmn.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* %.17g used in pn_jsmn_emit_double is outside the pn_snprintf
 * minimal subset. pn_snprintf dispatches to libc when
 * PUBNUB_CFG_MINIMAL_FORMATTER=0; the double path is compiled out
 * on bare-metal profiles where the minimal formatter lacks precision
 * specifiers. */

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_serialization_provider_t* pn_serialization_default(void);

/**
 * @brief Discriminator for the SDK-internal jsmn-backed node type.
 *
 * Mapped 1:1 onto @ref pubnub_json_type_t at the vtable boundary. The
 * separation keeps the public enum free of jsmn-specific encoding
 * concerns and lets the backend extend its own representation if
 * needed (e.g. a future view-into-RX variant) without changing the
 * public type tag.
 */
typedef enum pn_jsv_type {
    /** JSON null literal. */
    PN_JSV_NULL = 0,
    /** JSON boolean (true / false). */
    PN_JSV_BOOL,
    /** JSON integer (int precision). */
    PN_JSV_INT,
    /** JSON floating-point. Gated on @c PUBNUB_CFG_JSON_DOUBLE. */
    PN_JSV_DOUBLE,
    /** JSON string (allocator-owned copy). */
    PN_JSV_STRING,
    /** JSON string aliasing caller-owned bytes (no copy, no free). */
    PN_JSV_STRING_VIEW,
    /** JSON array. */
    PN_JSV_ARRAY,
    /** JSON object. */
    PN_JSV_OBJECT,
    /** Pre-serialized verbatim bytes. */
    PN_JSV_RAW
} pn_jsv_type_t;

typedef struct pn_jsv_node pn_jsv_node_t;
typedef struct pn_jsv_pair pn_jsv_pair_t;

/**
 * @brief jsmn-backed JSON value node.
 *
 * Carries the type tag plus a discriminated union of payloads. All
 * variable-length storage (strings, array items, object pairs) is
 * allocator-owned and freed recursively by @ref pn_jsv_free_node.
 */
struct pn_jsv_node {
    /** Node type tag. */
    pn_jsv_type_t type;

    /** Slab base pointer. Non-NULL on ALL nodes within a slab-allocated
     *  parse tree (root and children alike). The root is identifiable by
     *  its fixed offset from the slab header (see @ref pn_slab_node_is_root).
     *  Ownership: only the root frees the slab in value_destroy. */
    void* _slab;

    union {
        /** PN_JSV_BOOL: 0 = false, 1 = true. */
        int b;
        /** PN_JSV_INT: integer value. */
        int i;
        /** PN_JSV_DOUBLE: IEEE-754 double value. */
        double d;

        /** PN_JSV_STRING and PN_JSV_RAW. */
        struct {
            /** Allocator-owned NUL-terminated copy of the bytes. */
            char* ptr;
            /** Byte length of @c ptr (excludes the trailing NUL). */
            size_t len;
        } s;

        /** PN_JSV_ARRAY. */
        struct {
            /** Heap array of child node pointers, length @c count. */
            pn_jsv_node_t** items;
            /** Number of populated entries. */
            size_t count;
            /** Allocated capacity of @c items in entries. */
            size_t cap;
        } arr;

        /** PN_JSV_OBJECT. */
        struct {
            /** Heap array of pair pointers, length @c count. */
            pn_jsv_pair_t** pairs;
            /** Number of populated entries. */
            size_t count;
            /** Allocated capacity of @c pairs in entries. */
            size_t cap;
        } obj;
    } u;
};

PUBNUB_STATIC_ASSERT(sizeof(pn_jsv_node_t) <= 40,
                     "pn_jsv_node_t must fit in 40 bytes for slab budget");

/**
 * @brief Single key/value pair owned by a @ref PN_JSV_OBJECT node.
 *
 * Keys are always copied at construction time. Pair lifetime is tied
 * to the parent object node.
 */
struct pn_jsv_pair {
    /** Allocator-owned NUL-terminated copy of the key bytes. */
    char* key;
    /** Byte length of @c key (excludes the trailing NUL). */
    size_t key_len;
    /** Owning pointer to the value subtree. */
    pn_jsv_node_t* value;
};

/**
 * @brief Provider extended struct: vtable + resolved allocator.
 *
 * First-member embedding lets the SDK pass a
 * `pubnub_serialization_provider_t*` through the vtable surface; the
 * backend casts back to the extended type to recover the allocator
 * pointer set during @ref pn_jsmn_init.
 */
typedef struct pn_jsmn_provider {
    /** Public vtable (must remain first member). */
    pubnub_serialization_provider_t base;
    /**
     * Resolved allocator. NULL until @ref pn_jsmn_init runs; when NULL
     * the backend falls back to libc malloc / realloc / free so the
     * vtable is callable in pre-init scenarios (e.g. unit tests that
     * construct trees directly without booting a full context).
     */
    pubnub_allocator_provider_t* allocator;
    /**
     * Init reference count. Incremented by @ref pn_jsmn_init and
     * decremented by @ref jsmn_deinit. The allocator is captured on the
     * 0 -> 1 transition and cleared only on the 1 -> 0 transition so a
     * shared singleton survives one context's deinit while another
     * remains live.
     */
    uint8_t ref_count;
} pn_jsmn_provider_t;

/**
 * @brief Iterator opaque-storage shape: object pointer + cursor index.
 *
 * Stored via @c memcpy into @ref pubnub_json_iter_t::opaque so no
 * alignment assumption is made on the underlying byte array.
 */
typedef struct pn_jsv_iter_state {
    /** Borrowed pointer to the object being iterated. */
    pn_jsv_node_t* obj;
    /** Index of the next pair to return. */
    size_t cursor;
} pn_jsv_iter_state_t;

PUBNUB_STATIC_ASSERT(sizeof(pn_jsv_iter_state_t)
                         <= sizeof(((pubnub_json_iter_t*)0)->opaque),
                     "jsmn iter state fits pubnub_json_iter_t opaque storage");

/**
 * @brief Array-iterator opaque-storage shape: array pointer + index.
 *
 * Stored via @c memcpy into @ref pubnub_json_array_iter_t::opaque so no
 * alignment assumption is made on the underlying byte array.
 */
typedef struct pn_jsv_array_iter_state {
    /** Borrowed pointer to the array being iterated. */
    pn_jsv_node_t* arr;
    /** Index of the next element to return. */
    size_t cursor;
} pn_jsv_array_iter_state_t;

PUBNUB_STATIC_ASSERT(
    sizeof(pn_jsv_array_iter_state_t)
        <= sizeof(((pubnub_json_array_iter_t*)0)->opaque),
    "jsmn array iter state fits pubnub_json_array_iter_t opaque storage");

/**
 * @brief Maximum number of times the parser doubles its token capacity.
 *
 * Each doubling starts from 32 tokens, so the hard ceiling is
 * @c 32 << PN_JSMN_MAX_TOKEN_DOUBLINGS = 32768 tokens. Pathological
 * inputs that exceed this cap fail parse cleanly rather than running
 * the allocator out of memory.
 */
#define PN_JSMN_MAX_TOKEN_DOUBLINGS 10

/**
 * @brief Initial token-array capacity for the first parse attempt.
 *
 * Most PubNub responses fit comfortably below 32 tokens; doubling on
 * @c JSMN_ERROR_NOMEM scales up for larger envelopes.
 */
#define PN_JSMN_INITIAL_TOKEN_CAP 32

/** @brief Slab bump-pointer alignment (8 bytes for double). */
#define PN_SLAB_ALIGN sizeof(double)

/** @brief Round @p x up to the next multiple of alignment @p a. */
#define PN_ALIGN_UP(x, a) (((x) + (a) - 1U) & ~((a) - 1U))

/**
 * @brief Bytes to add to pointer @p p to reach alignment @p a (a power of 2).
 *
 * Used for pointer alignment via arithmetic (add the offset to @p p)
 * instead of an integer-to-pointer cast.
 */
#define PN_ALIGN_OFFSET(p, a) \
    (((a) - ((uintptr_t)(p) & ((a) - 1U))) & ((a) - 1U))

PUBNUB_STATIC_ASSERT(0U == (PN_SLAB_ALIGN & (PN_SLAB_ALIGN - 1U)),
                     "slab alignment must be power of 2");

/**
 * @brief Header for a contiguous slab that holds all parse-tree nodes,
 *        pairs, strings, and pointer arrays for a single parse call.
 */
typedef struct pn_jsmn_slab {
    /** Next free byte inside the slab. */
    uint8_t* cursor;
    /** One past the last byte of the slab. */
    uint8_t* end;
} pn_jsmn_slab_t;

/** @brief Bump-allocate @p size bytes from @p slab with natural alignment. */
static void* pn_slab_bump(pn_jsmn_slab_t* slab, size_t size)
{
    uint8_t* aligned;
    size_t   padded;

    if (NULL == slab || 0 == size) {
        return NULL;
    }
    aligned = slab->cursor + PN_ALIGN_OFFSET(slab->cursor, PN_SLAB_ALIGN);
    if (aligned >= slab->end) {
        return NULL;
    }
    padded = (size_t)(slab->end - aligned);
    if (padded < size) {
        return NULL;
    }
    slab->cursor = aligned + size;
    return aligned;
}

/**
 * @brief Allocate @p size bytes through the resolved allocator.
 *
 * Falls back to libc @c malloc when @ref pn_jsmn_provider::allocator
 * is NULL (pre-init scenarios). The returned memory is NOT zero-
 * initialized; callers that need zeroing must @c memset explicitly.
 */
static void* pn_jsv_alloc(pn_jsmn_provider_t* prov, size_t size)
{
    if (NULL == prov || 0 == size) {
        return NULL;
    }
    if (NULL == prov->allocator) {
        return malloc(size);
    }
    return prov->allocator->alloc(prov->allocator, size, 0);
}

/**
 * @brief Reallocate a previously-allocated block.
 *
 * @p old_size is forwarded to allocator implementations that lack
 * libc's per-block size tracking (arenas / pools). Falls back to libc
 * @c realloc when no allocator is bound.
 */
static void* pn_jsv_realloc(pn_jsmn_provider_t* prov,
                            void*               ptr,
                            size_t              old_size,
                            size_t              new_size)
{
    if (NULL == prov) {
        return NULL;
    }
    if (NULL == prov->allocator) {
        return realloc(ptr, new_size);
    }
    if (NULL == prov->allocator->realloc) {
        /* Allocator does not support in-place realloc; fall back to
         * alloc-new + copy + free-old. Arena allocators that omit
         * realloc typically do not need it on this code path because
         * we only grow the items / pairs / scratch arrays during
         * tree construction. */
        void* new_ptr = prov->allocator->alloc(prov->allocator, new_size, 0);
        if (NULL == new_ptr) {
            return NULL;
        }
        if (NULL != ptr && old_size > 0) {
            size_t copy_len = old_size < new_size ? old_size : new_size;
            memcpy(new_ptr, ptr, copy_len);
            prov->allocator->free(prov->allocator, ptr);
        }
        return new_ptr;
    }
    return prov->allocator->realloc(prov->allocator, ptr, old_size, new_size, 0);
}

/**
 * @brief Free a block previously returned by @ref pn_jsv_alloc.
 */
static void pn_jsv_free(pn_jsmn_provider_t* prov, void* ptr)
{
    if (NULL == prov || NULL == ptr) {
        return;
    }
    if (NULL == prov->allocator) {
        free(ptr);
        return;
    }
    prov->allocator->free(prov->allocator, ptr);
}

static void pn_jsv_free_node(pn_jsmn_provider_t* prov, pn_jsv_node_t* node);

/**
 * @brief Free a key/value pair and its value subtree.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static void pn_jsv_free_pair(pn_jsmn_provider_t* prov, pn_jsv_pair_t* pair)
{
    if (NULL == pair) {
        return;
    }
    pn_jsv_free(prov, pair->key);
    pn_jsv_free_node(prov, pair->value);
    pn_jsv_free(prov, pair);
}

/**
 * @brief Returns non-zero if @p node is the slab-allocated tree root.
 *
 * The root is always the first bump allocation in the slab. We compute
 * its address by aligning the ADDRESS past the header (matching what
 * pn_slab_bump does), not by adding an aligned SIZE to the base. The
 * distinction matters when the allocator returns a base that is not
 * PN_SLAB_ALIGN-aligned (e.g., arena on ESP32 with 4-byte zone_b).
 */
static int pn_slab_node_is_root(const pn_jsv_node_t* node)
{
    const uint8_t* base  = (const uint8_t*)node->_slab + sizeof(pn_jsmn_slab_t);
    const uint8_t* first = base + PN_ALIGN_OFFSET(base, PN_SLAB_ALIGN);
    return (const uint8_t*)node == first;
}

/**
 * @brief Recursively free a node and any owned children / strings.
 *
 * Safe on NULL. Slab-tagged nodes are handled via whole-slab free when
 * the root is encountered; non-root slab nodes are no-ops. Constructor-
 * built nodes walk into arrays and objects to free element nodes and
 * pairs.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static void pn_jsv_free_node(pn_jsmn_provider_t* prov, pn_jsv_node_t* node)
{
    size_t i;

    if (NULL == node) {
        return;
    }
    if (NULL != node->_slab) {
        /* Slab node: root frees the entire slab; children are freed
         * as part of the slab and need no individual free. */
        if (pn_slab_node_is_root(node)) {
            pn_jsv_free(prov, node->_slab);
        }
        return;
    }
    switch (node->type) {
    case PN_JSV_STRING:
    case PN_JSV_RAW: pn_jsv_free(prov, node->u.s.ptr); break;
    case PN_JSV_STRING_VIEW:
        /* Borrowed bytes - caller retains ownership. Do NOT free. */
        break;
    case PN_JSV_ARRAY: {
        for (i = 0; i < node->u.arr.count; ++i) {
            pn_jsv_free_node(prov, node->u.arr.items[i]);
        }
        pn_jsv_free(prov, (void*)node->u.arr.items);
        break;
    }
    case PN_JSV_OBJECT: {
        for (i = 0; i < node->u.obj.count; ++i) {
            pn_jsv_free_pair(prov, node->u.obj.pairs[i]);
        }
        pn_jsv_free(prov, (void*)node->u.obj.pairs);
        break;
    }
    case PN_JSV_NULL:
    case PN_JSV_BOOL:
    case PN_JSV_INT:
    case PN_JSV_DOUBLE:
    default: break;
    }
    pn_jsv_free(prov, node);
}

/**
 * @brief Allocate a zero-initialized node.
 */
static pn_jsv_node_t* pn_jsv_alloc_node(pn_jsmn_provider_t* prov)
{
    pn_jsv_node_t* node = (pn_jsv_node_t*)pn_jsv_alloc(prov, sizeof(*node));
    if (NULL == node) {
        return NULL;
    }
    memset(node, 0, sizeof(*node));
    return node;
}

/**
 * @brief Allocate a zero-initialized object pair.
 */
static pn_jsv_pair_t* pn_jsv_alloc_pair(pn_jsmn_provider_t* prov)
{
    pn_jsv_pair_t* pair = (pn_jsv_pair_t*)pn_jsv_alloc(prov, sizeof(*pair));
    if (NULL == pair) {
        return NULL;
    }
    memset(pair, 0, sizeof(*pair));
    return pair;
}

/**
 * @brief Allocator-aware @c strdup that copies @p len bytes and NUL-terminates.
 *
 * Returns NULL when @p src is NULL or allocation fails. Empty (@p len == 0)
 * is a legal input that returns a freshly-allocated 1-byte buffer
 * containing only the NUL terminator - callers can pass it to
 * functions expecting a NUL-terminated string without special-casing.
 */
static char* pn_jsv_dup_str(pn_jsmn_provider_t* prov, const char* src, size_t len)
{
    if (NULL == src) {
        return NULL;
    }
    char* dst = (char*)pn_jsv_alloc(prov, len + 1);
    if (NULL == dst) {
        return NULL;
    }
    if (len > 0) {
        memcpy(dst, src, len);
    }
    dst[len] = '\0';
    return dst;
}

/**
 * @brief Ensure an array node has capacity for @p min_cap entries.
 *
 * Doubles the capacity until the request fits; never shrinks. Returns
 * @c PUBNUB_OK on success, @c PUBNUB_ERR_OUT_OF_MEMORY on allocation
 * failure (the array is left untouched on failure).
 */
static pubnub_res_t pn_jsv_array_reserve(pn_jsmn_provider_t* prov,
                                         pn_jsv_node_t*      arr,
                                         size_t              min_cap)
{
    if (arr->u.arr.cap >= min_cap) {
        return PUBNUB_OK;
    }
    size_t new_cap = arr->u.arr.cap > 0 ? arr->u.arr.cap : 4;
    while (new_cap < min_cap) {
        size_t doubled = new_cap * 2;
        if (doubled < new_cap) {
            new_cap = min_cap;
            break;
        }
        new_cap = doubled;
    }
    pn_jsv_node_t** items =
        (pn_jsv_node_t**)pn_jsv_realloc(prov,
                                        (void*)arr->u.arr.items,
                                        arr->u.arr.cap * sizeof(pn_jsv_node_t*),
                                        new_cap * sizeof(pn_jsv_node_t*));
    if (NULL == items) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    arr->u.arr.items = items;
    arr->u.arr.cap   = new_cap;
    return PUBNUB_OK;
}

/**
 * @brief Append a child node to an array, growing capacity as needed.
 *
 * On success ownership of @p child transfers to @p arr; on failure the
 * caller still owns @p child.
 */
static pubnub_res_t pn_jsv_array_push(pn_jsmn_provider_t* prov,
                                      pn_jsv_node_t*      arr,
                                      pn_jsv_node_t*      child)
{
    pubnub_res_t rc = pn_jsv_array_reserve(prov, arr, arr->u.arr.count + 1);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    arr->u.arr.items[arr->u.arr.count++] = child;
    return PUBNUB_OK;
}

/**
 * @brief Ensure an object node has capacity for @p min_cap pairs.
 */
static pubnub_res_t pn_jsv_object_reserve_int(pn_jsmn_provider_t* prov,
                                              pn_jsv_node_t*      obj,
                                              size_t              min_cap)
{
    if (obj->u.obj.cap >= min_cap) {
        return PUBNUB_OK;
    }
    size_t new_cap = obj->u.obj.cap > 0 ? obj->u.obj.cap : 4;
    while (new_cap < min_cap) {
        size_t doubled = new_cap * 2;
        if (doubled < new_cap) {
            new_cap = min_cap;
            break;
        }
        new_cap = doubled;
    }
    pn_jsv_pair_t** pairs =
        (pn_jsv_pair_t**)pn_jsv_realloc(prov,
                                        (void*)obj->u.obj.pairs,
                                        obj->u.obj.cap * sizeof(pn_jsv_pair_t*),
                                        new_cap * sizeof(pn_jsv_pair_t*));
    if (NULL == pairs) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    obj->u.obj.pairs = pairs;
    obj->u.obj.cap   = new_cap;
    return PUBNUB_OK;
}

/**
 * @brief Find a pair by key bytes; returns the index or SIZE_MAX.
 */
static size_t pn_jsv_object_find(const pn_jsv_node_t* obj, const char* key, size_t key_len)
{
    size_t i;

    for (i = 0; i < obj->u.obj.count; ++i) {
        const pn_jsv_pair_t* pair = obj->u.obj.pairs[i];
        if (pair->key_len == key_len
            && (0 == key_len || 0 == memcmp(pair->key, key, key_len))) {
            return i;
        }
    }
    return SIZE_MAX;
}

/**
 * @brief Insert or replace a pair by key.
 *
 * On replace, the prior pair (and its value subtree) is freed before
 * the new pair takes its slot. On insert, the object grows its pair
 * array as needed.
 */
static pubnub_res_t pn_jsv_object_set(pn_jsmn_provider_t* prov,
                                      pn_jsv_node_t*      obj,
                                      const char*         key,
                                      size_t              key_len,
                                      pn_jsv_node_t*      child)
{
    size_t existing = pn_jsv_object_find(obj, key, key_len);
    if (existing != SIZE_MAX) {
        pn_jsv_pair_t* pair = obj->u.obj.pairs[existing];
        if (pair->value == child) {
            /* Self-assign: freeing the old value then re-storing the same
             * node would read freed memory. Value already set — no-op. */
            return PUBNUB_OK;
        }
        pn_jsv_free_node(prov, pair->value);
        pair->value = child;
        return PUBNUB_OK;
    }
    pubnub_res_t rc = pn_jsv_object_reserve_int(prov, obj, obj->u.obj.count + 1);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    pn_jsv_pair_t* pair = pn_jsv_alloc_pair(prov);
    if (NULL == pair) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    pair->key = pn_jsv_dup_str(prov, key, key_len);
    if (NULL == pair->key) {
        pn_jsv_free(prov, pair);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    pair->key_len                        = key_len;
    pair->value                          = child;
    obj->u.obj.pairs[obj->u.obj.count++] = pair;
    return PUBNUB_OK;
}

/**
 * @brief Reinterpret an internal node pointer as the public opaque
 *        handle.
 *
 * `pubnub_json_value_t` is forward-declared in the public provider
 * header; consumers only ever hold pointers to it. The cast is a pure
 * pointer-type reinterpretation.
 */
static pubnub_json_value_t* node_to_opaque(pn_jsv_node_t* node)
{
    return (pubnub_json_value_t*)node;
}

/**
 * @brief Inverse of @ref node_to_opaque.
 *
 * Drops @c const because mutators take a non-const handle even when
 * the underlying tree object is the same; accessors that observe
 * @c const inputs still cast through here and treat the result as
 * read-only at the source level.
 */
static pn_jsv_node_t* opaque_to_node(const pubnub_json_value_t* value)
{
    return (pn_jsv_node_t*)value;
}

/**
 * @brief Recover @ref pn_jsmn_provider_t from the public vtable pointer.
 *
 * First-member embedding makes this a pure pointer-type cast.
 */
static pn_jsmn_provider_t* pn_jsmn_self(pubnub_serialization_provider_t* self)
{
    return (pn_jsmn_provider_t*)self;
}

/**
 * @brief Per-context init: capture @p deps->allocator, ref-counted.
 *
 * Captures the allocator on the first init (@c ref_count 0 -> 1) and
 * increments the count on every subsequent init. When a later context
 * supplies a different allocator instance, the mismatch is logged at
 * WARNING level and the first-registered allocator is retained; this
 * keeps a shared singleton usable across contexts that all wire the
 * same allocator (the common embedded case).
 *
 * Returning 0 signals success; the SDK reports a non-zero return as
 * provider-init failure during context bring-up.
 */
static int pn_jsmn_init(pubnub_serialization_provider_t* self,
                        const pubnub_provider_deps_t*    deps)
{
    if (NULL == self || NULL == deps) {
        return -1;
    }
    pn_jsmn_provider_t* prov = pn_jsmn_self(self);
    if (0 == prov->ref_count) {
        prov->allocator = deps->allocator;
    } else if (prov->allocator != deps->allocator) {
        PUBNUB_LOG_TEXT(deps->logger,
                        PUBNUB_LOG_LEVEL_WARNING,
                        "jsmn serialization singleton already bound to a "
                        "different allocator; retaining the first one. "
                        "Contexts sharing this provider must use the same "
                        "allocator instance.");
    }
    /* ref_count is uint8_t; supports up to 255 concurrent contexts sharing
     * this singleton (well beyond any realistic embedded deployment). */
    prov->ref_count++;
    return 0;
}

/**
 * @brief Per-context deinit: release one init reference.
 *
 * Decrements the reference count and clears the stored allocator only
 * when the last context releases it (@c ref_count 1 -> 0). The
 * allocator instance itself is not owned by this provider; the
 * platform owns it. Defensive against an unbalanced deinit: a call
 * while @c ref_count is already zero is a no-op.
 */
static void jsmn_deinit(pubnub_serialization_provider_t* self)
{
    if (NULL == self) {
        return;
    }
    pn_jsmn_provider_t* prov = pn_jsmn_self(self);
    if (prov->ref_count > 0) {
        prov->ref_count--;
    }
    if (0 == prov->ref_count) {
        prov->allocator = NULL;
    }
}

/**
 * @brief Iterative sizing pass: compute the total slab bytes needed to
 *        materialize a token array into a node tree.
 *
 * Walks the jsmn token array once without recursion and sums up aligned
 * sizes for every node, pair, string copy, and pointer array. The
 * result is passed to a single allocator call in
 * @ref pn_jsmn_provider_parse.
 *
 * Uses a goto-based state machine to avoid recursion (embedded stack
 * safety). All locals are declared at function top before the first
 * label (C99 goto constraint).
 */
static size_t pn_jsmn_compute_slab_size(const jsmntok_t* tokens, int token_count)
{
    size_t           total    = 0;
    int              cursor   = 0;
    int              n        = 0;
    int              i        = 0;
    int              byte_len = 0;
    int              depth    = 0;
    int              parent_n[PUBNUB_CFG_JSON_MAX_NESTING_DEPTH];
    int              parent_i[PUBNUB_CFG_JSON_MAX_NESTING_DEPTH];
    int              parent_is_obj[PUBNUB_CFG_JSON_MAX_NESTING_DEPTH];
    const jsmntok_t* tok = NULL;

    if (NULL == tokens || token_count <= 0) {
        return 0;
    }

    /* Slab header lives at the front. Budget worst-case alignment
     * padding (PN_SLAB_ALIGN - 1) for allocators that return a base
     * not naturally aligned to PN_SLAB_ALIGN (e.g., arena on ESP32). */
    total += PN_ALIGN_UP(sizeof(pn_jsmn_slab_t), PN_SLAB_ALIGN)
           + (PN_SLAB_ALIGN - 1U);

loop:
    if (cursor >= token_count) {
        goto done;
    }
    tok = &tokens[cursor++];

    switch (tok->type) {
    case JSMN_PRIMITIVE:
    case JSMN_UNDEFINED:
        /* One node. */
        total += PN_ALIGN_UP(sizeof(pn_jsv_node_t), PN_SLAB_ALIGN);
        goto pop;

    case JSMN_STRING:
        /* One node + string copy (len + NUL). */
        byte_len = tok->end - tok->start;
        if (byte_len < 0) {
            byte_len = 0;
        }
        total += PN_ALIGN_UP(sizeof(pn_jsv_node_t), PN_SLAB_ALIGN);
        total += PN_ALIGN_UP((size_t)byte_len + 1, PN_SLAB_ALIGN);
        goto pop;

    case JSMN_ARRAY:
        n = tok->size;
        if (n < 0) {
            n = 0;
        }
        /* One node + items pointer array. */
        total += PN_ALIGN_UP(sizeof(pn_jsv_node_t), PN_SLAB_ALIGN);
        if (n > 0) {
            total += PN_ALIGN_UP((size_t)n * sizeof(pn_jsv_node_t*), PN_SLAB_ALIGN);
        }
        if (0 == n) {
            goto pop;
        }
        if (depth >= PUBNUB_CFG_JSON_MAX_NESTING_DEPTH) {
            goto done;
        }
        parent_n[depth]      = n;
        parent_i[depth]      = 0;
        parent_is_obj[depth] = 0;
        depth++;
        goto loop;

    case JSMN_OBJECT:
        n = tok->size;
        if (n < 0) {
            n = 0;
        }
        /* One node + pairs pointer array + n pairs + n key copies. */
        total += PN_ALIGN_UP(sizeof(pn_jsv_node_t), PN_SLAB_ALIGN);
        if (n > 0) {
            total += PN_ALIGN_UP((size_t)n * sizeof(pn_jsv_pair_t*), PN_SLAB_ALIGN);
            total += (size_t)n * PN_ALIGN_UP(sizeof(pn_jsv_pair_t), PN_SLAB_ALIGN);
        }
        if (0 == n) {
            goto pop;
        }
        if (depth >= PUBNUB_CFG_JSON_MAX_NESTING_DEPTH) {
            goto done;
        }
        parent_n[depth]      = n;
        parent_i[depth]      = 0;
        parent_is_obj[depth] = 1;
        depth++;
        goto process_key_then_value;

    default: goto done;
    }

process_key_then_value:
    if (cursor >= token_count) {
        goto done;
    }
    tok = &tokens[cursor++];
    /* Key string: only count the string copy, not a node (the
     * pn_jsv_pair_t already accounted for the key storage). */
    byte_len = tok->end - tok->start;
    if (byte_len < 0) {
        byte_len = 0;
    }
    total += PN_ALIGN_UP((size_t)byte_len + 1, PN_SLAB_ALIGN);
    /* Fall through to process the value. */
    goto loop;

pop:
    if (0 == depth) {
        goto done;
    }
    i = ++parent_i[depth - 1];
    n = parent_n[depth - 1];
    if (i >= n) {
        depth--;
        goto pop;
    }
    if (parent_is_obj[depth - 1]) {
        goto process_key_then_value;
    }
    goto loop;

done:
    return total;
}

/**
 * @brief Walk-state for the recursive token-to-tree builder.
 */
typedef struct pn_jsmn_walk {
    pn_jsmn_provider_t* prov;
    const char*         src;
    const jsmntok_t*    tokens;
    int                 token_count;
    int                 cursor;
    /** Current nesting depth. Bumped on entry to make_array /
     *  make_object, decremented on exit. Inputs that would push
     *  past @c PUBNUB_CFG_JSON_MAX_NESTING_DEPTH are rejected to
     *  bound recursive stack consumption on small embedded targets. */
    int depth;
    /** Slab for parse-path allocation. NULL when constructing trees
     *  via the public value_create_* API (per-node alloc mode). */
    pn_jsmn_slab_t* slab;
} pn_jsmn_walk_t;

/** @brief Allocate a zero-initialized node from the slab or allocator. */
static pn_jsv_node_t* pn_jsmn_walk_alloc_node(pn_jsmn_walk_t* walk)
{
    pn_jsv_node_t* node;
    if (NULL != walk->slab) {
        node = (pn_jsv_node_t*)pn_slab_bump(walk->slab, sizeof(pn_jsv_node_t));
        if (NULL == node) {
            return NULL;
        }
        memset(node, 0, sizeof(*node));
        node->_slab = (void*)walk->slab;
        return node;
    }
    return pn_jsv_alloc_node(walk->prov);
}

/** @brief Copy a string from the source into the slab or allocator. */
static char* pn_jsmn_walk_dup_str(pn_jsmn_walk_t* walk, const char* src, size_t len)
{
    char* dst;
    if (NULL != walk->slab) {
        dst = (char*)pn_slab_bump(walk->slab, len + 1);
        if (NULL == dst) {
            return NULL;
        }
        if (len > 0) {
            memcpy(dst, src, len);
        }
        dst[len] = '\0';
        return dst;
    }
    return pn_jsv_dup_str(walk->prov, src, len);
}

/** @brief Allocate a pair and set its key from the slab or allocator. */
static pn_jsv_pair_t* pn_jsmn_walk_add_pair(pn_jsmn_walk_t* walk,
                                            const char*     key,
                                            size_t          key_len,
                                            pn_jsv_node_t*  value)
{
    pn_jsv_pair_t* pair;
    if (NULL != walk->slab) {
        pair = (pn_jsv_pair_t*)pn_slab_bump(walk->slab, sizeof(pn_jsv_pair_t));
        if (NULL == pair) {
            return NULL;
        }
        memset(pair, 0, sizeof(*pair));
        pair->key = pn_jsmn_walk_dup_str(walk, key, key_len);
        if (NULL == pair->key) {
            return NULL;
        }
        pair->key_len = key_len;
        pn_json_unescape_inplace(pair->key, &pair->key_len);
        pair->value = value;
        return pair;
    }
    pair = pn_jsv_alloc_pair(walk->prov);
    if (NULL == pair) {
        return NULL;
    }
    pair->key = pn_jsv_dup_str(walk->prov, key, key_len);
    if (NULL == pair->key) {
        pn_jsv_free(walk->prov, pair);
        return NULL;
    }
    pair->key_len = key_len;
    pn_json_unescape_inplace(pair->key, &pair->key_len);
    pair->value = value;
    return pair;
}

/**
 * @brief Classify a primitive token's source text.
 *
 * jsmn lumps numbers, booleans, and @c null into @c JSMN_PRIMITIVE.
 * The classifier inspects the leading byte (and, for numbers, scans
 * for a decimal point or exponent) to discriminate between integer,
 * floating-point, boolean, and null literals. The numeric value is
 * decoded from the source bytes via @c strtol / @c strtod.
 */
static pn_jsv_node_t* pn_jsmn_make_primitive(pn_jsmn_walk_t*  walk,
                                             const jsmntok_t* tok)
{
    const char* start    = walk->src + tok->start;
    int         byte_len = tok->end - tok->start;
    size_t      span;
    char        first;
    char        number_buf[64];
    int         is_floating;
    size_t      si;
    char        ch;

    if (byte_len <= 0) {
        return NULL;
    }
    span  = (size_t)byte_len;
    first = start[0];

    /* Booleans and null: discriminate on the leading byte. jsmn's
     * primitive parser already validated the token shape. */
    if ('t' == first || 'f' == first) {
        pn_jsv_node_t* node = pn_jsmn_walk_alloc_node(walk);
        if (NULL == node) {
            return NULL;
        }
        node->type = PN_JSV_BOOL;
        node->u.b  = ('t' == first) ? 1 : 0;
        return node;
    }
    if ('n' == first) {
        pn_jsv_node_t* node = pn_jsmn_walk_alloc_node(walk);
        if (NULL == node) {
            return NULL;
        }
        node->type = PN_JSV_NULL;
        return node;
    }

    /* Number: decide int vs double by scanning for fractional /
     * exponent characters. The token bytes are not NUL-terminated --
     * we copy into a stack buffer (sufficient for any realistic
     * numeric literal; PubNub timetokens are 17 digits) for use with
     * strtol / strtod. */
    if (NULL != walk->slab && span >= sizeof(number_buf)) {
        /* Slab mode: no heap fallback for pathologically long
         * numeric literals; the sizing pass did not budget for it. */
        return NULL;
    }
    if (span >= sizeof(number_buf)) {
        /* Pathologically long numeric literal - fall back to double
         * via strtod with a heap buffer if doubles are enabled, else
         * fail. */
#if PUBNUB_CFG_JSON_DOUBLE
        char* heap = pn_jsv_dup_str(walk->prov, start, span);
        if (NULL == heap) {
            return NULL;
        }
        pn_jsv_node_t* node = pn_jsmn_walk_alloc_node(walk);
        if (NULL == node) {
            pn_jsv_free(walk->prov, heap);
            return NULL;
        }
        node->type = PN_JSV_DOUBLE;
        node->u.d  = strtod(heap, NULL);
        pn_jsv_free(walk->prov, heap);
        return node;
#else
        return NULL;
#endif
    }
    memcpy(number_buf, start, span);
    number_buf[span] = '\0';

    is_floating = 0;
    for (si = 0; si < span; ++si) {
        ch = number_buf[si];
        if ('.' == ch || 'e' == ch || 'E' == ch) {
            is_floating = 1;
            break;
        }
    }

    if (!is_floating) {
#if defined(__ZEPHYR__)
        /* Zephyr/picolibc: avoid errno (newlib errno.h may expand to
         * __errno() which picolibc does not export). Detect overflow
         * via boundary comparison — acceptable for PubNub payloads. */
        char* end       = NULL;
        long  parsed    = strtol(number_buf, &end, 10);
        int   range_err = (LONG_MAX == parsed || LONG_MIN == parsed);
#else
        int saved_errno = errno;
        errno           = 0;
        char* end       = NULL;
        long  parsed    = strtol(number_buf, &end, 10);
        int   range_err = (ERANGE == errno);
        errno           = saved_errno;
#endif
        if (!range_err && NULL != end && '\0' == *end && parsed >= (long)INT_MIN
            && parsed <= (long)INT_MAX) {
            pn_jsv_node_t* node = pn_jsmn_walk_alloc_node(walk);
            if (NULL == node) {
                return NULL;
            }
            node->type = PN_JSV_INT;
            node->u.i  = (int)parsed;
            return node;
        }
        /* Overflowed int range - fall through to double. */
    }

#if PUBNUB_CFG_JSON_DOUBLE
    {
        pn_jsv_node_t* node = pn_jsmn_walk_alloc_node(walk);
        if (NULL == node) {
            return NULL;
        }
        node->type = PN_JSV_DOUBLE;
        node->u.d  = strtod(number_buf, NULL);
        return node;
    }
#else
    /* Doubles are not supported in this build (no FPU on bare-metal
     * profiles). The node carries no usable value - @c u.d is left at
     * 0.0 and the type tag stays @c PN_JSV_DOUBLE so callers can detect
     * the unsupported branch via @c value_type. On serialize the
     * emitter writes the literal `null` for double-typed nodes when
     * the toggle is off, so the document remains valid JSON (lossy
     * but well-formed). The asymmetry is documented in the file-level
     * @par block. */
    {
        pn_jsv_node_t* node = pn_jsmn_walk_alloc_node(walk);
        if (NULL == node) {
            return NULL;
        }
        node->type = PN_JSV_DOUBLE;
        node->u.d  = 0.0;
        return node;
    }
#endif
}

static pn_jsv_node_t* pn_jsmn_walk_next(pn_jsmn_walk_t* walk);

/**
 * @brief Build a string node from a JSMN_STRING token.
 *
 * Bytes are copied into an owned buffer and JSON escape sequences
 * are decoded in place so @c value_as_string returns the decoded
 * string value, not the raw JSON representation.
 */
static pn_jsv_node_t* pn_jsmn_make_string(pn_jsmn_walk_t* walk, const jsmntok_t* tok)
{
    int byte_len = tok->end - tok->start;
    if (byte_len < 0) {
        return NULL;
    }
    pn_jsv_node_t* node = pn_jsmn_walk_alloc_node(walk);
    if (NULL == node) {
        return NULL;
    }
    node->type = PN_JSV_STRING;
    node->u.s.ptr =
        pn_jsmn_walk_dup_str(walk, walk->src + tok->start, (size_t)byte_len);
    if (NULL == node->u.s.ptr) {
        if (NULL == walk->slab) {
            pn_jsv_free(walk->prov, node);
        }
        return NULL;
    }
    node->u.s.len = (size_t)byte_len;
    pn_json_unescape_inplace(node->u.s.ptr, &node->u.s.len);
    return node;
}

/**
 * @brief Build an array node by recursively consuming child tokens.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static pn_jsv_node_t* pn_jsmn_make_array(pn_jsmn_walk_t* walk, const jsmntok_t* tok)
{
    int            n;
    int            i;
    pn_jsv_node_t* child;

    if (walk->depth >= PUBNUB_CFG_JSON_MAX_NESTING_DEPTH) {
        return NULL;
    }
    pn_jsv_node_t* node = pn_jsmn_walk_alloc_node(walk);
    if (NULL == node) {
        return NULL;
    }
    node->type = PN_JSV_ARRAY;
    n          = tok->size;
    if (n < 0) {
        if (NULL == walk->slab) {
            pn_jsv_free_node(walk->prov, node);
        }
        return NULL;
    }
    if (n > 0) {
        if (NULL != walk->slab) {
            /* Pre-allocate items array from slab. */
            node->u.arr.items = (pn_jsv_node_t**)pn_slab_bump(
                walk->slab, (size_t)n * sizeof(pn_jsv_node_t*));
            if (NULL == node->u.arr.items) {
                return NULL;
            }
            node->u.arr.cap = (size_t)n;
        } else {
            pubnub_res_t rc = pn_jsv_array_reserve(walk->prov, node, (size_t)n);
            if (PUBNUB_OK != rc) {
                pn_jsv_free_node(walk->prov, node);
                return NULL;
            }
        }
    }
    walk->depth++;
    for (i = 0; i < n; ++i) {
        child = pn_jsmn_walk_next(walk);
        if (NULL == child) {
            walk->depth--;
            if (NULL == walk->slab) {
                pn_jsv_free_node(walk->prov, node);
            }
            return NULL;
        }
        if (NULL != walk->slab) {
            /* Slab: items array was pre-allocated to exact size. */
            node->u.arr.items[node->u.arr.count++] = child;
        } else {
            if (PUBNUB_OK != pn_jsv_array_push(walk->prov, node, child)) {
                pn_jsv_free_node(walk->prov, child);
                walk->depth--;
                pn_jsv_free_node(walk->prov, node);
                return NULL;
            }
        }
    }
    walk->depth--;
    return node;
}

/**
 * @brief Build an object node by recursively consuming key/value pairs.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static pn_jsv_node_t* pn_jsmn_make_object(pn_jsmn_walk_t* walk, const jsmntok_t* tok)
{
    int              n;
    int              i;
    int              key_len;
    const jsmntok_t* key_tok;
    pn_jsv_node_t*   value;
    pn_jsv_pair_t*   pair;

    if (walk->depth >= PUBNUB_CFG_JSON_MAX_NESTING_DEPTH) {
        return NULL;
    }
    pn_jsv_node_t* node = pn_jsmn_walk_alloc_node(walk);
    if (NULL == node) {
        return NULL;
    }
    node->type = PN_JSV_OBJECT;
    n          = tok->size;
    if (n < 0) {
        if (NULL == walk->slab) {
            pn_jsv_free_node(walk->prov, node);
        }
        return NULL;
    }
    if (n > 0) {
        if (NULL != walk->slab) {
            /* Pre-allocate pairs pointer array from slab. */
            node->u.obj.pairs = (pn_jsv_pair_t**)pn_slab_bump(
                walk->slab, (size_t)n * sizeof(pn_jsv_pair_t*));
            if (NULL == node->u.obj.pairs) {
                return NULL;
            }
            node->u.obj.cap = (size_t)n;
        } else {
            pubnub_res_t rc =
                pn_jsv_object_reserve_int(walk->prov, node, (size_t)n);
            if (PUBNUB_OK != rc) {
                pn_jsv_free_node(walk->prov, node);
                return NULL;
            }
        }
    }
    walk->depth++;
    for (i = 0; i < n; ++i) {
        if (walk->cursor >= walk->token_count) {
            walk->depth--;
            if (NULL == walk->slab) {
                pn_jsv_free_node(walk->prov, node);
            }
            return NULL;
        }
        key_tok = &walk->tokens[walk->cursor++];
        if (JSMN_STRING != key_tok->type) {
            walk->depth--;
            if (NULL == walk->slab) {
                pn_jsv_free_node(walk->prov, node);
            }
            return NULL;
        }
        key_len = key_tok->end - key_tok->start;
        if (key_len < 0) {
            walk->depth--;
            if (NULL == walk->slab) {
                pn_jsv_free_node(walk->prov, node);
            }
            return NULL;
        }
        value = pn_jsmn_walk_next(walk);
        if (NULL == value) {
            walk->depth--;
            if (NULL == walk->slab) {
                pn_jsv_free_node(walk->prov, node);
            }
            return NULL;
        }
        if (NULL != walk->slab) {
            /* Slab mode: append pair directly, no deduplication. */
            pair = pn_jsmn_walk_add_pair(
                walk, walk->src + key_tok->start, (size_t)key_len, value);
            if (NULL == pair) {
                walk->depth--;
                return NULL;
            }
            node->u.obj.pairs[node->u.obj.count++] = pair;
        } else {
            /* Unescape the key into a temporary copy so
             * object_set stores decoded key bytes. */
            size_t ukey_len = (size_t)key_len;
            char*  ukey =
                pn_jsv_dup_str(walk->prov, walk->src + key_tok->start, ukey_len);
            pubnub_res_t set_rc;
            if (NULL == ukey) {
                pn_jsv_free_node(walk->prov, value);
                walk->depth--;
                pn_jsv_free_node(walk->prov, node);
                return NULL;
            }
            pn_json_unescape_inplace(ukey, &ukey_len);
            set_rc = pn_jsv_object_set(walk->prov, node, ukey, ukey_len, value);
            pn_jsv_free(walk->prov, ukey);
            if (PUBNUB_OK != set_rc) {
                pn_jsv_free_node(walk->prov, value);
                walk->depth--;
                pn_jsv_free_node(walk->prov, node);
                return NULL;
            }
        }
    }
    walk->depth--;
    return node;
}

/**
 * @brief Consume the next token from the walk and build its node.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static pn_jsv_node_t* pn_jsmn_walk_next(pn_jsmn_walk_t* walk)
{
    if (walk->cursor >= walk->token_count) {
        return NULL;
    }
    const jsmntok_t* tok = &walk->tokens[walk->cursor++];
    switch (tok->type) {
    case JSMN_OBJECT: return pn_jsmn_make_object(walk, tok);
    case JSMN_ARRAY: return pn_jsmn_make_array(walk, tok);
    case JSMN_STRING: return pn_jsmn_make_string(walk, tok);
    case JSMN_PRIMITIVE: return pn_jsmn_make_primitive(walk, tok);
    case JSMN_UNDEFINED:
    default: return NULL;
    }
}

/**
 * @brief Parse a JSON document into a jsmn-backed node tree.
 *
 * Allocates a token array (initial capacity @ref PN_JSMN_INITIAL_TOKEN_CAP),
 * doubles on @c JSMN_ERROR_NOMEM up to @ref PN_JSMN_MAX_TOKEN_DOUBLINGS,
 * then walks the tokens linearly to build the tree. Bytes are COPIED
 * into allocator-backed storage; the input buffer may be released
 * after this call returns.
 */
static pubnub_json_value_t* pn_jsmn_provider_parse(pubnub_serialization_provider_t* self,
                                                   const uint8_t* data,
                                                   size_t         len)
{
    pn_jsmn_provider_t* prov;
    size_t              cap;
    size_t              prev_cap;
    jsmntok_t*          tokens;
    jsmntok_t*          new_tokens;
    int                 token_count;
    int                 attempt;
    jsmn_parser         parser;
    int                 rc;
    size_t              doubled;
    size_t              slab_size;
    void*               slab_mem;
    pn_jsmn_slab_t*     slab_hdr;
    pn_jsmn_walk_t      walk;
    pn_jsv_node_t*      root;

    if (NULL == self || NULL == data || 0 == len) {
        return NULL;
    }

    prov        = pn_jsmn_self(self);
    cap         = PN_JSMN_INITIAL_TOKEN_CAP;
    prev_cap    = 0;
    tokens      = NULL;
    token_count = 0;

    for (attempt = 0; attempt <= PN_JSMN_MAX_TOKEN_DOUBLINGS; ++attempt) {
        new_tokens = (jsmntok_t*)pn_jsv_realloc(
            prov, tokens, prev_cap * sizeof(jsmntok_t), cap * sizeof(jsmntok_t));
        if (NULL == new_tokens) {
            pn_jsv_free(prov, tokens);
            return NULL;
        }
        tokens = new_tokens;
        jsmn_init(&parser);
        rc = jsmn_parse(&parser, (const char*)data, len, tokens, (unsigned int)cap);
        if (rc >= 0) {
            token_count = rc;
            break;
        }
        if (JSMN_ERROR_NOMEM != rc) {
            pn_jsv_free(prov, tokens);
            return NULL;
        }
        doubled = cap * 2;
        if (doubled <= cap) {
            pn_jsv_free(prov, tokens);
            return NULL;
        }
        prev_cap = cap;
        cap      = doubled;
    }

    if (token_count <= 0) {
        pn_jsv_free(prov, tokens);
        return NULL;
    }

    /* Sizing pass: compute exact slab bytes from the token array. */
    slab_size = pn_jsmn_compute_slab_size(tokens, token_count);
    if (0 == slab_size) {
        pn_jsv_free(prov, tokens);
        return NULL;
    }

    /* Request PN_SLAB_ALIGN (8-byte) alignment so the slab base
     * matches the sizing pass's alignment assumptions. On 32-bit
     * targets the default alloc alignment is 4 bytes; a 4-mod-8
     * base would consume unbudgeted padding on the first bump. */
    if (NULL != prov->allocator) {
        slab_mem =
            prov->allocator->alloc(prov->allocator, slab_size, PN_SLAB_ALIGN);
    } else {
        slab_mem = malloc(slab_size);
    }
    if (NULL == slab_mem) {
        pn_jsv_free(prov, tokens);
        return NULL;
    }
    memset(slab_mem, 0, slab_size);

    /* Initialize slab header at the front of the allocation.
     * Align cursor to the actual ADDRESS past the header so that
     * pn_slab_bump's first allocation is a no-op align. */
    slab_hdr         = (pn_jsmn_slab_t*)slab_mem;
    slab_hdr->cursor = (uint8_t*)slab_mem + sizeof(pn_jsmn_slab_t);
    slab_hdr->cursor += PN_ALIGN_OFFSET(slab_hdr->cursor, PN_SLAB_ALIGN);
    slab_hdr->end = (uint8_t*)slab_mem + slab_size;

    walk.prov        = prov;
    walk.src         = (const char*)data;
    walk.tokens      = tokens;
    walk.token_count = token_count;
    walk.cursor      = 0;
    walk.depth       = 0;
    walk.slab        = slab_hdr;

    root = pn_jsmn_walk_next(&walk);
    pn_jsv_free(prov, tokens);

    if (NULL == root) {
        pn_jsv_free(prov, slab_mem);
        return NULL;
    }
    /* All slab nodes already carry _slab from pn_jsmn_walk_alloc_node;
     * no separate root tagging needed. */
    return node_to_opaque(root);
}

/**
 * @brief Output-buffer cursor used during serialize.
 *
 * Wrapping the destination state in a struct lets the recursive
 * emit functions short-circuit cleanly on first overflow and report
 * the failure through @ref pn_jsmn_emit_byte.
 */
typedef struct pn_jsmn_out {
    uint8_t* buf;
    size_t   cap;
    size_t   len;
    int      overflow;
} pn_jsmn_out_t;

/**
 * @brief Append a single byte to @p out, marking overflow on overrun.
 */
static void pn_jsmn_emit_byte(pn_jsmn_out_t* out, uint8_t byte)
{
    if (out->overflow) {
        return;
    }
    if (out->len + 1 > out->cap) {
        out->overflow = 1;
        return;
    }
    out->buf[out->len++] = byte;
}

/**
 * @brief Append @p len bytes to @p out, marking overflow on overrun.
 */
static void pn_jsmn_emit_bytes(pn_jsmn_out_t* out, const void* bytes, size_t len)
{
    if (out->overflow || 0 == len) {
        return;
    }
    if (out->len + len > out->cap) {
        out->overflow = 1;
        return;
    }
    memcpy(out->buf + out->len, bytes, len);
    out->len += len;
}

/**
 * @brief Emit a JSON-escaped string literal into @p out.
 *
 * Implements the RFC 8259 §7 escape rules: `"`, `\`, and the C0
 * control characters (`\b`, `\f`, `\n`, `\r`, `\t`, plus `\u00XX`
 * for the rest). The forward slash is left unescaped (RFC 8259
 * permits both forms) so that round-trip output matches the
 * canonical compact form.
 */
static void pn_jsmn_emit_escaped(pn_jsmn_out_t* out, const char* str, size_t len)
{
    size_t i;

    pn_jsmn_emit_byte(out, '"');
    for (i = 0; i < len && !out->overflow; ++i) {
        unsigned char c = (unsigned char)str[i];
        switch (c) {
        case '"': pn_jsmn_emit_bytes(out, "\\\"", 2); break;
        case '\\': pn_jsmn_emit_bytes(out, "\\\\", 2); break;
        case '\b': pn_jsmn_emit_bytes(out, "\\b", 2); break;
        case '\f': pn_jsmn_emit_bytes(out, "\\f", 2); break;
        case '\n': pn_jsmn_emit_bytes(out, "\\n", 2); break;
        case '\r': pn_jsmn_emit_bytes(out, "\\r", 2); break;
        case '\t': pn_jsmn_emit_bytes(out, "\\t", 2); break;
        default:
            if (c < 0x20) {
                /* Hand-rolled "\u00XX" emission. The fixed format (six
                 * bytes, two hex digits) lets us avoid pulling libc
                 * snprintf into the embedded build path. The high
                 * nibble is always 0 for c < 0x20; only the low byte's
                 * two hex digits vary. */
                static const char hex_digits[] = "0123456789abcdef";
                char              esc[6];
                esc[0] = '\\';
                esc[1] = 'u';
                esc[2] = '0';
                esc[3] = '0';
                esc[4] = hex_digits[(c >> 4) & 0x0F];
                esc[5] = hex_digits[c & 0x0F];
                pn_jsmn_emit_bytes(out, esc, sizeof(esc));
            } else {
                pn_jsmn_emit_byte(out, c);
            }
            break;
        }
    }
    pn_jsmn_emit_byte(out, '"');
}

static void pn_jsmn_emit_node(pn_jsmn_out_t* out, const pn_jsv_node_t* node);

/**
 * @brief Emit an integer literal into @p out via @c pn_snprintf.
 *
 * The 16-byte stack buffer fits INT_MIN (`-2147483648`, 11 chars)
 * with margin.
 */
static void pn_jsmn_emit_int(pn_jsmn_out_t* out, int value)
{
    char buf[16];
    int  written = pn_snprintf(buf, sizeof(buf), "%d", value);
    if (written < 0 || (size_t)written >= sizeof(buf)) {
        out->overflow = 1;
        return;
    }
    pn_jsmn_emit_bytes(out, buf, (size_t)written);
}

#if PUBNUB_CFG_JSON_DOUBLE && PUBNUB_CFG_MINIMAL_FORMATTER
#error "PUBNUB_CFG_JSON_DOUBLE=1 requires PUBNUB_CFG_MINIMAL_FORMATTER=0 (libc snprintf needed for %.17g)"
#endif

#if PUBNUB_CFG_JSON_DOUBLE
/**
 * @brief Emit a floating-point literal at full IEEE-754 precision.
 *
 * @c "%.17g" produces the shortest round-trip-stable decimal for any
 * IEEE-754 double. NaN / infinity inputs are not valid JSON; the
 * provider emits @c null in those cases (consistent with the JSON
 * spec's lack of a non-finite literal).
 */
static void pn_jsmn_emit_double(pn_jsmn_out_t* out, double value)
{
    /* JSON has no representation for NaN / infinity - emit null. */
    if (value != value || value > 1.0e308 || value < -1.0e308) {
        pn_jsmn_emit_bytes(out, "null", 4);
        return;
    }
    char buf[40];
    int  written = pn_snprintf(buf, sizeof(buf), "%.17g", value);
    if (written < 0 || (size_t)written >= sizeof(buf)) {
        out->overflow = 1;
        return;
    }
    pn_jsmn_emit_bytes(out, buf, (size_t)written);
}
#endif

/**
 * @brief Emit a node and any descendants as compact JSON.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static void pn_jsmn_emit_node(pn_jsmn_out_t* out, const pn_jsv_node_t* node)
{
    size_t i;

    if (out->overflow) {
        return;
    }
    if (NULL == node) {
        pn_jsmn_emit_bytes(out, "null", 4);
        return;
    }
    switch (node->type) {
    case PN_JSV_NULL: pn_jsmn_emit_bytes(out, "null", 4); break;
    case PN_JSV_BOOL:
        if (node->u.b) {
            pn_jsmn_emit_bytes(out, "true", 4);
        } else {
            pn_jsmn_emit_bytes(out, "false", 5);
        }
        break;
    case PN_JSV_INT: pn_jsmn_emit_int(out, node->u.i); break;
    case PN_JSV_DOUBLE:
#if PUBNUB_CFG_JSON_DOUBLE
        pn_jsmn_emit_double(out, node->u.d);
#else
        /* JSON_DOUBLE disabled: emit `null` so the document remains
         * valid JSON. The asymmetry is documented in the file-level
         * @par block. */
        pn_jsmn_emit_bytes(out, "null", 4);
#endif
        break;
    case PN_JSV_STRING:
    case PN_JSV_STRING_VIEW:
        pn_jsmn_emit_escaped(out, node->u.s.ptr, node->u.s.len);
        break;
    case PN_JSV_RAW:
        pn_jsmn_emit_bytes(out, node->u.s.ptr, node->u.s.len);
        break;
    case PN_JSV_ARRAY:
        pn_jsmn_emit_byte(out, '[');
        for (i = 0; i < node->u.arr.count; ++i) {
            if (i > 0) {
                pn_jsmn_emit_byte(out, ',');
            }
            pn_jsmn_emit_node(out, node->u.arr.items[i]);
        }
        pn_jsmn_emit_byte(out, ']');
        break;
    case PN_JSV_OBJECT:
        pn_jsmn_emit_byte(out, '{');
        for (i = 0; i < node->u.obj.count; ++i) {
            if (i > 0) {
                pn_jsmn_emit_byte(out, ',');
            }
            pn_jsmn_emit_escaped(
                out, node->u.obj.pairs[i]->key, node->u.obj.pairs[i]->key_len);
            pn_jsmn_emit_byte(out, ':');
            pn_jsmn_emit_node(out, node->u.obj.pairs[i]->value);
        }
        pn_jsmn_emit_byte(out, '}');
        break;
    default: pn_jsmn_emit_bytes(out, "null", 4); break;
    }
}

/**
 * @brief Serialize a tree into a caller-provided buffer.
 *
 * Returns @c PUBNUB_OK on success with @c *out_len populated to the
 * number of bytes written (excluding any trailing NUL - the
 * provider does NOT NUL-terminate the output, matching cJSON's
 * behavior). Returns @c PUBNUB_ERR_BUFFER_TOO_SMALL when the buffer
 * is undersized; @c *out_len is reset to 0 in that case so callers
 * can rely on a single failure signal.
 */
static pubnub_res_t jsmn_serialize(pubnub_serialization_provider_t* self,
                                   const pubnub_json_value_t*       value,
                                   uint8_t*                         buf,
                                   size_t                           buf_len,
                                   size_t*                          out_len)
{
    (void)self;
    if (NULL == value || NULL == buf || NULL == out_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    *out_len = 0;
    if (0 == buf_len) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }
    pn_jsmn_out_t out = {
        .buf      = buf,
        .cap      = buf_len,
        .len      = 0,
        .overflow = 0,
    };
    pn_jsmn_emit_node(&out, opaque_to_node(value));
    if (out.overflow) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }
    *out_len = out.len;
    return PUBNUB_OK;
}

/**
 * @brief Free a tree returned by @ref jsmn_parse or constructed via
 *        the constructors.
 *
 * Slab-allocated trees (from parse) are freed as a single block.
 * Per-node trees (from value_create_*) use recursive free.
 */
static void jsmn_value_destroy(pubnub_serialization_provider_t* self,
                               pubnub_json_value_t*             value)
{
    pn_jsv_node_t* node;

    if (NULL == self || NULL == value) {
        return;
    }
    node = opaque_to_node(value);
    if (NULL != node->_slab) {
        if (pn_slab_node_is_root(node)) {
            pn_jsv_free(pn_jsmn_self(self), node->_slab);
        }
        /* Slab sub-node: value_destroy on a borrowed child is a no-op.
         * The slab is freed when the root is destroyed. */
        return;
    }
    pn_jsv_free_node(pn_jsmn_self(self), node);
}

static pubnub_json_value_t* jsmn_value_create_object(pubnub_serialization_provider_t* self)
{
    pn_jsv_node_t* node = pn_jsv_alloc_node(pn_jsmn_self(self));
    if (NULL == node) {
        return NULL;
    }
    node->type = PN_JSV_OBJECT;
    return node_to_opaque(node);
}

static pubnub_json_value_t* jsmn_value_create_array(pubnub_serialization_provider_t* self)
{
    pn_jsv_node_t* node = pn_jsv_alloc_node(pn_jsmn_self(self));
    if (NULL == node) {
        return NULL;
    }
    node->type = PN_JSV_ARRAY;
    return node_to_opaque(node);
}

static pubnub_json_value_t* jsmn_value_create_null(pubnub_serialization_provider_t* self)
{
    pn_jsv_node_t* node = pn_jsv_alloc_node(pn_jsmn_self(self));
    if (NULL == node) {
        return NULL;
    }
    node->type = PN_JSV_NULL;
    return node_to_opaque(node);
}

static pubnub_json_value_t*
jsmn_value_create_bool(pubnub_serialization_provider_t* self, int truthy)
{
    pn_jsv_node_t* node = pn_jsv_alloc_node(pn_jsmn_self(self));
    if (NULL == node) {
        return NULL;
    }
    node->type = PN_JSV_BOOL;
    node->u.b  = (0 != truthy) ? 1 : 0;
    return node_to_opaque(node);
}

static pubnub_json_value_t* jsmn_value_create_int(pubnub_serialization_provider_t* self,
                                                  int v)
{
    pn_jsv_node_t* node = pn_jsv_alloc_node(pn_jsmn_self(self));
    if (NULL == node) {
        return NULL;
    }
    node->type = PN_JSV_INT;
    node->u.i  = v;
    return node_to_opaque(node);
}

#if PUBNUB_CFG_JSON_DOUBLE
/**
 * @brief Construct a JSON double node.
 *
 * Compiled out when @c PUBNUB_CFG_JSON_DOUBLE is 0; the vtable
 * slot is then NULL.
 */
static pubnub_json_value_t*
jsmn_value_create_double(pubnub_serialization_provider_t* self, double v)
{
    pn_jsv_node_t* node = pn_jsv_alloc_node(pn_jsmn_self(self));
    if (NULL == node) {
        return NULL;
    }
    node->type = PN_JSV_DOUBLE;
    node->u.d  = v;
    return node_to_opaque(node);
}
#endif

static pubnub_json_value_t* jsmn_value_create_string(pubnub_serialization_provider_t* self,
                                                     const char* str,
                                                     size_t      len)
{
    if (NULL == str) {
        return NULL;
    }
    pn_jsmn_provider_t* prov = pn_jsmn_self(self);
    pn_jsv_node_t*      node = pn_jsv_alloc_node(prov);
    if (NULL == node) {
        return NULL;
    }
    node->type    = PN_JSV_STRING;
    node->u.s.ptr = pn_jsv_dup_str(prov, str, len);
    if (NULL == node->u.s.ptr) {
        pn_jsv_free(prov, node);
        return NULL;
    }
    node->u.s.len = len;
    return node_to_opaque(node);
}

/**
 * @brief Construct a JSON string node aliasing @p str (no copy).
 *
 * Unlike the cJSON backend (which can only alias NUL-terminated input
 * via @c cJSON_CreateStringReference), the jsmn backend stores the
 * @c (ptr, len) pair directly and emits via the recorded length. Any
 * @c (str, len) span - NUL-terminated or not - is aliasable.
 *
 * The caller MUST keep @p str alive for the lifetime of the resulting
 * tree (until @ref value_destroy on the root). The bytes are NOT
 * copied; mutations of @p str after construction are visible through
 * accessors and serialize.
 */
static pubnub_json_value_t*
jsmn_value_create_string_view(pubnub_serialization_provider_t* self,
                              const char*                      str,
                              size_t                           len)
{
    if (NULL == str) {
        return NULL;
    }
    pn_jsmn_provider_t* prov = pn_jsmn_self(self);
    pn_jsv_node_t*      node = pn_jsv_alloc_node(prov);
    if (NULL == node) {
        return NULL;
    }
    /* Aliased bytes: the public type tag is STRING (mapped via
     * @ref jsmn_value_type) but the internal tag is VIEW so
     * destroy does NOT free the borrowed pointer. The caller MUST
     * keep @p str alive for the tree's lifetime. */
    node->type = PN_JSV_STRING_VIEW;
    /* Cast away const so the union ptr field can hold either an
     * owning or aliasing pointer. The lifetime contract is the
     * caller's responsibility, mirroring the public header. */
    node->u.s.ptr = (char*)str;
    /* For NUL-terminated input (the contract documented in
     * `serialization.h`: caller passes @p len = 0 when @p str is
     * NUL-terminated) resolve the actual byte length via strlen so
     * accessors and serialize report the correct span. Otherwise
     * use the caller-provided length verbatim. */
    node->u.s.len = (0 == len) ? strlen(str) : len;
    return node_to_opaque(node);
}

/**
 * @brief Construct a verbatim raw-JSON node.
 *
 * Bytes are copied via @ref pn_jsv_dup_str into allocator-backed
 * storage and emitted unchanged on @c serialize. Empty input is
 * rejected with NULL because the empty byte sequence is not a valid
 * JSON value (matching the cJSON backend's contract).
 */
static pubnub_json_value_t* jsmn_value_create_raw(pubnub_serialization_provider_t* self,
                                                  const uint8_t* bytes,
                                                  size_t         len)
{
    if (NULL == bytes || 0 == len) {
        return NULL;
    }
    pn_jsmn_provider_t* prov = pn_jsmn_self(self);
    pn_jsv_node_t*      node = pn_jsv_alloc_node(prov);
    if (NULL == node) {
        return NULL;
    }
    node->type    = PN_JSV_RAW;
    node->u.s.ptr = pn_jsv_dup_str(prov, (const char*)bytes, len);
    if (NULL == node->u.s.ptr) {
        pn_jsv_free(prov, node);
        return NULL;
    }
    node->u.s.len = len;
    return node_to_opaque(node);
}

static pubnub_res_t jsmn_object_set(pubnub_serialization_provider_t* self,
                                    pubnub_json_value_t*             obj,
                                    const char*                      key,
                                    size_t                           key_len,
                                    pubnub_json_value_t*             child)
{
    pn_jsv_node_t* node;

    if (NULL == obj || NULL == key || NULL == child) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    node = opaque_to_node(obj);
    if (NULL != node->_slab) {
        return PUBNUB_ERR_NOT_SUPPORTED;
    }
    if (PN_JSV_OBJECT != node->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return pn_jsv_object_set(
        pn_jsmn_self(self), node, key, key_len, opaque_to_node(child));
}

static pubnub_res_t jsmn_array_append(pubnub_serialization_provider_t* self,
                                      pubnub_json_value_t*             arr,
                                      pubnub_json_value_t*             item)
{
    pn_jsv_node_t* node;

    if (NULL == arr || NULL == item) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    node = opaque_to_node(arr);
    if (NULL != node->_slab) {
        return PUBNUB_ERR_NOT_SUPPORTED;
    }
    if (PN_JSV_ARRAY != node->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return pn_jsv_array_push(pn_jsmn_self(self), node, opaque_to_node(item));
}

static pubnub_res_t jsmn_object_remove(pubnub_serialization_provider_t* self,
                                       pubnub_json_value_t*             obj,
                                       const char*                      key,
                                       size_t                           key_len)
{
    pn_jsv_node_t*      node;
    pn_jsmn_provider_t* prov;
    size_t              idx;
    size_t              i;

    if (NULL == obj || NULL == key) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    node = opaque_to_node(obj);
    if (NULL != node->_slab) {
        return PUBNUB_ERR_NOT_SUPPORTED;
    }
    if (PN_JSV_OBJECT != node->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    idx = pn_jsv_object_find(node, key, key_len);
    if (SIZE_MAX == idx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    prov = pn_jsmn_self(self);
    pn_jsv_free_pair(prov, node->u.obj.pairs[idx]);
    /* Shift trailing entries down to fill the gap. */
    for (i = idx + 1; i < node->u.obj.count; ++i) {
        node->u.obj.pairs[i - 1] = node->u.obj.pairs[i];
    }
    node->u.obj.count--;
    return PUBNUB_OK;
}

static pubnub_res_t jsmn_array_remove(pubnub_serialization_provider_t* self,
                                      pubnub_json_value_t*             arr,
                                      size_t                           index)
{
    pn_jsv_node_t*      node;
    pn_jsmn_provider_t* prov;
    size_t              i;

    if (NULL == arr) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    node = opaque_to_node(arr);
    if (NULL != node->_slab) {
        return PUBNUB_ERR_NOT_SUPPORTED;
    }
    if (PN_JSV_ARRAY != node->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (index >= node->u.arr.count) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    prov = pn_jsmn_self(self);
    pn_jsv_free_node(prov, node->u.arr.items[index]);
    for (i = index + 1; i < node->u.arr.count; ++i) {
        node->u.arr.items[i - 1] = node->u.arr.items[i];
    }
    node->u.arr.count--;
    return PUBNUB_OK;
}

static pubnub_res_t jsmn_object_reserve(pubnub_serialization_provider_t* self,
                                        pubnub_json_value_t*             obj,
                                        size_t                           n)
{
    pn_jsv_node_t* node;

    if (NULL == obj) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    node = opaque_to_node(obj);
    if (PN_JSV_OBJECT != node->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL != node->_slab) {
        /* Slab-backed parse trees are immutable. */
        return PUBNUB_ERR_NOT_SUPPORTED;
    }
    return pn_jsv_object_reserve_int(pn_jsmn_self(self), node, node->u.obj.count + n);
}

static pubnub_res_t jsmn_array_reserve(pubnub_serialization_provider_t* self,
                                       pubnub_json_value_t*             arr,
                                       size_t                           n)
{
    pn_jsv_node_t* node;

    if (NULL == arr) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    node = opaque_to_node(arr);
    if (PN_JSV_ARRAY != node->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL != node->_slab) {
        /* Slab-backed parse trees are immutable. */
        return PUBNUB_ERR_NOT_SUPPORTED;
    }
    return pn_jsv_array_reserve(pn_jsmn_self(self), node, node->u.arr.count + n);
}

static pubnub_json_type_t jsmn_value_type(const pubnub_json_value_t* value)
{
    if (NULL == value) {
        return PUBNUB_JSON_NULL;
    }
    pn_jsv_node_t* node = opaque_to_node(value);
    switch (node->type) {
    case PN_JSV_NULL: return PUBNUB_JSON_NULL;
    case PN_JSV_BOOL: return PUBNUB_JSON_BOOL;
    case PN_JSV_INT: return PUBNUB_JSON_INT;
    case PN_JSV_DOUBLE: return PUBNUB_JSON_DOUBLE;
    case PN_JSV_STRING:
    case PN_JSV_STRING_VIEW: return PUBNUB_JSON_STRING;
    case PN_JSV_ARRAY: return PUBNUB_JSON_ARRAY;
    case PN_JSV_OBJECT: return PUBNUB_JSON_OBJECT;
    case PN_JSV_RAW: return PUBNUB_JSON_RAW;
    default: return PUBNUB_JSON_NULL;
    }
}

static const char* jsmn_value_as_string(const pubnub_json_value_t* value,
                                        size_t*                    out_len)
{
    if (NULL == value || NULL == out_len) {
        return NULL;
    }
    pn_jsv_node_t* node = opaque_to_node(value);
    if (PN_JSV_STRING != node->type && PN_JSV_STRING_VIEW != node->type
        && PN_JSV_RAW != node->type) {
        return NULL;
    }
    *out_len = node->u.s.len;
    return node->u.s.ptr;
}

static pubnub_res_t jsmn_value_as_int(const pubnub_json_value_t* value, int* out)
{
    if (NULL == value || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    pn_jsv_node_t* node = opaque_to_node(value);
    if (PN_JSV_INT == node->type) {
        *out = node->u.i;
        return PUBNUB_OK;
    }
    if (PN_JSV_DOUBLE == node->type) {
        double d = node->u.d;
        if (!(d >= (double)INT_MIN) || !(d <= (double)INT_MAX)) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        if ((double)(int)d != d) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        *out = (int)d;
        return PUBNUB_OK;
    }
    return PUBNUB_ERR_INVALID_ARGUMENT;
}

#if PUBNUB_CFG_JSON_DOUBLE
static pubnub_res_t jsmn_value_as_double(const pubnub_json_value_t* value,
                                         double*                    out)
{
    if (NULL == value || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    pn_jsv_node_t* node = opaque_to_node(value);
    if (PN_JSV_DOUBLE == node->type) {
        *out = node->u.d;
        return PUBNUB_OK;
    }
    if (PN_JSV_INT == node->type) {
        *out = (double)node->u.i;
        return PUBNUB_OK;
    }
    return PUBNUB_ERR_INVALID_ARGUMENT;
}
#endif

static pubnub_res_t jsmn_value_as_bool(const pubnub_json_value_t* value,
                                       int*                       out_truthy)
{
    if (NULL == value || NULL == out_truthy) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    pn_jsv_node_t* node = opaque_to_node(value);
    if (PN_JSV_BOOL != node->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    *out_truthy = node->u.b;
    return PUBNUB_OK;
}

static pubnub_json_value_t* jsmn_object_get(const pubnub_json_value_t* obj,
                                            const char*                key,
                                            size_t                     key_len)
{
    if (NULL == obj || NULL == key) {
        return NULL;
    }
    pn_jsv_node_t* node = opaque_to_node(obj);
    if (PN_JSV_OBJECT != node->type) {
        return NULL;
    }
    size_t idx = pn_jsv_object_find(node, key, key_len);
    if (SIZE_MAX == idx) {
        return NULL;
    }
    return node_to_opaque(node->u.obj.pairs[idx]->value);
}

static size_t jsmn_object_size(const pubnub_json_value_t* obj)
{
    if (NULL == obj) {
        return 0;
    }
    pn_jsv_node_t* node = opaque_to_node(obj);
    if (PN_JSV_OBJECT != node->type) {
        return 0;
    }
    return node->u.obj.count;
}

static pubnub_json_value_t* jsmn_array_get(const pubnub_json_value_t* arr,
                                           size_t                     index)
{
    if (NULL == arr) {
        return NULL;
    }
    pn_jsv_node_t* node = opaque_to_node(arr);
    if (PN_JSV_ARRAY != node->type) {
        return NULL;
    }
    if (index >= node->u.arr.count) {
        return NULL;
    }
    return node_to_opaque(node->u.arr.items[index]);
}

static size_t jsmn_array_size(const pubnub_json_value_t* arr)
{
    if (NULL == arr) {
        return 0;
    }
    pn_jsv_node_t* node = opaque_to_node(arr);
    if (PN_JSV_ARRAY != node->type) {
        return 0;
    }
    return node->u.arr.count;
}

static int jsmn_object_iter_init(const pubnub_json_value_t* obj,
                                 pubnub_json_iter_t*        iter)
{
    if (NULL == iter) {
        return 0;
    }
    pn_jsv_iter_state_t state = {.obj = NULL, .cursor = 0};
    if (NULL != obj) {
        pn_jsv_node_t* node = opaque_to_node(obj);
        if (PN_JSV_OBJECT == node->type && node->u.obj.count > 0) {
            state.obj = node;
        }
    }
    memcpy(iter->opaque, &state, sizeof(state));
    return (state.obj != NULL) ? 1 : 0;
}

static int jsmn_object_iter_next(pubnub_json_iter_t*   iter,
                                 const char**          out_key,
                                 size_t*               out_key_len,
                                 pubnub_json_value_t** out_value)
{
    if (NULL == iter) {
        return 0;
    }
    pn_jsv_iter_state_t state;
    memcpy(&state, iter->opaque, sizeof(state));
    if (NULL == state.obj || state.cursor >= state.obj->u.obj.count) {
        return 0;
    }
    const pn_jsv_pair_t* pair = state.obj->u.obj.pairs[state.cursor];
    if (NULL != out_key) {
        *out_key = pair->key != NULL ? pair->key : "";
    }
    if (NULL != out_key_len) {
        *out_key_len = pair->key_len;
    }
    if (NULL != out_value) {
        *out_value = node_to_opaque(pair->value);
    }
    state.cursor++;
    memcpy(iter->opaque, &state, sizeof(state));
    return 1;
}

static int jsmn_array_iter_init(const pubnub_json_value_t* arr,
                                pubnub_json_array_iter_t*  iter)
{
    pn_jsv_array_iter_state_t state = {.arr = NULL, .cursor = 0};
    if (NULL == iter) {
        return 0;
    }
    if (NULL != arr) {
        pn_jsv_node_t* node = opaque_to_node(arr);
        if (PN_JSV_ARRAY == node->type && node->u.arr.count > 0) {
            state.arr = node;
        }
    }
    memcpy(iter->opaque, &state, sizeof(state));
    return (state.arr != NULL) ? 1 : 0;
}

static int jsmn_array_iter_next(pubnub_json_array_iter_t* iter,
                                pubnub_json_value_t**     out_value)
{
    pn_jsv_array_iter_state_t state;
    if (NULL == iter) {
        return 0;
    }
    memcpy(&state, iter->opaque, sizeof(state));
    if (NULL == state.arr || state.cursor >= state.arr->u.arr.count) {
        return 0;
    }
    if (NULL != out_value) {
        *out_value = node_to_opaque(state.arr->u.arr.items[state.cursor]);
    }
    state.cursor++;
    memcpy(iter->opaque, &state, sizeof(state));
    return 1;
}

/**
 * @brief File-scope singleton instance.
 *
 * Embeds the public vtable as the first member; the @c allocator
 * slot is populated by @ref pn_jsmn_init and cleared by @ref jsmn_deinit.
 * Slots that would cost embedded code-size when unused are gated by
 * compile-time toggles:
 *   - @c value_create_double / @c value_as_double are NULL when
 *     @c PUBNUB_CFG_JSON_DOUBLE == 0.
 *
 * Unlike the cJSON backend, @c object_reserve and @c array_reserve are
 * IMPLEMENTED on this backend because the SDK-owned tree
 * representation supports explicit pre-allocation.
 */
static pn_jsmn_provider_t pn_jsmn_serialization = {
    .base =
        {
               .parse               = pn_jsmn_provider_parse,
               .serialize           = jsmn_serialize,
               .value_destroy       = jsmn_value_destroy,
               .init                = pn_jsmn_init,
               .deinit              = jsmn_deinit,
               .value_create_object = jsmn_value_create_object,
               .value_create_array  = jsmn_value_create_array,
               .value_create_null   = jsmn_value_create_null,
               .value_create_bool   = jsmn_value_create_bool,
               .value_create_int    = jsmn_value_create_int,
#if PUBNUB_CFG_JSON_DOUBLE
               .value_create_double = jsmn_value_create_double,
#else
            .value_create_double = NULL,
#endif
               .value_create_string      = jsmn_value_create_string,
               .value_create_string_view = jsmn_value_create_string_view,
               .value_create_raw         = jsmn_value_create_raw,
               .object_set               = jsmn_object_set,
               .array_append             = jsmn_array_append,
               .object_remove            = jsmn_object_remove,
               .array_remove             = jsmn_array_remove,
               .object_reserve           = jsmn_object_reserve,
               .array_reserve            = jsmn_array_reserve,
               .value_type               = jsmn_value_type,
               .value_as_string          = jsmn_value_as_string,
               .value_as_int             = jsmn_value_as_int,
#if PUBNUB_CFG_JSON_DOUBLE
               .value_as_double = jsmn_value_as_double,
#else
            .value_as_double = NULL,
#endif
               .value_as_bool    = jsmn_value_as_bool,
               .object_get       = jsmn_object_get,
               .object_size      = jsmn_object_size,
               .array_get        = jsmn_array_get,
               .array_size       = jsmn_array_size,
               .object_iter_init = jsmn_object_iter_init,
               .object_iter_next = jsmn_object_iter_next,
               .array_iter_init  = jsmn_array_iter_init,
               .array_iter_next  = jsmn_array_iter_next,
               },
    .allocator = NULL,
    .ref_count = 0,
};

pubnub_serialization_provider_t* pn_serialization_default(void)
{
    return &pn_jsmn_serialization.base;
}
