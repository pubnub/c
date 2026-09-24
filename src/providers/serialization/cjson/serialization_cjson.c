/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file serialization_cjson.c
 * @brief cJSON-backed serialization provider.
 *
 * The `cjson` provider is the default JSON serialization backend for
 * hosted profiles (`full`, `minimal`). It wraps upstream cJSON v1.7.18
 * (MIT-licensed; fetched via FetchContent) behind the
 * `pubnub_serialization_provider_t` vtable.
 *
 * The provider implements the full vtable surface: the three mandatory
 * wire I/O entries (`parse`, `serialize`, `value_destroy`) plus the
 * constructor / mutator / accessor groups that materialize the
 * `pubnub_json_value_t` data model.
 *
 * @par Verbatim raw nodes
 *
 * `value_create_raw` maps to upstream `cJSON_CreateRaw`, which copies
 * the bytes and emits them unchanged on serialize. This satisfies the
 * byte-stable round-trip contract that PAM signature computation
 * depends on.
 *
 * @par Allocator wiring (deferred)
 *
 * The optional lifecycle callbacks (`init` / `deinit`) stay NULL on
 * this branch. cJSON exposes memory hooks as **global** state
 * (`cJSON_InitHooks`), which does not fit the per-context provider
 * model without cross-context interference when contexts carry
 * different allocators. With a single stdlib allocator shared by
 * every context, letting cJSON use libc `malloc`/`free` directly is
 * both correct and simpler.
 *
 * The provider carries no per-instance state, so a single static
 * singleton is returned from @ref pn_serialization_default; callers
 * can share it freely across contexts.
 *
 * @par PUBNUB_CFG_JSON_DOUBLE asymmetry
 *
 * When @c PUBNUB_CFG_JSON_DOUBLE is 0, this backend does NOT
 * enable @c value_create_double or @c value_as_double in the vtable,
 * but the cJSON parser still produces nodes of type
 * @c PUBNUB_JSON_DOUBLE for floating-point JSON literals encountered
 * in inbound payloads (cJSON has no parse-time filter that would
 * suppress doubles). Callers MUST check @c value_type and treat
 * @c PUBNUB_JSON_DOUBLE-typed nodes as opaque/unsupported when
 * @c value_as_double is NULL: the node can be carried through the
 * tree, serialized verbatim, and freed, but its numeric value cannot
 * be read.
 */

/* cJSON exposes memory hooks as process-global state (`cJSON_InitHooks`),
 * which is incompatible with the per-context allocator model. The cjson
 * backend can therefore only be paired with the stdlib allocator.
 * _pn_validate_provider_combinations() enforces this at CMake
 * configure time; the #error below is a C-side cross-check for
 * out-of-band invocations (e.g. direct compilation without CMake). */
#if !defined(PN_BUILTIN_ALLOCATOR_STDLIB) || PN_BUILTIN_ALLOCATOR_STDLIB != 1
#error "cJSON serialization requires the stdlib allocator. cJSON's global memory hooks (cJSON_InitHooks) cannot be wired to a per-context allocator. Switch PUBNUB_PROVIDER_SERIALIZATION to jsmn, or switch PUBNUB_PROVIDER_ALLOCATOR to stdlib."
#endif

#include "pubnub/providers/serialization.h"

#include "pubnub/pubnub_compat.h"

#include <cJSON.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_serialization_provider_t* pn_serialization_default(void);

/** Iterator-cursor invariant: a `cJSON*` must fit in the opaque
 *  storage reserved for the provider in @ref pubnub_json_iter_t. */
PUBNUB_STATIC_ASSERT(sizeof(cJSON*) <= sizeof(((pubnub_json_iter_t*)0)->opaque),
                     "cJSON cursor fits pubnub_json_iter_t opaque storage");

/** Array-iterator-cursor invariant: a `cJSON*` must fit in the opaque
 *  storage reserved for the provider in @ref pubnub_json_array_iter_t. */
PUBNUB_STATIC_ASSERT(
    sizeof(cJSON*) <= sizeof(((pubnub_json_array_iter_t*)0)->opaque),
    "cJSON cursor fits pubnub_json_array_iter_t opaque storage");

/**
 * @brief Reinterpret a cJSON tree pointer as the SDK's opaque handle.
 *
 * `pubnub_json_value_t` is a forward-declared incomplete struct in
 * the public provider header (`providers/serialization.h`). Consumers
 * only ever hold pointers to it and cannot observe its layout, which
 * leaves each backend free to choose its own concrete storage type.
 * This provider stores cJSON trees; the cast is a pure pointer-type
 * reinterpretation (same size, same representation, different name).
 */
static pubnub_json_value_t* tree_to_opaque(cJSON* tree)
{
    return (pubnub_json_value_t*)tree;
}

/**
 * @brief Recover a cJSON tree pointer from the SDK's opaque handle.
 *
 * Inverse of @ref tree_to_opaque. The cast also drops `const`
 * because cJSON's outer print API takes a non-const `cJSON*` even
 * though the internal `print_value` treats the argument as
 * `const cJSON* const` and never mutates the tree.  `-Wcast-qual`
 * is not in the project's warning set (see `cmake/compiler.cmake`),
 * so the direct C-style cast is accepted.
 */
static cJSON* opaque_to_tree(const pubnub_json_value_t* value)
{
    return (cJSON*)value;
}

/**
 * @brief Cap @p buf_len to `INT_MAX` for cJSON's `int length` API.
 *
 * `cJSON_PrintPreallocated` accepts an `int` length parameter. A
 * caller-provided `size_t` larger than `INT_MAX` would narrow to a
 * negative value, which cJSON would reject (or worse, misinterpret
 * as an overflow). Clamping here keeps the narrowing lossless for
 * any representable buffer size.
 */
static int clamp_to_int_max(size_t buf_len)
{
    return buf_len > (size_t)INT_MAX ? INT_MAX : (int)buf_len;
}

/** Maximum object/array key buffer copied onto the stack for NUL
 *  termination during `object_set` / `object_remove` / `object_get`.
 *  Keys longer than this take the heap-fallback branch. */
#define PN_CJSON_KEY_STACK_BUF 128

/**
 * @brief NUL-terminate a key span into a heap or stack scratch.
 *
 * cJSON's object APIs take a NUL-terminated `const char*` even though
 * the SDK's vtable accepts a `(ptr, len)` pair. This helper produces
 * a NUL-terminated copy: it tries the caller's stack buffer first and
 * falls back to `malloc` for unusually large keys (caller frees via
 * @ref free_key_buffer).
 *
 * @param key      Source bytes (need not be NUL-terminated).
 * @param key_len  Length of @p key in bytes; if 0, @p key is treated
 *                 as already NUL-terminated and returned as-is.
 * @param stack    Caller-provided stack buffer of at least
 *                 @ref PN_CJSON_KEY_STACK_BUF bytes.
 * @param out_heap On success, set to non-NULL when a heap allocation
 *                 was used so the caller can free it later. The
 *                 caller MUST initialize @p *out_heap to NULL.
 * @return Pointer to a NUL-terminated copy of @p key, or NULL on
 *         allocation failure.
 */
static const char*
nul_terminate_key(const char* key, size_t key_len, char* stack, char** out_heap)
{
    if (NULL == key) {
        return NULL;
    }
    if (0 == key_len) {
        /* By contract, len 0 means the caller passes an already
         * NUL-terminated key; cJSON reads it directly, so return as-is. */
        return key;
    }
    if (key_len < PN_CJSON_KEY_STACK_BUF) {
        memcpy(stack, key, key_len);
        stack[key_len] = '\0';
        return stack;
    }
    {
        char* heap = (char*)malloc(key_len + 1);
        if (heap == NULL) {
            return NULL;
        }
        memcpy(heap, key, key_len);
        heap[key_len] = '\0';
        *out_heap     = heap;
        return heap;
    }
}

/** Counterpart to @ref nul_terminate_key: free the heap buffer (if
 *  any) returned through @c out_heap. Safe on NULL. */
static void free_key_buffer(char* heap)
{
    if (heap != NULL) {
        free(heap);
    }
}

/**
 * @brief Parse a JSON document from a caller-owned buffer.
 *
 * Uses `cJSON_ParseWithLength`, which honours the length argument and
 * does not require the input to be NUL-terminated - important
 * because the SDK's transport layer fills response buffers without
 * appending a NUL.
 *
 * A NULL or zero-length input is treated as a parse failure rather
 * than an empty-document success, matching the contract in the
 * provider header ("returns NULL on parse error").
 */
static pubnub_json_value_t* cjson_parse(pubnub_serialization_provider_t* self,
                                        const uint8_t*                   data,
                                        size_t                           len)
{
    (void)self;

    if (data == NULL || len == 0) {
        return NULL;
    }

    return tree_to_opaque(cJSON_ParseWithLength((const char*)data, len));
}

/**
 * @brief Serialize a JSON tree into a caller-provided buffer.
 *
 * Uses `cJSON_PrintPreallocated` with `fmt=0` (compact output - the
 * SDK never needs pretty-printed JSON over the wire). The function
 * returns non-zero on success; failure is mapped to
 * `PUBNUB_ERR_BUFFER_TOO_SMALL` because the overwhelmingly common
 * cause is an under-sized output buffer. True internal errors (cJSON
 * allocation failures during printing) are rare on a well-formed tree
 * and share the same failure signal; callers distinguish them via
 * buffer sizing rather than error code.
 */
static pubnub_res_t cjson_serialize(pubnub_serialization_provider_t* self,
                                    const pubnub_json_value_t*       value,
                                    uint8_t*                         buf,
                                    size_t                           buf_len,
                                    size_t*                          out_len)
{
    (void)self;

    if (value == NULL || buf == NULL || out_len == NULL) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Every subsequent error path returns BUFFER_TOO_SMALL; zero
     * `out_len` up-front so a caller that inspects it on error sees
     * the same "nothing was written" signal regardless of which
     * branch triggered. */
    *out_len = 0;

    if (buf_len == 0) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    if (!cJSON_PrintPreallocated(
            opaque_to_tree(value), (char*)buf, clamp_to_int_max(buf_len), 0)) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    *out_len = strlen((const char*)buf);
    return PUBNUB_OK;
}

/**
 * @brief Release a parsed or constructed JSON tree.
 *
 * Forwards to `cJSON_Delete`, which walks the tree and frees every
 * node via the library's configured allocator. `cJSON_Delete(NULL)`
 * is a documented no-op, so double-free attempts through this
 * provider are safe as long as the caller also nulls their handle.
 */
static void cjson_value_destroy(pubnub_serialization_provider_t* self,
                                pubnub_json_value_t*             value)
{
    (void)self;
    cJSON_Delete(opaque_to_tree(value));
}

/* Group A: constructors. */

static pubnub_json_value_t*
cjson_value_create_object(pubnub_serialization_provider_t* self)
{
    (void)self;
    return tree_to_opaque(cJSON_CreateObject());
}

static pubnub_json_value_t* cjson_value_create_array(pubnub_serialization_provider_t* self)
{
    (void)self;
    return tree_to_opaque(cJSON_CreateArray());
}

static pubnub_json_value_t* cjson_value_create_null(pubnub_serialization_provider_t* self)
{
    (void)self;
    return tree_to_opaque(cJSON_CreateNull());
}

static pubnub_json_value_t*
cjson_value_create_bool(pubnub_serialization_provider_t* self, int truthy)
{
    (void)self;
    return tree_to_opaque(cJSON_CreateBool(truthy != 0));
}

static pubnub_json_value_t*
cjson_value_create_int(pubnub_serialization_provider_t* self, int v)
{
    (void)self;
    return tree_to_opaque(cJSON_CreateNumber((double)v));
}

#if PUBNUB_CFG_JSON_DOUBLE
/**
 * @brief Construct a JSON double node.
 *
 * Compiled out when @c PUBNUB_CFG_JSON_DOUBLE is 0; the vtable
 * slot is then NULL and callers must check before invoking.
 */
static pubnub_json_value_t*
cjson_value_create_double(pubnub_serialization_provider_t* self, double v)
{
    (void)self;
    return tree_to_opaque(cJSON_CreateNumber(v));
}
#endif

/**
 * @brief Construct a JSON string node by copying @p str.
 *
 * cJSON's `cJSON_CreateString` requires a NUL-terminated argument.
 * For length-counted input we materialise a NUL-terminated scratch
 * (stack buffer for short strings, malloc fallback for long ones)
 * and feed it through. cJSON itself copies the bytes, so the scratch
 * is freed before return.
 */
static pubnub_json_value_t*
cjson_value_create_string(pubnub_serialization_provider_t* self,
                          const char*                      str,
                          size_t                           len)
{
    (void)self;

    if (str == NULL) {
        return NULL;
    }
    if (len == 0) {
        return tree_to_opaque(cJSON_CreateString(""));
    }

    {
        char  stack_buf[PN_CJSON_KEY_STACK_BUF];
        char* heap = NULL;
        const char* nul_terminated = nul_terminate_key(str, len, stack_buf, &heap);
        cJSON* created = NULL;

        if (nul_terminated == NULL) {
            return NULL;
        }
        created = cJSON_CreateString(nul_terminated);
        free_key_buffer(heap);
        return tree_to_opaque(created);
    }
}

/**
 * @brief Construct a JSON string node aliasing @p str (no copy).
 *
 * cJSON's `cJSON_CreateStringReference` stores the pointer directly
 * and skips the free-on-delete path. Caller MUST keep @p str alive
 * for the entire lifetime of the resulting tree.
 *
 * The cJSON backend can only alias NUL-terminated input. When @p len
 * is 0, the caller is asserting @p str is NUL-terminated and we
 * return a non-copying view via `cJSON_CreateStringReference`. When
 * @p len is non-zero, this provider returns NULL - callers MUST fall
 * back to @ref cjson_value_create_string for length-counted byte
 * spans on cJSON backends. We cannot probe @p str at offset @p len
 * to detect NUL termination because the public contract permits
 * length-counted byte slices that are NOT NUL-terminated, so reading
 * @c str[len] would be a one-byte out-of-bounds read.
 */
static pubnub_json_value_t*
cjson_value_create_string_view(pubnub_serialization_provider_t* self,
                               const char*                      str,
                               size_t                           len)
{
    (void)self;

    if (NULL == str) {
        return NULL;
    }
    /* Length-counted spans cannot be aliased safely on this backend:
     * `cJSON_CreateStringReference` requires NUL termination at the
     * exact span end, and probing @c str[len] would be OOB on a
     * non-NUL-terminated span. Signal "cannot alias" so the caller
     * falls back to @ref cjson_value_create_string. */
    if (0 != len) {
        return NULL;
    }
    return tree_to_opaque(cJSON_CreateStringReference(str));
}

/**
 * @brief Construct a verbatim raw-JSON node.
 *
 * Maps to upstream `cJSON_CreateRaw`, which copies the bytes and
 * emits them unchanged on serialize. The vendored cJSON has not been
 * patched here; the byte-stable round-trip contract is already
 * satisfied by upstream.
 *
 * Empty input (`len == 0`) is rejected with NULL: the empty byte
 * sequence is not a valid JSON value, and emitting an empty raw node
 * would produce invalid JSON on serialize. The caller is responsible
 * for treating an empty payload as "no node to attach".
 */
static pubnub_json_value_t* cjson_value_create_raw(pubnub_serialization_provider_t* self,
                                                   const uint8_t* bytes,
                                                   size_t         len)
{
    (void)self;

    if (NULL == bytes || 0 == len) {
        return NULL;
    }

    {
        char        stack_buf[PN_CJSON_KEY_STACK_BUF];
        char*       heap = NULL;
        const char* nul_terminated =
            nul_terminate_key((const char*)bytes, len, stack_buf, &heap);
        cJSON* created = NULL;

        if (nul_terminated == NULL) {
            return NULL;
        }
        created = cJSON_CreateRaw(nul_terminated);
        free_key_buffer(heap);
        return tree_to_opaque(created);
    }
}

/* Group B: mutators. */

/**
 * @brief Insert or replace a key in a JSON object.
 *
 * cJSON's `cJSON_AddItemToObject` does not remove an existing key;
 * the caller would silently get duplicates. We probe with
 * `cJSON_GetObjectItemCaseSensitive` first and use
 * `cJSON_ReplaceItemInObjectCaseSensitive` for the replace path so
 * the prior subtree is freed and ownership of @p child transfers
 * cleanly.
 */
static pubnub_res_t cjson_object_set(pubnub_serialization_provider_t* self,
                                     pubnub_json_value_t*             obj,
                                     const char*                      key,
                                     size_t                           key_len,
                                     pubnub_json_value_t*             child)
{
    (void)self;

    if (obj == NULL || key == NULL || child == NULL) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    cJSON* tree = opaque_to_tree(obj);
    if (!cJSON_IsObject(tree)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    char  stack_buf[PN_CJSON_KEY_STACK_BUF];
    char* heap = NULL;
    const char* nul_terminated = nul_terminate_key(key, key_len, stack_buf, &heap);
    if (nul_terminated == NULL) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    pubnub_res_t result     = PUBNUB_OK;
    cJSON*       child_tree = opaque_to_tree(child);

    if (cJSON_GetObjectItemCaseSensitive(tree, nul_terminated) != NULL) {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(tree, nul_terminated, child_tree)) {
            result = PUBNUB_ERR_OUT_OF_MEMORY;
        }
    } else if (!cJSON_AddItemToObject(tree, nul_terminated, child_tree)) {
        result = PUBNUB_ERR_OUT_OF_MEMORY;
    }

    free_key_buffer(heap);
    return result;
}

static pubnub_res_t cjson_array_append(pubnub_serialization_provider_t* self,
                                       pubnub_json_value_t*             arr,
                                       pubnub_json_value_t*             item)
{
    (void)self;

    if (arr == NULL || item == NULL) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    cJSON* tree = opaque_to_tree(arr);
    if (!cJSON_IsArray(tree)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (!cJSON_AddItemToArray(tree, opaque_to_tree(item))) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    return PUBNUB_OK;
}

static pubnub_res_t cjson_object_remove(pubnub_serialization_provider_t* self,
                                        pubnub_json_value_t*             obj,
                                        const char*                      key,
                                        size_t key_len)
{
    (void)self;

    if (obj == NULL || key == NULL) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    cJSON* tree = opaque_to_tree(obj);
    if (!cJSON_IsObject(tree)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    char  stack_buf[PN_CJSON_KEY_STACK_BUF];
    char* heap = NULL;
    const char* nul_terminated = nul_terminate_key(key, key_len, stack_buf, &heap);
    if (nul_terminated == NULL) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    pubnub_res_t result = PUBNUB_OK;
    if (cJSON_GetObjectItemCaseSensitive(tree, nul_terminated) == NULL) {
        result = PUBNUB_ERR_INVALID_ARGUMENT;
    } else {
        cJSON_DeleteItemFromObjectCaseSensitive(tree, nul_terminated);
    }

    free_key_buffer(heap);
    return result;
}

static pubnub_res_t cjson_array_remove(pubnub_serialization_provider_t* self,
                                       pubnub_json_value_t*             arr,
                                       size_t                           index)
{
    (void)self;

    if (arr == NULL) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    cJSON* tree = opaque_to_tree(arr);
    if (!cJSON_IsArray(tree)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    int size = cJSON_GetArraySize(tree);
    if (size < 0 || index >= (size_t)size || index > (size_t)INT_MAX) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    cJSON_DeleteItemFromArray(tree, (int)index);
    return PUBNUB_OK;
}

/* Group C: accessors. */

static pubnub_json_type_t cjson_value_type(const pubnub_json_value_t* value)
{
    if (value == NULL) {
        return PUBNUB_JSON_NULL;
    }
    cJSON* tree = opaque_to_tree(value);
    /* Mask off flag bits (`cJSON_IsReference` 256, `cJSON_StringIsConst`
     * 512) that cJSON ORs into the type field. The lower 8 bits carry
     * the actual type discriminator. */
    int type_bits = tree->type & 0xFF;

    switch (type_bits) {
    case cJSON_NULL: return PUBNUB_JSON_NULL;
    case cJSON_True:
    case cJSON_False: return PUBNUB_JSON_BOOL;
    case cJSON_Number: {
        /* Classify as INT when the double value is an exact integer
         * within int range; otherwise DOUBLE. */
        double d = tree->valuedouble;
        if (d >= (double)INT_MIN && d <= (double)INT_MAX && (double)(int)d == d) {
            return PUBNUB_JSON_INT;
        }
        return PUBNUB_JSON_DOUBLE;
    }
    case cJSON_String: return PUBNUB_JSON_STRING;
    case cJSON_Array: return PUBNUB_JSON_ARRAY;
    case cJSON_Object: return PUBNUB_JSON_OBJECT;
    case cJSON_Raw: return PUBNUB_JSON_RAW;
    default: return PUBNUB_JSON_NULL;
    }
}

static const char* cjson_value_as_string(const pubnub_json_value_t* value,
                                         size_t*                    out_len)
{
    if (value == NULL || out_len == NULL) {
        return NULL;
    }
    cJSON* tree = opaque_to_tree(value);
    if (!cJSON_IsString(tree) && !cJSON_IsRaw(tree)) {
        return NULL;
    }
    if (tree->valuestring == NULL) {
        return NULL;
    }
    *out_len = strlen(tree->valuestring);
    return tree->valuestring;
}

static pubnub_res_t cjson_value_as_int(const pubnub_json_value_t* value, int* out)
{
    if (NULL == value || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    cJSON* tree = opaque_to_tree(value);
    if (!cJSON_IsNumber(tree)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    double d = tree->valuedouble;
    /* Accept only exact integers within int range. */
    if (!(d >= (double)INT_MIN) || !(d <= (double)INT_MAX)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if ((double)(int)d != d) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    *out = (int)d;
    return PUBNUB_OK;
}

#if PUBNUB_CFG_JSON_DOUBLE
static pubnub_res_t cjson_value_as_double(const pubnub_json_value_t* value,
                                          double*                    out)
{
    if (value == NULL || out == NULL) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    cJSON* tree = opaque_to_tree(value);
    if (!cJSON_IsNumber(tree)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    *out = tree->valuedouble;
    return PUBNUB_OK;
}
#endif

static pubnub_res_t cjson_value_as_bool(const pubnub_json_value_t* value,
                                        int*                       out_truthy)
{
    if (value == NULL || out_truthy == NULL) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    cJSON* tree = opaque_to_tree(value);
    if (cJSON_IsTrue(tree)) {
        *out_truthy = 1;
        return PUBNUB_OK;
    }
    if (cJSON_IsFalse(tree)) {
        *out_truthy = 0;
        return PUBNUB_OK;
    }
    return PUBNUB_ERR_INVALID_ARGUMENT;
}

static pubnub_json_value_t* cjson_object_get(const pubnub_json_value_t* obj,
                                             const char*                key,
                                             size_t                     key_len)
{
    if (obj == NULL || key == NULL) {
        return NULL;
    }
    cJSON* tree = opaque_to_tree(obj);
    if (!cJSON_IsObject(tree)) {
        return NULL;
    }

    char  stack_buf[PN_CJSON_KEY_STACK_BUF];
    char* heap = NULL;
    const char* nul_terminated = nul_terminate_key(key, key_len, stack_buf, &heap);
    if (nul_terminated == NULL) {
        return NULL;
    }

    cJSON* found = cJSON_GetObjectItemCaseSensitive(tree, nul_terminated);
    free_key_buffer(heap);
    return tree_to_opaque(found);
}

static size_t cjson_object_size(const pubnub_json_value_t* obj)
{
    if (obj == NULL) {
        return 0;
    }
    cJSON* tree = opaque_to_tree(obj);
    if (!cJSON_IsObject(tree)) {
        return 0;
    }
    int size = cJSON_GetArraySize(tree);
    return size < 0 ? 0 : (size_t)size;
}

static pubnub_json_value_t* cjson_array_get(const pubnub_json_value_t* arr,
                                            size_t                     index)
{
    if (arr == NULL) {
        return NULL;
    }
    cJSON* tree = opaque_to_tree(arr);
    if (!cJSON_IsArray(tree)) {
        return NULL;
    }
    if (index > (size_t)INT_MAX) {
        return NULL;
    }
    return tree_to_opaque(cJSON_GetArrayItem(tree, (int)index));
}

static size_t cjson_array_size(const pubnub_json_value_t* arr)
{
    if (arr == NULL) {
        return 0;
    }
    cJSON* tree = opaque_to_tree(arr);
    if (!cJSON_IsArray(tree)) {
        return 0;
    }
    int size = cJSON_GetArraySize(tree);
    return size < 0 ? 0 : (size_t)size;
}

/**
 * @brief Initialize an iterator over @p obj's keys.
 *
 * The iterator stores a `cJSON*` cursor in the opaque payload via
 * `memcpy`, which avoids any alignment assumption on the underlying
 * storage. The static assert at the top of this file proves the
 * pointer fits.
 */
static int cjson_object_iter_init(const pubnub_json_value_t* obj,
                                  pubnub_json_iter_t*        iter)
{
    if (iter == NULL) {
        return 0;
    }
    cJSON* cursor = NULL;
    if (obj != NULL) {
        cJSON* tree = opaque_to_tree(obj);
        if (cJSON_IsObject(tree)) {
            cursor = tree->child;
        }
    }
    memcpy(iter->opaque, (const void*)&cursor, sizeof(cJSON*));
    return cursor != NULL ? 1 : 0;
}

static int cjson_object_iter_next(pubnub_json_iter_t*   iter,
                                  const char**          out_key,
                                  size_t*               out_key_len,
                                  pubnub_json_value_t** out_value)
{
    if (iter == NULL) {
        return 0;
    }
    cJSON* cursor = NULL;
    memcpy((void*)&cursor, iter->opaque, sizeof(cJSON*));
    if (cursor == NULL) {
        return 0;
    }
    if (out_key != NULL) {
        *out_key = cursor->string != NULL ? cursor->string : "";
    }
    if (out_key_len != NULL) {
        *out_key_len = cursor->string != NULL ? strlen(cursor->string) : 0;
    }
    if (out_value != NULL) {
        *out_value = tree_to_opaque(cursor);
    }
    cJSON* next = cursor->next;
    memcpy(iter->opaque, (const void*)&next, sizeof(cJSON*));
    return 1;
}

/**
 * @brief Initialize an iterator over @p arr's elements.
 *
 * The iterator stores a `cJSON*` cursor in the opaque payload via
 * `memcpy`, which avoids any alignment assumption on the underlying
 * storage. The static assert at the top of this file proves the
 * pointer fits. Walking with the cursor is O(1) per step, versus the
 * O(n) traversal `cJSON_GetArrayItem` performs per index.
 */
static int cjson_array_iter_init(const pubnub_json_value_t* arr,
                                 pubnub_json_array_iter_t*  iter)
{
    cJSON* cursor = NULL;
    cJSON* tree;

    if (NULL == iter) {
        return 0;
    }
    if (NULL != arr) {
        tree = opaque_to_tree(arr);
        if (cJSON_IsArray(tree)) {
            cursor = tree->child;
        }
    }
    memcpy(iter->opaque, (const void*)&cursor, sizeof(cJSON*));
    return NULL != cursor ? 1 : 0;
}

static int cjson_array_iter_next(pubnub_json_array_iter_t* iter,
                                 pubnub_json_value_t**     out_value)
{
    cJSON* cursor = NULL;
    cJSON* next;

    if (NULL == iter) {
        return 0;
    }
    memcpy((void*)&cursor, iter->opaque, sizeof(cJSON*));
    if (NULL == cursor) {
        return 0;
    }
    if (NULL != out_value) {
        *out_value = tree_to_opaque(cursor);
    }
    next = cursor->next;
    memcpy(iter->opaque, (const void*)&next, sizeof(cJSON*));
    return 1;
}

/**
 * @brief File-scope singleton instance.
 *
 * cJSON-specific notes captured at the field level:
 *   - `init` / `deinit` stay NULL; allocator wiring is deferred (see
 *     file-level docstring).
 *   - `value_create_double` / `value_as_double` are NULL when
 *     `PUBNUB_CFG_JSON_DOUBLE` is 0 - callers must check.
 *   - `object_reserve` / `array_reserve` are NULL because cJSON has
 *     no pre-reserve API; callers proceed with `object_set` /
 *     `array_append`, which will fail with `PUBNUB_ERR_OUT_OF_MEMORY`
 *     if capacity is actually exhausted.
 */
static pubnub_serialization_provider_t pn_cjson_serialization = {
    .parse               = cjson_parse,
    .serialize           = cjson_serialize,
    .value_destroy       = cjson_value_destroy,
    .init                = NULL,
    .deinit              = NULL,
    .value_create_object = cjson_value_create_object,
    .value_create_array  = cjson_value_create_array,
    .value_create_null   = cjson_value_create_null,
    .value_create_bool   = cjson_value_create_bool,
    .value_create_int    = cjson_value_create_int,
#if PUBNUB_CFG_JSON_DOUBLE
    .value_create_double = cjson_value_create_double,
#else
    .value_create_double = NULL,
#endif
    .value_create_string      = cjson_value_create_string,
    .value_create_string_view = cjson_value_create_string_view,
    .value_create_raw         = cjson_value_create_raw,
    .object_set               = cjson_object_set,
    .array_append             = cjson_array_append,
    .object_remove            = cjson_object_remove,
    .array_remove             = cjson_array_remove,
    .object_reserve           = NULL,
    .array_reserve            = NULL,
    .value_type               = cjson_value_type,
    .value_as_string          = cjson_value_as_string,
    .value_as_int             = cjson_value_as_int,
#if PUBNUB_CFG_JSON_DOUBLE
    .value_as_double = cjson_value_as_double,
#else
    .value_as_double = NULL,
#endif
    .value_as_bool    = cjson_value_as_bool,
    .object_get       = cjson_object_get,
    .object_size      = cjson_object_size,
    .array_get        = cjson_array_get,
    .array_size       = cjson_array_size,
    .object_iter_init = cjson_object_iter_init,
    .object_iter_next = cjson_object_iter_next,
    .array_iter_init  = cjson_array_iter_init,
    .array_iter_next  = cjson_array_iter_next,
};

pubnub_serialization_provider_t* pn_serialization_default(void)
{
    return &pn_cjson_serialization;
}
