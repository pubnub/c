/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_cbor.h"

#include <string.h>

/**
 * @brief Parse stack frame for iterative map processing.
 *
 * Each active map pushes one frame. The parser pops the frame
 * once all entries for that map have been consumed.
 */
typedef struct pn_cbor_parse_frame {
    /** Map node currently being filled. */
    pn_cbor_value_t* map_node;
    /** Number of entries remaining to parse. */
    size_t remaining;
    /** Index of the current entry being populated. */
    size_t entry_index;
    /** 0 = next item is a key, 1 = next item is a value. */
    int expecting_value;
} pn_cbor_parse_frame_t;

/**
 * @brief Read cursor for bounded input traversal.
 */
typedef struct pn_cbor_cursor {
    /** Start of input buffer. */
    const uint8_t* base;
    /** Current read position offset. */
    size_t pos;
    /** Total input length. */
    size_t len;
} pn_cbor_cursor_t;

/**
 * @brief Cleanup stack frame for iterative tree deallocation.
 */
typedef struct pn_cbor_cleanup_frame {
    /** Map node being iterated for child cleanup. */
    pn_cbor_value_t* node;
    /** Next entry index to process. */
    size_t index;
} pn_cbor_cleanup_frame_t;

static pn_cbor_value_t* pn_cbor_alloc_node(pubnub_allocator_provider_t* alloc)
{
    pn_cbor_value_t* node =
        (pn_cbor_value_t*)PN_ALLOC(alloc, sizeof(pn_cbor_value_t), 0);
    if (NULL != node) {
        memset(node, 0, sizeof(*node));
        node->type = PN_CBOR_INVALID;
    }
    return node;
}

/**
 * @brief Decode the CBOR additional info field into a uint64 value.
 *
 * Handles inline (0-23), 1-byte (24), 2-byte (25), 4-byte (26),
 * and 8-byte (27) encodings with big-endian byte order.
 *
 * @return 0 on success (advances cursor), non-zero on bounds error.
 */
static int pn_cbor_decode_uint(pn_cbor_cursor_t* cursor,
                               uint8_t           additional,
                               uint64_t*         out)
{
    if (additional <= 23) {
        *out = additional;
        return 0;
    }

    if (24 == additional) {
        if (cursor->pos + 1 > cursor->len) {
            return -1;
        }
        *out = cursor->base[cursor->pos];
        cursor->pos += 1;
        return 0;
    }

    if (25 == additional) {
        if (cursor->pos + 2 > cursor->len) {
            return -1;
        }
        *out = ((uint64_t)cursor->base[cursor->pos] << 8)
             | (uint64_t)cursor->base[cursor->pos + 1];
        cursor->pos += 2;
        return 0;
    }

    if (26 == additional) {
        if (cursor->pos + 4 > cursor->len) {
            return -1;
        }
        *out = ((uint64_t)cursor->base[cursor->pos] << 24)
             | ((uint64_t)cursor->base[cursor->pos + 1] << 16)
             | ((uint64_t)cursor->base[cursor->pos + 2] << 8)
             | (uint64_t)cursor->base[cursor->pos + 3];
        cursor->pos += 4;
        return 0;
    }

    if (27 == additional) {
        if (cursor->pos + 8 > cursor->len) {
            return -1;
        }
        *out = ((uint64_t)cursor->base[cursor->pos] << 56)
             | ((uint64_t)cursor->base[cursor->pos + 1] << 48)
             | ((uint64_t)cursor->base[cursor->pos + 2] << 40)
             | ((uint64_t)cursor->base[cursor->pos + 3] << 32)
             | ((uint64_t)cursor->base[cursor->pos + 4] << 24)
             | ((uint64_t)cursor->base[cursor->pos + 5] << 16)
             | ((uint64_t)cursor->base[cursor->pos + 6] << 8)
             | (uint64_t)cursor->base[cursor->pos + 7];
        cursor->pos += 8;
        return 0;
    }

    /* additional >= 28: reserved/indefinite — not supported. */
    return -1;
}

/**
 * @brief Decode one CBOR item at the cursor into a pre-allocated node.
 *
 * For map items, only the map header is consumed (entry count stored);
 * child entries are parsed by the outer iterative loop.
 *
 * @return 0 on success, non-zero on any error.
 */
static int pn_cbor_decode_item(pn_cbor_cursor_t*            cursor,
                               pn_cbor_value_t*             node,
                               pubnub_allocator_provider_t* alloc)
{
    if (cursor->pos >= cursor->len) {
        return -1;
    }

    uint8_t  header     = cursor->base[cursor->pos];
    uint8_t  major_type = (header >> 5) & 0x07;
    uint8_t  additional = header & 0x1F;
    uint64_t argument   = 0;

    cursor->pos += 1;

    if (0 != pn_cbor_decode_uint(cursor, additional, &argument)) {
        return -1;
    }

    switch (major_type) {
    case 0: /* Unsigned integer */
        node->type          = PN_CBOR_UINT;
        node->data.uint_val = argument;
        return 0;

    case 2: /* Byte string */
        if (cursor->pos + argument > cursor->len) {
            return -1;
        }
        node->type           = PN_CBOR_BYTES;
        node->data.bytes.ptr = cursor->base + cursor->pos;
        node->data.bytes.len = (size_t)argument;
        cursor->pos += (size_t)argument;
        return 0;

    case 3: /* Text string */
        if (cursor->pos + argument > cursor->len) {
            return -1;
        }
        node->type            = PN_CBOR_STRING;
        node->data.string.ptr = (const char*)(cursor->base + cursor->pos);
        node->data.string.len = (size_t)argument;
        cursor->pos += (size_t)argument;
        return 0;

    case 5: { /* Map */
        /* Each map pair needs at least 2 bytes (1-byte key + 1-byte
         * value). Reject counts that exceed remaining input to prevent
         * integer overflow in the allocation size calculation. */
        size_t remaining_bytes = cursor->len - cursor->pos;
        if (argument > remaining_bytes / 2) {
            return -1;
        }
        size_t count         = (size_t)argument;
        node->type           = PN_CBOR_MAP;
        node->data.map.count = count;

        if (0 == count) {
            node->data.map.entries = NULL;
            return 0;
        }

        size_t               entries_size = count * sizeof(pn_cbor_map_entry_t);
        pn_cbor_map_entry_t* entries =
            (pn_cbor_map_entry_t*)PN_ALLOC(alloc, entries_size, 0);
        if (NULL == entries) {
            return -1;
        }
        memset(entries, 0, entries_size);
        node->data.map.entries = entries;
        return 0;
    }

    default:
        /* Types 1 (neg int), 4 (array), 6 (tag), 7 (float/special)
         * are not used in PubNub token format. */
        return -1;
    }
}

/**
 * @brief Iteratively clean up a CBOR value tree without recursion.
 *
 * Uses an explicit stack to walk the tree depth-first and free
 * nodes bottom-up.
 */
static void pn_cbor_cleanup_iterative(pn_cbor_value_t*             root,
                                      pubnub_allocator_provider_t* alloc)
{
    pn_cbor_cleanup_frame_t stack[PN_CBOR_MAX_DEPTH + 1];
    int                     depth = 0;

    stack[0].node  = root;
    stack[0].index = 0;
    depth          = 1;

    while (depth > 0) {
        pn_cbor_cleanup_frame_t* frame = &stack[depth - 1];
        pn_cbor_value_t*         node  = frame->node;

        if (PN_CBOR_MAP != node->type || frame->index >= node->data.map.count) {
            /* Leaf or exhausted map — free this node. */
            if (PN_CBOR_MAP == node->type && NULL != node->data.map.entries) {
                PN_FREE(alloc, node->data.map.entries);
            }
            PN_FREE(alloc, node);
            --depth;
            continue;
        }

        /* Process next entry in the current map. */
        pn_cbor_map_entry_t* entry = &node->data.map.entries[frame->index];
        frame->index += 1;

        /* Free the key (always a leaf in PubNub tokens). */
        if (NULL != entry->key) {
            PN_FREE(alloc, entry->key);
            entry->key = NULL;
        }

        /* Handle the value. */
        if (NULL == entry->value) {
            continue;
        }

        if (PN_CBOR_MAP == entry->value->type) {
            /* Push nested map for depth-first traversal. */
            if (depth < PN_CBOR_MAX_DEPTH + 1) {
                stack[depth].node  = entry->value;
                stack[depth].index = 0;
                ++depth;
            } else {
                /* Should not happen with valid parse output. */
                PN_FREE(alloc, entry->value);
            }
        } else {
            PN_FREE(alloc, entry->value);
        }
        entry->value = NULL;
    }
}

pn_cbor_value_t* pn_cbor_parse(const uint8_t*               input,
                               size_t                       input_len,
                               pubnub_allocator_provider_t* alloc)
{
    if (NULL == input || NULL == alloc || 0 == input_len) {
        return NULL;
    }

    if (input_len > PN_CBOR_MAX_INPUT) {
        return NULL;
    }

    pn_cbor_cursor_t cursor;
    cursor.base = input;
    cursor.pos  = 0;
    cursor.len  = input_len;

    /* Allocate root node. */
    pn_cbor_value_t* root = pn_cbor_alloc_node(alloc);
    if (NULL == root) {
        return NULL;
    }

    /* Decode the root item. */
    if (0 != pn_cbor_decode_item(&cursor, root, alloc)) {
        PN_FREE(alloc, root);
        return NULL;
    }

    /* If root is not a map, we're done — single scalar value. */
    if (PN_CBOR_MAP != root->type) {
        if (cursor.pos != cursor.len) {
            PN_FREE(alloc, root);
            return NULL;
        }
        return root;
    }

    /* Iterative map parsing with an explicit stack. */
    pn_cbor_parse_frame_t stack[PN_CBOR_MAX_DEPTH];
    int                   depth = 0;

    stack[0].map_node        = root;
    stack[0].remaining       = root->data.map.count;
    stack[0].entry_index     = 0;
    stack[0].expecting_value = 0;
    depth                    = 1;

    while (depth > 0) {
        pn_cbor_parse_frame_t* frame = &stack[depth - 1];

        /* Check if current map is fully parsed. */
        if (0 == frame->remaining && 0 == frame->expecting_value) {
            --depth;
            continue;
        }

        /* Decode the next item. */
        pn_cbor_value_t* node = pn_cbor_alloc_node(alloc);
        if (NULL == node) {
            pn_cbor_cleanup(root, alloc);
            return NULL;
        }

        if (0 != pn_cbor_decode_item(&cursor, node, alloc)) {
            PN_FREE(alloc, node);
            pn_cbor_cleanup(root, alloc);
            return NULL;
        }

        /* Assign the node to the appropriate slot. */
        pn_cbor_map_entry_t* entry =
            &frame->map_node->data.map.entries[frame->entry_index];

        if (0 == frame->expecting_value) {
            /* This item is a key. */
            entry->key             = node;
            frame->expecting_value = 1;
        } else {
            /* This item is a value. */
            entry->value           = node;
            frame->expecting_value = 0;
            frame->entry_index += 1;
            frame->remaining -= 1;

            /* If the value is a map, push a new frame. */
            if (PN_CBOR_MAP == node->type && node->data.map.count > 0) {
                if (depth >= PN_CBOR_MAX_DEPTH) {
                    pn_cbor_cleanup(root, alloc);
                    return NULL;
                }
                stack[depth].map_node        = node;
                stack[depth].remaining       = node->data.map.count;
                stack[depth].entry_index     = 0;
                stack[depth].expecting_value = 0;
                ++depth;
            }
        }
    }

    /* Reject trailing bytes — well-formed tokens consume all input. */
    if (cursor.pos != cursor.len) {
        pn_cbor_cleanup(root, alloc);
        return NULL;
    }

    return root;
}

pn_cbor_value_t* pn_cbor_map_get(const pn_cbor_value_t* map,
                                 const char*            key,
                                 size_t                 key_len)
{
    size_t i;

    if (NULL == map || PN_CBOR_MAP != map->type || NULL == key) {
        return NULL;
    }

    for (i = 0; i < map->data.map.count; ++i) {
        const pn_cbor_map_entry_t* entry = &map->data.map.entries[i];
        if (NULL == entry->key) {
            continue;
        }

        /* PubNub tokens use byte-string keys (major type 2) for
         * compactness; match both text and byte string types. */
        if (PN_CBOR_STRING == entry->key->type) {
            if (entry->key->data.string.len != key_len) {
                continue;
            }
            if (0 == memcmp(entry->key->data.string.ptr, key, key_len)) {
                return entry->value;
            }
        } else if (PN_CBOR_BYTES == entry->key->type) {
            if (entry->key->data.bytes.len != key_len) {
                continue;
            }
            if (0 == memcmp(entry->key->data.bytes.ptr, key, key_len)) {
                return entry->value;
            }
        }
    }
    return NULL;
}

void pn_cbor_cleanup(pn_cbor_value_t* root, pubnub_allocator_provider_t* alloc)
{
    if (NULL == root || NULL == alloc) {
        return;
    }
    pn_cbor_cleanup_iterative(root, alloc);
}
