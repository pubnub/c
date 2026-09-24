# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Arena allocator sizing calculator.
#
# Computes PUBNUB_CFG_ARENA_POOL_SIZE and PUBNUB_CFG_ARENA_ALLOC_BUDGET from
# current feature/buffer/concurrency settings. Called from embedded profile
# application (profiles.cmake) and ESP-IDF component (PubnubESP.cmake).

# ---------------------------------------------------------------------------
# Upper bounds per component (conservative, architecture-independent).
# Derived from struct size analysis on 32-bit targets with mbedTLS.
# Update when structs grow significantly.
# ---------------------------------------------------------------------------
set(PN_ARENA_BOUND_TRANSPORT_BASE 1024)
# TLS context is a single arena allocation covering the base mbedTLS config
# (x509_crt chain dominates, ~1.3KB) plus the hostname-indexed session cache.
# Each cache entry is ~840B (mbedtls_ssl_session + 256B fixed ticket buffer +
# host key). Measured sizeof(pn_mbedtls_ctx): 1672 base, 3344 at the embedded
# default (cache=2), 3472 with the Files hostname bump (host=128), 5776 at the
# hosted default (cache=4). 3584 covers the embedded worst case on both 32- and
# 64-bit with margin; hosted profiles use stdlib malloc so this bound does not
# gate them. Raise if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE is overridden above 2.
set(PN_ARENA_BOUND_TLS_CTX 3584)
set(PN_ARENA_BOUND_TLS_SESSION 2048)
set(PN_ARENA_BOUND_REQUEST_SLOT 1024)
set(PN_ARENA_BOUND_PENDING_SLOT 1024)
set(PN_ARENA_BOUND_MIDDLEWARE_BASE 512)
set(PN_ARENA_BOUND_SUBSCRIBE_MGR 512)
set(PN_ARENA_BOUND_PRESENCE_MGR 512)
set(PN_ARENA_BOUND_DNS_CACHE_ENTRY 200)
set(PN_ARENA_BOUND_OVERHEAD 512)

# Serialization peak: transient Zone B for jsmn token arrays during parsing.
#
# Heavy (4096B): multi-item responses — subscribe batch, history fetch,
#   app_context list, files list, message_actions get, presence here_now.
#   128-token array (2560B) + ~40 nodes × 16B + string copies. Covers
#   3-message subscribe batches, 25-message history fetches, and here_now
#   with MAX_SUBSCRIBE_CHANNELS occupants on 32-bit targets.
#
# Light (1024B): single-result or small-list responses — publish ([1,"Sent",tt]),
#   time ([tt]), signal, channel_groups list, push list_channels, PAM grant
#   response. 64 tokens (1024B) + slab overhead. Slab-based parse packs
#   nodes, pairs, strings, and pointer arrays into a single allocation sized
#   from the token array, so the light peak is lower than pre-slab.
set(PN_ARENA_BOUND_SERIALIZATION_PEAK 4096)
set(PN_ARENA_BOUND_SERIALIZATION_PEAK_LIGHT 1024)

# ---------------------------------------------------------------------------
# pubnub_compute_arena_sizes()
#
# Compute Zone A (deterministic buffer slots) and Zone B (structural allocs)
# for the arena allocator. Respects user -D overrides via the global property
# mechanism established by pubnub_snapshot_user_overrides().
#
# Sets PUBNUB_CFG_ARENA_POOL_SIZE and PUBNUB_CFG_ARENA_ALLOC_BUDGET in the
# parent scope (or cache when called from a function).
# ---------------------------------------------------------------------------
function(pubnub_compute_arena_sizes)
    # ------------------------------------------------------------------
    # Zone A: deterministic from buffer sizes and concurrency limits.
    #   MAX_IN_FLIGHT * RESPONSE_BUF
    #   + OBJ_SLOT_COUNT * OBJECT_BUF
    #   + MAX_IN_FLIGHT * SCRATCH_BUF
    #
    # OBJ slot count accounts for compression: when request compression
    # is enabled, the compression middleware acquires two OBJ-purpose
    # slots per in-flight compressed request (original body + compressed
    # copy).
    # ------------------------------------------------------------------
    if(PUBNUB_ENABLE_REQUEST_COMPRESSION)
        math(
            EXPR
            PN_OBJ_SLOT_COUNT
            "${PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS} * 2 + ${PUBNUB_CFG_MAX_PENDING_REQUESTS}"
        )
    else()
        math(
            EXPR
            PN_OBJ_SLOT_COUNT
            "${PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS} + ${PUBNUB_CFG_MAX_PENDING_REQUESTS}"
        )
    endif()
    math(
        EXPR
        PN_ARENA_ZONE_A
        "${PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS} * ${PUBNUB_CFG_RESPONSE_BUFFER_SIZE} + ${PN_OBJ_SLOT_COUNT} * ${PUBNUB_CFG_OBJECT_BUFFER_SIZE} + ${PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS} * ${PUBNUB_CFG_SCRATCH_BUFFER_SIZE}"
    )

    # ------------------------------------------------------------------
    # Zone B: recommended budget from component upper bounds.
    # ------------------------------------------------------------------

    # Transport base (always present)
    set(PN_BUDGET ${PN_ARENA_BOUND_TRANSPORT_BASE})

    # TLS context (once per context) and per-connection sessions
    if(PUBNUB_ENABLE_SECURE_TRANSPORT)
        math(EXPR PN_BUDGET "${PN_BUDGET} + ${PN_ARENA_BOUND_TLS_CTX}")
        math(
            EXPR
            PN_BUDGET
            "${PN_BUDGET} + ${PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS} * ${PN_ARENA_BOUND_TLS_SESSION}"
        )
    endif()

    # Request and pending pool
    math(
        EXPR
        PN_BUDGET
        "${PN_BUDGET} + ${PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS} * ${PN_ARENA_BOUND_REQUEST_SLOT} + ${PUBNUB_CFG_MAX_PENDING_REQUESTS} * ${PN_ARENA_BOUND_PENDING_SLOT}"
    )

    # Prep pool: staging entries for feature request building before dispatch.
    # Each prep entry has the same layout as a pending slot.
    math(
        EXPR
        PN_BUDGET
        "${PN_BUDGET} + ${PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS} * ${PN_ARENA_BOUND_PENDING_SLOT}"
    )

    # Middleware base (always: auth, pnsdk, userid)
    math(EXPR PN_BUDGET "${PN_BUDGET} + ${PN_ARENA_BOUND_MIDDLEWARE_BASE}")

    # Subscribe manager (lazy-alloc, but budget must cover it).
    if(PUBNUB_ENABLE_SUBSCRIBE)
        math(EXPR PN_BUDGET "${PN_BUDGET} + ${PN_ARENA_BOUND_SUBSCRIBE_MGR}")
    endif()

    # Presence manager (lazy-alloc on first subscribe, but budget must cover it).
    if(PUBNUB_ENABLE_PRESENCE)
        math(EXPR PN_BUDGET "${PN_BUDGET} + ${PN_ARENA_BOUND_PRESENCE_MGR}")
    endif()

    # Serialization transient peak for parsing JSON response bodies.
    # Every feature that makes HTTP requests receives JSON — the jsmn token
    # array and intermediate parse state consume Zone B transiently. Budget
    # the full peak for features with multi-item responses (batches, lists,
    # object collections); a lighter peak for features returning simple
    # envelopes (single-result or small fixed-size arrays).
    #
    # Response sizes are ultimately bounded by PUBNUB_CFG_RESPONSE_BUFFER_SIZE
    # (typically 4KB on embedded). Worst-case jsmn tokens for a 4KB response:
    #   ~200 tokens × 16B = 3200B (real-world: subscribe batch, history fetch,
    #   app_context list). Lighter responses (publish, time, signal, push list,
    #   channel_groups list) fit comfortably in ~1.5KB of token budget.
    if(
        PUBNUB_ENABLE_SUBSCRIBE
        OR PUBNUB_ENABLE_HISTORY
        OR PUBNUB_ENABLE_APP_CONTEXT
        OR PUBNUB_ENABLE_FILES
        OR PUBNUB_ENABLE_MESSAGE_ACTIONS
        OR PUBNUB_ENABLE_PRESENCE
    )
        math(EXPR PN_BUDGET "${PN_BUDGET} + ${PN_ARENA_BOUND_SERIALIZATION_PEAK}")
    elseif(
        PUBNUB_ENABLE_CHANNEL_GROUPS
        OR PUBNUB_ENABLE_PUSH_NOTIFICATIONS
        OR PUBNUB_ENABLE_PAM
        OR PUBNUB_ENABLE_PUBLISH
        OR PUBNUB_ENABLE_SIGNAL
        OR PUBNUB_ENABLE_TIME
    )
        math(EXPR PN_BUDGET "${PN_BUDGET} + ${PN_ARENA_BOUND_SERIALIZATION_PEAK_LIGHT}")
    endif()

    # Decompression peak: tinfl workspace (~11KB) + per-connection output buffer.
    #
    # The workspace is acquired and released inside a single inflate call, so
    # only one is ever live regardless of concurrency — budget it once. The
    # output buffer is owned by the connection and retained until the next
    # request reuses that connection, so MAX_IN_FLIGHT of them can be live
    # simultaneously and the budget must scale by N.
    if(PUBNUB_ENABLE_COMPRESSION)
        set(PN_ARENA_BOUND_TINFL_WORKSPACE 11264)
        math(
            EXPR
            PN_BUDGET
            "${PN_BUDGET} + ${PN_ARENA_BOUND_TINFL_WORKSPACE} + ${PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS} * ${PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE}"
        )
    endif()

    # DNS cache entries
    if(DEFINED PUBNUB_CFG_DNS_CACHE_SIZE)
        math(
            EXPR
            PN_BUDGET
            "${PN_BUDGET} + ${PUBNUB_CFG_DNS_CACHE_SIZE} * ${PN_ARENA_BOUND_DNS_CACHE_ENTRY}"
        )
    endif()

    # Alignment/overhead
    math(EXPR PN_BUDGET "${PN_BUDGET} + ${PN_ARENA_BOUND_OVERHEAD}")

    # ------------------------------------------------------------------
    # Three-way override logic:
    #   1. User set POOL_SIZE explicitly -> derive budget; validate.
    #   2. User set ALLOC_BUDGET explicitly -> derive pool.
    #   3. Neither set -> use computed budget, derive pool.
    # ------------------------------------------------------------------
    get_property(_user_set_pool GLOBAL PROPERTY _PN_USER_SET_PUBNUB_CFG_ARENA_POOL_SIZE)
    get_property(_user_set_budget GLOBAL PROPERTY _PN_USER_SET_PUBNUB_CFG_ARENA_ALLOC_BUDGET)

    # ESP-IDF/wrapper builds: pubnub_snapshot_user_overrides() never runs, so
    # the global properties above are empty. Fall back to DEFINED check for
    # plain variables set before the include (e.g. in a wrapper component).
    # In host builds the global property is already set before reaching here,
    # so this fallback never fires there.
    if(NOT _user_set_pool AND DEFINED PUBNUB_CFG_ARENA_POOL_SIZE)
        set(_user_set_pool TRUE)
    endif()
    if(NOT _user_set_budget AND DEFINED PUBNUB_CFG_ARENA_ALLOC_BUDGET)
        set(_user_set_budget TRUE)
    endif()

    if(_user_set_pool AND _user_set_budget)
        # Both explicit: respect user values, validate only.
        set(PN_FINAL_POOL "${PUBNUB_CFG_ARENA_POOL_SIZE}")
        set(PN_FINAL_BUDGET "${PUBNUB_CFG_ARENA_ALLOC_BUDGET}")
        math(EXPR _minimum_pool "${PN_ARENA_ZONE_A} + ${PN_FINAL_BUDGET}")
        if(PN_FINAL_POOL LESS _minimum_pool)
            message(
                WARNING
                "[PubNub] Arena: POOL_SIZE (${PN_FINAL_POOL}) < Zone A (${PN_ARENA_ZONE_A})"
                " + ALLOC_BUDGET (${PN_FINAL_BUDGET}) = ${_minimum_pool}. OOM likely at runtime."
            )
        endif()
        set(_source "user override")

    elseif(_user_set_pool)
        # User set pool only: derive budget = pool - zone_a.
        set(PN_FINAL_POOL "${PUBNUB_CFG_ARENA_POOL_SIZE}")
        math(EXPR PN_FINAL_BUDGET "${PN_FINAL_POOL} - ${PN_ARENA_ZONE_A}")
        if(PN_FINAL_BUDGET LESS PN_BUDGET)
            message(
                WARNING
                "[PubNub] Arena: derived budget (${PN_FINAL_BUDGET}) < recommended"
                " minimum (${PN_BUDGET}). Increase PUBNUB_CFG_ARENA_POOL_SIZE or"
                " reduce buffer sizes."
            )
        endif()
        set(_source "pool from user, budget derived")

    elseif(_user_set_budget)
        # User set budget only: derive pool = zone_a + budget.
        set(PN_FINAL_BUDGET "${PUBNUB_CFG_ARENA_ALLOC_BUDGET}")
        math(EXPR PN_FINAL_POOL "${PN_ARENA_ZONE_A} + ${PN_FINAL_BUDGET}")
        set(_source "budget from user, pool derived")

    else()
        # Neither set: auto-compute both.
        set(PN_FINAL_BUDGET "${PN_BUDGET}")
        math(EXPR PN_FINAL_POOL "${PN_ARENA_ZONE_A} + ${PN_FINAL_BUDGET}")
        set(_source "auto-computed")
    endif()

    # ------------------------------------------------------------------
    # Round budget up to a 256-byte cell boundary so that
    #   PUBNUB_CFG_ARENA_ALLOC_BUDGET == PUBNUB_ARENA_MAX_ZONE_B_CELLS * 256
    # is always satisfied (required by the static assert in allocator_arena.c).
    # Component bounds that are not multiples of 256 (e.g. DNS_CACHE_ENTRY=200)
    # can produce a budget that is not cell-aligned; rounding up here ensures
    # the cell count is an integer and the invariant holds without truncation.
    # The pool is updated to match so Zone A + Zone B stays consistent.
    # ------------------------------------------------------------------
    math(EXPR PN_FINAL_BUDGET "(${PN_FINAL_BUDGET} + 255) / 256 * 256")
    math(EXPR PN_FINAL_POOL "${PN_ARENA_ZONE_A} + ${PN_FINAL_BUDGET}")
    math(EXPR PUBNUB_ARENA_MAX_ZONE_B_CELLS "${PN_FINAL_BUDGET} / 256")

    # ------------------------------------------------------------------
    # Apply values to cache.
    # ------------------------------------------------------------------
    set(PUBNUB_CFG_ARENA_POOL_SIZE "${PN_FINAL_POOL}" CACHE STRING "" FORCE)
    set(PUBNUB_CFG_ARENA_ALLOC_BUDGET "${PN_FINAL_BUDGET}" CACHE STRING "" FORCE)
    set(PUBNUB_ARENA_MAX_ZONE_B_CELLS "${PUBNUB_ARENA_MAX_ZONE_B_CELLS}" CACHE STRING "" FORCE)

    if(PUBNUB_ARENA_POOL_OWNER STREQUAL "user")
        set(_owner_note "(user-owned; no SDK BSS allocation)")
    else()
        set(_owner_note "(SDK-owned BSS)")
    endif()
    message(
        STATUS
        "[PubNub] Arena: Zone A = ${PN_ARENA_ZONE_A} bytes,"
        " Zone B budget = ${PN_FINAL_BUDGET} bytes,"
        " pool = ${PN_FINAL_POOL} bytes (${_source}) ${_owner_note}"
    )
endfunction()
