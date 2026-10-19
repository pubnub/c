/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "presence_manager.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_manager.c requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "presence_event_queue.h"
#include "presence_internal.h"

#include "core/core_internal.h"
#include "core/pn_string.h"
#include "core/runtime/pipeline_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"
#include "core/runtime/timer_list_internal.h"

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport.h"

#include <string.h>

/**
 * @brief Compute the heartbeat interval in milliseconds from config.
 *
 * heartbeat_interval == 0 is the explicit opt-out: it disables
 * automatic heartbeat dispatch and returns 0. Any non-zero value is
 * used directly (converted from seconds to milliseconds). The caller
 * must not schedule a timer when the result is 0.
 */
static uint32_t compute_heartbeat_interval_ms(const pubnub_config_t* config)
{
    if (0 == config->heartbeat_interval) {
        return 0;
    }

    return config->heartbeat_interval * 1000U;
}

pn_presence_manager_t* pn_presence_manager_create(pubnub_context_t* ctx,
                                                  pubnub_allocator_provider_t* alloc)
{
    pn_presence_manager_t* mgr;

    if (NULL == ctx || NULL == alloc) {
        return NULL;
    }

    mgr = (pn_presence_manager_t*)PN_ALLOC(
        alloc, sizeof(pn_presence_manager_t), sizeof(void*));
    if (NULL == mgr) {
        return NULL;
    }

    memset(mgr, 0, sizeof(*mgr));
    mgr->ctx                    = ctx;
    mgr->ee_state               = PN_PRESENCE_STATE_HEARTBEAT_INACTIVE;
    mgr->active_slot_id         = PUBNUB_SLOT_ID_INVALID;
    mgr->active_slot_generation = 0;
    mgr->wait_timer             = NULL;

    /* Cache config fields. */
    const pubnub_config_t* config = pn_context_config(ctx);
    if (NULL != config) {
        mgr->suppress_leave        = config->suppress_leave_events;
        mgr->presence_timeout_sec  = (0U != config->presence_timeout)
                                       ? config->presence_timeout
                                       : PN_PRESENCE_DEFAULT_TIMEOUT_SEC;
        mgr->heartbeat_interval_ms = compute_heartbeat_interval_ms(config);
    }

    pn_timer_list_init(
        &mgr->timers, mgr->timer_entries, PUBNUB_CFG_PRESENCE_MAX_TIMERS);
    pn_presence_event_queue_init(&mgr->event_queue);

    return mgr;
}

static void cancel_active_slot(pn_presence_manager_t* mgr)
{
    pn_request_pool_t* pool = pn_context_request_pool(mgr->ctx);
    uint16_t           slot_id;
    uint16_t           generation = PN_GENERATION_ANY;
    pn_request_t*      slot;

    if (NULL == pool) {
        return;
    }
    slot_id = mgr->active_slot_id;
    if (slot_id >= pn_context_pool_capacity(mgr->ctx)) {
        /* Pending-range id: cancel the queued request, or follow it to the
         * pool slot it was promoted into. The async callback is suppressed
         * to avoid re-entry into the manager that is being destroyed. */
        pn_pending_ref_t ref = pn_context_pending_cancel_or_resolve(
            mgr->ctx, slot_id, mgr->active_slot_generation, 0);

        if (PN_PENDING_REF_REAL != ref.kind) {
            return;
        }
        slot_id    = ref.real_slot;
        generation = ref.real_generation;
    }

    slot = pn_request_pool_get(pool, slot_id);
    if (NULL != slot && PN_GENERATION_ANY != generation
        && generation != slot->generation) {
        return;
    }
    if (NULL != slot && !pn_request_is_terminal(slot) && !pn_request_is_idle(slot)) {
        pn_request_abort(mgr->ctx, slot_id, generation, PUBNUB_ERR_CANCELLED, 0);
    }
    if (NULL != slot && pn_request_is_terminal(slot)) {
        pn_context_release_terminal_slot(mgr->ctx, slot_id, PN_GENERATION_ANY);
    }
}

void pn_presence_manager_cleanup(void* state, pubnub_allocator_provider_t* alloc)
{
    pn_presence_manager_t* mgr;

    if (NULL == state || NULL == alloc) {
        return;
    }

    mgr           = (pn_presence_manager_t*)state;
    mgr->draining = 1;

    if (NULL != mgr->wait_timer) {
        pn_timer_list_remove(&mgr->timers, mgr->wait_timer);
        mgr->wait_timer = NULL;
    }

    if (PUBNUB_SLOT_ID_INVALID != mgr->active_slot_id) {
        cancel_active_slot(mgr);
        mgr->active_slot_id         = PUBNUB_SLOT_ID_INVALID;
        mgr->active_slot_generation = 0;
    }

    pn_strfree(mgr->channels, alloc);
    pn_strfree(mgr->groups, alloc);
    pn_strfree(mgr->leave_channels, alloc);
    pn_strfree(mgr->leave_groups, alloc);
    PN_FREE(alloc, state);
}
