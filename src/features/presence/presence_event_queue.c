/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "presence_event_queue.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_event_queue.c requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#define PN_EEQ_QUEUE_T    pn_presence_event_queue_t
#define PN_EEQ_EVENT_T    pn_presence_ee_event_t
#define PN_EEQ_CAPACITY   PUBNUB_CFG_PRESENCE_EVENT_QUEUE_SIZE
#define PN_EEQ_INIT       pn_presence_event_queue_init
#define PN_EEQ_PUSH       pn_presence_event_queue_push
#define PN_EEQ_POP        pn_presence_event_queue_pop
#define PN_EEQ_HAS_EVENTS pn_presence_event_queue_has_events
#define PN_EEQ_CLEAR      pn_presence_event_queue_clear

#include "core/protocol_common/pn_ee_event_queue_impl.h"

#undef PN_EEQ_QUEUE_T
#undef PN_EEQ_EVENT_T
#undef PN_EEQ_CAPACITY
#undef PN_EEQ_INIT
#undef PN_EEQ_PUSH
#undef PN_EEQ_POP
#undef PN_EEQ_HAS_EVENTS
#undef PN_EEQ_CLEAR
