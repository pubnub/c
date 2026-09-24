# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Internal build helpers shared across the SDK's CMake tree.

# _pn_sdk_library(<target> [sources...])
#
# Create an OBJECT library and register it for aggregation into the
# final `pubnub` target. All internal SDK targets (pn_* and
# pubnub_provider_*) must use this instead of bare add_library().
#
# Sources may be passed inline or added later via target_sources().
function(_pn_sdk_library target)
    add_library(${target} OBJECT ${ARGN})
    set_property(GLOBAL APPEND PROPERTY PN_ALL_OBJECT_TARGETS ${target})
endfunction()

# _pn_derive_profile_embedded(<out_var>)
#
# Derive the internal embedded-vs-hosted profile signal that config_internal.h
# consumes as PN_PROFILE_EMBEDDED. Constrained targets (the "embedded" profile
# or any no-heap configuration) enforce tight socket-transport stack/resource
# ceilings; hosted targets relax them. Sets <out_var> to exactly 1 or 0 in the
# CALLER's scope so it is visible to the configure_file(config_internal.h.in)
# call that must follow it.
#
# The "embedded" profile and PUBNUB_CFG_NO_HEAP are decoupled deliberately: a
# hosted OS build may opt into no-heap and must still select the tight ceilings.
# Do not collapse this to a single variable. This is the single source of truth
# for the derivation — every configure_file(config_internal.h.in) site must call
# it first (host build and ESP-IDF build both do).
function(_pn_derive_profile_embedded out_var)
    if(PUBNUB_PROFILE STREQUAL "embedded" OR PUBNUB_CFG_NO_HEAP)
        set(${out_var} 1 PARENT_SCOPE)
    else()
        set(${out_var} 0 PARENT_SCOPE)
    endif()
endfunction()
