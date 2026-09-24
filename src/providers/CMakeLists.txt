# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# Each provider family selects exactly one backend subdirectory.
# Custom providers use an external absolute path and need a binary dir.
# "none" providers are disabled entirely — no subdirectory to add;
# we create an INTERFACE library so link targets still resolve.

macro(_pn_add_provider_subdir family)
    pubnub_provider_subdir("${family}" _pn_${family}_subdir)
    if("${_pn_${family}_subdir}" STREQUAL "none")
        # Disabled provider — create an empty INTERFACE target so that
        # target_link_libraries(pubnub ... pubnub_provider_${family}) works.
        add_library(pubnub_provider_${family} INTERFACE)
        target_link_libraries(pubnub_provider_${family} INTERFACE pubnub_public_headers)
    elseif(IS_ABSOLUTE "${_pn_${family}_subdir}")
        # External custom directory — provide a binary dir under the build tree.
        add_subdirectory("${_pn_${family}_subdir}" "${CMAKE_CURRENT_BINARY_DIR}/${family}/custom")
    else()
        # Built-in provider — relative path under this directory.
        add_subdirectory("${family}/${_pn_${family}_subdir}")
    endif()
endmacro()

_pn_add_provider_subdir(allocator)
_pn_add_provider_subdir(crypto)
_pn_add_provider_subdir(logger)
_pn_add_provider_subdir(platform)
_pn_add_provider_subdir(serialization)
_pn_add_provider_subdir(transport)
