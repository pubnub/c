# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# Resolve the selected transport provider backend.
pubnub_provider_subdir("transport" _pn_transport_subdir)
add_subdirectory("${_pn_transport_subdir}")
