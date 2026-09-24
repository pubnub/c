# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# Resolve the selected serialization provider backend.
pubnub_provider_subdir("serialization" _pn_serialization_subdir)
add_subdirectory("${_pn_serialization_subdir}")
