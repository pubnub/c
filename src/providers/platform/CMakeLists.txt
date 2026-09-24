# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# Resolve the selected platform provider backend.
pubnub_provider_subdir("platform" _pn_platform_subdir)
add_subdirectory("${_pn_platform_subdir}")
