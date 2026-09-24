# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# Resolve the selected crypto provider backend.
pubnub_provider_subdir("crypto" _pn_crypto_subdir)
add_subdirectory("${_pn_crypto_subdir}")
