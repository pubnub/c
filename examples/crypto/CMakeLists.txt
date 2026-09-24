# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the crypto module feature.
#
# Demonstrates creating a crypto module, attaching it to a context, and
# publishing encrypted messages using two consumption styles:
#
#   cooperative.c -- pumps pubnub_process() in a polling loop.
#   async.c       -- registers pubnub_async() completion callback.
#
# The remaining files each cover one crypto-module operation so that each
# serves as a self-contained doc snippet:
#
#   module_legacy.c            -- legacy-default module, round trip.
#   module_custom_cryptors.c   -- pubnub_crypto_module_create() plus a
#                                 custom pubnub_crypto_provider_t vtable.
#   encrypt_decrypt_buf.c      -- no-allocation fixed-buffer variants.
#   encrypt_decrypt_alloc.c    -- SDK-allocated variants.
#   encrypt_decrypt_base64.c   -- base64 text variants.
#   migrate_legacy.c           -- legacy to AES-CBC without re-encrypting.

add_executable(example_crypto_cooperative cooperative.c)
target_link_libraries(example_crypto_cooperative PRIVATE pubnub)
set_target_properties(
    example_crypto_cooperative
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_crypto_cooperative)
pubnub_target_sanitizers(example_crypto_cooperative)

add_executable(example_crypto_async async.c)
target_link_libraries(example_crypto_async PRIVATE pubnub)
set_target_properties(
    example_crypto_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_crypto_async)
pubnub_target_sanitizers(example_crypto_async)

add_executable(example_crypto_module_legacy module_legacy.c)
target_link_libraries(example_crypto_module_legacy PRIVATE pubnub)
set_target_properties(
    example_crypto_module_legacy
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_crypto_module_legacy)
pubnub_target_sanitizers(example_crypto_module_legacy)

add_executable(example_crypto_module_custom_cryptors module_custom_cryptors.c)
target_link_libraries(example_crypto_module_custom_cryptors PRIVATE pubnub)
set_target_properties(
    example_crypto_module_custom_cryptors
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_crypto_module_custom_cryptors)
pubnub_target_sanitizers(example_crypto_module_custom_cryptors)

add_executable(example_crypto_encrypt_decrypt_buf encrypt_decrypt_buf.c)
target_link_libraries(example_crypto_encrypt_decrypt_buf PRIVATE pubnub)
set_target_properties(
    example_crypto_encrypt_decrypt_buf
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_crypto_encrypt_decrypt_buf)
pubnub_target_sanitizers(example_crypto_encrypt_decrypt_buf)

add_executable(example_crypto_encrypt_decrypt_alloc encrypt_decrypt_alloc.c)
target_link_libraries(example_crypto_encrypt_decrypt_alloc PRIVATE pubnub)
set_target_properties(
    example_crypto_encrypt_decrypt_alloc
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_crypto_encrypt_decrypt_alloc)
pubnub_target_sanitizers(example_crypto_encrypt_decrypt_alloc)

add_executable(example_crypto_encrypt_decrypt_base64 encrypt_decrypt_base64.c)
target_link_libraries(example_crypto_encrypt_decrypt_base64 PRIVATE pubnub)
set_target_properties(
    example_crypto_encrypt_decrypt_base64
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_crypto_encrypt_decrypt_base64)
pubnub_target_sanitizers(example_crypto_encrypt_decrypt_base64)

add_executable(example_crypto_migrate_legacy migrate_legacy.c)
target_link_libraries(example_crypto_migrate_legacy PRIVATE pubnub)
set_target_properties(
    example_crypto_migrate_legacy
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_crypto_migrate_legacy)
pubnub_target_sanitizers(example_crypto_migrate_legacy)
