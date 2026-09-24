# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the access manager (PAM) feature.
#
#   grant_token.c       -- grant with multiple channels + pattern.
#   grant_token_async.c -- grant with async callback completion.
#   revoke_token.c      -- revoke a previously granted token.
#   parse_token.c       -- local token decode (no network).

add_executable(example_access_grant_token grant_token.c)
target_link_libraries(example_access_grant_token PRIVATE pubnub)
set_target_properties(
    example_access_grant_token
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_access_grant_token)
pubnub_target_sanitizers(example_access_grant_token)

add_executable(example_access_grant_token_async grant_token_async.c)
target_link_libraries(example_access_grant_token_async PRIVATE pubnub)
set_target_properties(
    example_access_grant_token_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_access_grant_token_async)
pubnub_target_sanitizers(example_access_grant_token_async)

add_executable(example_access_revoke_token revoke_token.c)
target_link_libraries(example_access_revoke_token PRIVATE pubnub)
set_target_properties(
    example_access_revoke_token
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_access_revoke_token)
pubnub_target_sanitizers(example_access_revoke_token)

add_executable(example_access_parse_token parse_token.c)
target_link_libraries(example_access_parse_token PRIVATE pubnub)
set_target_properties(
    example_access_parse_token
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_access_parse_token)
pubnub_target_sanitizers(example_access_parse_token)
