/*
 * Compile-only probe for PUBNUB_CLEAR_VALUE on Windows DLL consumers.
 *
 * Driven by tests/ci/CMakeLists.txt. Two shapes of the same usage:
 *   - block scope (default): run-time assignment, valid for every build
 *     flavour including PUBNUB_SHARED (dllimport);
 *   - file scope (-DPN_CHECK_FILE_SCOPE): static initializer, valid for
 *     static builds but rejected by MSVC with C2099 when the marker is a
 *     dllimport data symbol (PUBNUB_SHARED).
 */

#include "pubnub/features/app_context.h"

#if defined(PN_CHECK_FILE_SCOPE)

static const pubnub_set_uuid_metadata_opts_t k_file_scope_opts = {
    .uuid = "uuid-1",
    .name = PUBNUB_CLEAR_VALUE,
};

int pn_ci_clear_value_check(void)
{
    return (PUBNUB_CLEAR_VALUE == k_file_scope_opts.name) ? 0 : 1;
}

#else

int pn_ci_clear_value_check(void)
{
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;

    opts.uuid = "uuid-1";
    opts.name = PUBNUB_CLEAR_VALUE;
    return (PUBNUB_CLEAR_VALUE == opts.name) ? 0 : 1;
}

#endif
