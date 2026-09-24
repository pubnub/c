/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#ifndef PUBNUB_IT_ENV_H
#define PUBNUB_IT_ENV_H

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Keys loaded from environment variables at test startup.
 * Any field may be NULL when the corresponding env var is absent.
 */
typedef struct it_env {
    const char* publish_key;
    const char* subscribe_key;
    const char* pam_publish_key;
    const char* pam_subscribe_key;
    const char* pam_secret_key;
} it_env_t;

/**
 * @brief Load keys from environment variables. Idempotent; safe to call
 * multiple times. Returns pointer to internal static storage.
 *
 * Variables read:
 *   PUBNUB_PUBLISH_KEY   PUBNUB_SUBSCRIBE_KEY
 *   PAM_PUBLISH_KEY      PAM_SUBSCRIBE_KEY      PAM_SECRET_KEY
 */
const it_env_t* it_env_load(void);

/**
 * @brief Skip the current cmocka test when the regular keyset is absent.
 * Must be the first call in setup() after it_env_load().
 */
#define SKIP_IF_NO_KEYS(env)                                              \
    do {                                                                  \
        if (NULL == (env)->publish_key || NULL == (env)->subscribe_key) { \
            skip();                                                       \
        }                                                                 \
    } while (0)

/**
 * @brief Skip when the PAM keyset is absent.
 */
#define SKIP_IF_NO_PAM_KEYS(env)                                               \
    do {                                                                       \
        if (NULL == (env)->pam_publish_key || NULL == (env)->pam_subscribe_key \
            || NULL == (env)->pam_secret_key) {                                \
            skip();                                                            \
        }                                                                      \
    } while (0)

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_IT_ENV_H */
