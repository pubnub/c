/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/configuration/configuration.c
 * @brief Every pubnub_config_t topic that the docs show as a fragment
 *        rather than a whole program.
 *
 * One static function per topic, each wrapped in its own snippet, so a
 * doc page can show the four lines that matter instead of a full program
 * with create and destroy boilerplate around them. main() calls them all
 * so nothing is dead code and the whole file is a compile gate.
 *
 * Snippets:
 *
 *   configurationInitialize    -- defaults, required fields, create/init.
 *   configurationStaticStorage -- pubnub_init into caller-owned memory.
 *   configurationRetry         -- retry policy and endpoint exclusions.
 *   configurationProxy         -- HTTP CONNECT and SOCKS5 proxies.
 *   configurationTcpKeepalive  -- keepalive probe tuning.
 *   configurationProviders     -- overriding provider pointers.
 *   configurationRuntimeUpdate -- the five post-init mutable settings.
 *   configurationEventLoop     -- pubnub_process and pubnub_await.
 *   configurationSerialization -- reaching the serialization vtable.
 *
 * Build: cmake --build build/full --target example_configuration
 * Run:   ./build/full/examples/configuration/example_configuration
 */

#include "pubnub/pubnub.h"

#include "pubnub/providers/serialization.h"

#include <stdio.h>

// snippet.configurationInitialize

/* pubnub_config_defaults() seeds five things: both timeouts, TCP
 * keepalive, the retry configuration, and the log level. It does NOT set
 * publish_key, subscribe_key, or user_id, so those are always yours to
 * fill in. A bare `pubnub_config_t cfg = {0}` instead leaves the retry
 * policy at PUBNUB_RETRY_NONE and the log level at
 * PUBNUB_LOG_LEVEL_NONE. */
static pubnub_context_t* create_client(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-configuration";

    /* Optional identity and networking fields. */
    cfg.auth_token                 = NULL;
    cfg.transaction_timeout_ms     = 10000;
    cfg.non_transaction_timeout_ms = 310000;

    /* pubnub_create() allocates the context and deep-copies every string
     * field, so the strings above need not outlive this call. */
    return pubnub_create(&cfg);
}

// snippet.configurationStaticStorage

/* On no-heap targets, hand pubnub_init() your own storage instead.
 * PUBNUB_CONTEXT_SIZE is fixed at CMake configure time and
 * pubnub_context_size() reports the real requirement at runtime, so
 * check one against the other before casting. Unlike pubnub_create(),
 * pubnub_init() BORROWS every string field: they must outlive the
 * context. Tear down with pubnub_deinit(), not pubnub_destroy(). */
static PUBNUB_ALIGNAS(max_align_t) uint8_t s_ctx_storage[PUBNUB_CONTEXT_SIZE];

static pubnub_context_t* init_client_static(void)
{
    static const char user_id[] = "example-configuration-static";

    if (sizeof(s_ctx_storage) < pubnub_context_size()) {
        return NULL; /* PUBNUB_CONTEXT_SIZE too small, rebuild needed. */
    }

    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = user_id;

    pubnub_context_t* ctx = (pubnub_context_t*)s_ctx_storage;
    if (PUBNUB_OK != pubnub_init(ctx, &cfg)) {
        return NULL;
    }
    return ctx;
}

// snippet.configurationRetry

/* pubnub_config_defaults() selects PUBNUB_RETRY_EXPONENTIAL and then
 * excludes every endpoint group except subscribe, so out of the box only
 * subscribe retries. Override excluded_endpoints to change that.
 * PUBNUB_RETRY_LINEAR is opt-in and is never a default. */
static void configure_retry(pubnub_config_t* cfg)
{
    cfg->retry_configuration.policy           = PUBNUB_RETRY_EXPONENTIAL;
    cfg->retry_configuration.delay_ms         = 2000;
    cfg->retry_configuration.maximum_delay_ms = 60000;
    cfg->retry_configuration.maximum_retry    = 6;

    /* Retry subscribe and presence, nothing else. */
    cfg->retry_configuration.excluded_endpoints =
        PUBNUB_ENDPOINT_MESSAGE_SEND | PUBNUB_ENDPOINT_MESSAGE_STORAGE
        | PUBNUB_ENDPOINT_CHANNEL_GROUPS | PUBNUB_ENDPOINT_APP_CONTEXT
        | PUBNUB_ENDPOINT_MESSAGE_REACTIONS | PUBNUB_ENDPOINT_PAM;
}

// snippet.configurationProxy

/* A zero-initialized proxy config means no proxy. Set it before creating
 * the context: the transport reads it once at init.
 *
 * The bundled curl transport supports HTTP CONNECT and SOCKS5 with Basic
 * auth. PUBNUB_PROXY_AUTO, PUBNUB_PROXY_AUTH_DIGEST, and
 * PUBNUB_PROXY_AUTH_NTLM return PUBNUB_ERR_NOT_SUPPORTED at send time on
 * that transport. */
static void configure_proxy(pubnub_config_t* cfg)
{
    const pubnub_proxy_config_t http_proxy = {
        .type     = PUBNUB_PROXY_HTTP_CONNECT,
        .auth     = PUBNUB_PROXY_AUTH_BASIC,
        .host     = "proxy.corp.example.com",
        .port     = 3128,
        .username = "device-001",
        .password = "s3cr3t",
    };
    cfg->proxy = http_proxy;

    /* SOCKS5 without authentication, for comparison. */
    const pubnub_proxy_config_t socks_proxy = {
        .type = PUBNUB_PROXY_SOCKS5,
        .host = "socks.corp.example.com",
        .port = 1080,
    };
    (void)socks_proxy;
}

// snippet.configurationTcpKeepalive

/* PUBNUB_TCP_KEEPALIVE_CONFIG_INIT is enabled, 60s idle, 20s interval,
 * 3 probes, and is what pubnub_config_defaults() installs. Tighten it to
 * detect a dead peer sooner on the long-lived subscribe connection.
 *
 * Immutable after init: the transport copies the values once, so changing
 * them later has no effect. */
static void configure_tcp_keepalive(pubnub_config_t* cfg)
{
    cfg->tcp_keepalive.enabled      = 1;
    cfg->tcp_keepalive.idle_sec     = 30;
    cfg->tcp_keepalive.interval_sec = 10;
    cfg->tcp_keepalive.probe_count  = 3;
}

// snippet.configurationProviders

/* Leave a provider pointer NULL to accept the backend chosen at CMake
 * configure time. Set one to substitute your own implementation for this
 * context only. Providers are borrowed, so each must outlive the
 * context. Whether a substitution is per-context or shared depends on
 * the provider: crypto and transport are per-context and receive
 * init/deinit calls, while the logger is shared and never does. */
static void configure_providers(pubnub_config_t*             cfg,
                                pubnub_allocator_provider_t* allocator,
                                pubnub_logger_provider_t*    logger,
                                pubnub_crypto_module_t*      crypto)
{
    cfg->allocator     = allocator;
    cfg->logger        = logger;
    cfg->crypto_module = crypto;

    /* cfg->platform, cfg->transport, and cfg->serialization follow the
     * same rule. pnsdk_override replaces the SDK identity string that
     * wrapper SDKs report. */
    cfg->pnsdk_override = "PubNub-MyWrapper/1.0";
}

// snippet.configurationRuntimeUpdate

/* Five settings are mutable after init. Everything else on
 * pubnub_config_t is read once and needs a new context to change.
 * The string ownership rule matches creation: deep-copied for a
 * pubnub_create() context, borrowed for a pubnub_init() one. */
static void update_at_runtime(pubnub_context_t* ctx)
{
    pubnub_set_user_id(ctx, "example-configuration-renamed");
    pubnub_set_auth_token(ctx, "p0F2AkF0Gm...");
    pubnub_set_log_level(ctx, PUBNUB_LOG_LEVEL_WARNING);

    /* dns_primary and dns_secondary move together. Passing NULL for the
     * primary clears both and reverts to system discovery. */
    pubnub_set_dns_servers(ctx, "8.8.8.8", "1.1.1.1");

    /* TLS trust settings apply to connections opened after the call.
     * Never disable verification outside development. */
    pubnub_set_tls_ca_bundle(ctx, NULL);
    pubnub_set_tls_skip_verify(ctx, 0);
}

// snippet.configurationEventLoop

/* pubnub_process() is one non-blocking tick: it dispatches queued
 * requests, drives transport I/O, and observes completions. Call it in
 * your own loop when you own the thread.
 *
 * pubnub_await() is the blocking alternative. It runs the same loop
 * internally and returns the final status, so never mix the two on one
 * future. */
static void drive_event_loop(pubnub_context_t* ctx, pubnub_future_t fut)
{
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
        /* Yield here on a cooperative scheduler: usleep, vTaskDelay,
         * k_msleep, or whatever your target provides. */
    }
}

// snippet.configurationSerialization

/* pubnub_serialization() returns the context's resolved serialization
 * provider. Every vtable entry is individually optional, so NULL-check
 * the provider and each function pointer before calling it. The pointer
 * is borrowed and valid until the context is destroyed. */
static void read_string_payload(pubnub_context_t* ctx, const pubnub_json_value_t* node)
{
    pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
    if (NULL == serial || NULL == serial->value_as_string || NULL == node) {
        return;
    }

    size_t      len = 0;
    const char* val = serial->value_as_string(node, &len);
    if (NULL != val) {
        printf("payload: %.*s\n", (int)len, val);
    }
}

// snippet.end

int main(void)
{
    pubnub_config_t probe = pubnub_config_defaults();
    configure_retry(&probe);
    configure_proxy(&probe);
    configure_tcp_keepalive(&probe);
    configure_providers(&probe, NULL, NULL, NULL);

    pubnub_context_t* ctx = create_client();
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    update_at_runtime(ctx);
    read_string_payload(ctx, NULL);

    pubnub_future_t fut = pubnub_time(ctx);
    drive_event_loop(ctx, fut);
    printf("time status: %s\n", pubnub_res_str(pubnub_future_status(fut)));
    pubnub_future_release(fut);
    pubnub_destroy(ctx);

    pubnub_context_t* static_ctx = init_client_static();
    if (NULL != static_ctx) {
        pubnub_deinit(static_ctx);
    }
    return 0;
}
