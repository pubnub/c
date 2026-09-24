/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_protocol.h"
#include "ks_test_runner.h"
#include "ks_tests.h"

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/providers/allocator_arena.h"
#include "pubnub/pubnub_compat.h"

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define WIFI_SSID          CONFIG_PUBNUB_KS_WIFI_SSID
#define WIFI_PASS          CONFIG_PUBNUB_KS_WIFI_PASSWORD
#define WIFI_CONNECTED_BIT BIT0

static EventGroupHandle_t s_wifi_event_group;

static uint8_t                  s_pool[PUBNUB_CFG_ARENA_POOL_SIZE];
static pubnub_arena_allocator_t s_arena;
static PUBNUB_ALIGNAS(max_align_t) uint8_t s_ctx_mem[PUBNUB_CONTEXT_SIZE];

PUBNUB_STATIC_ASSERT(KS_CRYPTO_POOL_SIZE
                         > (size_t)PUBNUB_ARENA_RX_SLOTS * PUBNUB_CFG_RESPONSE_BUFFER_SIZE
                               + (size_t)PUBNUB_ARENA_OBJ_SLOTS * PUBNUB_CFG_OBJECT_BUFFER_SIZE
                               + (size_t)PUBNUB_ARENA_SCRATCH_SLOTS
                                     * PUBNUB_CFG_SCRATCH_BUFFER_SIZE,
                     "crypto pool must exceed arena Zone A footprint");

/** Crypto test resources (second context with crypto module). */
uint8_t*                 g_crypto_pool;
pubnub_arena_allocator_t g_crypto_arena;
PUBNUB_ALIGNAS(max_align_t) uint8_t g_crypto_ctx_mem[PUBNUB_CONTEXT_SIZE];

/**
 * Aggregate test table built from per-feature arrays.
 * This is sized generously; unused slots are harmless.
 */
#define KS_MAX_TESTS 128
static ks_test_entry_t s_all_tests[KS_MAX_TESTS];
static size_t          s_all_test_count;

static void build_test_table(void)
{
    size_t idx = 0;

#define APPEND_TESTS(arr, cnt)                                 \
    do {                                                       \
        size_t _i;                                             \
        for (_i = 0; _i < (cnt) && idx < KS_MAX_TESTS; _i++) { \
            s_all_tests[idx++] = (arr)[_i];                    \
        }                                                      \
    } while (0)

    APPEND_TESTS(ks_time_tests, ks_time_test_count);
    APPEND_TESTS(ks_publish_tests, ks_publish_test_count);
    APPEND_TESTS(ks_subscribe_tests, ks_subscribe_test_count);
    APPEND_TESTS(ks_presence_tests, ks_presence_test_count);
    APPEND_TESTS(ks_history_tests, ks_history_test_count);
    APPEND_TESTS(ks_signal_tests, ks_signal_test_count);
    APPEND_TESTS(ks_message_actions_tests, ks_message_actions_test_count);
    APPEND_TESTS(ks_channel_groups_tests, ks_channel_groups_test_count);
    APPEND_TESTS(ks_app_context_tests, ks_app_context_test_count);
    APPEND_TESTS(ks_files_tests, ks_files_test_count);
    APPEND_TESTS(ks_crypto_tests, ks_crypto_test_count);

#undef APPEND_TESTS

    s_all_test_count = idx;
}

static void wifi_event_handler(void*            arg,
                               esp_event_base_t event_base,
                               int32_t          event_id,
                               void*            event_data)
{
    (void)arg;
    (void)event_data;

    if (WIFI_EVENT == event_base) {
        if (WIFI_EVENT_STA_START == event_id) {
            printf("[WiFi] STA started, connecting...\n");
            esp_wifi_connect();
        } else if (WIFI_EVENT_STA_CONNECTED == event_id) {
            printf("[WiFi] L2 connected, waiting for DHCP...\n");
        } else if (WIFI_EVENT_STA_DISCONNECTED == event_id) {
            printf("[WiFi] Disconnected, reconnecting...\n");
            esp_wifi_connect();
        }
    } else if (IP_EVENT == event_base && IP_EVENT_STA_GOT_IP == event_id) {
        ip_event_got_ip_t* ev = (ip_event_got_ip_t*)event_data;
        printf("[WiFi] Got IP: " IPSTR "\n", IP2STR(&ev->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void)
{
    wifi_init_config_t           cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_event_handler_instance_t inst_any;
    esp_event_handler_instance_t inst_ip;
    wifi_config_t                wifi_config = {
                       .sta =
            {
                  .ssid     = WIFI_SSID,
                  .password = WIFI_PASS,
                  },
    };

    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &inst_any));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &inst_ip));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_start());

    xEventGroupWaitBits(
        s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
}

static void ntp_sync(void)
{
    time_t now      = 0;
    int    attempts = 0;

    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();

    while (now < 1000000000L && attempts < 100) {
        vTaskDelay(pdMS_TO_TICKS(100));
        time(&now);
        attempts++;
    }

    if (now >= 1000000000L) {
        printf("[NTP] Time synced: %s", ctime(&now));
    } else {
        printf("[NTP] Sync timed out\n");
    }
}

static void ks_task(void* arg)
{
    pubnub_allocator_provider_t* alloc;
    pubnub_config_t              cfg;
    pubnub_context_t*            ctx;
    pubnub_res_t                 rc;
    ks_runner_t                  runner;

    (void)arg;

    alloc = pubnub_arena_allocator_init(&s_arena, s_pool, sizeof(s_pool));
    if (NULL == alloc) {
        printf("[KS] Arena allocator init failed\n");
        vTaskDelete(NULL);
        return;
    }

    cfg                  = pubnub_config_defaults();
    cfg.subscribe_key    = CONFIG_PUBNUB_KS_SUB_KEY;
    cfg.publish_key      = CONFIG_PUBNUB_KS_PUB_KEY;
    cfg.user_id          = CONFIG_PUBNUB_KS_USER_ID;
    cfg.allocator        = alloc;
    cfg.presence_timeout = 120;

    ctx = (pubnub_context_t*)s_ctx_mem;
    if (sizeof(s_ctx_mem) < pubnub_context_size()) {
        printf("[KS] Context buffer too small "
               "(need %u, have %u)\n",
               (unsigned)pubnub_context_size(),
               (unsigned)sizeof(s_ctx_mem));
        vTaskDelete(NULL);
        return;
    }

    rc = pubnub_init(ctx, &cfg);
    if (PUBNUB_OK != rc) {
        printf("[KS] pubnub_init failed: %d (%s)\n", (int)rc, pubnub_res_str(rc));
        vTaskDelete(NULL);
        return;
    }
    printf("[KS] pubnub_init OK\n");
    pubnub_set_log_level(ctx, PUBNUB_LOG_LEVEL_TRACE);

    build_test_table();

    g_crypto_pool = (uint8_t*)pvPortMalloc(KS_CRYPTO_POOL_SIZE);
    if (NULL == g_crypto_pool) {
        printf("[KS] crypto pool alloc failed (%u bytes)"
               " -- crypto tests will skip\n",
               (unsigned)KS_CRYPTO_POOL_SIZE);
    }

    memset(&runner, 0, sizeof(runner));
    ks_runner_init(&runner, ctx, s_all_tests, s_all_test_count);
    runner.alloc = alloc;

    ks_runner_run_all(&runner);

    if (NULL != g_crypto_pool) {
        vPortFree(g_crypto_pool);
        g_crypto_pool = NULL;
    }

    ks_runner_print_summary(&runner);

    /* Publish summary to result channel if companion was online. */
    if (runner.companion_online) {
        char                  result_ch[48] = {0};
        const char*           done_msg;
        pubnub_publish_opts_t done_opts = PUBNUB_PUBLISH_OPTS_INIT;
        pubnub_future_t       fut;

        ks_protocol_result_channel(runner.run_id, result_ch, sizeof(result_ch));

        done_msg = ks_protocol_done_msg(
            runner.pass_count, runner.fail_count, runner.skip_count);

        done_opts.channel = result_ch;
        done_opts.message = done_msg;

        fut = pubnub_publish(ctx, &done_opts);
        (void)ks_pump_until_ready(ctx, fut, 10000);
        pubnub_future_release(fut);
    }

    pubnub_deinit(ctx);
    printf("[KS] Done. Deleting task.\n");
    vTaskDelete(NULL);
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ESP_ERR_NVS_NO_FREE_PAGES == ret || ESP_ERR_NVS_NEW_VERSION_FOUND == ret) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    printf("[KS] WiFi init\n");
    wifi_init_sta();
    printf("[KS] WiFi connected, starting NTP\n");
    ntp_sync();
    printf("[KS] NTP done, creating kitchensink task\n");

    xTaskCreate(ks_task, "ks_task", CONFIG_PUBNUB_KS_TASK_STACK_SIZE, NULL, 5, NULL);
}
