/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file arena_echo_esp32.c
 * @brief ESP32-S3 arena-echo example: subscribes to "arena-echo-in" and
 *        publishes received messages back on "arena-echo-out".
 *
 * Messages with custom_message_type "led" are consumed locally to drive the
 * WS2812B RGB LED (if present). All other messages are echoed back verbatim.
 *
 * LED message payload format: {"r":<0-255>,"g":<0-255>,"b":<0-255>}
 * The LED support is gated by CONFIG_PUBNUB_EXAMPLE_HAS_RGB_LED.
 */

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#if CONFIG_PUBNUB_EXAMPLE_HAS_RGB_LED
#include "led_strip.h"
#endif

#include "pubnub/client.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/providers/allocator_arena.h"
#include "pubnub/pubnub_compat.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* WiFi credentials from Kconfig (menuconfig). */
#define WIFI_SSID CONFIG_PUBNUB_EXAMPLE_WIFI_SSID
#define WIFI_PASS CONFIG_PUBNUB_EXAMPLE_WIFI_PASSWORD

/* WiFi event group bits. */
#define WIFI_CONNECTED_BIT BIT0

static EventGroupHandle_t s_wifi_event_group;

/* Static arena pool and context memory. */
static uint8_t                  s_pool[PUBNUB_CFG_ARENA_POOL_SIZE];
static pubnub_arena_allocator_t s_arena;
static PUBNUB_ALIGNAS(max_align_t) uint8_t s_ctx_mem[PUBNUB_CONTEXT_SIZE];

static pubnub_context_t* s_ctx;

#if CONFIG_PUBNUB_EXAMPLE_HAS_RGB_LED
/** WS2812B handle -- NULL when LED is absent or failed to initialise. */
static led_strip_handle_t s_led;

static void led_init(void)
{
    led_strip_config_t cfg = {
        .strip_gpio_num = 38,
        .max_leds       = 1,
    };
    led_strip_rmt_config_t rmt = {
        .resolution_hz  = 10 * 1000 * 1000,
        .flags.with_dma = true, /* DMA required for reliable RMT on S3 */
    };
    esp_err_t err = led_strip_new_rmt_device(&cfg, &rmt, &s_led);
    if (ESP_OK != err) {
        s_led = NULL;
        printf("[LED] init failed (err=0x%x)\n", err);
        return;
    }
    led_strip_clear(s_led);
}

static void led_set(uint8_t r, uint8_t g, uint8_t b)
{
    if (NULL == s_led) {
        return;
    }
    if (ESP_OK != led_strip_set_pixel(s_led, 0, r, g, b)) {
        return;
    }
    led_strip_refresh(s_led);
}

static void led_off(void)
{
    if (NULL != s_led) {
        led_strip_clear(s_led);
    }
}
#endif /* CONFIG_PUBNUB_EXAMPLE_HAS_RGB_LED */

/** Return 1 if event->custom_message_type equals the given literal. */
static int cmt_equals(const pubnub_subscribe_event_t* event,
                      const char*                     literal,
                      size_t                          literal_len)
{
    return literal_len == event->custom_message_type.len
        && NULL != event->custom_message_type.ptr
        && 0 == memcmp(event->custom_message_type.ptr, literal, literal_len);
}

/**
 * Serialize event->payload to buf using the context's serialization
 * provider. Returns the number of bytes written (0 on failure).
 */
static size_t serialize_payload(const pubnub_json_value_t* payload, char* buf, size_t cap)
{
    if (NULL == payload || cap < 2) {
        return 0;
    }
    pubnub_serialization_provider_t* serial = pubnub_serialization(s_ctx);
    if (NULL == serial || NULL == serial->serialize) {
        return 0;
    }
    size_t out_len = 0;
    if (PUBNUB_OK
        != serial->serialize(serial, payload, (uint8_t*)buf, cap - 1, &out_len)) {
        return 0;
    }
    buf[out_len] = '\0';
    return out_len;
}

#if CONFIG_PUBNUB_EXAMPLE_HAS_RGB_LED
/**
 * Extract LED command from the parsed payload node and drive the LED.
 * Reads are done via the serialization vtable -- zero allocations.
 *
 * Supported payloads (custom_message_type must be "led"):
 *   {"r":N,"g":N,"b":N}  -- set color (0-255 each)
 *   {"off":true}          -- explicit off (same as r=g=b=0)
 *   {}                    -- all fields absent: defaults to 0,0,0 (off)
 */
static void handle_led_message(const pubnub_subscribe_event_t* event)
{
    if (NULL == event->payload) {
        return;
    }
    pubnub_serialization_provider_t* serial = pubnub_serialization(s_ctx);
    if (NULL == serial || NULL == serial->object_get
        || NULL == serial->value_as_int || NULL == serial->value_as_bool) {
        return;
    }

    /* Explicit off command. */
    const pubnub_json_value_t* off_node =
        serial->object_get(event->payload, "off", 3);
    if (NULL != off_node) {
        int truthy = 0;
        (void)serial->value_as_bool(off_node, &truthy);
        if (truthy) {
            led_off();
            return;
        }
    }

    int r = 0, g = 0, b = 0;

    const pubnub_json_value_t* node = serial->object_get(event->payload, "r", 1);
    if (NULL != node) {
        (void)serial->value_as_int(node, &r);
    }
    node = serial->object_get(event->payload, "g", 1);
    if (NULL != node) {
        (void)serial->value_as_int(node, &g);
    }
    node = serial->object_get(event->payload, "b", 1);
    if (NULL != node) {
        (void)serial->value_as_int(node, &b);
    }

    /* Clamp to valid range. */
    if (r < 0) {
        r = 0;
    } else if (r > 255) {
        r = 255;
    }
    if (g < 0) {
        g = 0;
    } else if (g > 255) {
        g = 255;
    }
    if (b < 0) {
        b = 0;
    } else if (b > 255) {
        b = 255;
    }

    led_set((uint8_t)r, (uint8_t)g, (uint8_t)b);
}
#endif /* CONFIG_PUBNUB_EXAMPLE_HAS_RGB_LED */

static void on_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)user_data;

    /* LED control messages: drive the LED, do not echo. */
    if (cmt_equals(event, "led", 3)) {
#if CONFIG_PUBNUB_EXAMPLE_HAS_RGB_LED
        handle_led_message(event);
#endif
        return;
    }

    /* All other messages: wrap and echo as {"echo":<payload>}. */
    char   inner[480] = {0};
    size_t inner_len  = serialize_payload(event->payload, inner, sizeof(inner));
    if (0 == inner_len) {
        return;
    }

    char payload_buf[512] = {0};
    int  written          = snprintf(
        payload_buf, sizeof(payload_buf), "{\"echo\":%.*s}", (int)inner_len, inner);
    if (written <= 0 || (size_t)written >= sizeof(payload_buf)) {
        return;
    }

    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    opts.channel               = "arena-echo-out";
    opts.message               = payload_buf;
    opts.message_len           = (size_t)written;

    pubnub_future_t fut = pubnub_publish(s_ctx, &opts);
    if (PUBNUB_IN_PROGRESS != fut.status) {
        printf("[PubNub] echo publish failed: %s\n", pubnub_res_str(fut.status));
    }
    /* Fire-and-forget: safe no-op for dropped futures. */
    pubnub_future_release(fut);
}

static void on_status(const pubnub_subscribe_status_event_t* event, void* user_data)
{
    (void)user_data;

    switch (event->status) {
    case PUBNUB_SUBSCRIBE_STATUS_CONNECTED:
        printf("[PubNub] subscribe: connected\n");
        break;
    case PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED:
        printf("[PubNub] subscribe: disconnected (user-initiated)\n");
        break;
    case PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED_UNEXPECTEDLY:
        if (PUBNUB_ERR_TIMEOUT == event->reason) {
            /* Normal: server closes long-poll every ~290s. */
            printf("[PubNub] subscribe: long-poll cycle complete, "
                   "reconnecting\n");
        } else {
            printf("[PubNub] subscribe: connection lost (reason=%s)\n",
                   pubnub_res_str(event->reason));
        }
        break;
    case PUBNUB_SUBSCRIBE_STATUS_CONNECTION_ERROR:
        printf("[PubNub] subscribe: connection error (reason=%s)\n",
               pubnub_res_str(event->reason));
        break;
    case PUBNUB_SUBSCRIBE_STATUS_SUBSCRIPTION_CHANGED:
        printf("[PubNub] subscribe: subscription set changed\n");
        break;
    }
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
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t inst_any;
    esp_event_handler_instance_t inst_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &inst_any));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &inst_ip));

    wifi_config_t wifi_config = {
        .sta =
            {
                  .ssid     = WIFI_SSID,
                  .password = WIFI_PASS,
                  },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    /* Disable power save so DHCP OFFER packets are never dropped during
     * modem sleep. Can be re-enabled after IP is acquired if needed. */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_start());

    xEventGroupWaitBits(
        s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
}

static void ntp_sync(void)
{
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();

    time_t now      = 0;
    int    attempts = 0;
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

static void pubnub_echo_task(void* arg)
{
    (void)arg;

    pubnub_allocator_provider_t* alloc =
        pubnub_arena_allocator_init(&s_arena, s_pool, sizeof(s_pool));
    if (NULL == alloc) {
        printf("[PubNub] Arena allocator init failed\n");
        vTaskDelete(NULL);
        return;
    }

    pubnub_config_t cfg  = pubnub_config_defaults();
    cfg.subscribe_key    = "demo";
    cfg.publish_key      = "demo";
    cfg.user_id          = "arena-echo-esp32-device-01";
    cfg.allocator        = alloc;
    cfg.presence_timeout = 120;

    pubnub_context_t* ctx = (pubnub_context_t*)s_ctx_mem;
    if (sizeof(s_ctx_mem) < pubnub_context_size()) {
        printf("[PubNub] Context buffer too small\n");
        vTaskDelete(NULL);
        return;
    }

    printf("[PubNub] Calling pubnub_init\n");
    pubnub_res_t rc = pubnub_init(ctx, &cfg);
    if (PUBNUB_OK != rc) {
        printf("[PubNub] pubnub_init failed: %d (%s)\n", (int)rc, pubnub_res_str(rc));
        vTaskDelete(NULL);
        return;
    }
    printf("[PubNub] pubnub_init OK\n");
    s_ctx = ctx;
    pubnub_set_log_level(ctx, PUBNUB_LOG_LEVEL_TRACE);

#if CONFIG_PUBNUB_EXAMPLE_HAS_RGB_LED
    led_init();
    /* Bright red at start -- confirms LED works before network. */
    led_set(64, 0, 0);
#endif

    pubnub_subscribe_listener_t listener = {0};
    listener.on_message                  = on_message;
    listener.on_status                   = on_status;

    pubnub_listener_handle_t lh = pubnub_add_listener(ctx, &listener);
    if (PUBNUB_LISTENER_HANDLE_INVALID == lh) {
        printf("[PubNub] Failed to register listener\n");
        pubnub_deinit(ctx);
        vTaskDelete(NULL);
        return;
    }

    pubnub_entity_t entity = pubnub_channel(ctx, "arena-echo-in");
    if (NULL == entity) {
        printf("[PubNub] Failed to create channel entity\n");
        pubnub_deinit(ctx);
        vTaskDelete(NULL);
        return;
    }

    pubnub_subscription_t sub = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    if (NULL == sub) {
        printf("[PubNub] Failed to create subscription\n");
        pubnub_deinit(ctx);
        vTaskDelete(NULL);
        return;
    }

    pubnub_subscription_subscribe(sub);
    printf("[PubNub] Subscribed to arena-echo-in, echoing to "
           "arena-echo-out\n");

#if CONFIG_PUBNUB_EXAMPLE_HAS_RGB_LED
    /* Green = connected. */
    led_set(0, 16, 0);
#endif

    /* Cooperative event loop. */
    uint32_t tick = 0;
    for (;;) {
        pubnub_process(ctx);
        vTaskDelay(1);
        tick++;
        if (0 == tick % 10000) {
            printf("[PubNub] alive tick=%lu\n", (unsigned long)tick);
        }
    }

    /* Unreachable in this demo -- shown for correct teardown pattern. */
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(ctx, lh);
    pubnub_deinit(ctx);

#if CONFIG_PUBNUB_EXAMPLE_HAS_RGB_LED
    /* Turn off LED before exit. WS2812B holds its last color until
     * power is removed; an explicit clear ensures a clean state on
     * soft restart. */
    led_off();
#endif

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

    printf("[App] WiFi init started\n");
    wifi_init_sta();
    printf("[App] WiFi connected, starting NTP\n");
    ntp_sync();
    printf("[App] NTP done, creating PubNub task\n");

    xTaskCreate(pubnub_echo_task,
                "pubnub_echo",
                CONFIG_PUBNUB_EXAMPLE_TASK_STACK_SIZE,
                NULL,
                5,
                NULL);
}
