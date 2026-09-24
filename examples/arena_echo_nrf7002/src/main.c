/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file main.c
 * @brief nRF7002 DK arena-echo example: subscribes to "arena-echo-in"
 *        and publishes received messages back on "arena-echo-out".
 *
 * Demonstrates the PubNub C SDK running on Zephyr RTOS with the
 * two-zone arena allocator (no dynamic heap usage by the SDK).
 * WiFi connectivity is handled via the nRF7002 companion chip using
 * Zephyr's net_mgmt API.
 *
 * Messages with custom_message_type "led" drive the onboard GPIO LEDs
 * (if present on the board). LED message payload format:
 *   {"r":<0-255>,"g":<0-255>,"b":<0-255>}
 * Mapping: r>127 -> led0 (red channel), led1 blinks on any received
 * message.
 */

#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/net_if.h>
#include <net/wifi_ready.h>
#include <zephyr/net/dhcpv4.h>
#include <zephyr/net/sntp.h>
#include <zephyr/net/wifi_mgmt.h>

#include "pubnub/client.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/providers/allocator_arena.h"
#include "pubnub/pubnub_compat.h"

#include <stdio.h>
#include <string.h>

#ifndef CONFIG_PUBNUB_EXAMPLE_WIFI_SSID
#define CONFIG_PUBNUB_EXAMPLE_WIFI_SSID "YOUR_SSID_HERE"
#endif
#ifndef CONFIG_PUBNUB_EXAMPLE_WIFI_PASSWORD
#define CONFIG_PUBNUB_EXAMPLE_WIFI_PASSWORD "YOUR_PASSWORD_HERE"
#endif
#ifndef CONFIG_PUBNUB_EXAMPLE_PUBLISH_KEY
#define CONFIG_PUBNUB_EXAMPLE_PUBLISH_KEY "demo"
#endif
#ifndef CONFIG_PUBNUB_EXAMPLE_SUBSCRIBE_KEY
#define CONFIG_PUBNUB_EXAMPLE_SUBSCRIBE_KEY "demo"
#endif
#ifndef CONFIG_PUBNUB_EXAMPLE_USER_ID
#define CONFIG_PUBNUB_EXAMPLE_USER_ID "nrf7002-echo"
#endif

static struct net_mgmt_event_callback s_wifi_cb;
static struct net_mgmt_event_callback s_ipv4_cb;
static struct net_mgmt_event_callback s_disconnect_cb;
static K_SEM_DEFINE(s_wifi_ready, 0, 1);
static K_SEM_DEFINE(s_wpa_ready, 0, 1);

static void on_wifi_ready(bool ready)
{
    if (ready) {
        k_sem_give(&s_wpa_ready);
    }
}

/* WiFi params at file scope for reconnect handler access. */
static struct wifi_connect_req_params s_wifi_params;

static void wifi_reconnect_work_handler(struct k_work* work);
static K_WORK_DELAYABLE_DEFINE(s_wifi_reconnect_work, wifi_reconnect_work_handler);

static void wifi_reconnect_work_handler(struct k_work* work)
{
    (void)work;
    struct net_if* iface = net_if_get_first_wifi();
    net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &s_wifi_params, sizeof(s_wifi_params));
}

/* Static arena pool and context memory. */
static uint8_t                  s_pool[CONFIG_PUBNUB_CFG_ARENA_POOL_SIZE];
static pubnub_arena_allocator_t s_arena;
static PUBNUB_ALIGNAS(max_align_t) uint8_t s_ctx_mem[PUBNUB_CONTEXT_SIZE];

static pubnub_context_t* s_ctx;

/* nRF7002 DK has 2 onboard LEDs accessible via DTS aliases led0-led1. */
#if DT_NODE_EXISTS(DT_ALIAS(led0))
static const struct gpio_dt_spec s_leds[] = {
    GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios),
    GPIO_DT_SPEC_GET(DT_ALIAS(led1), gpios),
};
#define PUBNUB_EXAMPLE_HAS_LEDS 1
#else
#define PUBNUB_EXAMPLE_HAS_LEDS 0
#endif

#if PUBNUB_EXAMPLE_HAS_LEDS
static void led_init(void)
{
    for (size_t i = 0; i < ARRAY_SIZE(s_leds); i++) {
        if (!gpio_is_ready_dt(&s_leds[i])) {
            printk("[LED] GPIO not ready for led%zu\n", i);
            continue;
        }
        gpio_pin_configure_dt(&s_leds[i], GPIO_OUTPUT_INACTIVE);
    }
}

static void led_set(uint8_t r, uint8_t g, uint8_t b)
{
    (void)g;
    (void)b;
    /* r > 127 -> led0 ON. Only led0 is used for colour indication;
     * led1 is reserved for activity blink. */
    gpio_pin_set_dt(&s_leds[0], r > 127 ? 1 : 0);
}

static void led_blink_activity(void)
{
    /* led1 blinks briefly on any received message. */
    gpio_pin_set_dt(&s_leds[1], 1);
    k_sleep(K_MSEC(50));
    gpio_pin_set_dt(&s_leds[1], 0);
}

/**
 * Extract LED command from the parsed payload node and drive the LEDs.
 * Reads are done via the serialization vtable -- zero allocations.
 *
 * Payload format: {"r":<0-255>,"g":<0-255>,"b":<0-255>}
 */
static void handle_led_message(const pubnub_subscribe_event_t* event)
{
    if (NULL == event->payload) {
        return;
    }
    pubnub_serialization_provider_t* serial = pubnub_serialization(s_ctx);
    if (NULL == serial || NULL == serial->object_get
        || NULL == serial->value_as_int) {
        return;
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
#endif /* PUBNUB_EXAMPLE_HAS_LEDS */

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

static void on_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)user_data;

#if PUBNUB_EXAMPLE_HAS_LEDS
    led_blink_activity();
#endif

    /* LED control messages: drive the LEDs, do not echo. */
    if (cmt_equals(event, "led", 3)) {
#if PUBNUB_EXAMPLE_HAS_LEDS
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
        printk("[PubNub] echo publish failed: %s\n", pubnub_res_str(fut.status));
    }
    pubnub_future_release(fut);
}

static void on_status(const pubnub_subscribe_status_event_t* event, void* user_data)
{
    (void)user_data;

    switch (event->status) {
    case PUBNUB_SUBSCRIBE_STATUS_CONNECTED:
        printk("[PubNub] subscribe: connected\n");
        break;
    case PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED:
        printk("[PubNub] subscribe: disconnected (user-initiated)\n");
        break;
    case PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED_UNEXPECTEDLY:
        if (PUBNUB_ERR_TIMEOUT == event->reason) {
            /* Normal: server closes long-poll every ~290s. */
            printk("[PubNub] subscribe: long-poll cycle complete, "
                   "reconnecting\n");
        } else {
            printk("[PubNub] subscribe: connection lost (reason=%d)\n",
                   (int)event->reason);
        }
        break;
    case PUBNUB_SUBSCRIBE_STATUS_CONNECTION_ERROR:
        printk("[PubNub] subscribe: connection error (reason=%d)\n",
               (int)event->reason);
        break;
    case PUBNUB_SUBSCRIBE_STATUS_SUBSCRIPTION_CHANGED:
        printk("[PubNub] subscribe: subscription set changed\n");
        break;
    }
}

static void wifi_mgmt_event_handler(struct net_mgmt_event_callback* cb,
                                    uint64_t                        mgmt_event,
                                    struct net_if*                  iface)
{
    (void)cb;

    if (NET_EVENT_WIFI_CONNECT_RESULT == mgmt_event) {
        /* L2 associated — start DHCP explicitly. net_config may have
         * attempted DHCP before WiFi was up and will not retry on its
         * own. */
        printk("[WiFi] L2 connected, starting DHCP\n");
        net_dhcpv4_start(iface);
    }
    if (NET_EVENT_IPV4_ADDR_ADD == mgmt_event) {
        printk("[WiFi] Got IP address\n");
        k_sem_give(&s_wifi_ready);
    }
    if (NET_EVENT_WIFI_DISCONNECT_RESULT == mgmt_event) {
        printk("[WiFi] Disconnected, attempting reconnect...\n");
        k_sem_reset(&s_wifi_ready);
        /* Schedule reconnect from system workqueue to avoid blocking
         * the net_mgmt callback thread. */
        k_work_schedule(&s_wifi_reconnect_work, K_SECONDS(2));
    }
}

static void wifi_connect(void)
{
    struct net_if* iface = net_if_get_first_wifi();

    memset(&s_wifi_params, 0, sizeof(s_wifi_params));
    s_wifi_params.ssid        = CONFIG_PUBNUB_EXAMPLE_WIFI_SSID;
    s_wifi_params.ssid_length = strlen(CONFIG_PUBNUB_EXAMPLE_WIFI_SSID);
    s_wifi_params.psk         = CONFIG_PUBNUB_EXAMPLE_WIFI_PASSWORD;
    s_wifi_params.psk_length  = strlen(CONFIG_PUBNUB_EXAMPLE_WIFI_PASSWORD);
    s_wifi_params.channel     = WIFI_CHANNEL_ANY;
    s_wifi_params.security    = WIFI_SECURITY_TYPE_PSK;

    net_mgmt_init_event_callback(
        &s_wifi_cb, wifi_mgmt_event_handler, NET_EVENT_WIFI_CONNECT_RESULT);
    net_mgmt_add_event_callback(&s_wifi_cb);

    net_mgmt_init_event_callback(
        &s_ipv4_cb, wifi_mgmt_event_handler, NET_EVENT_IPV4_ADDR_ADD);
    net_mgmt_add_event_callback(&s_ipv4_cb);

    net_mgmt_init_event_callback(&s_disconnect_cb,
                                 wifi_mgmt_event_handler,
                                 NET_EVENT_WIFI_DISCONNECT_RESULT);
    net_mgmt_add_event_callback(&s_disconnect_cb);

    int rc = net_mgmt(
        NET_REQUEST_WIFI_CONNECT, iface, &s_wifi_params, sizeof(s_wifi_params));
    if (0 != rc) {
        printk("[WiFi] Connect request failed: %d\n", rc);
        return;
    }

    printk("[WiFi] Connecting to %s...\n", CONFIG_PUBNUB_EXAMPLE_WIFI_SSID);
    k_sem_take(&s_wifi_ready, K_FOREVER);
    printk("[WiFi] Connected, IP address assigned\n");
}

static void sntp_sync(void)
{
    struct sntp_time ts = {0};
    int              rc = sntp_simple("pool.ntp.org", 5000, &ts);
    if (0 == rc) {
        printk("[NTP] Time synced: epoch=%llu s\n", (unsigned long long)ts.seconds);
    } else {
        printk("[NTP] Sync failed (rc=%d)\n", rc);
    }
}

int main(void)
{
    printk("[PubNub] nRF7002 DK Arena Echo starting\n");

    /* Poll until the WiFi interface is registered, then gate on wifi_ready
     * so the NM layer is fully set up before we attempt to connect. */
    struct net_if* wifi_if = NULL;
    int            poll_ms = 0;
    while (NULL == wifi_if) {
        wifi_if = net_if_get_first_wifi();
        if (NULL == wifi_if) {
            k_sleep(K_MSEC(100));
            poll_ms += 100;
            if (0 == (poll_ms % 1000)) {
                printk("[WiFi] Waiting for WiFi interface... (%d s)\n",
                       poll_ms / 1000);
            }
        }
    }
    wifi_ready_callback_t wpa_cb = {.wifi_ready_cb = on_wifi_ready};
    int reg_rc = register_wifi_ready_callback(wpa_cb, wifi_if);
    if (0 != reg_rc) {
        k_sem_give(&s_wpa_ready);
    }
    k_sem_take(&s_wpa_ready, K_FOREVER);
    wifi_connect();
    sntp_sync();

    pubnub_allocator_provider_t* alloc =
        pubnub_arena_allocator_init(&s_arena, s_pool, sizeof(s_pool));
    if (NULL == alloc) {
        printk("[PubNub] Arena allocator init failed\n");
        return -1;
    }

    pubnub_config_t cfg  = pubnub_config_defaults();
    cfg.subscribe_key    = CONFIG_PUBNUB_EXAMPLE_SUBSCRIBE_KEY;
    cfg.publish_key      = CONFIG_PUBNUB_EXAMPLE_PUBLISH_KEY;
    cfg.user_id          = CONFIG_PUBNUB_EXAMPLE_USER_ID;
    cfg.allocator        = alloc;
    cfg.presence_timeout = 120;

    pubnub_context_t* ctx = (pubnub_context_t*)s_ctx_mem;
    if (sizeof(s_ctx_mem) < pubnub_context_size()) {
        printk("[PubNub] Context buffer too small\n");
        return -1;
    }

    pubnub_res_t rc = pubnub_init(ctx, &cfg);
    if (PUBNUB_OK != rc) {
        printk("[PubNub] pubnub_init failed: %d\n", (int)rc);
        return -1;
    }
    s_ctx = ctx;
    pubnub_set_log_level(ctx, PUBNUB_LOG_LEVEL_TRACE);

#if PUBNUB_EXAMPLE_HAS_LEDS
    led_init();
#endif

    pubnub_subscribe_listener_t listener = {0};
    listener.on_message                  = on_message;
    listener.on_status                   = on_status;

    pubnub_listener_handle_t lh = pubnub_add_listener(ctx, &listener);
    if (PUBNUB_LISTENER_HANDLE_INVALID == lh) {
        printk("[PubNub] Failed to register listener\n");
        pubnub_deinit(ctx);
        return -1;
    }

    pubnub_entity_t entity = pubnub_channel(ctx, "arena-echo-in");
    if (NULL == entity) {
        printk("[PubNub] Failed to create channel entity\n");
        pubnub_deinit(ctx);
        return -1;
    }

    pubnub_subscription_t sub = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    if (NULL == sub) {
        printk("[PubNub] Failed to create subscription\n");
        pubnub_deinit(ctx);
        return -1;
    }

    pubnub_subscription_subscribe(sub);
    printk("[PubNub] Subscribed to arena-echo-in, echoing to "
           "arena-echo-out\n");

    /* Cooperative event loop. */
    for (;;) {
        pubnub_process(ctx);
        k_sleep(K_MSEC(10));
    }

    /* Unreachable in this demo -- shown for correct teardown pattern. */
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(ctx, lh);
    pubnub_deinit(ctx);

    return 0;
}
