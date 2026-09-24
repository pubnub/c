/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifdef __APPLE__

#include "proxy_wpad.h"

#include <CFNetwork/CFNetwork.h>
#include <CoreFoundation/CoreFoundation.h>
#include <string.h>

/** Static buffer for the resolved proxy hostname. */
static char pn_wpad_host_buf[256];

int pn_proxy_wpad_resolve(const char* target_url, pn_proxy_config_t* out)
{
    if (NULL == target_url || NULL == out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    pn_wpad_host_buf[0] = '\0';

    CFStringRef url_str = CFStringCreateWithCString(
        kCFAllocatorDefault, target_url, kCFStringEncodingUTF8);
    if (NULL == url_str) {
        return -1;
    }

    CFURLRef url = CFURLCreateWithString(kCFAllocatorDefault, url_str, NULL);
    CFRelease(url_str);
    if (NULL == url) {
        return -1;
    }

    CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
    if (NULL == settings) {
        CFRelease(url);
        return -1;
    }

    CFArrayRef proxies = CFNetworkCopyProxiesForURL(url, settings);
    CFRelease(url);
    CFRelease(settings);
    if (NULL == proxies) {
        return -1;
    }

    CFIndex count = CFArrayGetCount(proxies);
    for (CFIndex i = 0; i < count; ++i) {
        CFDictionaryRef proxy = (CFDictionaryRef)CFArrayGetValueAtIndex(proxies, i);
        CFStringRef type =
            (CFStringRef)CFDictionaryGetValue(proxy, kCFProxyTypeKey);

        if (NULL == type) {
            continue;
        }

        /* Direct connection — no proxy needed. */
        if (CFEqual(type, kCFProxyTypeNone)) {
            CFRelease(proxies);
            return 0;
        }

        /* Accept HTTP or HTTPS proxy types. */
        if (CFEqual(type, kCFProxyTypeHTTP) || CFEqual(type, kCFProxyTypeHTTPS)) {
            CFStringRef host =
                (CFStringRef)CFDictionaryGetValue(proxy, kCFProxyHostNameKey);
            CFNumberRef port_num =
                (CFNumberRef)CFDictionaryGetValue(proxy, kCFProxyPortNumberKey);

            if (NULL == host) {
                continue;
            }

            if (!CFStringGetCString(host,
                                    pn_wpad_host_buf,
                                    (CFIndex)sizeof(pn_wpad_host_buf),
                                    kCFStringEncodingUTF8)) {
                continue;
            }

            uint16_t port = 8080;
            if (NULL != port_num) {
                int port_val = 0;
                CFNumberGetValue(port_num, kCFNumberIntType, &port_val);
                port = (uint16_t)port_val;
            }

            out->host      = pn_wpad_host_buf;
            out->port      = port;
            out->auth_type = PN_PROXY_AUTH_NONE;
            CFRelease(proxies);
            return 0;
        }
    }

    CFRelease(proxies);
    return 0; /* No usable HTTP/HTTPS proxy — direct connection. */
}

void pn_proxy_wpad_free(pn_proxy_config_t* config)
{
    if (NULL == config) {
        return;
    }
    pn_wpad_host_buf[0] = '\0';
    memset(config, 0, sizeof(*config));
}

#endif /* __APPLE__ */
