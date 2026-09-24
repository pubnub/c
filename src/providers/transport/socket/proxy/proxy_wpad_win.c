/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifdef _WIN32

#include "proxy_wpad.h"

#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>

/** Static buffer for the resolved proxy hostname.
 * Single-use during transport init (not re-entrant). */
static char pn_wpad_host_buf[256];

/** @brief WPAD network timeout (milliseconds). */
#ifndef PN_WPAD_TIMEOUT_MS
#define PN_WPAD_TIMEOUT_MS 5000
#endif

/**
 * @brief Parse host:port from the populated pn_wpad_host_buf.
 *
 * Strips optional "http://" or "https://" prefix, splits on the last
 * colon for the port. Modifies the buffer in place (NUL-terminates the
 * host portion).
 *
 * @return Parsed port number (default 8080 if absent or zero).
 */
static uint16_t pn_wpad_parse_host_port(void)
{
    char* host_start = pn_wpad_host_buf;

    /* Truncate at first semicolon or space (WinHTTP may return
     * semicolon-separated lists like "http://p1:8080;socks=p2:1080"). */
    char* sep = pn_wpad_host_buf;
    while ('\0' != *sep && ';' != *sep && ' ' != *sep) {
        ++sep;
    }
    *sep = '\0';

    /* Strip optional scheme prefix. */
    host_start = pn_wpad_host_buf;
    if (0 == strncmp(host_start, "http://", 7)) {
        memmove(pn_wpad_host_buf, host_start + 7, strlen(host_start + 7) + 1);
    } else if (0 == strncmp(host_start, "https://", 8)) {
        memmove(pn_wpad_host_buf, host_start + 8, strlen(host_start + 8) + 1);
    }

    /* Strip optional "protocol=" prefix (e.g., "https=proxy:8080"). */
    char* eq = strchr(pn_wpad_host_buf, '=');
    if (NULL != eq) {
        memmove(pn_wpad_host_buf, eq + 1, strlen(eq + 1) + 1);
    }

    char*    colon = strrchr(pn_wpad_host_buf, ':');
    uint16_t port  = 8080;
    if (NULL != colon) {
        *colon     = '\0';
        int parsed = (int)strtol(colon + 1, NULL, 10);
        if (0 < parsed && parsed <= 65535) {
            port = (uint16_t)parsed;
        }
    }

    return port;
}

/**
 * @brief Attempt WPAD auto-detection via WinHttpGetProxyForUrl.
 *
 * @param wide_url  Target URL as wide string.
 * @param out       Output proxy config.
 * @return 0 on success, -1 on failure (caller should try IE fallback).
 */
static int pn_wpad_try_auto_detect(const wchar_t* wide_url, pn_proxy_config_t* out)
{
    HINTERNET session = WinHttpOpen(L"PubNub/1.0",
                                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS,
                                    0);
    if (NULL == session) {
        return -1;
    }

    /* Bound WPAD network I/O to avoid 30s default stall. */
    DWORD timeout_ms = PN_WPAD_TIMEOUT_MS;
    WinHttpSetOption(
        session, WINHTTP_OPTION_RESOLVE_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
    WinHttpSetOption(
        session, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
    WinHttpSetOption(
        session, WINHTTP_OPTION_SEND_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
    WinHttpSetOption(
        session, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout_ms, sizeof(timeout_ms));

    WINHTTP_AUTOPROXY_OPTIONS options;
    memset(&options, 0, sizeof(options));
    options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
    options.dwAutoDetectFlags =
        WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    options.fAutoLogonIfChallenged = TRUE;

    WINHTTP_PROXY_INFO info;
    memset(&info, 0, sizeof(info));

    BOOL ok = WinHttpGetProxyForUrl(session, wide_url, &options, &info);
    if (!ok) {
        WinHttpCloseHandle(session);
        return -1;
    }

    WinHttpCloseHandle(session);

    /* Direct connection — no proxy needed. */
    if (WINHTTP_ACCESS_TYPE_NO_PROXY == info.dwAccessType || NULL == info.lpszProxy) {
        if (NULL != info.lpszProxy) {
            GlobalFree(info.lpszProxy);
        }
        if (NULL != info.lpszProxyBypass) {
            GlobalFree(info.lpszProxyBypass);
        }
        return 0;
    }

    /* Convert wide proxy string to UTF-8. */
    int converted = WideCharToMultiByte(CP_UTF8,
                                        0,
                                        info.lpszProxy,
                                        -1,
                                        pn_wpad_host_buf,
                                        (int)sizeof(pn_wpad_host_buf),
                                        NULL,
                                        NULL);
    GlobalFree(info.lpszProxy);
    if (NULL != info.lpszProxyBypass) {
        GlobalFree(info.lpszProxyBypass);
    }

    if (0 >= converted) {
        return -1;
    }

    uint16_t port  = pn_wpad_parse_host_port();
    out->host      = pn_wpad_host_buf;
    out->port      = port;
    out->auth_type = PN_PROXY_AUTH_NONE;
    return 0;
}

/**
 * @brief Attempt fallback via IE/system proxy settings.
 *
 * @param out  Output proxy config.
 * @return 0 on success, -1 on failure.
 */
static int pn_wpad_try_ie_fallback(pn_proxy_config_t* out)
{
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie_config;
    memset(&ie_config, 0, sizeof(ie_config));

    if (!WinHttpGetIEProxyConfigForCurrentUser(&ie_config)) {
        return -1;
    }

    int result = -1;

    if (NULL != ie_config.lpszProxy) {
        int converted = WideCharToMultiByte(CP_UTF8,
                                            0,
                                            ie_config.lpszProxy,
                                            -1,
                                            pn_wpad_host_buf,
                                            (int)sizeof(pn_wpad_host_buf),
                                            NULL,
                                            NULL);
        if (0 < converted) {
            uint16_t port  = pn_wpad_parse_host_port();
            out->host      = pn_wpad_host_buf;
            out->port      = port;
            out->auth_type = PN_PROXY_AUTH_NONE;
            result         = 0;
        }
    }

    if (NULL != ie_config.lpszProxy) {
        GlobalFree(ie_config.lpszProxy);
    }
    if (NULL != ie_config.lpszProxyBypass) {
        GlobalFree(ie_config.lpszProxyBypass);
    }
    if (NULL != ie_config.lpszAutoConfigUrl) {
        GlobalFree(ie_config.lpszAutoConfigUrl);
    }

    return result;
}

int pn_proxy_wpad_resolve(const char* target_url, pn_proxy_config_t* out)
{
    if (NULL == target_url || NULL == out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    pn_wpad_host_buf[0] = '\0';

    /* Convert target URL to wide string. */
    wchar_t wide_url[512];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, target_url, -1, wide_url, 512);
    if (0 == wlen) {
        return -1;
    }

    /* Try WPAD auto-detection first. */
    if (0 == pn_wpad_try_auto_detect(wide_url, out)) {
        return 0;
    }

    /* Fallback: IE/system proxy settings. */
    return pn_wpad_try_ie_fallback(out);
}

void pn_proxy_wpad_free(pn_proxy_config_t* config)
{
    if (NULL == config) {
        return;
    }
    pn_wpad_host_buf[0] = '\0';
    memset(config, 0, sizeof(*config));
}

#endif /* _WIN32 */
