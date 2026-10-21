/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// The ESP-IDF platform for code pairing (code_pairing.h): HTTPS with the
// certificate bundle, an X25519 key and a one-time-code secret in NVS, HPKE
// primitives from PSA Crypto, and the status LED or screen.

#include "code_pairing_esp.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"

#include "app.h"
#include "code_pairing.h"
#include "config_store.h"
#include "identity.h"
#include "led_status.h"
#include "link_pairing.h"
#include "muse_hpke.h"
#include "pairing_transcript.h"
#include "vm_api.h"
#include "wifi_mgr.h"

#if CONFIG_GADGET_CODE_PAIRING_QR
#include "pixel_font.h"
#include "qrcode.h"
#endif

static const char *TAG = "link.code_pair";

// NVS keys. A setup reset deletes the key pair and the code secret
// (config_clear_setup()); pairing deletes all three.
#define KEY_NVS "cp_key"      // X25519 private key, base64url
#define SECRET_NVS "cp_otp"   // one-time-code secret, base64url
#define CLAIM_NVS "cp_claim"  // a claim sticker's code, written at flash time
#define MAX_RESPONSE_BYTES 4096
#define HTTP_TIMEOUT_MS 15000
#define TASK_STACK 8192
#define NET_POLL_MS 500

#define BIT_START   (1u << 0)
#define BIT_RESTART (1u << 1)
#define BIT_STOP    (1u << 2)

static TaskHandle_t s_task;
static atomic_int s_task_state;  // 0 none, 1 being created, 2 running
static volatile code_pairing_state_t s_state = CODE_PAIRING_IDLE;
static code_pairing_t s_cp;
static char s_base_url[256];
static char s_user_agent[48];
static char s_claim[CODE_PAIRING_OTP_LEN + 1];
static char s_username[64];
static char s_pairing_auth[24];
static bool s_code_shown;
static bool s_image_shown;

// ---- Network seam ---------------------------------------------------------------

__attribute__((weak)) bool code_pairing_net_up(void) {
    return wifi_mgr_is_connected();
}

__attribute__((weak)) bool code_pairing_net_wait_up(uint32_t timeout_ms) {
    TickType_t start = xTaskGetTickCount();
    while (!code_pairing_net_up()) {
        if (xTaskGetTickCount() - start >= pdMS_TO_TICKS(timeout_ms)) return false;
        vTaskDelay(pdMS_TO_TICKS(NET_POLL_MS));
    }
    return true;
}

// ---- HTTP -----------------------------------------------------------------------

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    bool overflow;
    int retry_after_s;
} http_resp_t;

static void resp_wipe_free(http_resp_t *r) {
    if (r->buf) {
        mbedtls_platform_zeroize(r->buf, r->cap);
        free(r->buf);
    }
    r->buf = NULL;
    r->len = r->cap = 0;
}

static esp_err_t http_event(esp_http_client_event_t *evt) {
    http_resp_t *r = (http_resp_t *)evt->user_data;
    if (!r) return ESP_OK;
    if (evt->event_id == HTTP_EVENT_ON_HEADER && evt->header_key && evt->header_value
        && strcasecmp(evt->header_key, "Retry-After") == 0) {
        // Delta-seconds only; an HTTP date falls back to the default wait.
        char *end = NULL;
        long v = strtol(evt->header_value, &end, 10);
        while (end && *end == ' ') end++;
        if (end && end != evt->header_value && *end == '\0' && v >= 0 && v <= 3600) {
            r->retry_after_s = (int)v;
        }
        return ESP_OK;
    }
    if (evt->event_id != HTTP_EVENT_ON_DATA || evt->data_len <= 0) return ESP_OK;
    if (r->overflow || r->len + (size_t)evt->data_len > MAX_RESPONSE_BYTES) {
        r->overflow = true;
        return ESP_OK;
    }
    if (r->len + (size_t)evt->data_len + 1 > r->cap) {
        size_t cap = r->cap ? r->cap : 512;
        while (cap < r->len + (size_t)evt->data_len + 1) cap *= 2;
        if (cap > MAX_RESPONSE_BYTES + 1) cap = MAX_RESPONSE_BYTES + 1;
        char *nb = malloc(cap);
        if (!nb) return ESP_FAIL;
        if (r->buf) memcpy(nb, r->buf, r->len);
        resp_wipe_free(r);
        r->buf = nb;
        r->cap = cap;
    }
    memcpy(r->buf + r->len, evt->data, evt->data_len);
    r->len += evt->data_len;
    r->buf[r->len] = '\0';
    return ESP_OK;
}

static int p_http_post_json(void *ctx, const char *url, const char *body, int *status,
                            char **resp_body, int *retry_after_s) {
    (void)ctx;
    http_resp_t r = {.retry_after_s = -1};
    *status = 0;
    *resp_body = NULL;
    *retry_after_s = -1;
    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = HTTP_TIMEOUT_MS,
        .buffer_size = 2048,
        .buffer_size_tx = 2048,
        .event_handler = http_event,
        .user_data = &r,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .disable_auto_redirect = true,
        .user_agent = s_user_agent,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) return CODE_PAIRING_HTTP_TRANSPORT_ERROR;
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "X-API-Version", "1.0.0");
    esp_http_client_set_post_field(client, body, (int)strlen(body));
    esp_err_t err = esp_http_client_perform(client);
    int code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    if (code <= 0) {
        ESP_LOGW(TAG, "request failed: %s", esp_err_to_name(err));
        resp_wipe_free(&r);
        return CODE_PAIRING_HTTP_TRANSPORT_ERROR;
    }
    *status = code;
    *retry_after_s = r.retry_after_s;
    if (r.overflow) {
        ESP_LOGW(TAG, "answer too large; ignoring its body");
        resp_wipe_free(&r);
    } else {
        *resp_body = r.buf;  // the state machine wipes and frees it
    }
    return 0;
}

// ---- Keys -----------------------------------------------------------------------------

static bool load_b64_32(const char *key, uint8_t out[32]) {
    char b64[64];
    bool ok = config_get_str(key, b64, sizeof(b64))
              && code_pairing_b64url_decode(b64, out, 32) == 32;
    mbedtls_platform_zeroize(b64, sizeof(b64));
    return ok;
}

static bool save_b64_32(const char *key, const uint8_t in[32]) {
    char b64[64];
    code_pairing_b64url_encode(in, 32, b64, sizeof(b64));
    bool ok = config_set_str(key, b64);
    mbedtls_platform_zeroize(b64, sizeof(b64));
    return ok;
}

static bool import_x25519(const uint8_t sk[32], psa_key_id_t *id) {
    if (psa_crypto_init() != PSA_SUCCESS) return false;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 255);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_status_t st = psa_import_key(&attr, sk, 32, id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS) ESP_LOGE(TAG, "X25519 key import failed: %d", (int)st);
    return st == PSA_SUCCESS;
}

static bool x25519_public(const uint8_t sk[32], uint8_t pk[32]) {
    psa_key_id_t id = 0;
    if (!import_x25519(sk, &id)) return false;
    size_t len = 0;
    psa_status_t st = psa_export_public_key(id, pk, 32, &len);
    psa_destroy_key(id);
    return st == PSA_SUCCESS && len == 32;
}

// The key pair and code secret: from NVS, or made from the hardware random
// source and saved first.
static bool p_load_keys(void *ctx, uint8_t pubkey[32], uint8_t code_secret[32]) {
    (void)ctx;
    uint8_t sk[32];
    bool ok = load_b64_32(KEY_NVS, sk) && load_b64_32(SECRET_NVS, code_secret);
    if (!ok) {
        esp_fill_random(sk, sizeof(sk));
        esp_fill_random(code_secret, 32);
        // A key that isn't kept would change after a restart, and a payload
        // sealed to it could never be opened.
        ok = save_b64_32(KEY_NVS, sk) && save_b64_32(SECRET_NVS, code_secret);
        if (ok) {
            ESP_LOGI(TAG, "made a new pairing key");
        } else {
            ESP_LOGE(TAG, "couldn't save the pairing key");
            config_erase_key(KEY_NVS);
            config_erase_key(SECRET_NVS);
        }
    }
    ok = ok && x25519_public(sk, pubkey);
    mbedtls_platform_zeroize(sk, sizeof(sk));
    if (!ok) mbedtls_platform_zeroize(code_secret, 32);
    return ok;
}

static void p_erase_keys(void *ctx) {
    (void)ctx;
    config_erase_key(KEY_NVS);
    config_erase_key(SECRET_NVS);
    config_erase_key(CLAIM_NVS);
    mbedtls_platform_zeroize(s_claim, sizeof(s_claim));
}

// ---- HPKE primitives (PSA Crypto) -------------------------------------------------------

static bool agree(const uint8_t sk[32], const uint8_t u[32], uint8_t out[32]) {
    psa_key_id_t id = 0;
    if (!import_x25519(sk, &id)) return false;
    size_t len = 0;
    psa_status_t st = psa_raw_key_agreement(PSA_ALG_ECDH, id, u, 32, out, 32, &len);
    psa_destroy_key(id);
    return st == PSA_SUCCESS && len == 32;
}

static bool hpke_x25519(void *ctx, const uint8_t scalar[32], const uint8_t u[32],
                        uint8_t out[32]) {
    (void)ctx;
    return agree(scalar, u, out);
}

static bool hpke_recipient_dh(void *ctx, const uint8_t u[32], uint8_t out[32]) {
    (void)ctx;
    uint8_t sk[32];
    bool ok = load_b64_32(KEY_NVS, sk) && agree(sk, u, out);
    mbedtls_platform_zeroize(sk, sizeof(sk));
    return ok;
}

static bool import_aes(const uint8_t key[16], psa_key_id_t *id) {
    if (psa_crypto_init() != PSA_SUCCESS) return false;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_status_t st = psa_import_key(&attr, key, 16, id);
    psa_reset_key_attributes(&attr);
    return st == PSA_SUCCESS;
}

static bool hpke_seal(void *ctx, const uint8_t key[16], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t len,
                      uint8_t *ct) {
    (void)ctx;
    psa_key_id_t id = 0;
    if (!import_aes(key, &id)) return false;
    size_t out_len = 0;
    psa_status_t st = psa_aead_encrypt(id, PSA_ALG_GCM, nonce, 12, aad, aad_len, pt, len,
                                       ct, len + MUSE_HPKE_TAG_BYTES, &out_len);
    psa_destroy_key(id);
    return st == PSA_SUCCESS && out_len == len + MUSE_HPKE_TAG_BYTES;
}

static bool hpke_open(void *ctx, const uint8_t key[16], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
                      uint8_t *pt) {
    (void)ctx;
    psa_key_id_t id = 0;
    if (!import_aes(key, &id)) return false;
    size_t out_len = 0;
    psa_status_t st = psa_aead_decrypt(id, PSA_ALG_GCM, nonce, 12, aad, aad_len, ct, ct_len,
                                       pt, ct_len - MUSE_HPKE_TAG_BYTES, &out_len);
    psa_destroy_key(id);
    return st == PSA_SUCCESS && out_len == ct_len - MUSE_HPKE_TAG_BYTES;
}

static bool hpke_random(void *ctx, uint8_t *out, size_t len) {
    (void)ctx;
    esp_fill_random(out, len);
    return true;
}

static const muse_hpke_ops_t HPKE_OPS = {
    .ctx = NULL,
    .x25519 = hpke_x25519,
    .recipient_dh = hpke_recipient_dh,
    .aes128gcm_seal = hpke_seal,
    .aes128gcm_open = hpke_open,
    .random_bytes = hpke_random,
};

// ---- Clock, randomness, network -------------------------------------------------------

static uint64_t p_now_ms(void *ctx) {
    (void)ctx;
    return (uint64_t)(esp_timer_get_time() / 1000);
}

static bool p_random_bytes(void *ctx, uint8_t *out, size_t len) {
    (void)ctx;
    esp_fill_random(out, len);
    return true;
}

static bool p_net_up(void *ctx) {
    (void)ctx;
    return code_pairing_net_up();
}

static bool p_net_wait_up(void *ctx, uint32_t timeout_ms) {
    (void)ctx;
    return code_pairing_net_wait_up(timeout_ms);
}

// ---- Display ------------------------------------------------------------------------

#if CONFIG_GADGET_CODE_PAIRING_QR
#define QR_MAX_VERSION 15     // room for the link (version 8 typically) at level M
#define QR_QUIET 4            // modules of white border
#define DRAW_ROWS 23          // led_status_draw_rect()'s limit, in full rows

static const char *s_qr_caption;
static bool s_qr_drawn;

// Text under the QR code: 5x8 glyphs, scaled.
static bool caption_dark(const char *text, int n, int scale, int x, int y) {
    int adv = (PIXEL_FONT_WIDTH + 1) * scale;
    int i = x / adv;
    int gx = (x % adv) / scale;
    int gy = y / scale;
    if (i >= n || gx >= PIXEL_FONT_WIDTH || gy >= PIXEL_FONT_HEIGHT) return false;
    unsigned char ch = (unsigned char)text[i];
    if (ch < PIXEL_FONT_FIRST || ch > PIXEL_FONT_LAST) ch = '?';
    return (pixel_font[ch - PIXEL_FONT_FIRST][gx] >> gy) & 1;
}

// Draws the whole screen, top to bottom: the QR code centred in the space
// above the caption, the caption, white elsewhere.
static void qr_render(esp_qrcode_handle_t qr) {
    int w = 0, h = 0;
    if (!led_status_display_info(&w, &h) || w <= 0 || h <= 0) return;
    const char *caption = s_qr_caption ? s_qr_caption : "";
    int n = (int)strlen(caption);
    // A margin at each side: on some boards the panel's edge sits under the
    // case.
    int text_max_w = w - w / 10;
    int ts = 4;
    while (ts > 1 && n * (PIXEL_FONT_WIDTH + 1) * ts > text_max_w) ts--;
    int text_w = n * (PIXEL_FONT_WIDTH + 1) * ts;
    int text_h = PIXEL_FONT_HEIGHT * ts;
    int area_h = h - text_h - 2 * ts;
    int size = esp_qrcode_get_size(qr);
    int quiet = QR_QUIET;
    int side = w < area_h ? w : area_h;
    int scale = side / (size + 2 * quiet);
    if (scale < 1) {
        quiet = 1;
        scale = side / (size + 2 * quiet);
    }
    if (scale < 1 || text_w > text_max_w) {
        ESP_LOGW(TAG, "screen too small for the QR code");
        return;
    }
    int qw = (size + 2 * quiet) * scale;
    int qx = (w - qw) / 2;
    int qy = (area_h - qw) / 2;
    int tx = (w - text_w) / 2;
    int ty = qy + qw + ts;

    uint16_t *rows = malloc((size_t)w * DRAW_ROWS * sizeof(uint16_t));
    if (!rows) return;
    bool ok = true;
    for (int y0 = 0; y0 < h && ok; y0 += DRAW_ROWS) {
        int nr = h - y0 < DRAW_ROWS ? h - y0 : DRAW_ROWS;
        for (int r = 0; r < nr; r++) {
            int y = y0 + r;
            for (int x = 0; x < w; x++) {
                bool dark = false;
                if (x >= qx && x < qx + qw && y >= qy && y < qy + qw) {
                    int mx = (x - qx) / scale - quiet;
                    int my = (y - qy) / scale - quiet;
                    dark = mx >= 0 && my >= 0 && mx < size && my < size
                           && esp_qrcode_get_module(qr, mx, my);
                } else if (x >= tx && x < tx + text_w && y >= ty && y < ty + text_h) {
                    dark = caption_dark(caption, n, ts, x - tx, y - ty);
                }
                rows[r * w + x] = dark ? 0x0000 : 0xFFFF;
            }
        }
        ok = led_status_draw_rect(0, y0, w, nr, rows);
    }
    free(rows);
    if (ok) {
        led_status_draw_done();
        s_qr_drawn = true;
    }
}

// Status screens with fewer than 16 bits per pixel are e-paper.
static bool epaper(void) {
    int bits = led_status_display_bits();
    return bits > 0 && bits < 16;
}

static bool show_qr(const char *text, const char *caption) {
    s_qr_caption = caption;
    s_qr_drawn = false;
    esp_qrcode_config_t cfg = {
        .display_func = qr_render,
        .max_qrcode_version = QR_MAX_VERSION,
        .qrcode_ecc_level = ESP_QRCODE_ECC_MED,
    };
    if (esp_qrcode_generate(&cfg, text) != ESP_OK) s_qr_drawn = false;
    s_qr_caption = NULL;
    return s_qr_drawn;
}
#endif  // CONFIG_GADGET_CODE_PAIRING_QR

static void clear_code(void) {
    if (!s_code_shown) return;
    s_code_shown = false;
    if (s_image_shown) led_status_show_animation();
    s_image_shown = false;
    led_status_set_title(NULL);
}

// Called again each time the code changes (every 10 s, or
// CONFIG_GADGET_CODE_PAIRING_EPAPER_STEP_S on e-paper). The link carries this
// gadget's public key and a one-time code, never the SDK token.
static void p_show_code(void *ctx, const char *link, const char *fingerprint,
                        uint32_t remaining_s) {
    (void)ctx;
    bool first = !s_code_shown;
    if (first) {
        ESP_LOGI(TAG, "Scan the code with the Muse app to pair (key %s, %u min left)",
                 fingerprint, (unsigned)((remaining_s + 59) / 60));
        led_status_set_state(LED_STATE_CODE_PAIRING);
    }
#if CONFIG_GADGET_CODE_PAIRING_QR
    if (show_qr(link, "Scan with the Muse app")) {
        s_code_shown = true;
        s_image_shown = true;
        if (first) ESP_LOGI(TAG, "pairing link: %s", link);
        return;
    }
#endif
    // No QR code on this screen: the serial console carries the link, new
    // every 10 seconds, for a maker at a bench.
    ESP_LOGI(TAG, "pairing link: %s", link);
    if (first) led_status_set_title("Pair in the Muse app");
    s_code_shown = true;
}

static void p_show_status(void *ctx, code_pairing_state_t state) {
    (void)ctx;
    s_state = state;
    switch (state) {
        case CODE_PAIRING_WAITING:
            led_status_set_state(LED_STATE_CODE_PAIRING);
            return;
        case CODE_PAIRING_PAIRED:
            clear_code();
            if (s_username[0]) {
                char title[80];
                snprintf(title, sizeof(title), "Paired to %s", s_username);
                ESP_LOGI(TAG, "%s", title);
                led_status_set_title(title);
            }
            return;
        case CODE_PAIRING_EXPIRED:
            ESP_LOGI(TAG, "Pairing closed. Press the button to show the code again, "
                          "or pair over Bluetooth.");
            break;
        case CODE_PAIRING_IDLE:
        case CODE_PAIRING_UNAVAILABLE:
        case CODE_PAIRING_ERROR:
            break;
    }
    clear_code();
    // Back to the Bluetooth setup light while unpaired.
    if (!config_setup_complete()) led_status_set_state(LED_STATE_BLE_ADVERTISING);
}

static void p_log(void *ctx, code_pairing_log_level_t level, const char *msg) {
    (void)ctx;
    switch (level) {
        case CODE_PAIRING_LOG_DEBUG: ESP_LOGD(TAG, "%s", msg); break;
        case CODE_PAIRING_LOG_INFO:  ESP_LOGI(TAG, "%s", msg); break;
        case CODE_PAIRING_LOG_WARN:  ESP_LOGW(TAG, "%s", msg); break;
        case CODE_PAIRING_LOG_ERROR: ESP_LOGE(TAG, "%s", msg); break;
    }
}

// ---- Tokens -------------------------------------------------------------------------

static bool p_save_tokens(void *ctx, const char *access_token, const char *refresh_token,
                          const char *device_id, const char *api_url_v2,
                          const char *noise_host, const char *username) {
    (void)ctx;
    snprintf(s_username, sizeof(s_username), "%s", username ? username : "");
    return app_code_pairing_store(access_token, refresh_token, device_id, api_url_v2,
                                  noise_host, username);
}

// The binding refresh, with the drop's tokens, before anything is saved.
static code_pairing_result_t p_bind_tokens(void *ctx, const char *access_token,
                                           const char *refresh_token,
                                           char **new_access, char **new_refresh) {
    (void)ctx;
    char problem[48];
    vm_device_tokens_t tokens = {0};
    int rc = vm_api_bind_device_token(access_token, refresh_token, identity_node_id(),
                                      &tokens, problem, sizeof(problem));
    if (rc == 0) {
        *new_access = tokens.access_token;  // the state machine wipes and frees them
        *new_refresh = tokens.refresh_token;
        return CODE_PAIRING_RESULT_OK;
    }
    vm_device_tokens_free(&tokens);
    if (strcmp(problem, "sdkTokenDeviceLimitReached") == 0
        || strcmp(problem, "sdkTokenInvalid") == 0 || strcmp(problem, "sdkTokenRevoked") == 0) {
        ESP_LOGW(TAG, "Muse refused the SDK token: %s", problem);
        return CODE_PAIRING_RESULT_SDK_REFUSED;
    }
    return rc == VM_API_ERR_AUTH ? CODE_PAIRING_RESULT_REJECTED : CODE_PAIRING_RESULT_RETRY;
}

static code_pairing_result_t p_verify_tokens(void *ctx, const char *access_token) {
    (void)ctx;
    vm_info_t vms[VM_API_MAX_VMS] = {0};
    int count = vm_api_fetch_vms(access_token, vms, VM_API_MAX_VMS);
    if (count >= 0) {
        vm_list_free(vms, count);
        return CODE_PAIRING_RESULT_OK;
    }
    return count == VM_API_ERR_AUTH ? CODE_PAIRING_RESULT_REJECTED : CODE_PAIRING_RESULT_RETRY;
}

static const code_pairing_platform_t PLATFORM = {
    .ctx = NULL,
    .http_post_json = p_http_post_json,
    .now_ms = p_now_ms,
    .random_bytes = p_random_bytes,
    .load_keys = p_load_keys,
    .erase_keys = p_erase_keys,
    .hpke = &HPKE_OPS,
    .net_up = p_net_up,
    .net_wait_up = p_net_wait_up,
    .show_code = p_show_code,
    .show_status = p_show_status,
    .log = p_log,
    .bind_tokens = p_bind_tokens,
    .verify_tokens = p_verify_tokens,
    .save_tokens = p_save_tokens,
};

// ---- Task ---------------------------------------------------------------------------

static bool valid_claim(const char *s) {
    if (strlen(s) != CODE_PAIRING_OTP_LEN) return false;
    for (const char *c = s; *c; c++) {
        if (!strchr("0123456789ABCDEFGHJKMNPQRSTVWXYZ", *c)) return false;
    }
    return true;
}

// Re-read before every start: the API root, the SDK token, a claim code.
static void configure(void) {
    const char *override = CONFIG_GADGET_CODE_PAIRING_API_URL;
    // Tokens are vetted (binding refresh, fetch_vms) at the same API root.
    if (override[0]) vm_api_set_base_url(override);
    snprintf(s_base_url, sizeof(s_base_url), "%s", vm_api_base_url());
    const esp_app_desc_t *app = esp_app_get_description();
    snprintf(s_user_agent, sizeof(s_user_agent), "muse-gadget/%.32s",
             app ? app->version : "unknown");

    // What get_device_info reports: community gadgets pair with "none".
    snprintf(s_pairing_auth, sizeof(s_pairing_auth), "none");
    cJSON *info = cJSON_CreateObject();
    if (info) {
        link_pairing_add_device_info(info);
        cJSON *auth = cJSON_GetObjectItem(info, "pairing_auth");
        if (cJSON_IsString(auth) && auth->valuestring) {
            snprintf(s_pairing_auth, sizeof(s_pairing_auth), "%s", auth->valuestring);
        }
        cJSON_Delete(info);
    }

    char claim[16];
    bool have_claim = config_get_str(CLAIM_NVS, claim, sizeof(claim)) && valid_claim(claim);
    snprintf(s_claim, sizeof(s_claim), "%s", have_claim ? claim : "");
    mbedtls_platform_zeroize(claim, sizeof(claim));

    code_pairing_config_t cfg = {
        .base_url = s_base_url,
        .node_id = identity_node_id(),
        .model = PAIRING_MODEL,
        .wifi = 'n',          // the payload carries no Wi-Fi credentials
        .mgcommands = false,
        .community = strcmp(s_pairing_auth, PAIRING_COMMUNITY_AUTH) == 0,
        .sdk_token = identity_sdk_token(),
        .claim_code = s_claim[0] ? s_claim : NULL,
        .window_s = CONFIG_GADGET_CODE_PAIRING_WINDOW_S,
#if CONFIG_GADGET_CODE_PAIRING_QR
        // E-paper takes seconds to redraw the QR code, so its code changes
        // less often.
        .step_s = epaper() ? CONFIG_GADGET_CODE_PAIRING_EPAPER_STEP_S : 0,
#endif
    };
    code_pairing_init(&s_cp, &PLATFORM, &cfg);
}

static void code_pairing_task(void *arg) {
    (void)arg;
    configure();
    bool scheduled = false;
    TickType_t next_at = 0;
    for (;;) {
        TickType_t wait = portMAX_DELAY;
        if (scheduled) {
            int32_t left = (int32_t)(next_at - xTaskGetTickCount());
            wait = left > 0 ? (TickType_t)left : 0;
        }
        uint32_t bits = 0;
        xTaskNotifyWait(0, UINT32_MAX, &bits, wait);

        if (bits & BIT_STOP) {
            code_pairing_stop(&s_cp);
            scheduled = false;
        }
        code_pairing_state_t st = code_pairing_state(&s_cp);
        bool start = false;
        if ((bits & BIT_RESTART) && st != CODE_PAIRING_WAITING && !config_setup_complete()) {
            // A new window, if the link is up; otherwise the heartbeat starts
            // one once it is.
            if (st != CODE_PAIRING_IDLE) code_pairing_stop(&s_cp);
            st = CODE_PAIRING_IDLE;
            start = code_pairing_net_up();
        }
        if ((bits & BIT_START) && st == CODE_PAIRING_IDLE && !config_setup_complete()) {
            start = true;
        }
        if (start) {
            configure();
            code_pairing_start(&s_cp);
            s_state = code_pairing_state(&s_cp);
            scheduled = s_state == CODE_PAIRING_WAITING;
            next_at = xTaskGetTickCount();
        }
        if (!scheduled || (int32_t)(next_at - xTaskGetTickCount()) > 0) continue;

        uint32_t delay = code_pairing_step(&s_cp, &st);
        s_state = st;
        if (delay == CODE_PAIRING_NO_STEP) {
            scheduled = false;
        } else {
            next_at = xTaskGetTickCount() + pdMS_TO_TICKS(delay);
        }
        if (st == CODE_PAIRING_PAIRED && delay == CODE_PAIRING_NO_STEP) app_code_pairing_done();
    }
}

static bool ensure_task(void) {
    int expected = 0;
    if (atomic_compare_exchange_strong(&s_task_state, &expected, 1)) {
        if (xTaskCreate(code_pairing_task, "code_pair", TASK_STACK, NULL, 4, &s_task)
            != pdPASS) {
            ESP_LOGE(TAG, "couldn't start the code pairing task");
            atomic_store(&s_task_state, 0);
            return false;
        }
        atomic_store(&s_task_state, 2);
        return true;
    }
    while (atomic_load(&s_task_state) == 1) vTaskDelay(1);
    return atomic_load(&s_task_state) == 2;
}

static void notify(uint32_t bits) {
    if (ensure_task()) xTaskNotify(s_task, bits, eSetBits);
}

void code_pairing_esp_start_if_idle(void) {
    if (s_state != CODE_PAIRING_IDLE && atomic_load(&s_task_state) == 2) return;
    notify(BIT_START);
}

void code_pairing_esp_restart(void) {
    notify(BIT_RESTART);
}

void code_pairing_esp_stop(void) {
    if (atomic_load(&s_task_state) != 2) return;  // never started: nothing to stop
    xTaskNotify(s_task, BIT_STOP, eSetBits);
}

bool code_pairing_esp_active(void) {
    return s_state == CODE_PAIRING_WAITING;
}
