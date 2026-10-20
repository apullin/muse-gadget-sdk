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

#include "code_pairing.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

#define POLL_PATH "/device_drop/poll"
#define ACK_PATH "/device_drop/ack"
#define DROP_INFO "muse-drop-v1"

#define DEFAULT_INTERVAL_S 5
#define MAX_INTERVAL_S 300
#define SLOW_DOWN_STEP_S 5
#define BACKOFF_MIN_S 2
#define BACKOFF_MAX_S 60
#define RATE_LIMITED_DEFAULT_S 60
#define UNKNOWN_PROBLEM_WAIT_MS 30000u

enum {
    PHASE_NONE,
    PHASE_POLL,
    PHASE_ACK,
    PHASE_BIND,
    PHASE_VERIFY,
};

// ---- Small helpers ----------------------------------------------------------

static void wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

static char *dup_str(const char *s) {
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

static void free_secret(char **s) {
    if (*s) {
        wipe(*s, strlen(*s));
        free(*s);
        *s = NULL;
    }
}

static void cp_log(code_pairing_t *cp, code_pairing_log_level_t level,
                   const char *fmt, ...) {
    if (!cp->p->log) return;
    char msg[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    cp->p->log(cp->p->ctx, level, msg);
}

static void set_state(code_pairing_t *cp, code_pairing_state_t state) {
    if (cp->state == state) return;
    cp->state = state;
    if (cp->p->show_status) cp->p->show_status(cp->p->ctx, state);
}

static void copy_str(char *dst, size_t cap, const char *src) {
    snprintf(dst, cap, "%s", src ? src : "");
}

static bool printable_ascii(const char *s, size_t max) {
    size_t n = strlen(s);
    if (n == 0 || n > max) return false;
    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e) return false;
    }
    return true;
}

static const char *json_str(const cJSON *obj, const char *key) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsString(item) && item->valuestring ? item->valuestring : NULL;
}

static bool json_int(const cJSON *obj, const char *key, long *out) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsNumber(item)) return false;
    *out = (long)item->valuedouble;
    return true;
}

static uint32_t clamp_interval(long v) {
    if (v <= 0) return DEFAULT_INTERVAL_S;
    return v > MAX_INTERVAL_S ? MAX_INTERVAL_S : (uint32_t)v;
}

static uint64_t now_ms(code_pairing_t *cp) {
    return cp->p->now_ms ? cp->p->now_ms(cp->p->ctx) : 0;
}

static uint32_t max_u32(uint32_t a, uint32_t b) { return a > b ? a : b; }

// Adds up to a quarter on top (never shortens the wait), when the platform
// has a random source.
static uint32_t jitter(code_pairing_t *cp, uint32_t ms) {
    uint8_t r = 0;
    if (!cp->p->random_bytes || !cp->p->random_bytes(cp->p->ctx, &r, 1)) return ms;
    return ms + (uint32_t)(((uint64_t)ms / 4) * r / 255);
}

// The next transport-error wait: 2, 4, 8 ... 60 s.
static uint32_t next_backoff_s(code_pairing_t *cp) {
    uint32_t b = cp->backoff_s ? cp->backoff_s : BACKOFF_MIN_S;
    cp->backoff_s = b * 2 > BACKOFF_MAX_S ? BACKOFF_MAX_S : b * 2;
    return b;
}

static void wipe_json(cJSON *item) {
    for (; item; item = item->next) {
        if (item->valuestring) wipe(item->valuestring, strlen(item->valuestring));
        if (item->child) wipe_json(item->child);
    }
}

// Frees a parsed or built JSON object, wiping its string values first.
static void json_free(cJSON *root) {
    if (!root) return;
    wipe_json(root->child);
    cJSON_Delete(root);
}

static char *print_and_free(cJSON *root) {
    if (!root) return NULL;
    char *body = cJSON_PrintUnformatted(root);
    json_free(root);
    return body;
}

// ---- Encodings --------------------------------------------------------------

static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t code_pairing_b64url_encode(const uint8_t *in, size_t len, char *out,
                                  size_t out_cap) {
    size_t need = (len / 3) * 4 + (len % 3 ? len % 3 + 1 : 0);
    if (!out || out_cap < need + 1) return 0;
    size_t o = 0;
    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
        out[o++] = B64URL[v >> 18 & 63];
        out[o++] = B64URL[v >> 12 & 63];
        out[o++] = B64URL[v >> 6 & 63];
        out[o++] = B64URL[v & 63];
    }
    if (len - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = B64URL[v >> 18 & 63];
        out[o++] = B64URL[v >> 12 & 63];
    } else if (len - i == 2) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
        out[o++] = B64URL[v >> 18 & 63];
        out[o++] = B64URL[v >> 12 & 63];
        out[o++] = B64URL[v >> 6 & 63];
    }
    out[o] = '\0';
    return o;
}

static int b64url_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

int code_pairing_b64url_decode(const char *in, uint8_t *out, size_t out_cap) {
    if (!in || !out) return -1;
    size_t len = strlen(in);
    while (len && in[len - 1] == '=') len--;
    if (len % 4 == 1) return -1;
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        int v = b64url_value(in[i]);
        if (v < 0) return -1;
        acc = acc << 6 | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= out_cap) return -1;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return (int)o;
}

// ---- Keys, codes and the link -------------------------------------------------------

void code_pairing_fingerprint(const uint8_t pubkey[CODE_PAIRING_PUBKEY_BYTES],
                              char out[CODE_PAIRING_FINGERPRINT_LEN]) {
    uint8_t digest[32];
    muse_hpke_sha256(pubkey, CODE_PAIRING_PUBKEY_BYTES, digest);
    for (int i = 0; i < 8; i++) snprintf(out + 2 * i, 3, "%02x", digest[i]);
}

static const char CROCKFORD[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

void code_pairing_otp(const uint8_t secret[CODE_PAIRING_SECRET_BYTES], uint64_t counter,
                      char out[CODE_PAIRING_OTP_LEN + 1]) {
    uint8_t msg[8], h[32];
    for (int i = 0; i < 8; i++) msg[i] = (uint8_t)(counter >> (56 - 8 * i));
    muse_hpke_hmac_sha256(secret, CODE_PAIRING_SECRET_BYTES, msg, sizeof(msg), h);
    int o = h[31] & 0x0f;
    uint64_t v = 0;
    for (int i = 0; i < 5; i++) v = v << 8 | h[o + i];
    for (int i = 0; i < CODE_PAIRING_OTP_LEN; i++) {
        out[i] = CROCKFORD[(v >> (35 - 5 * i)) & 31];
    }
    out[CODE_PAIRING_OTP_LEN] = '\0';
    wipe(h, sizeof(h));
}

// Percent-encodes s as a URL query value (RFC 3986 unreserved characters
// stay as they are).
static bool append_pct(char *out, size_t cap, size_t *len, const char *s) {
    static const char HEX[] = "0123456789ABCDEF";
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                     || c == '-' || c == '_' || c == '.' || c == '~';
        size_t need = plain ? 1 : 3;
        if (*len + need >= cap) return false;
        if (plain) {
            out[(*len)++] = (char)c;
        } else {
            out[(*len)++] = '%';
            out[(*len)++] = HEX[c >> 4];
            out[(*len)++] = HEX[c & 15];
        }
    }
    out[*len] = '\0';
    return true;
}

static bool append_raw(char *out, size_t cap, size_t *len, const char *s) {
    size_t n = strlen(s);
    if (*len + n >= cap) return false;
    memcpy(out + *len, s, n + 1);
    *len += n;
    return true;
}

size_t code_pairing_link(const code_pairing_config_t *cfg,
                         const uint8_t pubkey[CODE_PAIRING_PUBKEY_BYTES], const char *otp,
                         char *out, size_t out_cap) {
    char pub_b64[48];
    code_pairing_b64url_encode(pubkey, CODE_PAIRING_PUBKEY_BYTES, pub_b64, sizeof(pub_b64));
    char w[2] = {cfg->wifi == 'o' || cfg->wifi == 'r' ? cfg->wifi : 'n', '\0'};
    size_t len = 0;
    if (!out_cap) return 0;
    out[0] = '\0';
    bool ok = append_raw(out, out_cap, &len, cfg->link_base ? cfg->link_base : CODE_PAIRING_LINK_BASE)
              && append_raw(out, out_cap, &len, "#v=1&n=")
              && append_pct(out, out_cap, &len, cfg->node_id)
              && append_raw(out, out_cap, &len, "&k=")
              && append_raw(out, out_cap, &len, pub_b64)
              && append_raw(out, out_cap, &len, "&o=")
              && append_pct(out, out_cap, &len, otp)
              && append_raw(out, out_cap, &len, "&m=")
              && append_pct(out, out_cap, &len, cfg->model)
              && append_raw(out, out_cap, &len, "&w=")
              && append_raw(out, out_cap, &len, w)
              && append_raw(out, out_cap, &len, cfg->mgcommands ? "&g=1" : "&g=0")
              && append_raw(out, out_cap, &len, cfg->community ? "&c=1" : "&c=0");
    if (!ok) {
        out[0] = '\0';
        return 0;
    }
    return len;
}

// ---- Scheduling -----------------------------------------------------------------------

static uint64_t counter_at(uint64_t now) {
    return now / 1000u / CODE_PAIRING_STEP_S;
}

static uint32_t ms_until(uint64_t now, uint64_t at) {
    if (at <= now) return 0;
    uint64_t d = at - now;
    return d > UINT32_MAX - 2 ? UINT32_MAX - 2 : (uint32_t)d;
}

static uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }

// Shows the QR code again when the code has changed.
static void refresh_code(code_pairing_t *cp, uint64_t now) {
    uint64_t c = counter_at(now);
    if (cp->shown && c == cp->shown_counter) return;
    cp->shown_counter = c;
    cp->shown = true;
    if (!cp->p->show_code) return;
    char otp[CODE_PAIRING_OTP_LEN + 1];
    char link[CODE_PAIRING_MAX_LINK];
    code_pairing_otp(cp->secret, c, otp);
    code_pairing_link(&cp->cfg, cp->pubkey, otp, link, sizeof(link));
    cp->p->show_code(cp->p->ctx, link, cp->fingerprint,
                     (uint32_t)(ms_until(now, cp->window_end_ms) / 1000u));
    wipe(otp, sizeof(otp));
    wipe(link, sizeof(link));
}

// The wait until the next thing to do: a poll, a new code, or the end of the
// window.
static uint32_t next_wake(code_pairing_t *cp, uint64_t now) {
    uint64_t next_code = (counter_at(now) + 1) * CODE_PAIRING_STEP_S * 1000u;
    uint32_t d = min_u32(ms_until(now, cp->next_poll_ms), ms_until(now, next_code));
    return min_u32(d, ms_until(now, cp->window_end_ms));
}

// ---- State changes ------------------------------------------------------------

static void forget_drop(code_pairing_t *cp) {
    free_secret(&cp->access_token);
    free_secret(&cp->refresh_token);
    wipe(cp->api_url_v2, sizeof(cp->api_url_v2));
    wipe(cp->noise_host, sizeof(cp->noise_host));
    wipe(cp->username, sizeof(cp->username));
    wipe(cp->ack_nonce, sizeof(cp->ack_nonce));
    wipe(cp->drop_otp, sizeof(cp->drop_otp));
}

static void end_pairing(code_pairing_t *cp, code_pairing_state_t state, const char *problem) {
    if (problem) copy_str(cp->problem, sizeof(cp->problem), problem);
    wipe(cp->secret, sizeof(cp->secret));
    forget_drop(cp);
    wipe(cp->skip_otps, sizeof(cp->skip_otps));
    cp->skip_next = 0;
    cp->shown = false;
    cp->phase = PHASE_NONE;
    set_state(cp, state);
}

static uint32_t fail(code_pairing_t *cp, code_pairing_state_t state, const char *problem) {
    end_pairing(cp, state, problem);
    return CODE_PAIRING_NO_STEP;
}

// ---- Requests -------------------------------------------------------------------

typedef struct {
    int rc;
    int status;
    int retry_after_s;
    cJSON *json;
    const char *type;
} answer_t;

static void post(code_pairing_t *cp, const char *path, char *body, answer_t *a) {
    char url[320];
    snprintf(url, sizeof(url), "%s%s", cp->cfg.base_url ? cp->cfg.base_url : "", path);
    char *resp = NULL;
    *a = (answer_t){.retry_after_s = -1};
    a->rc = body && cp->p->http_post_json
        ? cp->p->http_post_json(cp->p->ctx, url, body, &a->status, &resp, &a->retry_after_s)
        : CODE_PAIRING_HTTP_TRANSPORT_ERROR;
    if (body) {
        wipe(body, strlen(body));
        free(body);
    }
    if (a->rc != 0) {
        a->rc = CODE_PAIRING_HTTP_TRANSPORT_ERROR;
        a->status = 0;
    }
    if (resp) {
        a->json = cJSON_Parse(resp);
        wipe(resp, strlen(resp));
        free(resp);
    }
    if (a->json && !cJSON_IsObject(a->json)) {
        json_free(a->json);
        a->json = NULL;
    }
    a->type = a->json ? json_str(a->json, "type") : NULL;
    if (!a->type) a->type = "";
}

static void answer_free(answer_t *a) {
    json_free(a->json);
    a->json = NULL;
}

static bool skipped(const code_pairing_t *cp, const char *otp) {
    for (unsigned i = 0; i < CODE_PAIRING_SKIP_OTPS; i++) {
        if (cp->skip_otps[i][0] && strcmp(cp->skip_otps[i], otp) == 0) return true;
    }
    return false;
}

// Leaves the code that brought a junk drop (or rejected tokens) out of later
// polls, so it can't shadow the real drop.
static void skip_otp(code_pairing_t *cp, const char *otp) {
    if (!otp || !printable_ascii(otp, CODE_PAIRING_OTP_LEN) || skipped(cp, otp)) return;
    copy_str(cp->skip_otps[cp->skip_next], sizeof(cp->skip_otps[0]), otp);
    cp->skip_next = (cp->skip_next + 1) % CODE_PAIRING_SKIP_OTPS;
}

static char *poll_body(code_pairing_t *cp, uint64_t now) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    cJSON_AddStringToObject(root, "node_id", cp->cfg.node_id ? cp->cfg.node_id : "");
    cJSON_AddStringToObject(root, "key_fingerprint", cp->fingerprint);
    cJSON *otps = cJSON_AddArrayToObject(root, "recent_otps");
    uint64_t c = counter_at(now);
    for (int i = 0; otps && i < CODE_PAIRING_RECENT_OTPS && (uint64_t)i <= c; i++) {
        char otp[CODE_PAIRING_OTP_LEN + 1];
        code_pairing_otp(cp->secret, c - (uint64_t)i, otp);
        if (!skipped(cp, otp)) cJSON_AddItemToArray(otps, cJSON_CreateString(otp));
        wipe(otp, sizeof(otp));
    }
    if (otps && cp->cfg.claim_code && cp->cfg.claim_code[0] && !skipped(cp, cp->cfg.claim_code)) {
        cJSON_AddItemToArray(otps, cJSON_CreateString(cp->cfg.claim_code));
    }
    if (cp->cfg.sdk_token && cp->cfg.sdk_token[0]) {
        cJSON_AddStringToObject(root, "sdk_token", cp->cfg.sdk_token);
    }
    return print_and_free(root);
}

// Opens a drop's sealed payload into a NUL-terminated string the caller wipes
// and frees, or NULL.
static char *open_sealed(code_pairing_t *cp, const cJSON *sealed) {
    long v = 0;
    const char *enc_b64 = json_str(sealed, "enc");
    const char *ct_b64 = json_str(sealed, "ct");
    if (!cJSON_IsObject(sealed) || !json_int(sealed, "v", &v) || v != 1 || !enc_b64 || !ct_b64) {
        return NULL;
    }
    uint8_t enc[MUSE_HPKE_KEY_BYTES];
    if (code_pairing_b64url_decode(enc_b64, enc, sizeof(enc)) != (int)sizeof(enc)) return NULL;
    size_t cap = strlen(ct_b64) * 3 / 4 + 3;
    if (cap > CODE_PAIRING_MAX_SEALED + MUSE_HPKE_TAG_BYTES + 3) return NULL;
    uint8_t *ct = malloc(cap);
    if (!ct) return NULL;
    int ct_len = code_pairing_b64url_decode(ct_b64, ct, cap);
    char *pt = NULL;
    const char *node_id = cp->cfg.node_id ? cp->cfg.node_id : "";
    if (ct_len > MUSE_HPKE_TAG_BYTES) {
        size_t pt_len = (size_t)ct_len - MUSE_HPKE_TAG_BYTES;
        pt = malloc(pt_len + 1);
        if (pt && muse_hpke_open(cp->p->hpke, cp->pubkey, enc,
                                 (const uint8_t *)DROP_INFO, strlen(DROP_INFO),
                                 (const uint8_t *)node_id, strlen(node_id),
                                 ct, (size_t)ct_len, (uint8_t *)pt)) {
            pt[pt_len] = '\0';
            if (strlen(pt) != pt_len) {  // an embedded NUL isn't JSON
                wipe(pt, pt_len);
                free(pt);
                pt = NULL;
            }
        } else {
            free(pt);
            pt = NULL;
        }
    }
    wipe(ct, cap);
    free(ct);
    return pt;
}

// The drop opened: keep its payload until the tokens are vetted. Returns
// false to ignore it (not provision_v2, or no tokens).
static bool take_drop(code_pairing_t *cp, const char *plaintext, const char *otp) {
    cJSON *msg = cJSON_Parse(plaintext);
    const char *action = msg ? json_str(msg, "action") : NULL;
    const char *access = msg ? json_str(msg, "access_token") : NULL;
    const char *refresh = msg ? json_str(msg, "refresh_token") : NULL;
    if (!cJSON_IsObject(msg) || !action || strcmp(action, "provision_v2") != 0
        || !access || !*access || !refresh || !*refresh) {
        json_free(msg);
        return false;
    }
    const char *api = json_str(msg, "api_url_v2");
    const char *noise = json_str(msg, "noise_host");
    const char *username = json_str(msg, "username");
    const char *nonce = json_str(msg, "ack_nonce");
    forget_drop(cp);
    cp->access_token = dup_str(access);
    cp->refresh_token = dup_str(refresh);
    copy_str(cp->api_url_v2, sizeof(cp->api_url_v2),
             api && printable_ascii(api, sizeof(cp->api_url_v2) - 1) ? api : "");
    copy_str(cp->noise_host, sizeof(cp->noise_host),
             noise && printable_ascii(noise, sizeof(cp->noise_host) - 1) ? noise : "");
    copy_str(cp->username, sizeof(cp->username),
             username && strlen(username) < sizeof(cp->username) ? username : "");
    copy_str(cp->ack_nonce, sizeof(cp->ack_nonce),
             nonce && printable_ascii(nonce, sizeof(cp->ack_nonce) - 1) ? nonce : "");
    copy_str(cp->drop_otp, sizeof(cp->drop_otp),
             otp && printable_ascii(otp, CODE_PAIRING_OTP_LEN) ? otp : "");
    json_free(msg);
    if (!cp->access_token || !cp->refresh_token) {
        forget_drop(cp);
        return false;
    }
    return true;
}

static bool bind_wanted(const code_pairing_t *cp) {
    return cp->cfg.sdk_token && cp->cfg.sdk_token[0] && cp->p->bind_tokens;
}


static uint32_t step_poll(code_pairing_t *cp) {
    uint64_t now = now_ms(cp);
    if (now >= cp->window_end_ms) {
        cp_log(cp, CODE_PAIRING_LOG_INFO,
               "pairing window closed; press the button to show the code again");
        return fail(cp, CODE_PAIRING_EXPIRED, NULL);
    }
    refresh_code(cp, now);
    if (now < cp->next_poll_ms) return next_wake(cp, now);

    if (cp->p->net_up && !cp->p->net_up(cp->p->ctx)) {
        if (!cp->net_logged) cp_log(cp, CODE_PAIRING_LOG_INFO, "waiting for the network");
        cp->net_logged = true;
        // Wake for the next code too: the QR code changes every 10 s.
        uint32_t wait = next_wake(cp, now);
        if (wait == 0) wait = ms_until(now, (counter_at(now) + 1) * CODE_PAIRING_STEP_S * 1000u);
        bool up = cp->p->net_wait_up && cp->p->net_wait_up(cp->p->ctx, wait ? wait : 1);
        return up ? 0 : next_wake(cp, now_ms(cp));
    }
    cp->net_logged = false;

    answer_t a;
    post(cp, POLL_PATH, poll_body(cp, now), &a);
    now = now_ms(cp);
    uint32_t interval_ms = cp->interval_s * 1000u;
    uint32_t wait_ms = interval_ms;

    if (a.rc != 0 || a.status >= 500) {
        uint32_t s = next_backoff_s(cp);
        wait_ms = max_u32(jitter(cp, s * 1000u), interval_ms);
        cp_log(cp, CODE_PAIRING_LOG_WARN, "poll failed (HTTP %d); retrying in %u s",
               a.status, (unsigned)(wait_ms / 1000));
    } else if (a.status == 200) {
        cp->backoff_s = 0;
        const char *otp = a.json ? json_str(a.json, "otp") : NULL;
        char *plaintext = a.json
            ? open_sealed(cp, cJSON_GetObjectItemCaseSensitive(a.json, "sealed")) : NULL;
        bool taken = plaintext && take_drop(cp, plaintext, otp);
        if (plaintext) {
            wipe(plaintext, strlen(plaintext));
            free(plaintext);
        }
        if (taken) {
            answer_free(&a);
            cp_log(cp, CODE_PAIRING_LOG_INFO, "a payload opened; checking its tokens with Muse");
            cp->phase = bind_wanted(cp) ? PHASE_BIND : PHASE_VERIFY;
            return 0;
        }
        // Anyone who saw the QR code can drop something; only the Muse
        // app's payload opens and carries tokens.
        skip_otp(cp, otp);
        cp_log(cp, CODE_PAIRING_LOG_WARN, "ignored a drop that isn't for this gadget");
    } else if (strcmp(a.type, "authorization_pending") == 0
               || strcmp(a.type, "slow_down") == 0) {
        cp->backoff_s = 0;
        bool slow = a.type[0] == 's';
        long interval = 0;
        uint32_t next = cp->interval_s;
        if (json_int(a.json, "interval", &interval) && interval > 0) {
            next = clamp_interval(interval);
        } else if (slow) {
            next = clamp_interval((long)cp->interval_s + SLOW_DOWN_STEP_S);
        }
        if (slow && next < cp->interval_s) next = cp->interval_s;
        if (slow && next != cp->interval_s) {
            cp_log(cp, CODE_PAIRING_LOG_INFO, "slowing down: polling every %u s", (unsigned)next);
        }
        cp->interval_s = next;
        wait_ms = cp->interval_s * 1000u;
    } else if (strcmp(a.type, "invalidRequest") == 0) {
        cp_log(cp, CODE_PAIRING_LOG_ERROR, "Muse refused the poll as malformed");
        answer_free(&a);
        return fail(cp, CODE_PAIRING_ERROR, "invalidRequest");
    } else if (strcmp(a.type, "devicePairUnavailable") == 0) {
        cp_log(cp, CODE_PAIRING_LOG_INFO, "code pairing is off; use Bluetooth setup");
        answer_free(&a);
        return fail(cp, CODE_PAIRING_UNAVAILABLE, "devicePairUnavailable");
    } else if (a.status == 429 || strcmp(a.type, "rateLimited") == 0) {
        cp->backoff_s = 0;
        int s = a.retry_after_s > 0 ? a.retry_after_s : RATE_LIMITED_DEFAULT_S;
        wait_ms = max_u32((uint32_t)s * 1000u, interval_ms);
        cp_log(cp, CODE_PAIRING_LOG_WARN, "rate limited; polling again in %u s",
               (unsigned)(wait_ms / 1000));
    } else {
        cp->backoff_s = 0;
        wait_ms = max_u32(UNKNOWN_PROBLEM_WAIT_MS, interval_ms);
        cp_log(cp, CODE_PAIRING_LOG_WARN, "unexpected answer (HTTP %d); polling again in %u s",
               a.status, (unsigned)(wait_ms / 1000));
    }
    answer_free(&a);
    cp->next_poll_ms = now + wait_ms;
    return next_wake(cp, now);
}

static uint32_t back_to_polling(code_pairing_t *cp) {
    forget_drop(cp);
    uint64_t now = now_ms(cp);
    if (now >= cp->window_end_ms) return fail(cp, CODE_PAIRING_EXPIRED, NULL);
    cp->phase = PHASE_POLL;
    cp->backoff_s = 0;
    cp->next_poll_ms = now + cp->interval_s * 1000u;
    refresh_code(cp, now);
    return next_wake(cp, now);
}

// The tokens aren't real: ignore the drop, and the code that brought it.
static uint32_t reject_drop(code_pairing_t *cp) {
    cp_log(cp, CODE_PAIRING_LOG_WARN, "Muse rejected the drop's tokens; ignoring it");
    skip_otp(cp, cp->drop_otp);
    return back_to_polling(cp);
}

static uint32_t step_bind(code_pairing_t *cp) {
    char *new_access = NULL, *new_refresh = NULL;
    code_pairing_result_t r = cp->p->bind_tokens(cp->p->ctx, cp->access_token,
                                                 cp->refresh_token, &new_access, &new_refresh);
    if (r == CODE_PAIRING_RESULT_OK && new_access && *new_access && new_refresh
        && *new_refresh) {
        // Use the pair the refresh returned from now on.
        free_secret(&cp->access_token);
        free_secret(&cp->refresh_token);
        cp->access_token = new_access;
        cp->refresh_token = new_refresh;
        new_access = new_refresh = NULL;
    }
    free_secret(&new_access);
    free_secret(&new_refresh);
    switch (r) {
        case CODE_PAIRING_RESULT_SDK_REFUSED:
            cp_log(cp, CODE_PAIRING_LOG_ERROR,
                   "Muse refused this gadget's SDK token (revoked, unknown, or at its "
                   "device limit); the maker can check it at gadgets.muse.ai");
            return fail(cp, CODE_PAIRING_ERROR, "sdkTokenRefused");
        case CODE_PAIRING_RESULT_REJECTED:
            return reject_drop(cp);
        case CODE_PAIRING_RESULT_RETRY:
            cp_log(cp, CODE_PAIRING_LOG_WARN,
                   "couldn't record the SDK token yet; keeping the payload's tokens");
            break;
        case CODE_PAIRING_RESULT_OK:
            break;
    }
    cp->phase = PHASE_VERIFY;
    return 0;
}

static uint32_t step_verify(code_pairing_t *cp) {
    code_pairing_result_t r = cp->p->verify_tokens
        ? cp->p->verify_tokens(cp->p->ctx, cp->access_token) : CODE_PAIRING_RESULT_OK;
    if (r == CODE_PAIRING_RESULT_REJECTED || r == CODE_PAIRING_RESULT_SDK_REFUSED) {
        return reject_drop(cp);
    }
    if (r == CODE_PAIRING_RESULT_RETRY) {
        // No verdict: nothing is saved. The drop stays on the server for two
        // minutes, so the next poll brings it back for another try.
        cp_log(cp, CODE_PAIRING_LOG_WARN, "couldn't check the drop's tokens; trying again");
        return back_to_polling(cp);
    }
    const char *api = cp->api_url_v2[0] ? cp->api_url_v2 : cp->cfg.base_url;
    if (!cp->p->save_tokens
        || !cp->p->save_tokens(cp->p->ctx, cp->access_token, cp->refresh_token,
                               cp->cfg.node_id, api,
                               cp->noise_host[0] ? cp->noise_host : NULL,
                               cp->username[0] ? cp->username : NULL)) {
        cp_log(cp, CODE_PAIRING_LOG_ERROR, "the tokens couldn't be saved");
        return fail(cp, CODE_PAIRING_ERROR, "storage");
    }
    cp_log(cp, CODE_PAIRING_LOG_INFO, "tokens checked and saved");
    free_secret(&cp->access_token);
    free_secret(&cp->refresh_token);
    cp->phase = PHASE_ACK;
    return 0;
}

// Best effort, one attempt: it only deletes the drop sooner. Then the keys
// go: the next pairing starts with a fresh key and code secret.
static uint32_t step_ack(code_pairing_t *cp) {
    if (cp->ack_nonce[0]) {
        cJSON *root = cJSON_CreateObject();
        if (root) {
            cJSON_AddStringToObject(root, "node_id", cp->cfg.node_id ? cp->cfg.node_id : "");
            cJSON_AddStringToObject(root, "key_fingerprint", cp->fingerprint);
            cJSON_AddStringToObject(root, "otp", cp->drop_otp);
            cJSON_AddStringToObject(root, "ack_nonce", cp->ack_nonce);
        }
        answer_t a;
        post(cp, ACK_PATH, print_and_free(root), &a);
        answer_free(&a);
    }
    if (cp->p->erase_keys) cp->p->erase_keys(cp->p->ctx);
    cp->problem[0] = '\0';
    cp_log(cp, CODE_PAIRING_LOG_INFO, "paired");
    return fail(cp, CODE_PAIRING_PAIRED, NULL);
}

// ---- Public API -----------------------------------------------------------------

void code_pairing_init(code_pairing_t *cp, const code_pairing_platform_t *platform,
                       const code_pairing_config_t *cfg) {
    memset(cp, 0, sizeof(*cp));
    cp->p = platform;
    cp->cfg = *cfg;
    cp->state = CODE_PAIRING_IDLE;
    cp->phase = PHASE_NONE;
    cp->interval_s = DEFAULT_INTERVAL_S;
}

void code_pairing_start(code_pairing_t *cp) {
    if (cp->phase != PHASE_NONE) return;
    cp->problem[0] = '\0';
    if (!cp->p->load_keys || !cp->p->load_keys(cp->p->ctx, cp->pubkey, cp->secret)) {
        cp_log(cp, CODE_PAIRING_LOG_ERROR, "device key unavailable");
        fail(cp, CODE_PAIRING_ERROR, "deviceKey");
        return;
    }
    code_pairing_fingerprint(cp->pubkey, cp->fingerprint);
    uint64_t now = now_ms(cp);
    uint32_t window = cp->cfg.window_s ? cp->cfg.window_s : CODE_PAIRING_WINDOW_S;
    cp->window_end_ms = now + (uint64_t)window * 1000u;
    cp->interval_s = DEFAULT_INTERVAL_S;
    cp->backoff_s = 0;
    cp->next_poll_ms = now + cp->interval_s * 1000u;
    cp->net_logged = false;
    cp->shown = false;
    cp->phase = PHASE_POLL;
    cp_log(cp, CODE_PAIRING_LOG_INFO, "pairing open for %u s; scan the code with the Muse app",
           (unsigned)window);
    set_state(cp, CODE_PAIRING_WAITING);
    refresh_code(cp, now);
}

void code_pairing_stop(code_pairing_t *cp) {
    end_pairing(cp, CODE_PAIRING_IDLE, NULL);
}

uint32_t code_pairing_step(code_pairing_t *cp, code_pairing_state_t *state) {
    uint32_t delay = CODE_PAIRING_NO_STEP;
    switch (cp->phase) {
        case PHASE_POLL:   delay = step_poll(cp); break;
        case PHASE_ACK:    delay = step_ack(cp); break;
        case PHASE_BIND:   delay = step_bind(cp); break;
        case PHASE_VERIFY: delay = step_verify(cp); break;
        default: break;
    }
    if (state) *state = cp->state;
    return delay;
}

code_pairing_state_t code_pairing_state(const code_pairing_t *cp) {
    return cp->state;
}

const char *code_pairing_last_problem(const code_pairing_t *cp) {
    return cp->problem;
}

const char *code_pairing_state_name(code_pairing_state_t state) {
    switch (state) {
        case CODE_PAIRING_IDLE:        return "idle";
        case CODE_PAIRING_WAITING:     return "waiting";
        case CODE_PAIRING_PAIRED:      return "paired";
        case CODE_PAIRING_EXPIRED:     return "expired";
        case CODE_PAIRING_UNAVAILABLE: return "unavailable";
        case CODE_PAIRING_ERROR:       return "error";
    }
    return "?";
}
