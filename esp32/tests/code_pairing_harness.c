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

// Drives main/code_pairing.c and main/muse_hpke.c against a scripted fake
// platform: a fake clock, scripted HTTP answers, an in-memory key/value store,
// and crypto primitives that are either fakes (always) or the host's libcrypto
// (built with -DHAVE_LIBCRYPTO, for the vectors in
// tests/vectors/code_pairing_hpke.json).
// Usage: code_pairing_harness <scenario|all> [vectors.json]; exits 0 when it passes.

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
#include <malloc.h>
#define HEAP_IN_USE() mallinfo2().uordblks
#endif

#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#endif

#include "cJSON.h"
#include "code_pairing.h"
#include "muse_hpke.h"

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, \
                    #cond);                                                  \
            exit(1);                                                         \
        }                                                                    \
    } while (0)
#define CHECK_STR(a, b)                                                       \
    do {                                                                      \
        const char *a_ = (a), *b_ = (b);                                      \
        if (!a_ || !b_ || strcmp(a_, b_) != 0) {                              \
            fprintf(stderr, "%s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__,  \
                    a_ ? a_ : "(null)", b_ ? b_ : "(null)");                  \
            exit(1);                                                          \
        }                                                                     \
    } while (0)
#define CHECK_EQ(a, b)                                                         \
    do {                                                                       \
        long long a_ = (long long)(a), b_ = (long long)(b);                    \
        if (a_ != b_) {                                                        \
            fprintf(stderr, "%s:%d: %s == %lld, want %lld\n", __FILE__,        \
                    __LINE__, #a, a_, b_);                                     \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

// ---- Crypto primitives ------------------------------------------------------------

typedef struct {
    uint8_t recipient_sk[32];  // the key recipient_dh uses
    uint8_t rand_seed;         // deterministic "random" bytes
    const uint8_t *rand_fixed; // when set, random_bytes returns these 32 bytes
} crypto_t;

static crypto_t C;

// Fake X25519: exponentiation in the multiplicative group mod 2^61 - 1, with
// the first 8 bytes of the scalar as exponent and the u-coordinate as base.
// Like X25519 it commutes: f(a, f(b, 9)) == f(b, f(a, 9)).
#define FAKE_P ((1ull << 61) - 1)

static uint64_t mulmod(uint64_t a, uint64_t b) {
    return (uint64_t)(((unsigned __int128)a * b) % FAKE_P);
}

static uint64_t le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

static bool fake_x25519(void *ctx, const uint8_t scalar[32], const uint8_t u[32],
                        uint8_t out[32]) {
    (void)ctx;
    uint64_t base = le64(u) % FAKE_P;
    uint64_t e = le64(scalar) | 1;
    if (base == 0) return false;
    uint64_t r = 1;
    while (e) {
        if (e & 1) r = mulmod(r, base);
        base = mulmod(base, base);
        e >>= 1;
    }
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(r >> (8 * i));
    return true;
}

static bool fake_recipient_dh(void *ctx, const uint8_t u[32], uint8_t out[32]) {
    return fake_x25519(ctx, C.recipient_sk, u, out);
}

// Fake AES-128-GCM: a SHA-256 keystream and an HMAC tag over nonce, aad and
// ciphertext, so tampering with any of them fails to open.
static void fake_keystream(const uint8_t key[16], const uint8_t nonce[12], uint8_t *buf,
                           size_t len) {
    for (size_t off = 0, ctr = 0; off < len; off += 32, ctr++) {
        uint8_t in[16 + 12 + 4], blk[32];
        memcpy(in, key, 16);
        memcpy(in + 16, nonce, 12);
        for (int i = 0; i < 4; i++) in[28 + i] = (uint8_t)(ctr >> (8 * i));
        muse_hpke_sha256(in, sizeof(in), blk);
        for (size_t i = 0; i < 32 && off + i < len; i++) buf[off + i] ^= blk[i];
    }
}

static void fake_tag(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
                     size_t aad_len, const uint8_t *ct, size_t len, uint8_t tag[16]) {
    size_t n = 12 + 8 + aad_len + len;
    uint8_t *buf = malloc(n);
    CHECK(buf);
    memcpy(buf, nonce, 12);
    for (int i = 0; i < 8; i++) buf[12 + i] = (uint8_t)((uint64_t)aad_len >> (8 * i));
    memcpy(buf + 20, aad, aad_len);
    memcpy(buf + 20 + aad_len, ct, len);
    uint8_t mac[32];
    muse_hpke_hmac_sha256(key, 16, buf, n, mac);
    memcpy(tag, mac, 16);
    free(buf);
}

static bool fake_seal(void *ctx, const uint8_t key[16], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t len,
                      uint8_t *ct) {
    (void)ctx;
    memcpy(ct, pt, len);
    fake_keystream(key, nonce, ct, len);
    fake_tag(key, nonce, aad, aad_len, ct, len, ct + len);
    return true;
}

static bool fake_open(void *ctx, const uint8_t key[16], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
                      uint8_t *pt) {
    (void)ctx;
    size_t len = ct_len - 16;
    uint8_t tag[16];
    fake_tag(key, nonce, aad, aad_len, ct, len, tag);
    if (memcmp(tag, ct + len, 16) != 0) return false;
    memcpy(pt, ct, len);
    fake_keystream(key, nonce, pt, len);
    return true;
}

static bool crypto_random(void *ctx, uint8_t *out, size_t len) {
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        out[i] = C.rand_fixed && len == 32 ? C.rand_fixed[i] : (uint8_t)(C.rand_seed + 7 * i + 1);
    }
    C.rand_seed++;
    return true;
}

static const muse_hpke_ops_t FAKE_OPS = {
    .ctx = NULL,
    .x25519 = fake_x25519,
    .recipient_dh = fake_recipient_dh,
    .aes128gcm_seal = fake_seal,
    .aes128gcm_open = fake_open,
    .random_bytes = crypto_random,
};

#ifdef HAVE_LIBCRYPTO
static bool real_x25519(void *ctx, const uint8_t scalar[32], const uint8_t u[32],
                        uint8_t out[32]) {
    (void)ctx;
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, scalar, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, u, 32);
    EVP_PKEY_CTX *pctx = priv ? EVP_PKEY_CTX_new(priv, NULL) : NULL;
    size_t len = 32;
    bool ok = pctx && peer && EVP_PKEY_derive_init(pctx) == 1
              && EVP_PKEY_derive_set_peer(pctx, peer) == 1
              && EVP_PKEY_derive(pctx, out, &len) == 1 && len == 32;
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(priv);
    return ok;
}

static bool real_recipient_dh(void *ctx, const uint8_t u[32], uint8_t out[32]) {
    return real_x25519(ctx, C.recipient_sk, u, out);
}

static bool real_gcm(bool seal, const uint8_t key[16], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                     uint8_t *out, uint8_t tag[16]) {
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int n = 0;
    bool ok = x && EVP_CipherInit_ex(x, EVP_aes_128_gcm(), NULL, NULL, NULL, seal) == 1
              && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1
              && EVP_CipherInit_ex(x, NULL, NULL, key, nonce, seal) == 1
              && (aad_len == 0 || EVP_CipherUpdate(x, NULL, &n, aad, (int)aad_len) == 1)
              && (len == 0 || EVP_CipherUpdate(x, out, &n, in, (int)len) == 1);
    if (ok && !seal) ok = EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1;
    if (ok) ok = EVP_CipherFinal_ex(x, out + len, &n) == 1;
    if (ok && seal) ok = EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(x);
    return ok;
}

static bool real_seal(void *ctx, const uint8_t key[16], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t len,
                      uint8_t *ct) {
    (void)ctx;
    return real_gcm(true, key, nonce, aad, aad_len, pt, len, ct, ct + len);
}

static bool real_open(void *ctx, const uint8_t key[16], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
                      uint8_t *pt) {
    (void)ctx;
    uint8_t tag[16];
    memcpy(tag, ct + ct_len - 16, 16);
    return real_gcm(false, key, nonce, aad, aad_len, ct, ct_len - 16, pt, tag);
}

static const muse_hpke_ops_t REAL_OPS = {
    .ctx = NULL,
    .x25519 = real_x25519,
    .recipient_dh = real_recipient_dh,
    .aes128gcm_seal = real_seal,
    .aes128gcm_open = real_open,
    .random_bytes = crypto_random,
};
#endif

static const uint8_t BASEPOINT[32] = {9};

// ---- Fake platform ------------------------------------------------------------

#define MAX_ANSWERS 64
#define MAX_REQUESTS 160
#define MAX_DROPS 8
#define MAX_STATES 64

typedef struct {
    int rc;
    int status;
    const char *body;
    int retry_after_s;
} answer_t;

typedef struct {
    char url[256];
    char *body;
    uint64_t at_ms;
} request_t;

typedef struct {
    char node_id[64];
    char fp[CODE_PAIRING_FINGERPRINT_LEN];
    char otp[16];
    char *sealed;  // {"v":1,...}
    char nonce[64];
    uint64_t filed_at;
    bool acked;
} drop_t;

// What a restart keeps: the gadget's own storage.
typedef struct {
    bool have_keys;
    uint8_t sk[32];
    int generated;
    int erased;
} nvs_t;

typedef struct {
    uint64_t now;
    uint8_t secret[32];
    // Scripted answers go first; with none left, the fake server answers.
    answer_t answers[MAX_ANSWERS];
    int answer_count, answer_next;
    char *owned[MAX_ANSWERS];
    int owned_count;
    request_t requests[MAX_REQUESTS];
    int request_count;
    int polls;
    drop_t drops[MAX_DROPS];
    int drop_count;
    int acks;
    int server_interval;
    bool net;
    uint64_t net_up_at;  // the link comes up at this time (0: never by itself)
    int net_waits;
    char logs[32768];
    int show_code_count;
    char shown_link[CODE_PAIRING_MAX_LINK], shown_fp[32];
    uint32_t shown_remaining;
    code_pairing_state_t states[MAX_STATES];
    int state_count;
    int save_count;
    bool save_ok;
    char saved_access[128], saved_refresh[128], saved_device[64], saved_api[128];
    char saved_noise[64], saved_user[64];
    bool saved_noise_null, saved_user_null;
    code_pairing_result_t bind_results[8];
    int bind_scripted, bind_next, bind_calls;
    code_pairing_result_t verify_results[8];
    int verify_count, verify_next, verify_calls;
    char bound_with[128], verified_with[128];
    bool keys_ok;
    const muse_hpke_ops_t *ops;
} fake_t;

static fake_t F;
static nvs_t NVS;
static unsigned random_window;
static code_pairing_platform_t PLATFORM;

#define T0 1000000u  // the clock at the start of each scenario: counter 100

static void fake_restart(void) {
    for (int i = 0; i < F.request_count; i++) free(F.requests[i].body);
    for (int i = 0; i < F.owned_count; i++) free(F.owned[i]);
    for (int i = 0; i < F.drop_count; i++) free(F.drops[i].sealed);
    const muse_hpke_ops_t *ops = F.ops ? F.ops : &FAKE_OPS;
    memset(&F, 0, sizeof(F));
    memset(&C, 0, sizeof(C));
    F.now = T0;
    F.net = true;
    F.save_ok = true;
    F.keys_ok = true;
    F.server_interval = 5;
    F.ops = ops;
    PLATFORM.hpke = ops;
}

static void fake_reset(void) {
    random_window = 0;
    F.ops = &FAKE_OPS;
    fake_restart();
    memset(&NVS, 0, sizeof(NVS));
}

static void push(int status, const char *body) {
    CHECK(F.answer_count < MAX_ANSWERS);
    F.answers[F.answer_count++] = (answer_t){.rc = 0, .status = status, .body = body,
                                              .retry_after_s = -1};
}

static void push_owned(int status, char *body) {
    CHECK(F.owned_count < MAX_ANSWERS);
    F.owned[F.owned_count++] = body;
    push(status, body);
}

static void push_retry_after(int status, const char *body, int retry_after_s) {
    push(status, body);
    F.answers[F.answer_count - 1].retry_after_s = retry_after_s;
}

static void push_transport_error(void) {
    CHECK(F.answer_count < MAX_ANSWERS);
    F.answers[F.answer_count++] = (answer_t){.rc = CODE_PAIRING_HTTP_TRANSPORT_ERROR,
                                              .retry_after_s = -1};
}

static char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    CHECK(d);
    memcpy(d, s, n);
    return d;
}

static const char *jstr(const cJSON *j, const char *k) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(j, k);
    return cJSON_IsString(item) ? item->valuestring : NULL;
}

static int field_count(const cJSON *j) {
    int n = 0;
    for (cJSON *c = j ? j->child : NULL; c; c = c->next) n++;
    return n;
}

// The fake server's poll: a drop filed under this node id, fingerprint and one
// of the presented codes, less than two minutes old and not acknowledged.
static char *server_poll(const char *body, int *status) {
    cJSON *req = cJSON_Parse(body);
    CHECK(req);
    const char *node = jstr(req, "node_id");
    const char *fp = jstr(req, "key_fingerprint");
    cJSON *otps = cJSON_GetObjectItemCaseSensitive(req, "recent_otps");
    CHECK(node && fp && cJSON_IsArray(otps));
    char *answer = NULL;
    for (int i = 0; i < F.drop_count && !answer; i++) {
        drop_t *d = &F.drops[i];
        if (d->acked || F.now - d->filed_at >= 120000 || strcmp(d->node_id, node) != 0
            || strcmp(d->fp, fp) != 0) {
            continue;
        }
        for (cJSON *o = otps->child; o; o = o->next) {
            if (cJSON_IsString(o) && strcmp(o->valuestring, d->otp) == 0) {
                size_t n = strlen(d->sealed) + 64;
                answer = malloc(n);
                CHECK(answer);
                snprintf(answer, n, "{\"sealed\":%s,\"otp\":\"%s\"}", d->sealed, d->otp);
                break;
            }
        }
    }
    cJSON_Delete(req);
    if (answer) {
        *status = 200;
        return answer;
    }
    *status = 400;
    char pending[96];
    snprintf(pending, sizeof(pending), "{\"type\":\"authorization_pending\",\"interval\":%d}",
             F.server_interval);
    return xstrdup(pending);
}

static char *server_ack(const char *body, int *status) {
    cJSON *req = cJSON_Parse(body);
    CHECK(req);
    for (int i = 0; i < F.drop_count; i++) {
        drop_t *d = &F.drops[i];
        if (strcmp(d->node_id, jstr(req, "node_id")) == 0 && strcmp(d->fp, jstr(req, "key_fingerprint")) == 0
            && strcmp(d->otp, jstr(req, "otp")) == 0 && strcmp(d->nonce, jstr(req, "ack_nonce")) == 0) {
            d->acked = true;
        }
    }
    cJSON_Delete(req);
    F.acks++;
    *status = 200;
    return xstrdup("{}");
}

static int f_http(void *ctx, const char *url, const char *body, int *status,
                  char **resp, int *retry_after_s) {
    (void)ctx;
    CHECK(F.request_count < MAX_REQUESTS);
    request_t *r = &F.requests[F.request_count++];
    snprintf(r->url, sizeof(r->url), "%s", url);
    r->body = xstrdup(body);
    r->at_ms = F.now;
    if (strstr(url, "/device_drop/poll")) F.polls++;
    *retry_after_s = -1;
    if (F.answer_next < F.answer_count) {
        answer_t *a = &F.answers[F.answer_next++];
        *status = a->status;
        *resp = a->body ? xstrdup(a->body) : NULL;
        *retry_after_s = a->retry_after_s;
        return a->rc;
    }
    if (strcmp(url, "https://api.example.test/device_drop/poll") == 0) {
        *resp = server_poll(body, status);
    } else if (strcmp(url, "https://api.example.test/device_drop/ack") == 0) {
        *resp = server_ack(body, status);
    } else {
        fprintf(stderr, "unexpected request to %s\n", url);
        exit(1);
    }
    return 0;
}

static uint64_t f_now(void *ctx) {
    (void)ctx;
    return F.now;
}

static bool f_random(void *ctx, uint8_t *out, size_t len) {
    (void)ctx;
    memset(out, 0, len);  // no jitter: keeps the timings exact
    if (len == 32) {
        ++random_window;  // simulated CSPRNG state survives the device reboot
        for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(i + 17 * random_window);
        memcpy(F.secret, out, len);
    }
    return true;
}

static void device_pk(uint8_t pk[32]) {
    CHECK(NVS.have_keys);
    CHECK(F.ops->x25519(NULL, NVS.sk, BASEPOINT, pk));
}

static bool f_load_keys(void *ctx, uint8_t pubkey[32]) {
    (void)ctx;
    if (!F.keys_ok) return false;
    if (!NVS.have_keys) {
        NVS.generated++;
        for (int i = 0; i < 32; i++) {
            NVS.sk[i] = (uint8_t)(0x40 + i + 31 * NVS.generated);
        }
        NVS.have_keys = true;
    }
    memcpy(C.recipient_sk, NVS.sk, 32);
    device_pk(pubkey);
    return true;
}

static void f_erase_keys(void *ctx) {
    (void)ctx;
    NVS.have_keys = false;
    memset(NVS.sk, 0, 32);
    memset(F.secret, 0, 32);
    NVS.erased++;
}

static bool f_net_up(void *ctx) {
    (void)ctx;
    if (!F.net && F.net_up_at && F.now >= F.net_up_at) F.net = true;
    return F.net;
}

static bool f_net_wait_up(void *ctx, uint32_t timeout_ms) {
    (void)ctx;
    F.net_waits++;
    CHECK(timeout_ms <= 10000);  // the QR code changes every 10 s
    if (f_net_up(NULL)) return true;
    if (F.net_up_at && F.net_up_at <= F.now + timeout_ms) {
        F.now = F.net_up_at;
        F.net = true;
        return true;
    }
    F.now += timeout_ms;
    return false;
}

static void f_show_code(void *ctx, const char *link, const char *fp, uint32_t remaining_s) {
    (void)ctx;
    F.show_code_count++;
    snprintf(F.shown_link, sizeof(F.shown_link), "%s", link);
    snprintf(F.shown_fp, sizeof(F.shown_fp), "%s", fp);
    F.shown_remaining = remaining_s;
}

static void f_show_status(void *ctx, code_pairing_state_t state) {
    (void)ctx;
    if (F.state_count < MAX_STATES) F.states[F.state_count++] = state;
}

static void f_log(void *ctx, code_pairing_log_level_t level, const char *msg) {
    (void)ctx;
    size_t used = strlen(F.logs);
    snprintf(F.logs + used, sizeof(F.logs) - used, "[%d] %s\n", (int)level, msg);
    if (getenv("CODE_PAIRING_VERBOSE")) fprintf(stderr, "log[%d] %s\n", (int)level, msg);
}

static bool f_save(void *ctx, const char *access, const char *refresh, const char *device,
                   const char *api, const char *noise, const char *user) {
    (void)ctx;
    F.save_count++;
    snprintf(F.saved_access, sizeof(F.saved_access), "%s", access);
    snprintf(F.saved_refresh, sizeof(F.saved_refresh), "%s", refresh);
    snprintf(F.saved_device, sizeof(F.saved_device), "%s", device);
    snprintf(F.saved_api, sizeof(F.saved_api), "%s", api ? api : "(null)");
    F.saved_noise_null = noise == NULL;
    snprintf(F.saved_noise, sizeof(F.saved_noise), "%s", noise ? noise : "");
    F.saved_user_null = user == NULL;
    snprintf(F.saved_user, sizeof(F.saved_user), "%s", user ? user : "");
    return F.save_ok;
}

// The binding refresh: by default Muse accepts and returns a new pair.
static code_pairing_result_t f_bind(void *ctx, const char *access, const char *refresh,
                                    char **new_access, char **new_refresh) {
    (void)ctx;
    CHECK_EQ(F.save_count, 0);  // vetted before anything is saved
    CHECK(access && *access && refresh && *refresh);
    F.bind_calls++;
    snprintf(F.bound_with, sizeof(F.bound_with), "%s", access);
    code_pairing_result_t r = F.bind_next < F.bind_scripted ? F.bind_results[F.bind_next++]
                                                            : CODE_PAIRING_RESULT_OK;
    if (r == CODE_PAIRING_RESULT_OK) {
        char buf[160];
        snprintf(buf, sizeof(buf), "%s-bound", access);
        *new_access = xstrdup(buf);
        snprintf(buf, sizeof(buf), "%s-bound", refresh);
        *new_refresh = xstrdup(buf);
    }
    return r;
}

static code_pairing_result_t f_verify(void *ctx, const char *access) {
    (void)ctx;
    CHECK_EQ(F.save_count, 0);
    F.verify_calls++;
    snprintf(F.verified_with, sizeof(F.verified_with), "%s", access);
    if (F.verify_next < F.verify_count) return F.verify_results[F.verify_next++];
    return CODE_PAIRING_RESULT_OK;
}

static code_pairing_platform_t PLATFORM = {
    .ctx = NULL,
    .http_post_json = f_http,
    .now_ms = f_now,
    .random_bytes = f_random,
    .load_keys = f_load_keys,
    .erase_keys = f_erase_keys,
    .hpke = &FAKE_OPS,
    .net_up = f_net_up,
    .net_wait_up = f_net_wait_up,
    .show_code = f_show_code,
    .show_status = f_show_status,
    .log = f_log,
    .bind_tokens = f_bind,
    .verify_tokens = f_verify,
    .save_tokens = f_save,
};

#define NODE "homelink-ab12cd"
#define SDK "mgst_testtoken0123456789"

static code_pairing_config_t default_cfg(void) {
    return (code_pairing_config_t){
        .base_url = "https://api.example.test",
        .node_id = NODE,
        .model = "hatch_link",
        .wifi = 'n',
        .mgcommands = false,
        .community = true,
        .sdk_token = SDK,
    };
}

// ---- The Muse app's side --------------------------------------------------------

static uint64_t counter_now(void) {
    return F.now / 10000u;
}

static void otp_at(uint64_t c, char out[9]) {
    CHECK(NVS.have_keys);
    code_pairing_otp(F.secret, c, out);
}

static void fingerprint_now(char fp[CODE_PAIRING_FINGERPRINT_LEN]) {
    uint8_t pk[32];
    device_pk(pk);
    code_pairing_fingerprint(pk, fp);
}

#define FULL_PAYLOAD                                                                    \
    "{\"action\":\"provision_v2\",\"access_token\":\"ACCESS-SECRET\","                  \
    "\"refresh_token\":\"REFRESH-SECRET\",\"token_type\":\"device\","                   \
    "\"api_url_v2\":\"https://api2.example.test\",\"noise_host\":\"vm.example.test\","  \
    "\"username\":\"person\",\"ack_nonce\":\"AckNonceSECRET0123456w\"}"
#define MIN_PAYLOAD                                                                     \
    "{\"action\":\"provision_v2\",\"access_token\":\"ACCESS-SECRET\","                  \
    "\"refresh_token\":\"REFRESH-SECRET\"}"

// {"v":1,"enc":...,"ct":...}: pt sealed to pk_r for `aad`.
static char *seal_json(const uint8_t pk_r[32], const char *aad, const char *pt, bool tamper) {
    size_t len = strlen(pt);
    uint8_t enc[32];
    uint8_t *ct = malloc(len + 16);
    CHECK(ct);
    CHECK(muse_hpke_seal(F.ops, pk_r, (const uint8_t *)"muse-drop-v1", 12,
                         (const uint8_t *)aad, strlen(aad), (const uint8_t *)pt, len, enc, ct));
    if (tamper) ct[len / 2] ^= 1;
    char enc_b64[48];
    char *ct_b64 = malloc(len * 2 + 64);
    CHECK(ct_b64);
    code_pairing_b64url_encode(enc, 32, enc_b64, sizeof(enc_b64));
    code_pairing_b64url_encode(ct, len + 16, ct_b64, len * 2 + 64);
    char *out = malloc(len * 2 + 160);
    CHECK(out);
    snprintf(out, len * 2 + 160, "{\"v\":1,\"enc\":\"%s\",\"ct\":\"%s\"}", enc_b64, ct_b64);
    free(ct);
    free(ct_b64);
    return out;
}

// The app scanned the code `age` steps old, sealed pt to the gadget's key and
// filed it on the server.
static void app_drop_as(int age, const char *pt, const char *fp_override, const char *nonce) {
    CHECK(F.drop_count < MAX_DROPS);
    drop_t *d = &F.drops[F.drop_count++];
    uint8_t pk[32];
    device_pk(pk);
    snprintf(d->node_id, sizeof(d->node_id), "%s", NODE);
    if (fp_override) {
        snprintf(d->fp, sizeof(d->fp), "%s", fp_override);
    } else {
        code_pairing_fingerprint(pk, d->fp);
    }
    otp_at(counter_now() - (uint64_t)age, d->otp);
    d->sealed = seal_json(pk, NODE, pt, false);
    snprintf(d->nonce, sizeof(d->nonce), "%s", nonce ? nonce : "");
    d->filed_at = F.now;
}

static void app_drop(const char *pt) {
    app_drop_as(0, pt, NULL, strstr(pt, "AckNonceSECRET0123456w") ? "AckNonceSECRET0123456w" : NULL);
}

// Runs steps, advancing the fake clock by each returned delay, until the
// machine has nothing to do, `steps` run out or the clock reaches `until`.
static uint32_t run_until(code_pairing_t *cp, int steps, uint64_t until, code_pairing_state_t *state) {
    uint32_t delay = 0;
    for (int i = 0; i < steps; i++) {
        delay = code_pairing_step(cp, state);
        if (delay == CODE_PAIRING_NO_STEP) break;
        if (until && F.now + delay > until) break;
        F.now += delay;
    }
    return delay;
}

static uint32_t run(code_pairing_t *cp, int steps, code_pairing_state_t *state) {
    return run_until(cp, steps, 0, state);
}

// Runs until n polls have been sent.
static void run_polls(code_pairing_t *cp, int n, code_pairing_state_t *state) {
    int target = F.polls + n;
    for (int i = 0; i < 1000 && F.polls < target; i++) {
        uint32_t delay = code_pairing_step(cp, state);
        if (delay == CODE_PAIRING_NO_STEP) break;
        if (F.polls >= target) break;
        F.now += delay;
    }
    CHECK_EQ(F.polls, target);
}

static cJSON *request_json(int i) {
    CHECK(i < F.request_count);
    cJSON *j = cJSON_Parse(F.requests[i].body);
    CHECK(j);
    return j;
}

static bool is_path(int i, const char *path) {
    char want[128];
    snprintf(want, sizeof(want), "https://api.example.test%s", path);
    return strcmp(F.requests[i].url, want) == 0;
}

static int nth_poll(int n) {
    for (int i = 0, seen = 0; i < F.request_count; i++) {
        if (is_path(i, "/device_drop/poll") && seen++ == n) return i;
    }
    CHECK(!"no such poll");
    return -1;
}

// A poll's body: node id, fingerprint, the codes for c..c-5 at its time,
// newest first, and the SDK token when configured.
static void check_poll_body_skipping(int i, const char *claim, bool with_sdk,
                                     const char *skip) {
    CHECK(is_path(i, "/device_drop/poll"));
    cJSON *poll = request_json(i);
    CHECK_EQ(field_count(poll), with_sdk ? 4 : 3);
    CHECK_STR(jstr(poll, "node_id"), NODE);
    char fp[CODE_PAIRING_FINGERPRINT_LEN];
    fingerprint_now(fp);
    CHECK_STR(jstr(poll, "key_fingerprint"), fp);
    if (with_sdk) {
        CHECK_STR(jstr(poll, "sdk_token"), SDK);
    } else {
        CHECK(!cJSON_GetObjectItemCaseSensitive(poll, "sdk_token"));
    }
    cJSON *otps = cJSON_GetObjectItemCaseSensitive(poll, "recent_otps");
    CHECK(cJSON_IsArray(otps));
    uint64_t c = F.requests[i].at_ms / 10000u;
    char want[8][9];
    int n = 0;
    for (int k = 0; k < 6; k++) {
        otp_at(c - (uint64_t)k, want[n]);
        if (!skip || strcmp(want[n], skip) != 0) n++;
    }
    if (claim) snprintf(want[n++], 9, "%s", claim);
    int k = 0;
    for (cJSON *o = otps->child; o; o = o->next, k++) {
        CHECK(k < n);
        CHECK_STR(o->valuestring, want[k]);
    }
    CHECK_EQ(k, n);
    cJSON_Delete(poll);
}

static void check_poll_body(int i, const char *claim, bool with_sdk) {
    check_poll_body_skipping(i, claim, with_sdk, NULL);
}

static bool poll_presents(int i, const char *otp) {
    cJSON *poll = request_json(i);
    cJSON *otps = cJSON_GetObjectItemCaseSensitive(poll, "recent_otps");
    bool found = false;
    for (cJSON *o = otps ? otps->child : NULL; o; o = o->next) {
        if (strcmp(o->valuestring, otp) == 0) found = true;
    }
    cJSON_Delete(poll);
    return found;
}

static void check_no_secrets_logged(void) {
    static const char *const secrets[] = {
        "ACCESS-SECRET", "REFRESH-SECRET", "mgst_testtoken", "AckNonceSECRET0123456w",
        "sealed", "\"ct\"", "CLAIMCOD",
    };
    for (size_t i = 0; i < sizeof(secrets) / sizeof(secrets[0]); i++) {
        if (strstr(F.logs, secrets[i])) {
            fprintf(stderr, "%s in logs:\n%s", secrets[i], F.logs);
            exit(1);
        }
    }
    // No one-time code either, from any poll.
    for (int i = 0; i < F.request_count; i++) {
        if (!is_path(i, "/device_drop/poll")) continue;
        cJSON *poll = request_json(i);
        cJSON *otps = cJSON_GetObjectItemCaseSensitive(poll, "recent_otps");
        for (cJSON *o = otps ? otps->child : NULL; o; o = o->next) {
            if (strstr(F.logs, o->valuestring)) {
                fprintf(stderr, "a one-time code in logs:\n%s", F.logs);
                exit(1);
            }
        }
        cJSON_Delete(poll);
    }
}

// ---- Scenarios --------------------------------------------------------------------

static void scenario_otp_vectors(void) {
    // The table in docs/code-pairing.md.
    uint8_t secret[32];
    for (int i = 0; i < 32; i++) secret[i] = (uint8_t)i;
    static const struct {
        uint64_t c;
        const char *code;
    } v[] = {
        {0, "J66JQ2A2"}, {1, "MG2GGDQN"}, {179251798, "XEPZ97F6"}, {179251799, "TW0NCKK8"},
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        char out[9];
        code_pairing_otp(secret, v[i].c, out);
        CHECK_STR(out, v[i].code);
    }
}

static void scenario_link(void) {
    uint8_t pk[32];
    for (int i = 0; i < 32; i++) pk[i] = (uint8_t)i;
    code_pairing_config_t cfg = default_cfg();
    char link[CODE_PAIRING_MAX_LINK];
    size_t n = code_pairing_link(&cfg, pk, "TW0NCKK8", link, sizeof(link));
    const char *want = "https://muse.ai/pair#v=1&n=homelink-ab12cd"
                       "&k=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
                       "&o=TW0NCKK8&m=hatch_link&w=n&g=0&c=1";
    CHECK_STR(link, want);
    CHECK_EQ(n, strlen(want));
    // Too small: nothing.
    CHECK_EQ(code_pairing_link(&cfg, pk, "TW0NCKK8", link, strlen(want)), 0);
    CHECK_STR(link, "");
    // Other values, and percent-encoding.
    cfg.node_id = "a b&c";
    cfg.model = "m/x";
    cfg.wifi = 'r';
    cfg.mgcommands = true;
    cfg.community = false;
    cfg.link_base = "http://127.0.0.1:8080/pair";
    code_pairing_link(&cfg, pk, "J66JQ2A2", link, sizeof(link));
    CHECK_STR(link, "http://127.0.0.1:8080/pair#v=1&n=a%20b%26c"
                    "&k=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
                    "&o=J66JQ2A2&m=m%2Fx&w=r&g=1&c=0");
    cfg.wifi = 0;  // unset: none
    code_pairing_link(&cfg, pk, "J66JQ2A2", link, sizeof(link));
    CHECK(strstr(link, "&w=n&"));
    // A slow screen's step goes last; the usual 10 s (or less) is left out.
    cfg.step_s = 10;
    code_pairing_link(&cfg, pk, "J66JQ2A2", link, sizeof(link));
    CHECK(!strstr(link, "&s="));
    cfg.step_s = 45;
    code_pairing_link(&cfg, pk, "J66JQ2A2", link, sizeof(link));
    const char *tail = "&c=0&s=45";
    CHECK(strlen(link) > strlen(tail) && strcmp(link + strlen(link) - strlen(tail), tail) == 0);
    // The SDK token never goes in it.
    CHECK(!strstr(link, "mgst_"));
}

static void scenario_happy_path(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    CHECK_EQ(code_pairing_state(&cp), CODE_PAIRING_IDLE);
    CHECK_EQ(code_pairing_step(&cp, NULL), CODE_PAIRING_NO_STEP);
    code_pairing_start(&cp);
    CHECK_EQ(code_pairing_state(&cp), CODE_PAIRING_WAITING);
    CHECK_EQ(NVS.generated, 1);
    // The QR code, straight away.
    CHECK_EQ(F.show_code_count, 1);
    uint8_t pk[32];
    device_pk(pk);
    char otp[9], fp[CODE_PAIRING_FINGERPRINT_LEN], link[CODE_PAIRING_MAX_LINK];
    otp_at(counter_now(), otp);
    code_pairing_link(&cfg, pk, otp, link, sizeof(link));
    CHECK_STR(F.shown_link, link);
    fingerprint_now(fp);
    CHECK_STR(F.shown_fp, fp);
    CHECK_EQ(F.shown_remaining, 600);

    code_pairing_state_t st;
    run_polls(&cp, 2, &st);
    CHECK_EQ(st, CODE_PAIRING_WAITING);
    CHECK_EQ(F.requests[nth_poll(0)].at_ms, T0 + 5000);  // 5 s, then every interval
    CHECK_EQ(F.requests[nth_poll(1)].at_ms, T0 + 10000);
    check_poll_body(nth_poll(0), NULL, true);
    check_poll_body(nth_poll(1), NULL, true);
    CHECK(F.show_code_count >= 2);  // a new code every 10 s

    // The person scans the code on screen; the app drops the payload.
    app_drop(FULL_PAYLOAD);
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    CHECK_EQ(F.polls, 3);
    // Vetted before saving: the binding refresh with the payload's tokens,
    // then fetch_vms with the pair it returned, which is what gets saved.
    CHECK_EQ(F.bind_calls, 1);
    CHECK_STR(F.bound_with, "ACCESS-SECRET");
    CHECK_EQ(F.verify_calls, 1);
    CHECK_STR(F.verified_with, "ACCESS-SECRET-bound");
    CHECK_EQ(F.save_count, 1);
    CHECK_STR(F.saved_access, "ACCESS-SECRET-bound");
    CHECK_STR(F.saved_refresh, "REFRESH-SECRET-bound");
    CHECK_STR(F.saved_device, NODE);
    CHECK_STR(F.saved_api, "https://api.example.test");
    CHECK(F.saved_noise_null);
    CHECK_STR(F.saved_user, "person");
    // The ack, with the code the drop was filed under.
    int ack = F.request_count - 1;
    CHECK(is_path(ack, "/device_drop/ack"));
    cJSON *a = request_json(ack);
    CHECK_EQ(field_count(a), 4);
    CHECK_STR(jstr(a, "node_id"), NODE);
    CHECK_STR(jstr(a, "key_fingerprint"), fp);
    CHECK_STR(jstr(a, "otp"), F.drops[0].otp);
    CHECK_STR(jstr(a, "ack_nonce"), "AckNonceSECRET0123456w");
    cJSON_Delete(a);
    CHECK(F.drops[0].acked);
    // Then the keys are deleted.
    CHECK(!NVS.have_keys);
    CHECK_EQ(NVS.erased, 1);
    CHECK_EQ(F.states[0], CODE_PAIRING_WAITING);
    CHECK_EQ(F.states[1], CODE_PAIRING_PAIRED);
    CHECK_EQ(F.state_count, 2);
    CHECK_EQ(code_pairing_step(&cp, &st), CODE_PAIRING_NO_STEP);
    check_no_secrets_logged();
}

static void scenario_pending_then_drop(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    code_pairing_state_t st;
    F.server_interval = 7;  // pending answers carry an interval
    run_polls(&cp, 3, &st);
    CHECK_EQ(F.requests[nth_poll(1)].at_ms - F.requests[nth_poll(0)].at_ms, 7000);
    CHECK_EQ(F.requests[nth_poll(2)].at_ms - F.requests[nth_poll(1)].at_ms, 7000);
    app_drop(MIN_PAYLOAD);
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    CHECK_EQ(F.acks, 0);  // no ack_nonce, no ack
    CHECK_STR(F.saved_api, "https://api.example.test");  // the API root code pairing used
    CHECK(F.saved_noise_null);
    CHECK(F.saved_user_null);
    check_no_secrets_logged();
}

static void scenario_stale_code(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    code_pairing_state_t st;
    F.now += 70000;  // a minute and more since the first code
    // Filed under a code from 60 seconds ago: never presented again.
    app_drop_as(6, MIN_PAYLOAD, NULL, NULL);
    run_polls(&cp, 10, &st);
    CHECK_EQ(st, CODE_PAIRING_WAITING);
    CHECK_EQ(F.save_count, 0);
    // 40 seconds old still is (the next poll comes within 10 s).
    app_drop_as(4, MIN_PAYLOAD, NULL, NULL);
    run_polls(&cp, 1, &st);
    run(&cp, 5, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    check_no_secrets_logged();
}

// E-paper: a 45 s step. The QR code is redrawn once a step, a poll carries the
// codes of the last three steps, and older codes are never presented.
#define SLOW_STEP_MS 45000u

static void slow_drop(int age) {
    app_drop_as(0, MIN_PAYLOAD, NULL, NULL);
    otp_at(F.now / SLOW_STEP_MS - (uint64_t)age, F.drops[F.drop_count - 1].otp);
}

static void scenario_slow_step(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    cfg.step_s = SLOW_STEP_MS / 1000u;
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    code_pairing_state_t st;
    // T0 is 35 s before a step boundary: 90 s cross two.
    run_until(&cp, 1000, T0 + 90000, &st);
    CHECK_EQ(st, CODE_PAIRING_WAITING);
    CHECK_EQ(F.show_code_count, 3);
    char otp[9], want[16];
    otp_at(F.now / SLOW_STEP_MS, otp);
    snprintf(want, sizeof(want), "&o=%s&", otp);
    CHECK(strstr(F.shown_link, want));
    CHECK(strstr(F.shown_link, "&s=45"));

    run_polls(&cp, 1, &st);
    cJSON *poll = request_json(nth_poll(F.polls - 1));
    cJSON *otps = cJSON_GetObjectItemCaseSensitive(poll, "recent_otps");
    int n = 0;
    for (cJSON *o = otps ? otps->child : NULL; o; o = o->next, n++) {
        otp_at(F.now / SLOW_STEP_MS - (uint64_t)n, otp);
        CHECK(cJSON_IsString(o) && strcmp(o->valuestring, otp) == 0);
    }
    CHECK_EQ(n, 3);
    cJSON_Delete(poll);

    // Three steps old: never presented.
    slow_drop(3);
    run_polls(&cp, 3, &st);
    CHECK_EQ(st, CODE_PAIRING_WAITING);
    CHECK_EQ(F.save_count, 0);
    // Two steps old: still good.
    slow_drop(2);
    run_polls(&cp, 1, &st);
    run(&cp, 5, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    check_no_secrets_logged();
}

static void scenario_wrong_fingerprint_or_code(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    app_drop_as(0, MIN_PAYLOAD, "0000000000000000", NULL);
    CHECK(F.drop_count == 1);
    // A code the gadget never showed.
    app_drop_as(0, MIN_PAYLOAD, NULL, NULL);
    snprintf(F.drops[1].otp, sizeof(F.drops[1].otp), "ZZZZZZZZ");
    code_pairing_state_t st;
    run_polls(&cp, 5, &st);
    CHECK_EQ(st, CODE_PAIRING_WAITING);
    CHECK_EQ(F.save_count, 0);
}

static void scenario_junk_ignored(void) {
    uint8_t pk[32], other_sk[32], other_pk[32];
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    device_pk(pk);
    for (int i = 0; i < 32; i++) other_sk[i] = (uint8_t)(0x11 * (i + 1));
    CHECK(F.ops->x25519(NULL, other_sk, BASEPOINT, other_pk));

    // Each is ignored, and polling goes on: anyone who saw the QR code can
    // drop something.
    char *junk[] = {
        seal_json(pk, NODE, FULL_PAYLOAD, true),                 // tampered
        seal_json(pk, "homelink-other1", FULL_PAYLOAD, false),   // another node id
        seal_json(other_pk, NODE, FULL_PAYLOAD, false),          // another key
        seal_json(pk, NODE, "{\"action\":\"provision\",\"access_token\":\"a\","
                            "\"refresh_token\":\"r\"}", false),
        seal_json(pk, NODE, "{\"action\":\"provision_v2\",\"access_token\":\"ACCESS-SECRET\"}",
                  false),
        seal_json(pk, NODE, "{\"action\":\"provision_v2\",\"access_token\":\"\","
                            "\"refresh_token\":\"r\"}", false),
        seal_json(pk, NODE, "not json at all", false),
        seal_json(pk, NODE, "[\"provision_v2\"]", false),
        seal_json(pk, NODE, "", false),
        xstrdup("{\"v\":2,\"enc\":\"AAAA\",\"ct\":\"AAAA\"}"),
        xstrdup("{\"v\":1,\"enc\":\"AAAA\",\"ct\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}"),
        xstrdup("\"x\""),
    };
    size_t count = sizeof(junk) / sizeof(junk[0]);
    for (size_t i = 0; i < count; i++) {
        size_t n = strlen(junk[i]) + 64;
        char *body = malloc(n);
        CHECK(body);
        snprintf(body, n, "{\"sealed\":%s,\"otp\":\"ABCDEFGH\"}", junk[i]);
        free(junk[i]);
        push_owned(200, body);
    }
    push(200, "{}");  // no sealed at all
    code_pairing_state_t st;
    run_polls(&cp, (int)count + 1, &st);
    CHECK_EQ(st, CODE_PAIRING_WAITING);
    CHECK_EQ(F.save_count, 0);
    CHECK_EQ(F.bind_calls, 0);
    CHECK(NVS.have_keys);
    // Every ignored drop waits the interval before the next poll.
    CHECK_EQ(F.requests[nth_poll(1)].at_ms - F.requests[nth_poll(0)].at_ms, 5000);

    // Junk filed under the code on screen: that code is left out of later
    // polls, so it can't shadow the real drop, which the app files under the
    // next code.
    F.drop_count = 0;
    app_drop_as(0, "{\"action\":\"provision\"}", NULL, NULL);
    char junk_otp[16];
    snprintf(junk_otp, sizeof(junk_otp), "%s", F.drops[0].otp);
    run_polls(&cp, 1, &st);
    int junk_poll = F.request_count - 1;
    CHECK(poll_presents(junk_poll, junk_otp));
    run_polls(&cp, 1, &st);
    CHECK(!poll_presents(F.request_count - 1, junk_otp));
    check_poll_body_skipping(F.request_count - 1, NULL, true, junk_otp);
    F.now += 10000;
    app_drop(FULL_PAYLOAD);
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    CHECK_EQ(F.save_count, 1);
    check_no_secrets_logged();
}

static void scenario_binding_refresh(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_state_t st;
    // The SDK token refused (limit, invalid, revoked): stay unpaired and stop;
    // nothing saved, the keys stay.
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    app_drop(FULL_PAYLOAD);
    F.bind_results[0] = CODE_PAIRING_RESULT_SDK_REFUSED;
    F.bind_scripted = 1;
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_ERROR);
    CHECK_STR(code_pairing_last_problem(&cp), "sdkTokenRefused");
    CHECK_EQ(F.bind_calls, 1);
    CHECK_EQ(F.verify_calls, 0);
    CHECK_EQ(F.save_count, 0);
    CHECK_EQ(F.acks, 0);
    CHECK(NVS.have_keys);
    int requests = F.request_count;
    CHECK_EQ(code_pairing_step(&cp, &st), CODE_PAIRING_NO_STEP);
    CHECK_EQ(F.request_count, requests);
    check_no_secrets_logged();

    // 401/403: the tokens aren't real. Ignore the drop, leave its code out,
    // keep polling; the real drop then pairs.
    fake_reset();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    app_drop(MIN_PAYLOAD);
    char fake_otp[16];
    snprintf(fake_otp, sizeof(fake_otp), "%s", F.drops[0].otp);
    F.bind_results[0] = CODE_PAIRING_RESULT_REJECTED;
    F.bind_scripted = 1;
    run_polls(&cp, 2, &st);
    CHECK_EQ(st, CODE_PAIRING_WAITING);
    CHECK_EQ(F.save_count, 0);
    CHECK_EQ(F.verify_calls, 0);
    CHECK(!poll_presents(F.request_count - 1, fake_otp));
    F.now += 10000;
    app_drop(FULL_PAYLOAD);
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    CHECK_EQ(F.save_count, 1);

    // No verdict: retry binding before verification or storage.
    fake_reset();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    app_drop(MIN_PAYLOAD);
    F.bind_results[0] = CODE_PAIRING_RESULT_RETRY;
    F.bind_scripted = 1;
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    CHECK_EQ(F.bind_calls, 2);
    CHECK_STR(F.verified_with, "ACCESS-SECRET-bound");
    CHECK_STR(F.saved_access, "ACCESS-SECRET-bound");

    // No SDK token: no binding refresh, and none in the poll.
    fake_reset();
    cfg.sdk_token = NULL;
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    run_polls(&cp, 1, &st);
    check_poll_body(nth_poll(0), NULL, false);
    app_drop(MIN_PAYLOAD);
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    CHECK_EQ(F.bind_calls, 0);
    CHECK_STR(F.saved_access, "ACCESS-SECRET");
}

static void scenario_slow_down(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    push(400, "{\"type\":\"slow_down\",\"interval\":12}");
    push(400, "{\"type\":\"authorization_pending\"}");
    push(400, "{\"type\":\"slow_down\"}");  // no interval: +5
    push(400, "{\"type\":\"authorization_pending\"}");
    push(400, "{\"type\":\"slow_down\",\"interval\":3}");  // never faster
    push(400, "{\"type\":\"authorization_pending\"}");
    code_pairing_state_t st;
    run_polls(&cp, 7, &st);
    static const uint32_t want[] = {12000, 12000, 17000, 17000, 17000, 17000};
    for (int i = 0; i < 6; i++) {
        CHECK_EQ(F.requests[nth_poll(i + 1)].at_ms - F.requests[nth_poll(i)].at_ms, want[i]);
    }
    CHECK_EQ(st, CODE_PAIRING_WAITING);
}

static void scenario_rate_limited(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    push_retry_after(429, "{\"type\":\"rateLimited\"}", 90);
    push(429, "{\"type\":\"rateLimited\"}");  // no Retry-After: 60 s
    push_retry_after(429, "{\"type\":\"rateLimited\"}", 1);  // never under the interval
    code_pairing_state_t st;
    run_polls(&cp, 4, &st);
    CHECK_EQ(F.requests[nth_poll(1)].at_ms - F.requests[nth_poll(0)].at_ms, 90000);
    CHECK_EQ(F.requests[nth_poll(2)].at_ms - F.requests[nth_poll(1)].at_ms, 60000);
    CHECK_EQ(F.requests[nth_poll(3)].at_ms - F.requests[nth_poll(2)].at_ms, 5000);
}

static void scenario_unavailable(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    push(403, "{\"type\":\"devicePairUnavailable\",\"title\":\"off\"}");
    code_pairing_state_t st;
    uint32_t d = run(&cp, 10, &st);
    CHECK_EQ(d, CODE_PAIRING_NO_STEP);
    CHECK_EQ(st, CODE_PAIRING_UNAVAILABLE);
    CHECK_EQ(F.polls, 1);
    CHECK_EQ(code_pairing_step(&cp, &st), CODE_PAIRING_NO_STEP);
    CHECK_EQ(F.polls, 1);

    // invalidRequest: a firmware bug; stop.
    fake_reset();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    push(400, "{\"type\":\"invalidRequest\",\"detail\":\"recent_otps\"}");
    d = run(&cp, 10, &st);
    CHECK_EQ(d, CODE_PAIRING_NO_STEP);
    CHECK_EQ(st, CODE_PAIRING_ERROR);
    CHECK_STR(code_pairing_last_problem(&cp), "invalidRequest");

    // An unknown answer: wait, and keep polling.
    fake_reset();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    push(400, "{\"type\":\"somethingNew\"}");
    run_polls(&cp, 2, &st);
    CHECK_EQ(st, CODE_PAIRING_WAITING);
    CHECK_EQ(F.requests[nth_poll(1)].at_ms - F.requests[nth_poll(0)].at_ms, 30000);
}

static void scenario_transport_backoff(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    // Six failures (2, 4, 8, 16, 32, 60 s; never under the 5 s interval), a
    // 500, then pending (the backoff resets), then one more failure.
    for (int i = 0; i < 6; i++) push_transport_error();
    push(500, NULL);
    push(400, "{\"type\":\"authorization_pending\"}");
    push_transport_error();
    code_pairing_state_t st;
    run_polls(&cp, 10, &st);
    static const uint32_t want[] = {5000, 5000, 8000, 16000, 32000, 60000, 60000, 5000, 5000};
    for (int i = 0; i < 9; i++) {
        CHECK_EQ(F.requests[nth_poll(i + 1)].at_ms - F.requests[nth_poll(i)].at_ms, want[i]);
    }
    CHECK_EQ(st, CODE_PAIRING_WAITING);
    check_no_secrets_logged();
}

static void scenario_network_down(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    F.net = false;
    F.net_up_at = T0 + 45000;
    code_pairing_start(&cp);
    code_pairing_state_t st;
    run_polls(&cp, 1, &st);
    // No poll until the link came up; the QR code kept changing meanwhile.
    CHECK_EQ(F.requests[nth_poll(0)].at_ms, T0 + 45000);
    CHECK(F.net_waits >= 4);
    CHECK(F.show_code_count >= 5);
    check_poll_body(nth_poll(0), NULL, true);
    CHECK(strstr(F.logs, "waiting for the network"));
    // Logged once, not on every wait.
    const char *first = strstr(F.logs, "waiting for the network");
    CHECK(!strstr(first + 1, "waiting for the network"));
}

static void scenario_reboot_keeps_keys(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    code_pairing_state_t st;
    run_polls(&cp, 2, &st);
    char fp[32], link[CODE_PAIRING_MAX_LINK];
    snprintf(fp, sizeof(fp), "%s", F.shown_fp);
    uint64_t at = F.now;
    snprintf(link, sizeof(link), "%s", F.shown_link);

    // Restart: the same storage, a fresh machine; at the same counter it
    // shows a fresh QR code while keeping the recipient key.
    fake_restart();
    F.now = at;
    code_pairing_t cp2;
    code_pairing_init(&cp2, &PLATFORM, &cfg);
    code_pairing_start(&cp2);
    CHECK_EQ(NVS.generated, 1);
    CHECK_STR(F.shown_fp, fp);
    CHECK(strcmp(F.shown_link, link) != 0);
    app_drop(MIN_PAYLOAD);
    run(&cp2, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
}

static void scenario_keys_erased_after_pairing(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    char fp[32];
    snprintf(fp, sizeof(fp), "%s", F.shown_fp);
    app_drop(MIN_PAYLOAD);
    code_pairing_state_t st;
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    CHECK(!NVS.have_keys);
    CHECK_EQ(NVS.erased, 1);
    // Unpaired later: a fresh key and code secret.
    code_pairing_start(&cp);
    CHECK_EQ(NVS.generated, 2);
    CHECK(strcmp(F.shown_fp, fp) != 0);

    // A Bluetooth setup that wins keeps them (they're deleted only when code
    // pairing pairs; a factory reset deletes them too).
    fake_reset();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    code_pairing_stop(&cp);
    CHECK(NVS.have_keys);
}

static void scenario_window(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    code_pairing_state_t st;
    uint32_t d = run(&cp, 1000, &st);
    CHECK_EQ(d, CODE_PAIRING_NO_STEP);
    CHECK_EQ(st, CODE_PAIRING_EXPIRED);
    CHECK_EQ(F.now, T0 + 600000);
    CHECK_EQ(F.polls, 119);  // every 5 s from 5 s to 595 s
    CHECK(F.requests[F.request_count - 1].at_ms < T0 + 600000);
    CHECK(F.show_code_count >= 60);
    CHECK_EQ(F.shown_remaining, 10);  // the last code: 10 s left
    CHECK_EQ(code_pairing_step(&cp, &st), CODE_PAIRING_NO_STEP);
    // A drop after the window is never fetched.
    app_drop(MIN_PAYLOAD);
    F.now += 5000;
    CHECK_EQ(code_pairing_step(&cp, &st), CODE_PAIRING_NO_STEP);
    CHECK_EQ(F.save_count, 0);
    // Asked again (a button): another 10 minutes, same keys.
    code_pairing_start(&cp);
    CHECK_EQ(code_pairing_state(&cp), CODE_PAIRING_WAITING);
    CHECK_EQ(NVS.generated, 1);
    run_polls(&cp, 1, &st);
    CHECK_EQ(F.save_count, 0);  // previous window's drop must not revive
    app_drop(MIN_PAYLOAD);     // a new scan of the fresh code
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);

    // A shorter window, configured.
    fake_reset();
    cfg.window_s = 60;
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    run(&cp, 1000, &st);
    CHECK_EQ(F.now, T0 + 60000);
    CHECK_EQ(st, CODE_PAIRING_EXPIRED);
}

static void scenario_verify(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    cfg.sdk_token = NULL;
    code_pairing_state_t st;
    // fetch_vms gives no verdict: keep pending tokens in RAM and retry.
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    app_drop(MIN_PAYLOAD);
    F.verify_results[0] = CODE_PAIRING_RESULT_RETRY;
    F.verify_count = 1;
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    CHECK_EQ(F.verify_calls, 2);
    CHECK_EQ(F.polls, 1);
    CHECK_EQ(F.save_count, 1);

    // 401/403: the tokens aren't real. Ignored, its code left out, still
    // pairing with the same keys.
    fake_reset();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    app_drop(MIN_PAYLOAD);
    char fake_otp[16];
    snprintf(fake_otp, sizeof(fake_otp), "%s", F.drops[0].otp);
    F.verify_results[0] = CODE_PAIRING_RESULT_REJECTED;
    F.verify_count = 1;
    run_polls(&cp, 3, &st);
    CHECK_EQ(st, CODE_PAIRING_WAITING);
    CHECK(NVS.have_keys);
    CHECK_EQ(F.save_count, 0);
    CHECK_EQ(F.verify_calls, 1);  // not fetched again
    CHECK(!poll_presents(F.request_count - 1, fake_otp));
    check_no_secrets_logged();

    // Saving fails: an error.
    fake_reset();
    F.save_ok = false;
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    app_drop(MIN_PAYLOAD);
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_ERROR);
    CHECK_STR(code_pairing_last_problem(&cp), "storage");
    CHECK(NVS.have_keys);

    // No keys: an error, with no request.
    fake_reset();
    F.keys_ok = false;
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    CHECK_EQ(code_pairing_state(&cp), CODE_PAIRING_ERROR);
    CHECK_EQ(code_pairing_step(&cp, &st), CODE_PAIRING_NO_STEP);
    CHECK_EQ(F.request_count, 0);
}

static void scenario_security(void) {
    code_pairing_t cp;
    code_pairing_state_t st;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_platform_t p = PLATFORM;
    p.verify_tokens = NULL;
    code_pairing_init(&cp, &p, &cfg);
    code_pairing_start(&cp);
    CHECK_STR(code_pairing_last_problem(&cp), "tokenVerifier");
    CHECK_EQ(F.polls, 0);
    p = PLATFORM;
    p.bind_tokens = NULL;
    code_pairing_init(&cp, &p, &cfg);
    code_pairing_start(&cp);
    CHECK_STR(code_pairing_last_problem(&cp), "tokenVerifier");
    p = PLATFORM;
    p.random_bytes = NULL;
    code_pairing_init(&cp, &p, &cfg);
    code_pairing_start(&cp);
    CHECK_STR(code_pairing_last_problem(&cp), "randomSource");
    CHECK_EQ(F.save_count, 0);

    // A server response cannot revive an old, unrequested code.
    fake_reset();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    app_drop_as(7, MIN_PAYLOAD, NULL, NULL);
    size_t n = strlen(F.drops[0].sealed) + 64;
    char *answer = malloc(n);
    CHECK(answer);
    snprintf(answer, n, "{\"sealed\":%s,\"otp\":\"%s\"}", F.drops[0].sealed, F.drops[0].otp);
    push_owned(200, answer);
    run_polls(&cp, 2, &st);
    CHECK_EQ(F.bind_calls, 0);
    CHECK_EQ(F.save_count, 0);
    code_pairing_stop(&cp);

    // Binding and verification outages expire without saving or acknowledging.
    for (int verify = 0; verify < 2; verify++) {
        fake_reset();
        cfg.window_s = 10;
        code_pairing_init(&cp, &PLATFORM, &cfg);
        code_pairing_start(&cp);
        app_drop(FULL_PAYLOAD);
        if (verify) {
            F.verify_results[0] = CODE_PAIRING_RESULT_RETRY;
            F.verify_count = 1;
        } else {
            F.bind_results[0] = CODE_PAIRING_RESULT_RETRY;
            F.bind_scripted = 1;
        }
        run(&cp, 100, &st);
        CHECK_EQ(st, CODE_PAIRING_EXPIRED);
        CHECK_EQ(F.save_count, 0);
        CHECK_EQ(F.acks, 0);
        CHECK(NVS.have_keys);
        CHECK(cp.access_token == NULL && cp.refresh_token == NULL);
        if (verify) CHECK_STR(F.verified_with, "ACCESS-SECRET-bound");
        else CHECK_EQ(F.verify_calls, 0);
    }

    // Retain rotated tokens across verification retries, without a second bind.
    fake_reset();
    cfg.window_s = 60;
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    app_drop(FULL_PAYLOAD);
    F.verify_results[0] = CODE_PAIRING_RESULT_RETRY;
    F.verify_count = 1;
    run(&cp, 100, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    CHECK_EQ(F.bind_calls, 1);
    CHECK_EQ(F.verify_calls, 2);
    CHECK_EQ(F.polls, 1);
    CHECK_STR(F.verified_with, "ACCESS-SECRET-bound");
    CHECK_STR(F.saved_api, cfg.base_url);
    CHECK(F.saved_noise_null);
}

static void scenario_claim_code(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    cfg.claim_code = "CLAIMCOD";
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    code_pairing_state_t st;
    run_polls(&cp, 1, &st);
    check_poll_body(nth_poll(0), "CLAIMCOD", true);
    // A drop filed under the sticker's code, at any time.
    app_drop_as(0, MIN_PAYLOAD, NULL, NULL);
    snprintf(F.drops[0].otp, sizeof(F.drops[0].otp), "CLAIMCOD");
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    check_no_secrets_logged();
}

static void scenario_early_counter(void) {
    // At counter 2 there are only three codes to present.
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    F.now = 20000;
    code_pairing_start(&cp);
    push(400, "{\"type\":\"authorization_pending\"}");
    code_pairing_state_t st;
    run_polls(&cp, 1, &st);
    cJSON *poll = request_json(nth_poll(0));
    cJSON *otps = cJSON_GetObjectItemCaseSensitive(poll, "recent_otps");
    int n = 0;
    for (cJSON *o = otps->child; o; o = o->next) n++;
    CHECK_EQ(n, 3);  // c = 2, 1, 0
    cJSON_Delete(poll);
}

static void scenario_stop(void) {
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    code_pairing_state_t st;
    run_polls(&cp, 1, &st);
    // Bluetooth setup won.
    code_pairing_stop(&cp);
    CHECK_EQ(code_pairing_state(&cp), CODE_PAIRING_IDLE);
    CHECK_EQ(code_pairing_step(&cp, NULL), CODE_PAIRING_NO_STEP);
    CHECK_EQ(F.polls, 1);
    // A second start while running does nothing.
    code_pairing_start(&cp);
    int shown = F.show_code_count;
    code_pairing_start(&cp);
    CHECK_EQ(F.show_code_count, shown);
    CHECK_EQ(code_pairing_state(&cp), CODE_PAIRING_WAITING);
}

static void hex(const uint8_t *d, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", d[i]);
}

static void scenario_encodings(void) {
    // RFC 4648 test vectors, in base64url without padding.
    static const struct {
        const char *in;
        const char *out;
    } v[] = {
        {"", ""}, {"f", "Zg"}, {"fo", "Zm8"}, {"foo", "Zm9v"},
        {"foob", "Zm9vYg"}, {"fooba", "Zm9vYmE"}, {"foobar", "Zm9vYmFy"},
    };
    char out[96];
    uint8_t dec[64];
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        size_t n = strlen(v[i].in);
        CHECK_EQ(code_pairing_b64url_encode((const uint8_t *)v[i].in, n, out, sizeof(out)),
                 strlen(v[i].out));
        CHECK_STR(out, v[i].out);
        CHECK_EQ(code_pairing_b64url_decode(v[i].out, dec, sizeof(dec)), (int)n);
        CHECK(memcmp(dec, v[i].in, n) == 0);
    }
    const uint8_t url_bytes[] = {0xfb, 0xff, 0xbf};
    CHECK_EQ(code_pairing_b64url_encode(url_bytes, 3, out, sizeof(out)), 4);
    CHECK_STR(out, "-_-_");
    CHECK_EQ(code_pairing_b64url_decode("Zm9vYg==", dec, sizeof(dec)), 4);
    CHECK_EQ(code_pairing_b64url_decode("Zm9v+g", dec, sizeof(dec)), -1);
    CHECK_EQ(code_pairing_b64url_decode("Z", dec, sizeof(dec)), -1);
    CHECK_EQ(code_pairing_b64url_encode((const uint8_t *)"foo", 3, out, 4), 0);
    CHECK_EQ(code_pairing_b64url_decode("Zm9vYmFy", dec, 5), -1);

    // SHA-256 (FIPS 180-2), HMAC-SHA256 (RFC 4231 case 2), HKDF (RFC 5869 case 1).
    uint8_t d[64];
    char h[129];
    muse_hpke_sha256((const uint8_t *)"abc", 3, d);
    hex(d, 32, h);
    CHECK_STR(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    muse_hpke_sha256((const uint8_t *)two, strlen(two), d);
    hex(d, 32, h);
    CHECK_STR(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    muse_hpke_sha256((const uint8_t *)"", 0, d);
    hex(d, 32, h);
    CHECK_STR(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    muse_hpke_hmac_sha256((const uint8_t *)"Jefe", 4,
                          (const uint8_t *)"what do ya want for nothing?", 28, d);
    hex(d, 32, h);
    CHECK_STR(h, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    uint8_t ikm[22], salt[13], info[10], prk[32], okm[42];
    memset(ikm, 0x0b, sizeof(ikm));
    for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
    for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
    muse_hpke_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
    hex(prk, 32, h);
    CHECK_STR(h, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    CHECK(muse_hpke_hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm)));
    hex(okm, 42, h);
    CHECK_STR(h, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                 "34007208d5b887185865");

    // Fingerprint: 16 hex characters of SHA-256 over the key.
    uint8_t pk[32];
    for (int i = 0; i < 32; i++) pk[i] = (uint8_t)i;
    char fp[CODE_PAIRING_FINGERPRINT_LEN];
    code_pairing_fingerprint(pk, fp);
    CHECK_STR(fp, "630dcd2966c43366");

    // HPKE round trip with the fake primitives, and what must not open.
    uint8_t sk[32], rpk[32], enc[32], ct[64], pt[64];
    for (int i = 0; i < 32; i++) sk[i] = (uint8_t)(i + 1);
    memcpy(C.recipient_sk, sk, 32);
    CHECK(fake_x25519(NULL, sk, BASEPOINT, rpk));
    CHECK(muse_hpke_seal(&FAKE_OPS, rpk, (const uint8_t *)"i", 1, (const uint8_t *)"a", 1,
                         (const uint8_t *)"hello", 5, enc, ct));
    CHECK(muse_hpke_open(&FAKE_OPS, rpk, enc, (const uint8_t *)"i", 1,
                         (const uint8_t *)"a", 1, ct, 21, pt));
    CHECK(memcmp(pt, "hello", 5) == 0);
    CHECK(!muse_hpke_open(&FAKE_OPS, rpk, enc, (const uint8_t *)"j", 1,
                          (const uint8_t *)"a", 1, ct, 21, pt));
    CHECK(!muse_hpke_open(&FAKE_OPS, rpk, enc, (const uint8_t *)"i", 1,
                          (const uint8_t *)"b", 1, ct, 21, pt));
    CHECK(!muse_hpke_open(&FAKE_OPS, rpk, enc, (const uint8_t *)"i", 1,
                          (const uint8_t *)"a", 1, ct, 15, pt));
}

// ---- Real crypto: vectors from independent implementations ------------------------

#ifdef HAVE_LIBCRYPTO
static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    CHECK(f);
    CHECK(fseek(f, 0, SEEK_END) == 0);
    long n = ftell(f);
    CHECK(n > 0);
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    CHECK(buf);
    CHECK(fread(buf, 1, (size_t)n, f) == (size_t)n);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static void unhex(const char *s, uint8_t *out, size_t n) {
    CHECK(s && strlen(s) == 2 * n);
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        CHECK(sscanf(s + 2 * i, "%2x", &v) == 1);
        out[i] = (uint8_t)v;
    }
}
#endif

static const char *s_vectors_path;

static void scenario_hpke_vectors(void) {
#ifndef HAVE_LIBCRYPTO
    printf("skip hpke_vectors: built without libcrypto\n");
#else
    CHECK(s_vectors_path);
    char *text = read_file(s_vectors_path);
    cJSON *vec = cJSON_Parse(text);
    free(text);
    CHECK(vec);

    // X25519 itself (RFC 7748 section 5.2).
    cJSON *x = cJSON_GetObjectItemCaseSensitive(vec, "x25519");
    uint8_t scalar[32], u[32], want[32], got[32];
    unhex(jstr(x, "scalar"), scalar, 32);
    unhex(jstr(x, "u"), u, 32);
    unhex(jstr(x, "out"), want, 32);
    CHECK(real_x25519(NULL, scalar, u, got));
    CHECK(memcmp(got, want, 32) == 0);

    // One-time codes.
    uint8_t secret[32];
    unhex(jstr(vec, "otp_secret"), secret, 32);
    cJSON *otps = cJSON_GetObjectItemCaseSensitive(vec, "otps");
    int checked = 0;
    for (cJSON *o = otps ? otps->child : NULL; o; o = o->next, checked++) {
        char code[9];
        code_pairing_otp(secret, strtoull(o->string, NULL, 10), code);
        CHECK_STR(code, o->valuestring);
    }
    CHECK(checked >= 4);

    // The gadget's key, from the fixture.
    F.ops = &REAL_OPS;
    PLATFORM.hpke = &REAL_OPS;
    NVS.have_keys = true;
    NVS.generated = 1;
    unhex(jstr(vec, "device_sk"), NVS.sk, 32);
    for (int i = 0; i < 32; i++) F.secret[i] = (uint8_t)i;
    memcpy(C.recipient_sk, NVS.sk, 32);
    uint8_t pk[32];
    device_pk(pk);
    char pk_b64[48], fp[CODE_PAIRING_FINGERPRINT_LEN];
    code_pairing_b64url_encode(pk, 32, pk_b64, sizeof(pk_b64));
    CHECK_STR(pk_b64, jstr(vec, "device_pk"));
    code_pairing_fingerprint(pk, fp);
    CHECK_STR(fp, jstr(vec, "fingerprint"));

    // Opening what an independent HPKE implementation sealed, and sealing it
    // again with the same ephemeral key.
    cJSON *payloads = cJSON_GetObjectItemCaseSensitive(vec, "payloads");
    int opened = 0;
    for (cJSON *p = payloads ? payloads->child : NULL; p; p = p->next) {
        uint8_t enc[32], ct[1024], pt[1024], sk_e[32], enc2[32], ct2[1024];
        CHECK_EQ(code_pairing_b64url_decode(jstr(p, "enc"), enc, 32), 32);
        int n = code_pairing_b64url_decode(jstr(p, "ct"), ct, sizeof(ct));
        CHECK(n > 16);
        const char *info = jstr(p, "info"), *aad = jstr(p, "aad");
        CHECK(muse_hpke_open(&REAL_OPS, pk, enc, (const uint8_t *)info, strlen(info),
                             (const uint8_t *)aad, strlen(aad), ct, (size_t)n, pt));
        CHECK_EQ((size_t)n - 16, strlen(jstr(p, "pt")));
        CHECK(memcmp(pt, jstr(p, "pt"), (size_t)n - 16) == 0);
        unhex(jstr(p, "sk_e"), sk_e, 32);
        C.rand_fixed = sk_e;
        CHECK(muse_hpke_seal(&REAL_OPS, pk, (const uint8_t *)info, strlen(info),
                             (const uint8_t *)aad, strlen(aad), pt, (size_t)n - 16, enc2, ct2));
        C.rand_fixed = NULL;
        CHECK(memcmp(enc2, enc, 32) == 0);
        CHECK(memcmp(ct2, ct, (size_t)n) == 0);
        ct[3] ^= 0x80;
        CHECK(!muse_hpke_open(&REAL_OPS, pk, enc, (const uint8_t *)info, strlen(info),
                              (const uint8_t *)aad, strlen(aad), ct, (size_t)n, pt));
        opened++;
    }
    CHECK_EQ(opened, 2);

    // Sealing to another key, as the independent implementation does.
    cJSON *sv = cJSON_GetObjectItemCaseSensitive(vec, "seal");
    uint8_t pk_r[32], sk_e[32], enc[32], ct[256];
    CHECK_EQ(code_pairing_b64url_decode(jstr(sv, "pk_r"), pk_r, 32), 32);
    unhex(jstr(sv, "sk_e"), sk_e, 32);
    const char *spt = jstr(sv, "pt"), *sinfo = jstr(sv, "info"), *saad = jstr(sv, "aad");
    C.rand_fixed = sk_e;
    CHECK(muse_hpke_seal(&REAL_OPS, pk_r, (const uint8_t *)sinfo, strlen(sinfo),
                         (const uint8_t *)saad, strlen(saad), (const uint8_t *)spt,
                         strlen(spt), enc, ct));
    C.rand_fixed = NULL;
    char b64[400];
    code_pairing_b64url_encode(enc, 32, b64, sizeof(b64));
    CHECK_STR(b64, jstr(sv, "enc"));
    code_pairing_b64url_encode(ct, strlen(spt) + 16, b64, sizeof(b64));
    CHECK_STR(b64, jstr(sv, "ct"));

    // End to end with real crypto: the vector's payload, dropped under the
    // code on screen, opens on the gadget.
    CHECK_STR(jstr(vec, "node_id"), NODE);
    code_pairing_t cp;
    code_pairing_config_t cfg = default_cfg();
    code_pairing_init(&cp, &PLATFORM, &cfg);
    code_pairing_start(&cp);
    cJSON *first = payloads->child;
    drop_t *d = &F.drops[F.drop_count++];
    snprintf(d->node_id, sizeof(d->node_id), "%s", NODE);
    snprintf(d->fp, sizeof(d->fp), "%s", fp);
    otp_at(counter_now(), d->otp);
    size_t n = strlen(jstr(first, "enc")) + strlen(jstr(first, "ct")) + 64;
    d->sealed = malloc(n);
    CHECK(d->sealed);
    snprintf(d->sealed, n, "{\"v\":1,\"enc\":\"%s\",\"ct\":\"%s\"}", jstr(first, "enc"),
             jstr(first, "ct"));
    cJSON *first_pt = cJSON_Parse(jstr(first, "pt"));
    CHECK(first_pt);
    snprintf(d->nonce, sizeof(d->nonce), "%s", jstr(first_pt, "ack_nonce"));
    CHECK_EQ(strlen(d->nonce), 22);  // 16 random bytes, base64url
    cJSON_Delete(first_pt);
    d->filed_at = F.now;
    code_pairing_state_t st;
    run(&cp, 20, &st);
    CHECK_EQ(st, CODE_PAIRING_PAIRED);
    CHECK_STR(F.bound_with, "ACCESS-SECRET-hpke");
    CHECK_STR(F.saved_access, "ACCESS-SECRET-hpke-bound");
    CHECK_STR(F.saved_refresh, "REFRESH-SECRET-hpke-bound");
    CHECK_STR(F.saved_user, "person");
    CHECK(d->acked);
    cJSON_Delete(vec);
#endif
}

static void scenario_state_names(void) {
    CHECK_STR(code_pairing_state_name(CODE_PAIRING_WAITING), "waiting");
    CHECK_STR(code_pairing_state_name(CODE_PAIRING_UNAVAILABLE), "unavailable");
}

static const struct {
    const char *name;
    void (*fn)(void);
} SCENARIOS[] = {
    {"otp_vectors", scenario_otp_vectors},
    {"link", scenario_link},
    {"happy_path", scenario_happy_path},
    {"pending_then_drop", scenario_pending_then_drop},
    {"stale_code", scenario_stale_code},
    {"slow_step", scenario_slow_step},
    {"wrong_fingerprint_or_code", scenario_wrong_fingerprint_or_code},
    {"junk_ignored", scenario_junk_ignored},
    {"binding_refresh", scenario_binding_refresh},
    {"slow_down", scenario_slow_down},
    {"rate_limited", scenario_rate_limited},
    {"unavailable", scenario_unavailable},
    {"transport_backoff", scenario_transport_backoff},
    {"network_down", scenario_network_down},
    {"reboot_keeps_keys", scenario_reboot_keeps_keys},
    {"keys_erased_after_pairing", scenario_keys_erased_after_pairing},
    {"window", scenario_window},
    {"verify", scenario_verify},
    {"security", scenario_security},
    {"claim_code", scenario_claim_code},
    {"early_counter", scenario_early_counter},
    {"stop", scenario_stop},
    {"encodings", scenario_encodings},
    {"hpke_vectors", scenario_hpke_vectors},
    {"state_names", scenario_state_names},
};

int main(int argc, char **argv) {
    size_t count = sizeof(SCENARIOS) / sizeof(SCENARIOS[0]);
    if (argc == 2 && strcmp(argv[1], "--list") == 0) {
        for (size_t i = 0; i < count; i++) printf("%s\n", SCENARIOS[i].name);
        return 0;
    }
    if (argc >= 3) s_vectors_path = argv[2];
    int ran = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    for (size_t i = 0; i < count; i++) {
        if (argc >= 2 && strcmp(argv[1], "all") != 0 && strcmp(argv[1], SCENARIOS[i].name) != 0) {
            continue;
        }
        // Once untimed: the C library allocates some things on first use.
        fake_reset();
        SCENARIOS[i].fn();
        fake_reset();
#ifdef HEAP_IN_USE
        // A leak check where sanitizers aren't available: everything the
        // machine allocates is freed by the end of a scenario.
        size_t before = HEAP_IN_USE();
#endif
        SCENARIOS[i].fn();
        fake_reset();
#ifdef HEAP_IN_USE
        size_t after = HEAP_IN_USE();
        if (after != before) {
            fprintf(stderr, "%s leaked %zu bytes\n", SCENARIOS[i].name, after - before);
            return 1;
        }
#endif
        printf("ok %s\n", SCENARIOS[i].name);
        ran++;
    }
    if (ran == 0) {
        fprintf(stderr, "no such scenario\n");
        return 2;
    }
    return 0;
}
