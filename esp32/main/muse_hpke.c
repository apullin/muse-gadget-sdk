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

#include "muse_hpke.h"

#include <string.h>

#define NK 16  // AES-128-GCM key
#define NN 12  // AES-128-GCM nonce
#define NH 32  // HKDF-SHA256 output

static const uint8_t KEM_SUITE_ID[] = {'K', 'E', 'M', 0x00, 0x20};
static const uint8_t HPKE_SUITE_ID[] = {'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x01};
static const uint8_t BASEPOINT[MUSE_HPKE_KEY_BYTES] = {9};

static void wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

// ---- SHA-256 (FIPS 180-4) -----------------------------------------------------------

typedef struct {
    uint32_t h[8];
    uint8_t blk[64];
    size_t fill;
    uint64_t total;
} sha256_ctx_t;

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR32(x, n) ((x) >> (n) | (x) << (32 - (n)))

static void sha256_block(uint32_t h[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)blk[4 * i] << 24 | (uint32_t)blk[4 * i + 1] << 16
               | (uint32_t)blk[4 * i + 2] << 8 | blk[4 * i + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], k = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = k + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25))
                      + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22))
                      + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += k;
    wipe(w, sizeof(w));
}

static void sha256_init(sha256_ctx_t *c) {
    static const uint32_t IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, IV, sizeof(IV));
    c->fill = 0;
    c->total = 0;
}

static void sha256_update(sha256_ctx_t *c, const uint8_t *data, size_t len) {
    c->total += len;
    while (len) {
        size_t n = 64 - c->fill < len ? 64 - c->fill : len;
        memcpy(c->blk + c->fill, data, n);
        c->fill += n;
        data += n;
        len -= n;
        if (c->fill == 64) {
            sha256_block(c->h, c->blk);
            c->fill = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    pad = 0;
    while (c->fill != 56) sha256_update(c, &pad, 1);
    uint8_t len_be[8];
    for (int j = 0; j < 8; j++) len_be[j] = (uint8_t)(bits >> (56 - 8 * j));
    sha256_update(c, len_be, 8);
    for (int j = 0; j < 8; j++) {
        out[4 * j] = (uint8_t)(c->h[j] >> 24);
        out[4 * j + 1] = (uint8_t)(c->h[j] >> 16);
        out[4 * j + 2] = (uint8_t)(c->h[j] >> 8);
        out[4 * j + 3] = (uint8_t)c->h[j];
    }
    wipe(c, sizeof(*c));
}

void muse_hpke_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx_t c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

// ---- HMAC-SHA256 and HKDF -----------------------------------------------------------

typedef struct {
    sha256_ctx_t inner;
    uint8_t opad_key[64];
} hmac_ctx_t;

static void hmac_start(hmac_ctx_t *m, const uint8_t *key, size_t key_len) {
    uint8_t k[64] = {0};
    if (key_len > 64) {
        muse_hpke_sha256(key, key_len, k);
    } else if (key_len) {
        memcpy(k, key, key_len);
    }
    uint8_t ipad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        m->opad_key[i] = k[i] ^ 0x5c;
    }
    sha256_init(&m->inner);
    sha256_update(&m->inner, ipad, 64);
    wipe(k, sizeof(k));
    wipe(ipad, sizeof(ipad));
}

static void hmac_update(hmac_ctx_t *m, const uint8_t *data, size_t len) {
    if (len) sha256_update(&m->inner, data, len);
}

static void hmac_finish(hmac_ctx_t *m, uint8_t out[32]) {
    uint8_t inner[32];
    sha256_final(&m->inner, inner);
    sha256_ctx_t outer;
    sha256_init(&outer);
    sha256_update(&outer, m->opad_key, 64);
    sha256_update(&outer, inner, 32);
    sha256_final(&outer, out);
    wipe(inner, sizeof(inner));
    wipe(m, sizeof(*m));
}

void muse_hpke_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                           size_t len, uint8_t out[32]) {
    hmac_ctx_t m;
    hmac_start(&m, key, key_len);
    hmac_update(&m, data, len);
    hmac_finish(&m, out);
}

void muse_hpke_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                            size_t ikm_len, uint8_t prk[32]) {
    // An empty salt is HashLen zero bytes, which HMAC pads the same way.
    muse_hpke_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

bool muse_hpke_hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                           uint8_t *out, size_t len) {
    if (len > 255 * NH) return false;
    uint8_t t[NH];
    size_t t_len = 0;
    for (uint8_t i = 1; len; i++) {
        hmac_ctx_t m;
        hmac_start(&m, prk, NH);
        hmac_update(&m, t, t_len);
        hmac_update(&m, info, info_len);
        hmac_update(&m, &i, 1);
        hmac_finish(&m, t);
        t_len = NH;
        size_t n = len < NH ? len : NH;
        memcpy(out, t, n);
        out += n;
        len -= n;
    }
    wipe(t, sizeof(t));
    return true;
}

// ---- RFC 9180 labeled HKDF ----------------------------------------------------------

static const uint8_t HPKE_V1[] = {'H', 'P', 'K', 'E', '-', 'v', '1'};

// Extract(salt, "HPKE-v1" || suite_id || label || ikm)
static void labeled_extract(const uint8_t *suite_id, size_t suite_len,
                            const uint8_t *salt, size_t salt_len, const char *label,
                            const uint8_t *ikm, size_t ikm_len, uint8_t prk[NH]) {
    hmac_ctx_t m;
    hmac_start(&m, salt, salt_len);
    hmac_update(&m, HPKE_V1, sizeof(HPKE_V1));
    hmac_update(&m, suite_id, suite_len);
    hmac_update(&m, (const uint8_t *)label, strlen(label));
    hmac_update(&m, ikm, ikm_len);
    hmac_finish(&m, prk);
}

// Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L), for
// L <= 32 (one HKDF block is all this suite needs).
static void labeled_expand(const uint8_t *suite_id, size_t suite_len, const uint8_t prk[NH],
                           const char *label, const uint8_t *info, size_t info_len,
                           uint8_t *out, size_t len) {
    uint8_t l2[2] = {(uint8_t)(len >> 8), (uint8_t)len};
    uint8_t one = 1;
    uint8_t t[NH];
    hmac_ctx_t m;
    hmac_start(&m, prk, NH);
    hmac_update(&m, l2, 2);
    hmac_update(&m, HPKE_V1, sizeof(HPKE_V1));
    hmac_update(&m, suite_id, suite_len);
    hmac_update(&m, (const uint8_t *)label, strlen(label));
    hmac_update(&m, info, info_len);
    hmac_update(&m, &one, 1);
    hmac_finish(&m, t);
    memcpy(out, t, len);
    wipe(t, sizeof(t));
}

// DHKEM ExtractAndExpand(dh, enc || pkRm) -> shared_secret.
static void kem_shared_secret(const uint8_t dh[32], const uint8_t enc[32],
                              const uint8_t pk_r[32], uint8_t shared[NH]) {
    uint8_t eae_prk[NH];
    uint8_t kem_context[64];
    memcpy(kem_context, enc, 32);
    memcpy(kem_context + 32, pk_r, 32);
    labeled_extract(KEM_SUITE_ID, sizeof(KEM_SUITE_ID), NULL, 0, "eae_prk", dh, 32, eae_prk);
    labeled_expand(KEM_SUITE_ID, sizeof(KEM_SUITE_ID), eae_prk, "shared_secret",
                   kem_context, sizeof(kem_context), shared, NH);
    wipe(eae_prk, sizeof(eae_prk));
}

// KeySchedule in mode_base with no PSK: the AEAD key and base nonce. A
// single-shot message uses sequence number 0, so its nonce is base_nonce.
static void key_schedule(const uint8_t shared[NH], const uint8_t *info, size_t info_len,
                         uint8_t key[NK], uint8_t nonce[NN]) {
    uint8_t ctx[1 + 2 * NH];
    ctx[0] = 0x00;  // mode_base
    labeled_extract(HPKE_SUITE_ID, sizeof(HPKE_SUITE_ID), NULL, 0, "psk_id_hash",
                    NULL, 0, ctx + 1);
    labeled_extract(HPKE_SUITE_ID, sizeof(HPKE_SUITE_ID), NULL, 0, "info_hash",
                    info, info_len, ctx + 1 + NH);
    uint8_t secret[NH];
    labeled_extract(HPKE_SUITE_ID, sizeof(HPKE_SUITE_ID), shared, NH, "secret",
                    NULL, 0, secret);
    labeled_expand(HPKE_SUITE_ID, sizeof(HPKE_SUITE_ID), secret, "key", ctx, sizeof(ctx),
                   key, NK);
    labeled_expand(HPKE_SUITE_ID, sizeof(HPKE_SUITE_ID), secret, "base_nonce", ctx,
                   sizeof(ctx), nonce, NN);
    wipe(secret, sizeof(secret));
}

// RFC 7748 section 6.1: an all-zero shared secret means a low-order point.
static bool all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

bool muse_hpke_open(const muse_hpke_ops_t *ops, const uint8_t pk_r[32], const uint8_t enc[32],
                    const uint8_t *info, size_t info_len, const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len, uint8_t *pt) {
    if (!ops || !ops->recipient_dh || !ops->aes128gcm_open || ct_len < MUSE_HPKE_TAG_BYTES) {
        return false;
    }
    uint8_t dh[32], shared[NH], key[NK], nonce[NN];
    bool ok = ops->recipient_dh(ops->ctx, enc, dh) && !all_zero(dh, sizeof(dh));
    if (ok) {
        kem_shared_secret(dh, enc, pk_r, shared);
        key_schedule(shared, info, info_len, key, nonce);
        ok = ops->aes128gcm_open(ops->ctx, key, nonce, aad, aad_len, ct, ct_len, pt);
    }
    if (!ok && ct_len > MUSE_HPKE_TAG_BYTES) wipe(pt, ct_len - MUSE_HPKE_TAG_BYTES);
    wipe(dh, sizeof(dh));
    wipe(shared, sizeof(shared));
    wipe(key, sizeof(key));
    wipe(nonce, sizeof(nonce));
    return ok;
}

bool muse_hpke_seal(const muse_hpke_ops_t *ops, const uint8_t pk_r[32], const uint8_t *info,
                    size_t info_len, const uint8_t *aad, size_t aad_len, const uint8_t *pt,
                    size_t pt_len, uint8_t enc[32], uint8_t *ct) {
    if (!ops || !ops->x25519 || !ops->random_bytes || !ops->aes128gcm_seal) return false;
    uint8_t sk_e[32], dh[32], shared[NH], key[NK], nonce[NN];
    bool ok = ops->random_bytes(ops->ctx, sk_e, sizeof(sk_e))
              && ops->x25519(ops->ctx, sk_e, BASEPOINT, enc)
              && ops->x25519(ops->ctx, sk_e, pk_r, dh)
              && !all_zero(dh, sizeof(dh));
    if (ok) {
        kem_shared_secret(dh, enc, pk_r, shared);
        key_schedule(shared, info, info_len, key, nonce);
        ok = ops->aes128gcm_seal(ops->ctx, key, nonce, aad, aad_len, pt, pt_len, ct);
    }
    wipe(sk_e, sizeof(sk_e));
    wipe(dh, sizeof(dh));
    wipe(shared, sizeof(shared));
    wipe(key, sizeof(key));
    wipe(nonce, sizeof(nonce));
    return ok;
}
