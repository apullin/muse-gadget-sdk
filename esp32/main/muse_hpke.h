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

#pragma once

// HPKE (RFC 9180) in base mode, single-shot, for one cipher suite:
// DHKEM(X25519, HKDF-SHA256) 0x0020, HKDF-SHA256 0x0001, AES-128-GCM 0x0001
// (the suite of RFC 9180 appendix A.1). Code pairing receives its tokens
// sealed this way (docs/code-pairing.md).
//
// Portable C11: the key schedule, SHA-256, HMAC and HKDF are here; X25519
// and AES-128-GCM come from the platform through muse_hpke_ops_t (mbedTLS/PSA
// on the device, the host's crypto library or fakes in tests). The
// recipient's private key never passes through this code.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MUSE_HPKE_KEY_BYTES 32   // X25519 keys and the encapsulated key
#define MUSE_HPKE_TAG_BYTES 16   // AES-128-GCM tag, appended to the ciphertext
#define MUSE_HPKE_SHA256_BYTES 32

typedef struct {
    void *ctx;  // passed back to every call
    // X25519(scalar, u) as in RFC 7748 (the scalar is clamped by the
    // function). Used for the sender's ephemeral key when sealing.
    bool (*x25519)(void *ctx, const uint8_t scalar[MUSE_HPKE_KEY_BYTES],
                   const uint8_t u[MUSE_HPKE_KEY_BYTES],
                   uint8_t out[MUSE_HPKE_KEY_BYTES]);
    // X25519 with the recipient's own private key, which stays with the
    // platform. Needed only to open.
    bool (*recipient_dh)(void *ctx, const uint8_t u[MUSE_HPKE_KEY_BYTES],
                         uint8_t out[MUSE_HPKE_KEY_BYTES]);
    // AES-128-GCM with a 12-byte nonce. Seal writes len + 16 bytes
    // (ciphertext, then tag); open takes them and writes ct_len - 16 bytes,
    // returning false if the tag doesn't verify.
    bool (*aes128gcm_seal)(void *ctx, const uint8_t key[16], const uint8_t nonce[12],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t len, uint8_t *ct);
    bool (*aes128gcm_open)(void *ctx, const uint8_t key[16], const uint8_t nonce[12],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len, uint8_t *pt);
    // Cryptographically secure random bytes, for the ephemeral key. Needed
    // only to seal.
    bool (*random_bytes)(void *ctx, uint8_t *out, size_t len);
} muse_hpke_ops_t;

// Opens ct (ciphertext and tag, ct_len >= 16) sealed to pk_r, whose private
// half ops->recipient_dh holds, into pt (ct_len - 16 bytes). False if it
// doesn't open; pt is then zeroed.
bool muse_hpke_open(const muse_hpke_ops_t *ops, const uint8_t pk_r[MUSE_HPKE_KEY_BYTES],
                    const uint8_t enc[MUSE_HPKE_KEY_BYTES],
                    const uint8_t *info, size_t info_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len, uint8_t *pt);

// Seals pt to pk_r with a fresh ephemeral key: enc gets the encapsulated key,
// ct pt_len + 16 bytes.
bool muse_hpke_seal(const muse_hpke_ops_t *ops, const uint8_t pk_r[MUSE_HPKE_KEY_BYTES],
                    const uint8_t *info, size_t info_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t enc[MUSE_HPKE_KEY_BYTES], uint8_t *ct);

// The primitives the key schedule is built on, for other callers.
void muse_hpke_sha256(const uint8_t *data, size_t len, uint8_t out[MUSE_HPKE_SHA256_BYTES]);
void muse_hpke_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t len,
                           uint8_t out[MUSE_HPKE_SHA256_BYTES]);
// HKDF-SHA256 (RFC 5869). Expand writes at most 255 * 32 bytes.
void muse_hpke_hkdf_extract(const uint8_t *salt, size_t salt_len,
                            const uint8_t *ikm, size_t ikm_len,
                            uint8_t prk[MUSE_HPKE_SHA256_BYTES]);
bool muse_hpke_hkdf_expand(const uint8_t prk[MUSE_HPKE_SHA256_BYTES],
                           const uint8_t *info, size_t info_len,
                           uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif
