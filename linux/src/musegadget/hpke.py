# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""HPKE (RFC 9180) base mode, single-shot, for one cipher suite.

The suite is DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM
(``0x0020`` / ``0x0001`` / ``0x0001``), the suite of RFC 9180 appendix A.1.
Code pairing uses it to carry the device tokens from the Muse app to the
device, and the device's acknowledgement back. Only ``cryptography``
primitives are used, so it runs on cryptography 3.3.2.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Callable, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0001
MODE_BASE = 0x00

N_SECRET = 32   # DHKEM(X25519, HKDF-SHA256) shared secret
N_ENC = 32      # encapsulated key
N_PK = 32
N_SK = 32
N_K = 16        # AES-128-GCM key
N_N = 12        # AES-128-GCM nonce
N_T = 16        # AES-128-GCM tag
N_H = 32        # SHA-256

_KEM_SUITE_ID = b"KEM" + KEM_ID.to_bytes(2, "big")
_HPKE_SUITE_ID = (b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big")
                  + AEAD_ID.to_bytes(2, "big"))


class OpenError(Exception):
    """The ciphertext didn't open: wrong key, info or aad, or it was changed."""


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * N_H, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(hashes.SHA256(), length, info).derive(prk)


def labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info
    return _expand(prk, labeled_info, length)


def _raw_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_bytes(private_key: X25519PrivateKey) -> bytes:
    """The 32-byte public key of ``private_key``."""
    return _raw_public(private_key.public_key())


def private_key_bytes(private_key: X25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def derive_key_pair(ikm: bytes) -> X25519PrivateKey:
    """DeriveKeyPair for DHKEM(X25519, HKDF-SHA256) (RFC 9180 §7.1.3)."""
    dkp_prk = labeled_extract(_KEM_SUITE_ID, b"", b"dkp_prk", ikm)
    sk = labeled_expand(_KEM_SUITE_ID, dkp_prk, b"sk", b"", N_SK)
    return X25519PrivateKey.from_private_bytes(sk)


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = labeled_extract(_KEM_SUITE_ID, b"", b"eae_prk", dh)
    return labeled_expand(_KEM_SUITE_ID, eae_prk, b"shared_secret", kem_context, N_SECRET)


def _dh(private_key: X25519PrivateKey, public_key: X25519PublicKey) -> bytes:
    try:
        shared = private_key.exchange(public_key)
    except ValueError:  # an all-zero result: a low-order public key
        raise OpenError("invalid public key") from None
    if shared == b"\x00" * 32:
        raise OpenError("invalid public key")
    return shared


def _encap(pk_r: X25519PublicKey, ephemeral: X25519PrivateKey) -> Tuple[bytes, bytes]:
    enc = public_key_bytes(ephemeral)
    dh = _dh(ephemeral, pk_r)
    shared_secret = _extract_and_expand(dh, enc + _raw_public(pk_r))
    return shared_secret, enc


def _decap(enc: bytes, sk_r: X25519PrivateKey) -> bytes:
    if len(enc) != N_ENC:
        raise OpenError("enc must be 32 bytes")
    pk_e = X25519PublicKey.from_public_bytes(enc)
    dh = _dh(sk_r, pk_e)
    return _extract_and_expand(dh, enc + public_key_bytes(sk_r))


def key_schedule(shared_secret: bytes, info: bytes) -> Tuple[bytes, bytes, bytes]:
    """Base-mode key schedule: ``(key, base_nonce, exporter_secret)``."""
    psk_id_hash = labeled_extract(_HPKE_SUITE_ID, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(_HPKE_SUITE_ID, b"", b"info_hash", info)
    context = bytes([MODE_BASE]) + psk_id_hash + info_hash
    secret = labeled_extract(_HPKE_SUITE_ID, shared_secret, b"secret", b"")
    key = labeled_expand(_HPKE_SUITE_ID, secret, b"key", context, N_K)
    base_nonce = labeled_expand(_HPKE_SUITE_ID, secret, b"base_nonce", context, N_N)
    exporter_secret = labeled_expand(_HPKE_SUITE_ID, secret, b"exp", context, N_H)
    return key, base_nonce, exporter_secret


def _as_public(pk_r) -> X25519PublicKey:
    if isinstance(pk_r, X25519PublicKey):
        return pk_r
    if not isinstance(pk_r, (bytes, bytearray)) or len(pk_r) != N_PK:
        raise ValueError("the recipient key must be 32 bytes")
    return X25519PublicKey.from_public_bytes(bytes(pk_r))


def seal(pk_r, info: bytes, aad: bytes, pt: bytes,
         ephemeral: Optional[X25519PrivateKey] = None,
         generate: Callable[[], X25519PrivateKey] = X25519PrivateKey.generate) -> Tuple[bytes, bytes]:
    """Encrypt ``pt`` to ``pk_r`` (a key or its 32 bytes); returns ``(enc, ct)``.

    ``ephemeral`` fixes the sender's ephemeral key, for test vectors only.
    """
    shared_secret, enc = _encap(_as_public(pk_r), ephemeral or generate())
    key, base_nonce, _ = key_schedule(shared_secret, info)
    # Single-shot: sequence number 0, so the nonce is the base nonce.
    return enc, AESGCM(key).encrypt(base_nonce, pt, aad)


def open(sk_r: X25519PrivateKey, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> bytes:  # noqa: A001
    """Decrypt what ``seal`` made for ``sk_r``; raises ``OpenError`` if it doesn't open."""
    if len(ct) < N_T:
        raise OpenError("ciphertext too short")
    try:
        shared_secret = _decap(enc, sk_r)
    except ValueError:
        raise OpenError("invalid encapsulated key") from None
    key, base_nonce, _ = key_schedule(shared_secret, info)
    try:
        return AESGCM(key).decrypt(base_nonce, ct, aad)
    except InvalidTag:
        raise OpenError("the ciphertext didn't open") from None


def generate_private_key() -> X25519PrivateKey:
    return X25519PrivateKey.generate()
