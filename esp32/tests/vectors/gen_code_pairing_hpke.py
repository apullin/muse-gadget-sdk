#!/usr/bin/env python3
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

"""Writes code_pairing_hpke.json, the HPKE and one-time-code vectors
tests/test_code_pairing.py checks main/muse_hpke.c and main/code_pairing.c
against, from independent implementations:

    python3 -m venv /tmp/hpke && /tmp/hpke/bin/pip install cryptography pyhpke
    /tmp/hpke/bin/python tests/vectors/gen_code_pairing_hpke.py

The keys are fixed test values, so the output is reproducible.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyPair

OUT = Path(__file__).with_name("code_pairing_hpke.json")
SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def x25519_pub(sk: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(sk)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def keypair(sk: bytes) -> KEMKeyPair:
    pk = x25519_pub(sk)
    return KEMKeyPair(
        SUITE.kem.deserialize_private_key(sk), SUITE.kem.deserialize_public_key(pk)
    )


def seal(pk_r: bytes, sk_e: bytes, info: bytes, aad: bytes, pt: bytes) -> tuple[bytes, bytes]:
    enc, ctx = SUITE.create_sender_context(
        SUITE.kem.deserialize_public_key(pk_r), info=info, eks=keypair(sk_e)
    )
    return enc, ctx.seal(pt, aad=aad)


def open_(sk_r: bytes, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> bytes:
    ctx = SUITE.create_recipient_context(enc, SUITE.kem.deserialize_private_key(sk_r), info=info)
    return ctx.open(ct, aad=aad)


CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def otp(secret: bytes, counter: int) -> str:
    """The one-time code of docs/code-pairing.md: HOTP with HMAC-SHA256."""
    h = hmac.new(secret, counter.to_bytes(8, "big"), hashlib.sha256).digest()
    o = h[31] & 0x0F
    v = int.from_bytes(h[o:o + 5], "big")
    return "".join(CROCKFORD[(v >> (35 - 5 * i)) & 31] for i in range(8))


def main() -> None:
    device_sk = bytes(range(0x40, 0x60))
    device_pk = x25519_pub(device_sk)
    node_id = "homelink-ab12cd"
    payloads = {
        "provision": {
            "action": "provision_v2",
            "access_token": "ACCESS-SECRET-hpke",
            "refresh_token": "REFRESH-SECRET-hpke",
            "token_type": "device",
            "api_url_v2": "https://api2.example.test",
            "noise_host": "vm.example.test",
            "username": "person",
            "ack_nonce": b64url(hashlib.sha256(b"ack-nonce").digest()[:16]),
        },
        "minimal": {
            "action": "provision_v2",
            "access_token": "ACCESS-SECRET-min",
            "refresh_token": "REFRESH-SECRET-min",
        },
    }
    vectors = []
    for name, payload in payloads.items():
        sk_e = hashlib.sha256(f"ephemeral-{name}".encode()).digest()
        pt = json.dumps(payload, separators=(",", ":")).encode()
        enc, ct = seal(device_pk, sk_e, b"muse-drop-v1", node_id.encode(), pt)
        assert open_(device_sk, enc, b"muse-drop-v1", node_id.encode(), ct) == pt
        vectors.append({
            "name": name,
            "info": "muse-drop-v1",
            "aad": node_id,
            "sk_e": sk_e.hex(),
            "enc": b64url(enc),
            "ct": b64url(ct),
            "pt": pt.decode(),
        })

    # Sealing, to check muse_hpke_seal (the tests use it to build drops).
    other_sk = bytes(range(0x80, 0xA0))
    other_pk = x25519_pub(other_sk)
    seal_sk_e = hashlib.sha256(b"ephemeral-seal").digest()
    seal_pt = b'{"hello":"world"}'
    seal_enc, seal_ct = seal(other_pk, seal_sk_e, b"muse-drop-v1", node_id.encode(), seal_pt)

    # RFC 7748 section 5.2, the first X25519 test vector.
    rfc7748 = {
        "scalar": "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "u": "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "out": "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    }
    got = X25519PrivateKey.from_private_bytes(bytes.fromhex(rfc7748["scalar"])).exchange(
        X25519PublicKey.from_public_bytes(bytes.fromhex(rfc7748["u"])))
    assert got.hex() == rfc7748["out"], got.hex()

    code_secret = bytes(range(32))
    otps = {str(c): otp(code_secret, c) for c in (0, 1, 2, 5, 179251798, 179251799)}
    # The contract's own table.
    assert otps["0"] == "J66JQ2A2" and otps["1"] == "MG2GGDQN"
    assert otps["179251798"] == "XEPZ97F6" and otps["179251799"] == "TW0NCKK8"

    data = {
        "comment": "Generated by gen_code_pairing_hpke.py with cryptography and pyhpke.",
        "suite": "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode",
        "device_sk": device_sk.hex(),
        "device_pk": b64url(device_pk),
        "fingerprint": hashlib.sha256(device_pk).digest()[:8].hex(),
        "node_id": node_id,
        "payloads": vectors,
        "seal": {
            "info": "muse-drop-v1",
            "aad": node_id,
            "pk_r": b64url(other_pk),
            "sk_r": other_sk.hex(),
            "sk_e": seal_sk_e.hex(),
            "pt": seal_pt.decode(),
            "enc": b64url(seal_enc),
            "ct": b64url(seal_ct),
        },
        "x25519": rfc7748,
        "otp_secret": code_secret.hex(),
        "otps": otps,
    }
    OUT.write_text(json.dumps(data, indent=2) + "\n")


if __name__ == "__main__":
    main()
