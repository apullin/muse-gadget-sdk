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

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from musegadget import hpke

h = bytes.fromhex

# RFC 9180 appendix A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
A11 = {
    "info": h("4f6465206f6e2061204772656369616e2055726e"),
    "ikmE": h("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"),
    "skEm": h("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"),
    "pkEm": h("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
    "ikmR": h("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"),
    "skRm": h("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"),
    "shared_secret": h("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"),
    "key": h("4531685d41d65f03dc48f6b8302c05b0"),
    "base_nonce": h("56d890e5accaaf011cff4b7d"),
    "exporter_secret": h("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8"),
    # Sequence number 0, the single-shot case.
    "pt": h("4265617574792069732074727574682c20747275746820626561757479"),
    "aad": h("436f756e742d30"),
    "ct": h("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9"
            "6d8770ac83d07bea87e13c512a"),
}


def test_rfc9180_a11_key_derivation_and_schedule():
    sk_e = hpke.derive_key_pair(A11["ikmE"])
    sk_r = hpke.derive_key_pair(A11["ikmR"])
    assert hpke.private_key_bytes(sk_e) == A11["skEm"]
    assert hpke.public_key_bytes(sk_e) == A11["pkEm"]
    assert hpke.private_key_bytes(sk_r) == A11["skRm"]
    shared_secret, enc = hpke._encap(sk_r.public_key(), sk_e)
    assert (shared_secret, enc) == (A11["shared_secret"], A11["pkEm"])
    assert hpke._decap(enc, sk_r) == A11["shared_secret"]
    assert hpke.key_schedule(shared_secret, A11["info"]) == (
        A11["key"], A11["base_nonce"], A11["exporter_secret"])


def test_rfc9180_a11_seal_and_open():
    sk_e = X25519PrivateKey.from_private_bytes(A11["skEm"])
    sk_r = X25519PrivateKey.from_private_bytes(A11["skRm"])
    enc, ct = hpke.seal(hpke.public_key_bytes(sk_r), A11["info"], A11["aad"], A11["pt"],
                        ephemeral=sk_e)
    assert (enc, ct) == (A11["pkEm"], A11["ct"])
    assert hpke.open(sk_r, A11["pkEm"], A11["info"], A11["aad"], A11["ct"]) == A11["pt"]


def test_round_trip_with_fresh_ephemeral_keys():
    sk_r = hpke.generate_private_key()
    enc1, ct1 = hpke.seal(sk_r.public_key(), b"info", b"aad", b"hello")
    enc2, ct2 = hpke.seal(hpke.public_key_bytes(sk_r), b"info", b"aad", b"hello")
    assert enc1 != enc2 and ct1 != ct2
    assert len(enc1) == 32 and len(ct1) == len(b"hello") + 16
    assert hpke.open(sk_r, enc1, b"info", b"aad", ct1) == b"hello"
    assert hpke.open(sk_r, enc2, b"info", b"aad", ct2) == b"hello"


@pytest.mark.parametrize("change", ["key", "info", "aad", "ct", "enc", "short", "enc_len",
                                    "low_order"])
def test_anything_wrong_fails_to_open(change):
    sk_r = hpke.generate_private_key()
    enc, ct = hpke.seal(sk_r.public_key(), b"info", b"aad", b"secret payload")
    args = {"sk_r": sk_r, "enc": enc, "info": b"info", "aad": b"aad", "ct": ct}
    if change == "key":
        args["sk_r"] = hpke.generate_private_key()
    elif change == "info":
        args["info"] = b"other"
    elif change == "aad":
        args["aad"] = b"aae"
    elif change == "ct":
        args["ct"] = ct[:-1] + bytes([ct[-1] ^ 1])
    elif change == "enc":
        args["enc"] = bytes([enc[0] ^ 1]) + enc[1:]
    elif change == "short":
        args["ct"] = ct[:15]
    elif change == "enc_len":
        args["enc"] = enc[:31]
    elif change == "low_order":
        args["enc"] = b"\x00" * 32
    with pytest.raises(hpke.OpenError):
        hpke.open(**args)


def test_seal_refuses_a_malformed_recipient_key():
    with pytest.raises(ValueError):
        hpke.seal(b"\x01" * 31, b"", b"", b"x")


def _pyhpke():
    pyhpke = pytest.importorskip("pyhpke")
    suite = pyhpke.CipherSuite.new(pyhpke.KEMId.DHKEM_X25519_HKDF_SHA256,
                                   pyhpke.KDFId.HKDF_SHA256, pyhpke.AEADId.AES128_GCM)
    return pyhpke, suite


def test_pyhpke_opens_what_we_seal():
    pyhpke, suite = _pyhpke()
    sk_r = hpke.generate_private_key()
    enc, ct = hpke.seal(sk_r.public_key(), b"muse-mailbox-v1", b"mailbox-id", b'{"a": 1}')
    recipient = suite.create_recipient_context(
        enc, pyhpke.KEMKey.from_pyca_cryptography_key(sk_r), info=b"muse-mailbox-v1")
    assert recipient.open(ct, aad=b"mailbox-id") == b'{"a": 1}'


def test_we_open_what_pyhpke_seals():
    pyhpke, suite = _pyhpke()
    sk_r = hpke.generate_private_key()
    enc, sender = suite.create_sender_context(
        pyhpke.KEMKey.from_pyca_cryptography_key(sk_r.public_key()), info=b"muse-mailbox-ack-v1")
    ct = sender.seal(b'{"status": "ok"}', aad=b"mailbox-id")
    assert hpke.open(sk_r, enc, b"muse-mailbox-ack-v1", b"mailbox-id", ct) == b'{"status": "ok"}'
    with pytest.raises(hpke.OpenError):
        hpke.open(sk_r, enc, b"muse-mailbox-v1", b"mailbox-id", ct)
