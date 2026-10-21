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

"""The fake Muse keeps the contract, so the end-to-end tests mean something."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import fake_drop_server as fds
from musegadget import code_pairing as cp
from musegadget import hpke, muse_api

SDK_TOKEN = "mgst_" + "A" * 43
NODE = "homelink-abcdef"


@pytest.fixture
def fake():
    with fds.FakeDropServer(interval=0.2, slow_down_step=0.2) as server:
        yield server


class Device:
    def __init__(self, fake, node_id=NODE):
        self.fake = fake
        self.node_id = node_id
        self.key = X25519PrivateKey.generate()
        self.public = hpke.public_key_bytes(self.key)
        self.fp = cp.fingerprint(self.public)
        self.secret = os.urandom(32)

    def code(self, c):
        return cp.one_time_code(self.secret, c)

    def link(self, c):
        return cp.pair_link(self.node_id, self.public, self.code(c))

    def post(self, path, body):
        return cp.urllib_transport(self.fake.base_url + path, body)

    def poll(self, codes, **over):
        body = {"node_id": self.node_id, "key_fingerprint": self.fp, "recent_otps": codes,
                "sdk_token": SDK_TOKEN}
        body.update(over)
        return self.post("/device_drop/poll", {k: v for k, v in body.items() if v is not None})

    def open(self, sealed):
        return cp.open_json(self.key, cp.PAYLOAD_INFO, self.node_id.encode(), sealed)


def control(fake, name, body=None):
    req = urllib.request.Request(fake.base_url + "/_fake/" + name,
                                 method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.getcode(), json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_nothing_waiting_is_a_uniform_authorization_pending(fake):
    device = Device(fake)
    status, body, _ = device.poll([device.code(5), device.code(4)])
    assert (status, body["type"], body["interval"]) == (400, "authorization_pending", 0.2)
    other = Device(fake, "homelink-000000")
    control(fake, "approve", {"url": other.link(1)})
    time.sleep(0.2)
    assert device.poll([device.code(5)])[1] == body  # something waiting for someone else


@pytest.mark.parametrize("over, detail", [
    ({"node_id": "has space"}, "node_id"),
    ({"key_fingerprint": "ABCDEF0123456789"}, "key_fingerprint"),
    ({"recent_otps": []}, "recent_otps"),
    ({"recent_otps": ["J66JQ2A2"] * 9}, "recent_otps"),
    ({"recent_otps": ["J66JQ2AI"]}, "recent_otps"),
    ({"sdk_token": "mgst_short"}, "sdk_token"),
])
def test_malformed_polls(fake, over, detail):
    device = Device(fake)
    body = {"recent_otps": [device.code(1)], **over}
    status, answer, _ = device.poll(body.pop("recent_otps"), **body)
    assert (status, answer["type"], answer["detail"]) == (400, "invalidRequest", detail)


def test_approve_takes_a_slow_screen_link(fake):
    # A gadget with a slow screen adds its code step (s=) to the link.
    device = Device(fake)
    status, approved = control(fake, "approve", {"url": device.link(7) + "&s=45"})
    assert status == 200 and approved["otp"] == device.code(7)
    # Like Muse, one pending drop per code: the app waits for the next code.
    status, again = control(fake, "approve", {"url": device.link(7) + "&s=45"})
    assert (status, again["type"]) == (409, "dropAlreadyDelivered")


def test_approve_seals_provision_v2_to_the_key_in_the_link(fake):
    fake.configure(api_url_v2="https://api.example.test", noise_host="noise.example.test")
    device = Device(fake)
    status, approved = control(fake, "approve", {"url": device.link(7)})
    assert status == 200
    assert (approved["node_id"], approved["key_fingerprint"], approved["otp"]) == (NODE, device.fp, device.code(7))

    # Filed under its code: any of the last few codes reaches it, another code doesn't.
    assert device.poll([device.code(9), device.code(8)])[1]["type"] == "authorization_pending"
    time.sleep(0.2)
    status, body, _ = device.poll([device.code(9), device.code(8), device.code(7)])
    assert status == 200 and body["otp"] == device.code(7)
    payload = device.open(body["sealed"])
    assert payload == {"action": "provision_v2", **approved["tokens"], "token_type": "device",
                       "username": "Sam", "api_url_v2": "https://api.example.test",
                       "noise_host": "noise.example.test", "ack_nonce": approved["ack_nonce"]}

    # Lost answer: the same drop again, until acknowledged.
    time.sleep(0.2)
    assert device.poll([device.code(7)])[1] == body
    ack = {"node_id": NODE, "key_fingerprint": device.fp, "otp": device.code(7)}
    assert device.post("/device_drop/ack", {**ack, "ack_nonce": "wrong"})[0] == 200
    assert fake.drops()["drops"]  # a wrong nonce deletes nothing
    assert device.post("/device_drop/ack", {**ack, "ack_nonce": payload["ack_nonce"]})[0] == 200
    assert fake.drops()["drops"] == []
    assert [a["matched"] for a in fake.drops()["acks"]] == [False, True]
    time.sleep(0.2)
    assert device.poll([device.code(7)])[1]["type"] == "authorization_pending"


def test_a_wrong_fingerprint_gets_nothing(fake):
    device = Device(fake)
    control(fake, "approve", {"url": device.link(3)})
    assert device.poll([device.code(3)], key_fingerprint="0" * 16)[1]["type"] == "authorization_pending"
    assert Device(fake).poll([device.code(3)])[1]["type"] == "authorization_pending"


def test_deliver_takes_what_the_caller_sealed_and_several_drops_per_node(fake):
    device = Device(fake)
    junk = {"v": 1, "enc": cp.b64url(os.urandom(32)), "ct": cp.b64url(os.urandom(40))}
    base = {"node_id": NODE, "key_fingerprint": device.fp}
    assert control(fake, "deliver", {**base, "otp": device.code(1), "sealed": junk})[0] == 200
    real = cp.seal_json(device.public, cp.PAYLOAD_INFO, NODE.encode(), {"action": "provision_v2"})
    assert control(fake, "deliver", {**base, "otp": device.code(2), "sealed": real,
                                     "ack_hash": fds.ack_hash("n")})[0] == 200
    status, body, _ = device.poll([device.code(2), device.code(1)])
    assert body == {"sealed": junk, "otp": device.code(1)}  # oldest first
    time.sleep(0.2)
    assert device.poll([device.code(2)])[1] == {"sealed": real, "otp": device.code(2)}
    for bad in ({**base, "otp": "nope", "sealed": real}, {**base, "otp": device.code(1), "sealed": {"v": 2}},
                {"node_id": NODE, "otp": device.code(1), "sealed": real}):
        assert control(fake, "deliver", bad)[0] == 400


def test_drops_expire(fake):
    fake.configure(drop_ttl=0.2)
    device = Device(fake)
    fake.approve(device.link(1))
    time.sleep(0.3)
    assert device.poll([device.code(1)])[1]["type"] == "authorization_pending"
    assert fake.drops()["drops"] == []


def test_pacing_slow_down_rate_limit_and_unavailable(fake):
    fake.configure(interval=1.0, slow_down_step=2)
    device = Device(fake)
    device.poll([device.code(1)])
    status, body, _ = device.poll([device.code(1)])
    assert (status, body["type"], body["interval"]) == (400, "slow_down", 3)
    fake.reset()
    fake.configure(interval=0.2, slow_down_step=0.1, slow_down_on_poll=1, rate_limit_poll=2,
                   retry_after=4)
    assert device.poll([device.code(1)])[1]["type"] == "slow_down"
    time.sleep(0.35)
    status, body, headers = device.poll([device.code(1)])
    assert body["type"] == "authorization_pending"
    status, body, headers = device.poll([device.code(1)])
    assert (status, body["type"], headers["retry-after"]) == (429, "rateLimited", "4")
    fake.configure(unavailable=True)
    assert device.poll([device.code(1)])[:2][1]["type"] == "devicePairUnavailable"


def test_refresh_rotates_records_the_sdk_token_and_can_refuse_it(fake):
    tokens = fake.mint(NODE)
    root = fake.base_url
    new, status, kind = muse_api.refresh_device_token_detailed(tokens["refresh_token"], NODE, root, SDK_TOKEN)
    assert status == 200 and kind is None and new["access_token"] != tokens["access_token"]
    assert fake.drops()["bound"] == {NODE: SDK_TOKEN[:12]}
    assert muse_api.fetch_vms_with_status(tokens["access_token"], root) == ([], 401)  # rotated away
    assert muse_api.fetch_vms_with_status(new["access_token"], root)[1] == 200
    assert muse_api.refresh_device_token_detailed(tokens["refresh_token"], NODE, root, None)[1:] == (401, "unauthorized")
    fake.configure(refresh_sdk_error="sdkTokenRevoked")
    assert muse_api.refresh_device_token_detailed(new["refresh_token"], NODE, root, SDK_TOKEN) == (
        None, 403, "sdkTokenRevoked")
    assert muse_api.refresh_device_token_detailed(new["refresh_token"], NODE, root, None)[1] == 200


def test_control_plane_config_requests_and_reset(fake):
    assert control(fake, "config", {"interval": 0.3})[1]["interval"] == 0.3
    for bad in ({"nope": 1}, {"mode": "approve"}, {"refresh_sdk_error": "bogus"}):
        assert control(fake, "config", bad)[0] == 400
    assert control(fake, "approve", {"url": "https://muse.ai/pair#v=1&n=a"})[0] == 400
    assert control(fake, "approve", {})[0] == 400
    device = Device(fake)
    _, approved = control(fake, "approve", {"url": device.link(1)})
    time.sleep(0.3)
    device.poll([device.code(1)])
    _, log = control(fake, "requests")
    assert [(r["path"], r["type"], r["otp_count"]) for r in log] == [("/device_drop/poll", "sealed", 1)]
    text = json.dumps(log)
    for secret in (SDK_TOKEN, device.code(1), approved["tokens"]["access_token"]):
        assert secret not in text
    assert control(fake, "reset", {}) == (200, {"ok": True})
    assert fake.drops() == {"drops": [], "acks": [], "bound": {}} and fake.requests() == []


def test_runs_as_a_script_and_prints_its_port():
    script = Path(fds.__file__)
    proc = subprocess.Popen([sys.executable, str(script), "--port", "0", "--interval", "0.5"],
                            stdout=subprocess.PIPE, text=True, env={**os.environ, "PYTHONPATH": ""})
    try:
        info = json.loads(proc.stdout.readline())
        assert info == {"port": info["port"], "base_url": f"http://127.0.0.1:{info['port']}"}
        with urllib.request.urlopen(info["base_url"] + "/_fake/drops", timeout=5) as resp:
            assert json.loads(resp.read()) == {"drops": [], "acks": [], "bound": {}}
    finally:
        proc.terminate()
        assert proc.wait(timeout=5) == 0
