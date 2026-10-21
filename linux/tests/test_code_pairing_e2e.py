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

"""End to end: the real device code against the fake Muse, over HTTP on 127.0.0.1.

The subprocess tests run ``musegadget pair --code`` with its own state
directory, scrape the ``pair url:`` line it prints, and play the Muse app with
``/_fake/approve``. The in-process tests drive ``CodePairing`` with a fake
clock, so they can make a QR code old without waiting.
"""

from __future__ import annotations

import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import fake_drop_server as fds
from musegadget import code_pairing as cp
from musegadget import config, hpke

SDK_TOKEN = "mgst_" + "A" * 43
NODE = "homelink-abcdef"
SRC = Path(__file__).resolve().parent.parent / "src"
PAIR_URL_LINE = re.compile(r"^pair url: (\S+)$")
FINGERPRINT_LINE = re.compile(r"^key fingerprint: ([0-9a-f]{16})$")


class Cli:
    """``musegadget pair --code`` in a subprocess, with its output collected line by line."""

    def __init__(self, fake, state_dir, *args, sdk_token=SDK_TOKEN):
        env = dict(os.environ)
        env.update({
            config.STATE_DIR_ENV: str(state_dir),
            "PYTHONPATH": os.pathsep.join(filter(None, [str(SRC), env.get("PYTHONPATH")])),
        })
        env.pop(config.SDK_TOKEN_ENV, None)
        if sdk_token:
            env[config.SDK_TOKEN_ENV] = sdk_token
        self.proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "musegadget", "pair", "--code",
             "--api-url", fake.base_url, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        )
        self.lines: "queue.Queue[str]" = queue.Queue()
        self.stdout: list[str] = []
        self._done = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            self.stdout.append(line.rstrip("\n"))
            self.lines.put(line.rstrip("\n"))
        self._done.set()

    def pair_url(self, timeout=15.0) -> str:
        deadline = time.monotonic() + timeout
        while True:
            try:
                line = self.lines.get(timeout=max(deadline - time.monotonic(), 0.01))
            except queue.Empty:
                raise AssertionError("no pair url printed; output so far:\n" + "\n".join(self.stdout))
            match = PAIR_URL_LINE.match(line)
            if match:
                return match.group(1)

    def finish(self, timeout=30.0) -> tuple[int, str, str]:
        code = self.proc.wait(timeout=timeout)
        stderr = self.proc.stderr.read()
        self._done.wait(5)
        return code, "\n".join(self.stdout), stderr


@pytest.fixture
def fake():
    with fds.FakeDropServer(interval=0.2, slow_down_step=0.3) as server:
        yield server


@pytest.fixture
def state(tmp_path):
    (tmp_path / config.IDENTITY_FILE).write_text(json.dumps({"mac": "02:00:00:ab:cd:ef"}))
    return tmp_path


def _types(fake, path="/device_drop/poll"):
    return [r["type"] for r in fake.requests() if r["path"] == path]


def _wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.03)


# --- The real command ----------------------------------------------------------

def test_pairs_when_the_phone_scans_the_qr_code(fake, state):
    cli = Cli(fake, state)
    url = cli.pair_url()
    params = cp.parse_pair_link(url)
    assert params["n"] == NODE and params["m"] == "hatch_link" and params["c"] == "1"
    assert url.startswith("https://muse.ai/pair#v=1&")
    approved = fake.approve(url)

    status, out, err = cli.finish()
    assert status == 0, err
    assert out.splitlines()[-1] == "Paired to Sam."
    fp = cp.fingerprint(cp.b64url_decode(params["k"]))
    assert [line for line in out.splitlines() if FINGERPRINT_LINE.match(line)] == [f"key fingerprint: {fp}"]
    assert approved["key_fingerprint"] == fp
    assert "\u2588" in out  # the QR code

    pairing = json.loads((state / config.PAIRING_FILE).read_text())
    # The binding refresh rotated the tokens the phone minted, and carried the SDK token.
    assert pairing["refresh_token"] != approved["tokens"]["refresh_token"]
    assert pairing["refresh_token"] in fake._refresh and pairing["access_token"] in fake._access
    assert pairing["username"] == "Sam" and pairing["api_url_v2"] == fake.base_url
    refreshes = [r for r in fake.requests() if r["path"] == "/device_token/refresh"]
    assert [(r["status"], r["body"]["device_id"], r["body"]["sdk_token"]) for r in refreshes] == [
        (200, NODE, "<redacted>")]
    assert fake.drops()["bound"] == {NODE: SDK_TOKEN[:12]}
    assert [r["authorized"] for r in fake.requests() if r["path"] == "/fetch_vms"] == [True]
    drops = fake.drops()
    assert drops["drops"] == [] and [a["matched"] for a in drops["acks"]] == [True]
    order = [r["path"] for r in fake.requests()][-3:]
    assert order == ["/device_token/refresh", "/fetch_vms", "/device_drop/ack"]

    assert not (state / cp.STATE_FILE).exists()  # key and code secret deleted once paired
    assert "slow_down" not in _types(fake)  # the device keeps to the interval
    for secret in (pairing["access_token"], pairing["refresh_token"], SDK_TOKEN, params["o"]):
        assert secret not in err


def test_a_restart_before_pairing_keeps_the_same_key(fake, state):
    cli = Cli(fake, state)
    first = cp.parse_pair_link(cli.pair_url())
    _wait_for(lambda: "authorization_pending" in _types(fake))
    cli.proc.send_signal(signal.SIGINT)
    status, _, err = cli.finish()
    assert status == 1 and "Stopped." in err
    assert (state / cp.STATE_FILE).exists()

    cli = Cli(fake, state)
    url = cli.pair_url()
    assert cp.parse_pair_link(url)["k"] == first["k"]
    assert cp.parse_pair_link(url)["o"] != first["o"]
    fake.approve(url)
    status, _, err = cli.finish()
    assert status == 0, err
    assert not (state / cp.STATE_FILE).exists()

    # The next pairing starts with a fresh key.
    cli = Cli(fake, state, "--force", "--timeout", "1")
    assert cp.parse_pair_link(cli.pair_url())["k"] != first["k"]
    assert cli.finish()[0] == 1


@pytest.mark.parametrize("kind, message", [
    ("sdkTokenDeviceLimitReached", "Can't pair: this SDK token already pairs as many gadgets as it can."),
    ("sdkTokenRevoked", "Can't pair: Muse doesn't accept this SDK token; check it at gadgets.muse.ai."),
])
def test_an_sdk_token_refusal_leaves_the_device_unpaired(fake, state, kind, message):
    fake.configure(refresh_sdk_error=kind)
    cli = Cli(fake, state)
    fake.approve(cli.pair_url())
    status, out, err = cli.finish()
    assert status == 1 and message in err
    assert not (state / config.PAIRING_FILE).exists()
    assert "Paired" not in out


def test_without_an_sdk_token_nothing_is_bound(fake, state):
    cli = Cli(fake, state, sdk_token=None)
    fake.approve(cli.pair_url())
    status, _, err = cli.finish()
    assert status == 0, err
    assert _types(fake, "/device_token/refresh") == []
    assert all("sdk_token" not in r["body"] for r in fake.requests() if r["path"] == "/device_drop/poll")


def test_unavailable_stays_on_the_code_pairing_route(fake, state):
    fake.configure(unavailable=True)
    status, out, err = Cli(fake, state).finish()
    assert status == 1
    assert "Retry later with `musegadget pair --code`. Bluetooth stays off." in err
    assert not (state / config.PAIRING_FILE).exists()


def test_slow_down_lengthens_the_interval(fake, state):
    fake.configure(slow_down_on_poll=2)
    cli = Cli(fake, state, "--timeout", "3")
    status, out, _ = cli.finish()
    assert status == 1
    assert "Muse asked to check less often: every 0.5 s." in out
    polls = [r for r in fake.requests() if r["path"] == "/device_drop/poll"]
    assert [p["type"] for p in polls[:3]] == ["authorization_pending", "slow_down", "authorization_pending"]
    gaps = [b["t"] - a["t"] for a, b in zip(polls[1:], polls[2:])]
    assert min(gaps) >= 0.45


def test_rate_limited_waits_retry_after(fake, state):
    fake.configure(rate_limit_poll=1, retry_after=1)
    status, out, _ = Cli(fake, state, "--timeout", "2").finish()
    assert status == 1 and "Muse is busy. Trying again in 1 s." in out
    polls = [r for r in fake.requests() if r["path"] == "/device_drop/poll"]
    assert polls[1]["type"] == "rateLimited"
    assert polls[2]["t"] - polls[1]["t"] >= 0.95


def test_the_window_closes(fake, state):
    status, out, err = Cli(fake, state, "--timeout", "1").finish()
    assert status == 1
    assert "Pairing closed without approval." in err
    assert (state / cp.STATE_FILE).exists()


# --- In process, with a fake clock -------------------------------------------------

class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def _run(fake, state, monkeypatch, clock, timeout_s=60, **kwargs):
    monkeypatch.setenv(config.STATE_DIR_ENV, str(state))
    monkeypatch.setenv(config.SDK_TOKEN_ENV, SDK_TOKEN)
    fake.configure(enforce_interval=False)  # the fake clock polls fast in real time
    return cp.CodePairing(api_root=fake.base_url, clock=clock, sleep=clock.sleep,
                          timeout_s=timeout_s, random_bytes=lambda n: bytes(range(n)), **kwargs).run()


@pytest.mark.parametrize("age, outcome", [(5, cp.Outcome.PAIRED), (7, cp.Outcome.TIMED_OUT)])
def test_a_qr_code_older_than_a_minute_is_never_picked_up(fake, state, monkeypatch, age, outcome):
    keys = cp.load_or_create_keys(state)
    clock = Clock()
    c = cp.counter(clock.t)
    approved = fake.approve(cp.pair_link(NODE, keys.public_key, cp.one_time_code(bytes(range(32)), c - age)))
    result = _run(fake, state, monkeypatch, clock)
    assert result.outcome is outcome
    drops = fake.drops()["drops"]
    if outcome is cp.Outcome.TIMED_OUT:
        assert drops[0]["otp"] == approved["otp"] and drops[0]["delivered"] == 0
        assert not (state / config.PAIRING_FILE).exists()


@pytest.mark.parametrize("wrong", ["fingerprint", "otp"])
def test_a_drop_for_another_key_or_code_gets_nothing(fake, state, monkeypatch, wrong):
    keys = cp.load_or_create_keys(state)
    clock = Clock()
    code = cp.one_time_code(bytes(range(32)), cp.counter(clock.t))
    if wrong == "fingerprint":
        other = hpke.public_key_bytes(X25519PrivateKey.generate())
        fake.approve(cp.pair_link(NODE, other, code))
    else:
        fake.approve(cp.pair_link(NODE, keys.public_key, "ZZZZZZZZ"))
    assert _run(fake, state, monkeypatch, clock, timeout_s=30).outcome is cp.Outcome.TIMED_OUT
    assert fake.drops()["drops"][0]["delivered"] == 0
    assert fake.requests()[-1]["type"] == "authorization_pending"


def test_junk_drops_are_ignored_and_the_real_one_picked_up(fake, state, monkeypatch):
    keys = cp.load_or_create_keys(state)
    clock = Clock()
    c = cp.counter(clock.t)
    base = {"node_id": NODE, "key_fingerprint": keys.fingerprint}
    # Junk that doesn't open, then a payload that opens but carries tokens Muse never minted:
    # anyone who saw the QR code can make both.
    fake.deliver(**base, otp=cp.one_time_code(bytes(range(32)), c - 1),
                 sealed={"v": 1, "enc": cp.b64url(os.urandom(32)), "ct": cp.b64url(os.urandom(48))})
    forged = cp.seal_json(keys.public_key, cp.PAYLOAD_INFO, NODE.encode(), {
        "action": "provision_v2", "access_token": "forged", "refresh_token": "forged",
        "token_type": "device", "username": "Mallory"})
    fake.deliver(**base, otp=cp.one_time_code(bytes(range(32)), c - 2), sealed=forged)
    fake.approve(cp.pair_link(NODE, keys.public_key, cp.one_time_code(bytes(range(32)), c)))

    statuses = []
    result = _run(fake, state, monkeypatch, clock,
                  on_status=lambda status, seconds: statuses.append(status))
    assert result == cp.Result(cp.Outcome.PAIRED, None, "Sam")
    assert statuses.count(cp.Status.IGNORED) == 2
    assert _types(fake) == ["sealed", "sealed", "sealed"]
    assert json.loads((state / config.PAIRING_FILE).read_text())["username"] == "Sam"


def test_a_claim_code_pairs_from_the_sticker(fake, state, monkeypatch):
    keys = cp.load_or_create_keys(state, claim_code="C1A1M0DE")
    sticker = cp.pair_link(NODE, keys.public_key, "C1A1M0DE")
    fake.approve(sticker)
    result = _run(fake, state, monkeypatch, Clock(), claim_code="C1A1M0DE")
    assert result.outcome is cp.Outcome.PAIRED
    assert fake.drops()["acks"][0]["otp"] == "C1A1M0DE"
    assert not (state / cp.STATE_FILE).exists()


def test_a_lost_poll_answer_is_handed_out_again(fake, state, monkeypatch):
    keys = cp.load_or_create_keys(state)
    clock = Clock()
    fake.approve(cp.pair_link(NODE, keys.public_key, cp.one_time_code(bytes(range(32)), cp.counter(clock.t))))
    dropped = []

    def lossy(url, body):
        answer = cp.urllib_transport(url, body)
        if answer[0] == 200 and "sealed" in answer[1] and not dropped:
            dropped.append(answer[1])
            raise cp.TransportError("connection reset")
        return answer

    assert _run(fake, state, monkeypatch, clock, transport=lossy).outcome is cp.Outcome.PAIRED
    assert _types(fake) == ["sealed", "sealed"]
