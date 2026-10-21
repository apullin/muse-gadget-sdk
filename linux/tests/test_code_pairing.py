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

import hashlib
import json
import logging
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from musegadget import code_pairing as cp
from musegadget import config, hpke, muse_api, qr

SDK_TOKEN = "mgst_" + "A" * 43
API = "https://api.example.test"
NODE = "homelink-abcdef"
T0 = 1_000_000.0     # counter 100000, at a counter boundary
SECRET = bytes(range(32))
C0 = 100_000


class Clock:
    def __init__(self, t=T0):
        self.t = t
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 3))
        self.t += seconds


class Script:
    """A transport that answers from a list, recording each request and when it came.

    An answer may be a callable taking ``(url, body)``, so it can seal to the
    device key once the device has created it. When the list runs out, polls
    get ``authorization_pending``.
    """

    def __init__(self, *answers, clock=None):
        self.answers = list(answers)
        self.calls: list[tuple[str, dict, float]] = []
        self.clock = clock

    def __call__(self, url, body):
        self.calls.append((url, json.loads(json.dumps(body)), self.clock() if self.clock else 0))
        answer = self.answers.pop(0) if self.answers else PENDING
        if callable(answer):
            answer = answer(url, body)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def paths(self) -> list[str]:
        return ["/" + url.split("/", 3)[-1] for url, _, _ in self.calls]

    def polls(self) -> list[dict]:
        return [body for url, body, _ in self.calls if url.endswith(cp.POLL_PATH)]


def problem(kind, status=400, headers=None, **extra):
    return status, {"type": kind, "title": kind, **extra}, headers or {}


PENDING = problem("authorization_pending", interval=5)
OK = (200, {}, {})


def keys(state) -> cp.PairingKeys:
    return cp.load_or_create_keys(state)


def provision(**over):
    payload = {"action": "provision_v2", "access_token": "AT-SECRET", "refresh_token": "RT-SECRET",
               "token_type": "device", "username": "Sam", "ack_nonce": "ACK-NONCE"}
    payload.update(over)
    return {k: v for k, v in payload.items() if v is not None}


def drop(state, payload=None, *, otp=None, aad=None, info=cp.PAYLOAD_INFO, key=None, raw=None):
    """A poll answer: ``payload`` sealed to the device key, filed under ``otp`` (default: newest code)."""
    def answer(url, body):
        message = raw if raw is not None else json.dumps(payload or provision()).encode()
        enc, ct = hpke.seal(key or keys(state).public_key, info,
                            aad if aad is not None else body["node_id"].encode(), message)
        return 200, {"sealed": {"v": 1, "enc": cp.b64url(enc), "ct": cp.b64url(ct)},
                     "otp": otp or body["recent_otps"][0]}, {}
    return answer


class Verify:
    def __init__(self, *answers):
        self.answers = list(answers) or [([{"vm_url": "wss://vm", "vm_auth_token": "v"}], 200)]
        self.calls: list[tuple[str, str]] = []

    def __call__(self, access_token, root):
        self.calls.append((access_token, root))
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]


class Refresh:
    def __init__(self, answer=None):
        self.answer = answer or ({"access_token": "AT-2", "refresh_token": "RT-2"}, 200, None)
        self.calls: list[tuple] = []

    def __call__(self, refresh_token, device_id, root, sdk_token):
        self.calls.append((refresh_token, device_id, root, sdk_token))
        return self.answer


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv(config.STATE_DIR_ENV, str(tmp_path))
    monkeypatch.setenv(config.SDK_TOKEN_ENV, SDK_TOKEN)
    (tmp_path / config.IDENTITY_FILE).write_text(json.dumps({"mac": "02:00:00:ab:cd:ef"}))
    return tmp_path


def run(script, clock=None, verify=None, refresh=None, api_root=API, **kwargs):
    clock = clock or Clock()
    if script.clock is None:
        script.clock = clock
    codes, statuses = [], []
    kwargs.setdefault("random_bytes", lambda n: SECRET[:n])
    result = cp.CodePairing(
        api_root=api_root, transport=script, clock=clock, sleep=clock.sleep,
        verify=verify or Verify(), refresh=refresh or Refresh(), on_code=codes.append,
        on_status=lambda status, seconds: statuses.append((status, seconds)), **kwargs,
    ).run()
    return result, codes, statuses


# --- One-time codes and the link -----------------------------------------------

@pytest.mark.parametrize("c, code", [(0, "J66JQ2A2"), (1, "MG2GGDQN"),
                                     (179251798, "XEPZ97F6"), (179251799, "TW0NCKK8")])
def test_one_time_code_vectors(c, code):
    assert cp.one_time_code(bytes(range(32)), c) == code


def test_counter_steps_every_ten_seconds():
    assert [cp.counter(t) for t in (0, 9.99, 10, 1792516248.5)] == [0, 0, 1, 179251624]


def test_pair_link_round_trips_and_fits_a_version_8_qr_code():
    public = bytes(range(32))
    link = cp.pair_link("homelink-ab12cd", public, "J66JQ2A2")
    assert link == ("https://muse.ai/pair#v=1&n=homelink-ab12cd&k=" + cp.b64url(public)
                    + "&o=J66JQ2A2&m=hatch_link&w=n&g=0&c=1")
    assert cp.parse_pair_link(link) == {"v": "1", "n": "homelink-ab12cd", "k": cp.b64url(public),
                                        "o": "J66JQ2A2", "m": "hatch_link", "w": "n", "g": "0",
                                        "c": "1"}
    assert len(qr.encode(link)) == 17 + 4 * 8
    odd = cp.pair_link("node id/ü&x", public, "J66JQ2A2", model="a b", wifi="r",
                       mgcommands=True, community=False)
    assert "n=node%20id%2F%C3%BC%26x" in odd and "m=a%20b" in odd
    assert cp.parse_pair_link(odd)["n"] == "node id/ü&x"
    assert cp.parse_pair_link(odd)["g"] == "1" and cp.parse_pair_link(odd)["c"] == "0"
    for bad in ("https://muse.ai/pair", "https://muse.ai/pair#v=2&n=a&k=b&o=c&m=d&w=n&g=0&c=1",
                "https://muse.ai/pair#v=1&n=a"):
        with pytest.raises(ValueError):
            cp.parse_pair_link(bad)


def test_fingerprint_format():
    public = bytes(range(32))
    assert cp.fingerprint(public) == hashlib.sha256(public).hexdigest()[:16]


# --- What the device keeps -----------------------------------------------------

def test_keys_are_private_kept_and_replaced_when_unreadable(state):
    first = keys(state)
    path = state / cp.STATE_FILE
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert first.claim_code is None
    assert "code_secret" not in json.loads(path.read_text())
    again = keys(state)
    assert again.public_key == first.public_key
    path.write_text('{"private_key": "short", "code_secret": "x"}')
    assert keys(state).public_key != first.public_key
    cp.delete_keys(state)
    assert not path.exists()


def test_a_claim_code_is_stored_with_the_keys(state):
    first = keys(state)
    with_claim = cp.load_or_create_keys(state, claim_code="C1A1M0DE")
    assert with_claim.public_key == first.public_key and with_claim.claim_code == "C1A1M0DE"
    assert keys(state).claim_code == "C1A1M0DE"
    with pytest.raises(ValueError):
        cp.load_or_create_keys(state, claim_code="ILLEGAL!")


# --- Happy path ------------------------------------------------------------

def test_pairs_binds_the_sdk_token_checks_saves_acks_and_forgets_the_keys(state):
    clock = Clock()
    verify, refresh = Verify(), Refresh()
    k = keys(state)
    script = Script(PENDING, PENDING, drop(state), OK)
    result, codes, statuses = run(script, clock=clock, verify=verify, refresh=refresh)

    assert result == cp.Result(cp.Outcome.PAIRED, None, "Sam")
    assert script.paths() == [cp.POLL_PATH] * 3 + [cp.ACK_PATH]
    expected = [cp.one_time_code(SECRET, n) for n in range(C0, C0 - 6, -1)]
    first = script.polls()[0]
    assert first == {"node_id": NODE, "key_fingerprint": k.fingerprint,
                     "recent_otps": expected, "sdk_token": SDK_TOKEN}
    assert [t for _, _, t in script.calls[:3]] == [T0, T0 + 5, T0 + 10]  # first poll right away

    assert codes[0] == cp.ShownCode(cp.pair_link(NODE, k.public_key, expected[0]), k.fingerprint,
                                    600, C0)
    assert codes[1].counter == C0 + 1  # redrawn when the counter moved
    assert statuses == [(cp.Status.WAITING, None), (cp.Status.APPROVED, None)]

    assert refresh.calls == [("RT-SECRET", NODE, API, SDK_TOKEN)]
    assert verify.calls == [("AT-2", API)]  # the rotated token
    saved = json.loads((state / config.PAIRING_FILE).read_text())
    assert saved == {
        "access_token": "AT-2", "refresh_token": "RT-2", "token_type": "device",
        "username": "Sam", "api_url": "", "api_url_v2": API, "noise_host": "",
        "access_token_saved_at": saved["access_token_saved_at"],
        "sdk_token_hint": SDK_TOKEN[:12],
    }
    # Filed under the newest code of the third poll (counter C0 + 1), acknowledged with it.
    assert script.calls[-1][1] == {"node_id": NODE, "key_fingerprint": k.fingerprint,
                                   "otp": cp.one_time_code(SECRET, C0 + 1),
                                   "ack_nonce": "ACK-NONCE"}
    assert not (state / cp.STATE_FILE).exists()


def test_without_an_sdk_token_there_is_no_binding_refresh(state, monkeypatch):
    monkeypatch.delenv(config.SDK_TOKEN_ENV)
    refresh = Refresh()
    script = Script(drop(state), OK)
    result = run(script, refresh=refresh)[0]
    assert result.outcome is cp.Outcome.PAIRED
    assert refresh.calls == [] and "sdk_token" not in script.polls()[0]
    saved = json.loads((state / config.PAIRING_FILE).read_text())
    assert saved["access_token"] == "AT-SECRET" and saved["sdk_token_hint"] == "none"


def test_no_ack_without_an_ack_nonce_and_no_username_is_fine(state):
    script = Script(drop(state, provision(ack_nonce=None, username=None)))
    assert run(script)[0] == cp.Result(cp.Outcome.PAIRED, None, None)
    assert cp.ACK_PATH not in script.paths()


@pytest.mark.parametrize("ack_answer", [cp.TransportError("down"), (503, {}, {}), (400, {}, {})])
def test_the_ack_answer_does_not_matter(state, ack_answer):
    assert run(Script(drop(state), ack_answer))[0].outcome is cp.Outcome.PAIRED


@pytest.mark.parametrize("api_root, payload_v2, saved_v2", [
    (muse_api.API_BASE, None, ""),
    (API, None, API),
    (API, "https://v2.example.test/", API),
    (API, "http://plain.example.test", API),
])
def test_payload_cannot_override_the_trusted_api_root(state, api_root, payload_v2, saved_v2):
    verify, refresh = Verify(), Refresh()
    script = Script(drop(state, provision(api_url_v2=payload_v2)), OK)
    assert run(script, verify=verify, refresh=refresh, api_root=api_root)[0].outcome is cp.Outcome.PAIRED
    assert script.calls[0][0] == api_root + cp.POLL_PATH
    root = saved_v2 or muse_api.API_BASE
    assert refresh.calls[0][2] == root and verify.calls[0][1] == root
    assert json.loads((state / config.PAIRING_FILE).read_text())["api_url_v2"] == saved_v2


def test_payload_cannot_override_the_noise_gateway(state):
    run(Script(drop(state, provision(noise_host="noise.example.test")), OK))
    assert json.loads((state / config.PAIRING_FILE).read_text())["noise_host"] == ""
    run(Script(drop(state, provision(noise_host="https://evil/path")), OK), force=True)
    assert json.loads((state / config.PAIRING_FILE).read_text())["noise_host"] == ""


def test_a_claim_code_is_presented_after_the_one_time_codes(state):
    script = Script(drop(state, otp="C1A1M0DE"), OK)
    assert run(script, claim_code="C1A1M0DE")[0].outcome is cp.Outcome.PAIRED
    codes = script.polls()[0]["recent_otps"]
    assert len(codes) == 7 and codes[-1] == "C1A1M0DE"
    assert script.calls[-1][1]["otp"] == "C1A1M0DE"
    assert not (state / cp.STATE_FILE).exists()  # deleted with the keys once paired


def test_a_clock_that_starts_at_zero_presents_only_codes_that_exist(state):
    script = Script(drop(state), OK)
    run(script, clock=Clock(t=12.0))
    assert len(script.polls()[0]["recent_otps"]) == 2  # counters 1 and 0


# --- Ignored drops -------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "wrong_aad", "wrong_info", "wrong_key", "tampered", "not_json", "array", "wrong_action",
    "no_access_token", "no_refresh_token", "version",
])
def test_a_drop_that_does_not_open_or_validate_is_ignored(state, bad):
    other = hpke.public_key_bytes(X25519PrivateKey.generate())
    k = keys(state)
    old = cp.one_time_code(SECRET, C0 - 1)
    answer = {
        "wrong_aad": drop(state, otp=old, aad=b"homelink-000000"),
        "wrong_info": drop(state, otp=old, info=b"muse-mailbox-v1"),
        "wrong_key": drop(state, otp=old, key=other),
        "not_json": drop(state, otp=old, raw=b"not json"),
        "array": drop(state, otp=old, raw=b"[1, 2]"),
        "wrong_action": drop(state, provision(action="wifi_scan"), otp=old),
        "no_access_token": drop(state, provision(access_token=None), otp=old),
        "no_refresh_token": drop(state, provision(refresh_token=""), otp=old),
    }.get(bad)
    if bad in ("tampered", "version"):
        def answer(url, body):
            status, data, headers = drop(state, otp=old)(url, body)
            if bad == "tampered":
                ct = bytearray(cp.b64url_decode(data["sealed"]["ct"]))
                ct[0] ^= 1
                data["sealed"]["ct"] = cp.b64url(bytes(ct))
            else:
                data["sealed"]["v"] = 2
            return status, data, headers
    refresh = Refresh()
    script = Script(answer, drop(state), OK)
    result, _, statuses = run(script, refresh=refresh)
    assert result.outcome is cp.Outcome.PAIRED
    polls = script.polls()
    assert old in polls[0]["recent_otps"] and old not in polls[1]["recent_otps"]
    assert (cp.Status.IGNORED, None) in statuses
    assert len(refresh.calls) == 1


@pytest.mark.parametrize("where", ["refresh", "verify"])
def test_a_drop_with_tokens_muse_rejects_is_ignored(state, where):
    # Anyone with the QR code can seal a payload to the device key; Muse rejects its tokens.
    answers = {"refresh": [(None, 401, None)], "verify": []}[where]

    def refresh(*args):
        return answers.pop(0) if answers else Refresh()(*args)

    verify = Verify(([], 401), ([{"vm_url": "wss://vm", "vm_auth_token": "v"}], 200)) \
        if where == "verify" else Verify()
    script = Script(drop(state, provision(access_token="JUNK", refresh_token="JUNK")), drop(state), OK)
    result, _, statuses = run(script, refresh=refresh, verify=verify)
    assert result.outcome is cp.Outcome.PAIRED
    assert (cp.Status.IGNORED, None) in statuses
    assert script.polls()[0]["recent_otps"][0] not in script.polls()[1]["recent_otps"]
    assert json.loads((state / config.PAIRING_FILE).read_text())["refresh_token"] == "RT-2"


def test_a_rejected_drop_never_replaces_an_existing_pairing(state):
    (state / config.PAIRING_FILE).write_text('{"access_token": "kept"}')
    verify = Verify(([], 401))
    result = run(Script(drop(state)), verify=verify, force=True, timeout_s=20)[0]
    assert result.outcome is cp.Outcome.TIMED_OUT
    assert json.loads((state / config.PAIRING_FILE).read_text()) == {"access_token": "kept"}


# --- After opening: SDK token and checks --------------------------------------

@pytest.mark.parametrize("kind, outcome", [
    ("sdkTokenDeviceLimitReached", cp.Outcome.SDK_TOKEN_LIMIT),
    ("sdkTokenInvalid", cp.Outcome.INVALID_SDK_TOKEN),
    ("sdkTokenRevoked", cp.Outcome.INVALID_SDK_TOKEN),
])
def test_an_sdk_token_refusal_on_the_binding_refresh_stays_unpaired(state, kind, outcome):
    script = Script(drop(state))
    result = run(script, refresh=Refresh((None, 403, kind)))[0]
    assert result.outcome is outcome and result.detail
    assert not (state / config.PAIRING_FILE).exists()
    assert cp.ACK_PATH not in script.paths()
    assert (state / cp.STATE_FILE).exists()  # still unpaired: the keys stay


@pytest.mark.parametrize("failure", [(None, None, None), (None, 503, None), (None, 400, None)])
def test_binding_must_succeed_before_verification_or_storage(state, failure):
    verify = Verify()
    script = Script(drop(state))
    result = run(script, refresh=Refresh(failure), verify=verify, timeout_s=20)[0]
    assert result.outcome is cp.Outcome.TIMED_OUT
    assert verify.calls == []
    assert len(script.polls()) == 1
    assert not (state / config.PAIRING_FILE).exists()
    assert (state / cp.STATE_FILE).exists()
    assert cp.ACK_PATH not in script.paths()


def test_verification_retries_keep_rotated_tokens_without_rebinding(state):
    refresh = Refresh()
    verify = Verify(([], None), ([], 502), ([{"vm_url": "wss://vm", "vm_auth_token": "v"}], 200))
    script = Script(drop(state), OK)
    result = run(script, verify=verify, refresh=refresh)[0]
    assert result == cp.Result(cp.Outcome.PAIRED, None, "Sam")
    assert len(refresh.calls) == 1 and len(script.polls()) == 1
    assert verify.calls == [("AT-2", API)] * 3
    assert json.loads((state / config.PAIRING_FILE).read_text())["refresh_token"] == "RT-2"


@pytest.mark.parametrize("answer", [([], None), ([], 502), ([], 200)])
def test_unverified_tokens_never_replace_pairing_or_erase_keys(state, answer):
    old = {"access_token": "kept"}
    (state / config.PAIRING_FILE).write_text(json.dumps(old))
    script = Script(drop(state))
    result = run(script, verify=Verify(answer), force=True, timeout_s=20)[0]
    assert result.outcome is cp.Outcome.TIMED_OUT
    assert json.loads((state / config.PAIRING_FILE).read_text()) == old
    assert (state / cp.STATE_FILE).exists()
    assert cp.ACK_PATH not in script.paths()


def test_successful_but_late_verification_does_not_commit(state):
    clock = Clock()
    def verify(*args):
        clock.t += 30
        return Verify()(*args)
    result = run(Script(drop(state)), verify=verify, clock=clock, timeout_s=20)[0]
    assert result.outcome is cp.Outcome.TIMED_OUT
    assert not (state / config.PAIRING_FILE).exists()


# --- Poll answers ----------------------------------------------------------

def test_slow_down_and_pending_set_the_interval(state):
    clock = Clock()
    script = Script(problem("slow_down", interval=10), problem("authorization_pending"),
                    problem("authorization_pending", interval=7), problem("slow_down"),
                    drop(state), OK)
    result, _, statuses = run(script, clock=clock)
    assert result.outcome is cp.Outcome.PAIRED
    times = [t - T0 for _, _, t in script.calls[:5]]
    assert times == [0, 10, 20, 27, 39]
    assert (cp.Status.SLOW_DOWN, 10.0) in statuses and (cp.Status.SLOW_DOWN, 12.0) in statuses


def test_rate_limited_waits_retry_after(state):
    clock = Clock()
    script = Script(problem("rateLimited", status=429, headers={"retry-after": "30"}),
                    problem("rateLimited", status=429), drop(state), OK)
    assert run(script, clock=clock)[0].outcome is cp.Outcome.PAIRED
    assert [t - T0 for _, _, t in script.calls[:3]] == [0, 30, 90]


def test_transport_errors_and_5xx_back_off_never_faster_than_the_interval(state):
    clock = Clock()
    failures = [cp.TransportError("down"), (503, {}, {}), problem("weird", status=418)] * 2 + \
        [cp.TransportError("down")] * 2
    script = Script(*failures, PENDING, drop(state), OK)
    result, _, statuses = run(script, clock=clock)
    assert result.outcome is cp.Outcome.PAIRED
    times = [t - T0 for _, _, t in script.calls]
    gaps = [b - a for a, b in zip(times, times[1:])][:9]
    assert gaps == [5, 5, 8, 16, 32, 60, 60, 60, 5]
    assert (cp.Status.RETRYING, 60) in statuses
    assert statuses.count((cp.Status.WAITING, None)) == 2  # shown again once Muse answers


def test_unavailable_stays_on_the_code_pairing_route(state):
    script = Script(PENDING, problem("devicePairUnavailable", status=403))
    assert run(script)[0].outcome is cp.Outcome.UNAVAILABLE
    assert (state / cp.STATE_FILE).exists()


def test_invalid_request_fails(state):
    result = run(Script(problem("invalidRequest", detail="recent_otps")))[0]
    assert result == cp.Result(cp.Outcome.FAILED, "Muse refused the request: recent_otps")


# --- The pairing window ------------------------------------------------------------

def test_the_window_closes_after_ten_minutes_and_keeps_the_keys(state):
    clock = Clock()
    script = Script()
    result, codes, _ = run(script, clock=clock)
    assert result.outcome is cp.Outcome.TIMED_OUT
    assert clock.t == T0 + 600
    assert len(script.polls()) == 120
    assert [c.counter for c in codes] == list(range(C0, C0 + 60))
    assert len({c.pair_url for c in codes}) == 60
    assert (state / cp.STATE_FILE).exists()


def test_timeout_shortens_the_window(state):
    clock = Clock()
    assert run(Script(), clock=clock, timeout_s=12)[0].outcome is cp.Outcome.TIMED_OUT
    assert clock.t == T0 + 12


def test_the_qr_code_is_redrawn_on_time_even_when_polls_are_slow(state):
    clock = Clock(t=T0 + 3)
    script = Script(problem("slow_down", interval=30), problem("authorization_pending"))
    _, codes, _ = run(script, clock=clock, timeout_s=40)
    assert [c.counter for c in codes] == [C0, C0 + 1, C0 + 2, C0 + 3, C0 + 4]
    assert [t - T0 for _, _, t in script.calls] == [3, 33]


def test_restart_with_reset_clock_keeps_key_but_never_reuses_codes(state):
    first = Script(PENDING, KeyboardInterrupt())
    result, shown, _ = run(first, clock=Clock(0))
    assert result.outcome is cp.Outcome.INTERRUPTED
    old_code = cp.parse_pair_link(shown[0].pair_url)["o"]
    again = Script(drop(state, otp=old_code), drop(state), OK)
    result, codes, _ = run(again, clock=Clock(0), random_bytes=lambda n: b"Z" * n)
    assert result.outcome is cp.Outcome.PAIRED
    assert codes[0].fingerprint == shown[0].fingerprint
    assert old_code not in again.polls()[0]["recent_otps"]
    assert codes[0].pair_url != shown[0].pair_url
    assert len(again.polls()) == 2  # a server replay of an unrequested code is ignored


def test_a_paired_device_is_left_alone_unless_forced(state):
    (state / config.PAIRING_FILE).write_text('{"access_token": "kept"}')
    script = Script()
    assert run(script)[0].outcome is cp.Outcome.ALREADY_PAIRED
    assert script.calls == [] and not (state / cp.STATE_FILE).exists()
    assert run(Script(drop(state), OK), force=True)[0].outcome is cp.Outcome.PAIRED


def test_an_invalid_local_sdk_token_stops_before_any_request(state, monkeypatch):
    monkeypatch.setenv(config.SDK_TOKEN_ENV, "not-a-token")
    script = Script()
    result = run(script)[0]
    assert result.outcome is cp.Outcome.INVALID_SDK_TOKEN and "not valid" in result.detail
    assert script.calls == []


# --- Secrets -----------------------------------------------------------------------

def test_no_secret_reaches_the_log(state, caplog):
    caplog.set_level(logging.DEBUG)
    k = keys(state)
    script = Script(cp.TransportError("down"), (503, {}, {}), problem("slow_down", interval=6),
                    drop(state, otp=cp.one_time_code(SECRET, C0 - 1), raw=b"junk"),
                    PENDING, drop(state), OK)
    assert run(script, refresh=Refresh())[0].outcome is cp.Outcome.PAIRED
    secrets = ["AT-SECRET", "RT-SECRET", "AT-2", "RT-2", "ACK-NONCE", SDK_TOKEN, SDK_TOKEN[5:],
               cp.b64url(SECRET), cp.b64url(hpke.private_key_bytes(k.private_key))]
    secrets += [code for body in script.polls() for code in body["recent_otps"]]
    assert caplog.text
    for secret in secrets:
        assert secret not in caplog.text


def test_migration_removes_old_code_secret_but_keeps_key_and_claim(state):
    k = cp.load_or_create_keys(state, claim_code="C1A1M0DE")
    data = json.loads((state / cp.STATE_FILE).read_text())
    data["code_secret"] = cp.b64url(SECRET)
    (state / cp.STATE_FILE).write_text(json.dumps(data))
    migrated = cp.load_or_create_keys(state)
    assert migrated.public_key == k.public_key and migrated.claim_code == k.claim_code
    assert "code_secret" not in json.loads((state / cp.STATE_FILE).read_text())


def test_randomness_failure_stays_unpaired_without_requests(state):
    def fail(n):
        raise OSError("unavailable")
    script = Script()
    assert run(script, random_bytes=fail)[0].outcome is cp.Outcome.FAILED
    assert not script.calls
    assert not (state / config.PAIRING_FILE).exists()
