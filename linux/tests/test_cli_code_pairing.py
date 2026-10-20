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

import io

import pytest

from musegadget import cli, muse_api
from musegadget import code_pairing as cp
from musegadget.pair import SETUP_WINDOW_S, PairOutcome, PairResult


def shown(n: int, closes_in: float = 600) -> cp.ShownCode:
    return cp.ShownCode(pair_url=f"https://muse.ai/pair#v=1&n=homelink-abcdef&o=CODE000{n}",
                        fingerprint="300c9c9603b92a4b", closes_in=closes_in, counter=n)


@pytest.fixture
def code_pairing(monkeypatch):
    calls = []

    def fake(outcome=cp.Outcome.PAIRED, detail=None, username=None, statuses=(), codes=(shown(1),)):
        def pair_with_code(**kwargs):
            calls.append(kwargs)
            for code in codes:
                kwargs["on_code"](code)
            for status, seconds in statuses:
                kwargs["on_status"](status, seconds)
            return cp.Result(outcome, detail, username)
        monkeypatch.setattr(cp, "pair_with_code", pair_with_code)
        return calls

    return fake


def test_pair_code_shows_the_qr_code_fingerprint_and_each_pair_url(code_pairing, capsys):
    calls = code_pairing(codes=[shown(1), shown(2, 590)], username="Sam", statuses=[
        (cp.Status.WAITING, None), (cp.Status.SLOW_DOWN, 10.0), (cp.Status.RETRYING, 8.0),
        (cp.Status.RATE_LIMITED, 60.0), (cp.Status.IGNORED, None), (cp.Status.APPROVED, None)])
    assert cli.main(["pair", "--code"]) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert [line for line in lines if line.startswith("pair url: ")] == [
        "pair url: " + shown(1).pair_url, "pair url: " + shown(2).pair_url]
    assert lines.count("key fingerprint: 300c9c9603b92a4b") == 1
    assert out.count("\u2588" * 10) >= 1 and out.count("Pairing stays open for 10 minutes.") == 1
    assert lines[-7:] == [
        "Waiting for approval in the Muse app...",
        "Muse asked to check less often: every 10 s.",
        "Can't reach Muse. Trying again in 8 s.",
        "Muse is busy. Trying again in 60 s.",
        "Ignored something that didn't come from the Muse app. Still waiting...",
        "Approved. Checking the new device token...",
        "Paired to Sam.",
    ]
    assert calls[0]["api_root"] == muse_api.API_BASE
    assert calls[0]["force"] is False and calls[0]["timeout_s"] is None


def test_on_a_terminal_the_qr_code_is_redrawn_in_place():
    stream = io.StringIO()
    stream.isatty = lambda: True
    screen = cli._CodeScreen(stream)
    screen.code(shown(1))
    screen.show_status(cp.Status.WAITING, None)
    screen.code(shown(2))
    out = stream.getvalue()
    assert out.count("\x1b[H\x1b[2J") == 2
    last = out.split("\x1b[H\x1b[2J")[-1]
    assert "\u2588" in last and "pair url: " + shown(2).pair_url in last
    assert "key fingerprint: 300c9c9603b92a4b" in last
    assert last.rstrip().endswith("Waiting for approval in the Muse app...")


def test_paired_without_a_username_and_with_a_note(code_pairing, capsys):
    code_pairing(detail="couldn't reach Muse to check the new device token")
    assert cli.main(["pair", "--code"]) == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines()[-1] == "Paired."
    assert "Note: couldn't reach Muse" in captured.err


def test_pair_code_passes_the_api_url_timeout_and_force(code_pairing):
    calls = code_pairing()
    assert cli.main(["pair", "--code", "--api-url", "http://127.0.0.1:9", "--timeout", "30",
                     "--force"]) == 0
    assert calls[0]["api_root"] == "http://127.0.0.1:9"
    assert calls[0]["timeout_s"] == 30 and calls[0]["force"] is True


def test_a_link_too_long_for_a_qr_code_still_prints_the_link(code_pairing, capsys):
    code_pairing(codes=[cp.ShownCode("https://muse.ai/pair#" + "x" * 300, "300c9c9603b92a4b", 600, 1)])
    assert cli.main(["pair", "--code"]) == 0
    out = capsys.readouterr().out
    assert "\u2588" not in out and "pair url: https://muse.ai/pair#xxx" in out


@pytest.mark.parametrize("outcome, detail, message", [
    (cp.Outcome.UNAVAILABLE, None, "Pair over Bluetooth instead: `musegadget pair`."),
    (cp.Outcome.INVALID_SDK_TOKEN, "the SDK token is not valid", "Can't pair: the SDK token is not valid."),
    (cp.Outcome.SDK_TOKEN_LIMIT, "this SDK token already pairs as many gadgets as it can",
     "Can't pair: this SDK token already pairs as many gadgets as it can."),
    (cp.Outcome.ALREADY_PAIRED, None, "Already paired. Run `musegadget unpair` first, or pass --force."),
    (cp.Outcome.INTERRUPTED, None, "Stopped."),
    (cp.Outcome.TIMED_OUT, None, "Pairing closed without approval."),
    (cp.Outcome.FAILED, "Muse refused the request", "Can't pair: Muse refused the request."),
])
def test_pair_code_failures_exit_1_with_a_reason(code_pairing, capsys, outcome, detail, message):
    code_pairing(outcome=outcome, detail=detail, codes=())
    assert cli.main(["pair", "--code"]) == 1
    assert message in capsys.readouterr().err


def test_api_url_needs_code_and_a_scheme(code_pairing, capsys):
    calls = code_pairing()
    assert cli.main(["pair", "--api-url", "https://x"]) == 1
    assert cli.main(["pair", "--code", "--api-url", "ftp://x"]) == 1
    assert calls == []
    err = capsys.readouterr().err
    assert "--api-url only works with --code." in err and "must start with https://" in err


def test_plain_pair_still_opens_bluetooth_setup(code_pairing, monkeypatch):
    calls = code_pairing()
    seen = []
    monkeypatch.setattr(cli, "pair", lambda **kwargs: seen.append(kwargs) or PairResult(PairOutcome.PAIRED))
    assert cli.main(["pair"]) == 0
    assert calls == [] and seen[0]["timeout_s"] == SETUP_WINDOW_S
    assert cli.main(["pair", "--timeout", "60"]) == 0
    assert seen[1]["timeout_s"] == 60


def test_unpair_forgets_the_code_pairing_keys_too(tmp_path, monkeypatch):
    monkeypatch.setenv("MUSEGADGET_STATE_DIR", str(tmp_path))
    (tmp_path / cp.STATE_FILE).write_text("{}")
    (tmp_path / "pairing.json").write_text("{}")
    assert cli.main(["unpair"]) == 0
    assert not (tmp_path / cp.STATE_FILE).exists() and not (tmp_path / "pairing.json").exists()
