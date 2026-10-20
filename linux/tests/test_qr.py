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

import random

import pytest

from musegadget import qr

INPUTS = [
    b"https://muse.ai/pair?code=WDJBMJHT",
    b"http://127.0.0.1:43211/pair?code=0123ABCD",
    b"a",
    "https://muse.ai/pair?code=\u00e9t\u00e9".encode("utf-8"),
    bytes(range(256))[:120],
    b"x" * 213,  # the most version 10 holds at level M
]


def _smallest_version(length: int) -> int:
    return next(v for v in range(1, qr.MAX_VERSION + 1) if qr._fits(v, length))


def _reference(data: bytes, version: int, mask: int) -> list:
    qrcode = pytest.importorskip("qrcode")
    import qrcode.util

    code = qrcode.QRCode(version=version, error_correction=qrcode.constants.ERROR_CORRECT_M,
                         border=0, mask_pattern=mask)
    code.add_data(qrcode.util.QRData(data, mode=qrcode.util.MODE_8BIT_BYTE))
    code.make(fit=False)
    return [[bool(m) for m in row] for row in code.modules]


@pytest.mark.parametrize("data", INPUTS, ids=lambda d: f"{len(d)}B")
@pytest.mark.parametrize("mask", range(8))
def test_matches_the_qrcode_package_for_every_mask(data, mask):
    version = _smallest_version(len(data))
    assert qr.encode(data, version=version, mask=mask) == _reference(data, version, mask)


def test_matches_the_qrcode_package_for_random_data_and_every_version():
    rng = random.Random(7)
    for version in range(1, qr.MAX_VERSION + 1):
        capacity = max(n for n in range(300) if qr._fits(version, n))
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, capacity + 1)))
        mask = rng.randrange(8)
        assert qr.encode(data, version=version, mask=mask) == _reference(data, version, mask), version


def test_the_penalty_matches_the_qrcode_package():
    pytest.importorskip("qrcode")
    from qrcode.util import lost_point

    data = INPUTS[0]
    for mask in range(8):
        matrix = qr.encode(data, version=3, mask=mask)
        assert qr.penalty(matrix) == lost_point(matrix)


def test_picks_the_smallest_version_and_the_lowest_penalty_mask():
    data = INPUTS[0]  # 35 bytes: version 3 at level M
    matrix = qr.encode(data)
    assert len(matrix) == 29
    scores = [qr.penalty(qr.encode(data, version=3, mask=m)) for m in range(8)]
    assert qr.penalty(matrix) == min(scores)
    assert matrix == qr.encode(data, version=3, mask=scores.index(min(scores)))


def test_accepts_text_as_utf8():
    assert qr.encode("https://muse.ai/pair?code=WDJBMJHT") == qr.encode(INPUTS[0])


def test_refuses_data_that_does_not_fit():
    with pytest.raises(ValueError):
        qr.encode(b"x" * 214)
    with pytest.raises(ValueError):
        qr.encode(b"x" * 20, version=1)
    with pytest.raises(ValueError):
        qr.encode(b"x", mask=8)


def test_terminal_rendering_has_a_quiet_zone_and_two_rows_per_line():
    matrix = qr.encode(b"a")  # version 1: 21 modules
    lines = qr.render_terminal(matrix).split("\n")
    width = 21 + 2 * qr.QUIET_ZONE
    assert len(lines) == (width + 1) // 2
    assert all(len(line) == width for line in lines)
    assert lines[0] == lines[1] == "\u2588" * width       # quiet zone, light
    assert lines[-1] == "\u2580" * width                  # last half row
    # The top-left finder's dark border starts after the quiet zone.
    assert lines[2][:qr.QUIET_ZONE] == "\u2588" * qr.QUIET_ZONE
    assert lines[2][qr.QUIET_ZONE] in (" ", "\u2584")


def test_terminal_rendering_round_trips_and_inverts():
    matrix = qr.encode(INPUTS[0])
    n = len(matrix)

    def decode(text: str, invert: bool) -> list:
        halves = {"\u2588": (True, True), "\u2580": (True, False),
                  "\u2584": (False, True), " ": (False, False)}
        rows = []
        for line in text.split("\n"):
            pairs = [halves[ch] for ch in line]
            rows.append([p[0] for p in pairs])
            rows.append([p[1] for p in pairs])
        q = qr.QUIET_ZONE
        drawn = [row[q:q + n] for row in rows[q:q + n]]
        return [[d if invert else not d for d in row] for row in drawn]

    assert decode(qr.render_terminal(matrix), invert=False) == matrix
    assert decode(qr.render_terminal(matrix, invert=True), invert=True) == matrix
