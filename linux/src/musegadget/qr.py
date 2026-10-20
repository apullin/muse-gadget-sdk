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

"""A small QR code encoder and terminal renderer, with no dependencies.

It covers what code pairing needs: byte mode, error correction level M,
versions 1 to 10 (up to 213 bytes), and the eight standard masks scored with
the standard penalty rules. ``encode`` returns the module matrix, ``True`` for
dark; ``render_terminal`` draws it with half-block characters.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

Matrix = List[List[bool]]

MAX_VERSION = 10
QUIET_ZONE = 4

# Level M, per version: (EC codewords per block, [(blocks, data codewords per block), ...]).
_BLOCKS_M = {
    1: (10, [(1, 16)]),
    2: (16, [(1, 28)]),
    3: (26, [(1, 44)]),
    4: (18, [(2, 32)]),
    5: (24, [(2, 43)]),
    6: (16, [(4, 27)]),
    7: (18, [(4, 31)]),
    8: (22, [(2, 38), (2, 39)]),
    9: (22, [(3, 36), (2, 37)]),
    10: (26, [(4, 43), (1, 44)]),
}
_ALIGNMENT = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
    7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
}
_FORMAT_BITS_M = 0b00  # the error correction level field for M
_MODE_BYTE = 0b0100


def _size(version: int) -> int:
    return 17 + 4 * version


def _data_capacity(version: int) -> int:
    return sum(count * size for count, size in _BLOCKS_M[version][1])


def _count_bits(version: int) -> int:
    return 8 if version <= 9 else 16


def _fits(version: int, length: int) -> bool:
    return 4 + _count_bits(version) + 8 * length <= 8 * _data_capacity(version)


# --- Reed-Solomon over GF(256), polynomial 0x11D --------------------------

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _rs_generator(degree: int) -> List[int]:
    """Coefficients of prod(x - a^i), i < degree, highest power first, leading 1 dropped."""
    poly = [1]
    for i in range(degree):
        nxt = [0] * (len(poly) + 1)
        for j, coef in enumerate(poly):
            nxt[j] ^= coef
            nxt[j + 1] ^= _gf_mul(coef, _EXP[i])
        poly = nxt
    return poly[1:]


def _rs_remainder(data: Sequence[int], degree: int) -> List[int]:
    gen = _rs_generator(degree)
    rem = [0] * degree
    for byte in data:
        factor = byte ^ rem[0]
        rem = rem[1:] + [0]
        for i, coef in enumerate(gen):
            rem[i] ^= _gf_mul(coef, factor)
    return rem


# --- Codewords -------------------------------------------------------------

def _codewords(data: bytes, version: int) -> List[int]:
    bits: List[int] = []

    def put(value: int, length: int) -> None:
        bits.extend((value >> i) & 1 for i in range(length - 1, -1, -1))

    put(_MODE_BYTE, 4)
    put(len(data), _count_bits(version))
    for byte in data:
        put(byte, 8)
    capacity = 8 * _data_capacity(version)
    put(0, min(4, capacity - len(bits)))
    put(0, -len(bits) % 8)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(words) < capacity // 8:
        words.append(pad)
        pad ^= 0xEC ^ 0x11

    ec_len, groups = _BLOCKS_M[version]
    blocks: List[List[int]] = []
    offset = 0
    for count, size in groups:
        for _ in range(count):
            blocks.append(words[offset:offset + size])
            offset += size
    ecs = [_rs_remainder(block, ec_len) for block in blocks]
    out: List[int] = []
    for i in range(max(len(b) for b in blocks)):
        out.extend(block[i] for block in blocks if i < len(block))
    for i in range(ec_len):
        out.extend(ec[i] for ec in ecs)
    return out


# --- Matrix ---------------------------------------------------------------

class _Builder:
    def __init__(self, version: int):
        self.version = version
        self.size = _size(version)
        self.dark: Matrix = [[False] * self.size for _ in range(self.size)]
        self.function = [[False] * self.size for _ in range(self.size)]
        self._draw_function_patterns()

    def _set(self, row: int, col: int, dark: bool) -> None:
        self.dark[row][col] = dark
        self.function[row][col] = True

    def _draw_function_patterns(self) -> None:
        n = self.size
        for i in range(n):
            self._set(6, i, i % 2 == 0)
            self._set(i, 6, i % 2 == 0)
        for row, col in ((3, 3), (3, n - 4), (n - 4, 3)):
            for dr in range(-4, 5):
                for dc in range(-4, 5):
                    r, c = row + dr, col + dc
                    if 0 <= r < n and 0 <= c < n:
                        self._set(r, c, max(abs(dr), abs(dc)) not in (2, 4))
        centers = _ALIGNMENT[self.version]
        last = len(centers) - 1
        for i, row in enumerate(centers):
            for j, col in enumerate(centers):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dr in range(-2, 3):
                    for dc in range(-2, 3):
                        self._set(row + dr, col + dc, max(abs(dr), abs(dc)) != 1)
        self.draw_format(0)  # reserves the format areas; redrawn per mask
        if self.version >= 7:
            rem = self.version
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            bits = self.version << 12 | rem
            for i in range(18):
                bit = bool((bits >> i) & 1)
                a, b = n - 11 + i % 3, i // 3
                self._set(b, a, bit)
                self._set(a, b, bit)

    def draw_format(self, mask: int) -> None:
        n = self.size
        data = _FORMAT_BITS_M << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412

        def bit(i: int) -> bool:
            return bool((bits >> i) & 1)

        for i in range(6):
            self._set(i, 8, bit(i))
        self._set(7, 8, bit(6))
        self._set(8, 8, bit(7))
        self._set(8, 7, bit(8))
        for i in range(9, 15):
            self._set(8, 14 - i, bit(i))
        for i in range(8):
            self._set(8, n - 1 - i, bit(i))
        for i in range(8, 15):
            self._set(n - 15 + i, 8, bit(i))
        self._set(n - 8, 8, True)  # the dark module

    def draw_codewords(self, words: Sequence[int]) -> None:
        n = self.size
        total = len(words) * 8
        i = 0
        right = n - 1
        while right >= 1:
            if right == 6:
                right = 5
            upward = ((right + 1) & 2) == 0
            for vert in range(n):
                row = n - 1 - vert if upward else vert
                for col in (right, right - 1):
                    if not self.function[row][col] and i < total:
                        self.dark[row][col] = bool((words[i >> 3] >> (7 - (i & 7))) & 1)
                        i += 1
            right -= 2

    def masked(self, mask: int) -> Matrix:
        self.draw_format(mask)
        out = [row[:] for row in self.dark]
        for r in range(self.size):
            for c in range(self.size):
                if not self.function[r][c] and _MASKS[mask](r, c):
                    out[r][c] = not out[r][c]
        return out


_MASKS = [
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]

_FINDER_LIKE = (
    [True, False, True, True, True, False, True, False, False, False, False],
    [False, False, False, False, True, False, True, True, True, False, True],
)


def penalty(matrix: Matrix) -> int:
    """The standard mask penalty score: runs, 2x2 blocks, finder-like patterns, balance."""
    n = len(matrix)
    lines = [list(row) for row in matrix] + [[matrix[r][c] for r in range(n)] for c in range(n)]
    score = 0
    for line in lines:
        run = 1
        for i in range(1, n + 1):
            if i < n and line[i] == line[i - 1]:
                run += 1
                continue
            if run >= 5:
                score += 3 + (run - 5)
            run = 1
        for i in range(n - 10):
            if line[i:i + 11] in _FINDER_LIKE:
                score += 40
    for r in range(n - 1):
        for c in range(n - 1):
            if matrix[r][c] == matrix[r][c + 1] == matrix[r + 1][c] == matrix[r + 1][c + 1]:
                score += 3
    dark = sum(sum(row) for row in matrix)
    score += 10 * (abs(dark * 100 // (n * n) - 50) // 5)
    return score


def encode(data: bytes | str, *, version: Optional[int] = None,
           mask: Optional[int] = None) -> Matrix:
    """The QR code for ``data`` in byte mode at level M, without a quiet zone.

    ``version`` and ``mask`` default to the smallest version that fits and the
    mask with the lowest penalty. Raises ValueError if ``data`` doesn't fit in
    version 10 (213 bytes) or in the requested version.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if version is None:
        version = next((v for v in range(1, MAX_VERSION + 1) if _fits(v, len(data))), None)
        if version is None:
            raise ValueError(f"{len(data)} bytes don't fit in a version {MAX_VERSION} QR code")
    elif not 1 <= version <= MAX_VERSION or not _fits(version, len(data)):
        raise ValueError(f"{len(data)} bytes don't fit in a version {version} QR code")
    if mask is not None and not 0 <= mask <= 7:
        raise ValueError("mask must be 0 to 7")

    builder = _Builder(version)
    builder.draw_codewords(_codewords(data, version))
    if mask is not None:
        return builder.masked(mask)
    candidates = [builder.masked(m) for m in range(8)]
    return min(candidates, key=penalty)  # min keeps the lowest mask number on a tie


def render_terminal(matrix: Matrix, *, invert: bool = False) -> str:
    """Draw ``matrix`` with half-block characters, two module rows per text line.

    Light modules and the 4-module quiet zone are drawn as filled blocks and
    dark modules as spaces, so the code reads correctly in a terminal with
    light text on a dark background. Pass ``invert=True`` for dark text on a
    light background.
    """
    n = len(matrix)
    full = n + 2 * QUIET_ZONE

    def light(r: int, c: int) -> bool:
        r -= QUIET_ZONE
        c -= QUIET_ZONE
        inside = 0 <= r < n and 0 <= c < n
        is_light = not (inside and matrix[r][c])
        return is_light != invert

    glyphs = {(True, True): "\u2588", (True, False): "\u2580",
              (False, True): "\u2584", (False, False): " "}
    lines = []
    for r in range(0, full, 2):
        lines.append("".join(
            glyphs[(light(r, c), light(r + 1, c) if r + 1 < full else False)]
            for c in range(full)
        ))
    return "\n".join(lines)
