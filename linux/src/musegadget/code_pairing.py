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

"""Code pairing: pair with Muse without Bluetooth, as a sealed drop.

The device shows a QR code with its node id, its X25519 public key and a
one-time code that changes every 10 seconds; it needs nothing from the server
for that. The person scans it in the Muse app, which mints the device's
tokens, seals them to the device's key with HPKE and drops the ciphertext on
the Muse server, filed under the node id, the key fingerprint and the code it
scanned. The device polls with its last few codes, opens what it gets, checks
the tokens and saves them where Bluetooth setup does. The protocol is in
``docs/code-pairing.md`` at the top of the repository.

The key pair and the code secret live in ``code_pairing.json`` in the state
directory. They are created when the device is unpaired and has none, kept
across restarts, and deleted once it pairs (and by ``musegadget unpair``), so
the next pairing starts with fresh ones.

Nothing here logs the key, the code secret, one-time codes, a sealed payload
or tokens.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import hmac
import json
import logging
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from musegadget import config, hpke, identity, muse_api
from musegadget.pairing import PAIRING_MODEL

log = logging.getLogger(__name__)

POLL_PATH = "/device_drop/poll"
ACK_PATH = "/device_drop/ack"
STATE_FILE = "code_pairing.json"
PAIR_LINK_BASE = "https://muse.ai/pair"
PAYLOAD_INFO = b"muse-drop-v1"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

STEP_S = 10                     # a new one-time code every 10 seconds
RECENT_CODES = 6                # c, c-1, ... c-5: the last 60 seconds
WINDOW_S = 600.0                # pairing stays open for 10 minutes
DEFAULT_INTERVAL_S = 5.0
MIN_INTERVAL_S = 0.1            # never poll faster, whatever the server says
SLOW_DOWN_STEP_S = 5.0          # add 5 s when slow_down has no interval
DEFAULT_RETRY_AFTER_S = 60.0
BACKOFF_MIN_S = 2.0
BACKOFF_MAX_S = 60.0
VERIFY_ATTEMPTS = 3
SDK_TOKEN_REFUSALS = ("sdkTokenDeviceLimitReached", "sdkTokenInvalid", "sdkTokenRevoked")


class Outcome(enum.Enum):
    PAIRED = "paired"
    UNAVAILABLE = "unavailable"              # code pairing is off: use Bluetooth setup
    INVALID_SDK_TOKEN = "invalid_sdk_token"  # malformed, unknown or revoked SDK token
    SDK_TOKEN_LIMIT = "sdk_token_limit"      # the SDK token pairs its maximum number of gadgets
    ALREADY_PAIRED = "already_paired"        # pass force=True to pair again
    INTERRUPTED = "interrupted"              # Ctrl-C; the key and code secret are kept
    TIMED_OUT = "timed_out"                  # the pairing window closed without a payload
    FAILED = "failed"                        # Muse refused the request


@dataclass(frozen=True)
class Result:
    outcome: Outcome
    detail: Optional[str] = None    # a short reason a person can read, never a secret
    username: Optional[str] = None  # who the device paired to, when Muse says


class Status(enum.Enum):
    WAITING = "waiting"            # QR code shown, waiting for the Muse app
    SLOW_DOWN = "slow_down"        # Muse asked for a longer interval; seconds = new interval
    RETRYING = "retrying"          # Muse unreachable or failing; seconds = delay
    RATE_LIMITED = "rate_limited"  # seconds = delay
    IGNORED = "ignored"            # a payload that didn't open or didn't work; still waiting
    APPROVED = "approved"          # a payload opened; checking its tokens


@dataclass(frozen=True)
class ShownCode:
    """What to show while pairing. ``pair_url`` changes every 10 seconds."""

    pair_url: str          # what the QR code holds
    fingerprint: str
    closes_in: float       # seconds until the pairing window closes
    counter: int


class TransportError(Exception):
    """No HTTP answer: DNS, connection, TLS or timeout."""


# Transport: (url, json body) -> (status, json body or {}, headers with lower-case names).
Transport = Callable[[str, dict], Tuple[int, dict, Dict[str, str]]]
# Refresh: (refresh_token, device_id, root, sdk_token) -> (tokens, status, problem type).
Refresh = Callable[[str, str, str, Optional[str]], Tuple[Optional[dict], Optional[int], Optional[str]]]


def urllib_transport(url: str, body: dict) -> Tuple[int, dict, Dict[str, str]]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, application/problem+json")
    req.add_header("X-API-Version", "1.0.0")
    req.add_header("User-Agent", muse_api.user_agent())
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status, raw, headers = resp.getcode(), resp.read(), resp.headers
    except urllib.error.HTTPError as exc:
        status, headers = exc.code, exc.headers
        try:
            raw = exc.read()
        except OSError:
            raw = b""
    except (urllib.error.URLError, OSError) as exc:
        raise TransportError(str(getattr(exc, "reason", exc))) from None
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        data = {}
    lower = {k.lower(): v for k, v in (headers.items() if headers is not None else [])}
    return status, data if isinstance(data, dict) else {}, lower


# --- Encoding, codes and the QR link ---------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: object) -> bytes:
    if not isinstance(text, str) or "=" in text or not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError("not unpadded base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fingerprint(public_key: bytes) -> str:
    """First 8 bytes of SHA-256 over the 32-byte public key, as 16 lowercase hex characters."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def counter(t: float) -> int:
    """The one-time-code counter for clock time ``t``: ``floor(t / 10)``."""
    return math.floor(t / STEP_S)


def one_time_code(code_secret: bytes, c: int) -> str:
    """HOTP with HMAC-SHA256, as 8 Crockford base32 characters (40 bits)."""
    h = hmac.new(code_secret, c.to_bytes(8, "big"), hashlib.sha256).digest()
    o = h[31] & 0x0F
    v = int.from_bytes(h[o:o + 5], "big")
    return "".join(CROCKFORD[(v >> shift) & 0x1F] for shift in range(35, -1, -5))


def is_code(text: object) -> bool:
    return isinstance(text, str) and len(text) == 8 and all(ch in CROCKFORD for ch in text)


def pair_link(node_id: str, public_key: bytes, code: str, *, model: str = PAIRING_MODEL,
              wifi: str = "n", mgcommands: bool = False, community: bool = True,
              base: str = PAIR_LINK_BASE) -> str:
    """The QR code's text: ``<base>#v=1&n=…&k=…&o=…&m=…&w=…&g=…&c=…``."""
    params = [("v", "1"), ("n", node_id), ("k", b64url(public_key)), ("o", code), ("m", model),
              ("w", wifi), ("g", "1" if mgcommands else "0"), ("c", "1" if community else "0")]
    return base + "#" + "&".join(
        f"{key}={urllib.parse.quote(value, safe='-_.')}" for key, value in params)


def parse_pair_link(link: str) -> Dict[str, str]:
    """The parameters of a QR link, decoded; raises ValueError if it isn't one."""
    _, sep, fragment = link.partition("#")
    if not sep:
        raise ValueError("no fragment")
    params = dict(urllib.parse.parse_qsl(fragment, keep_blank_values=True, strict_parsing=True))
    if params.get("v") != "1" or not all(params.get(key) for key in "nkomwgc"):
        raise ValueError("not a version 1 pairing link")
    return params


def seal_json(public_key: bytes, info: bytes, aad: bytes, message: dict) -> dict:
    """``message`` sealed as a ``{"v": 1, "enc", "ct"}`` object."""
    enc, ct = hpke.seal(public_key, info, aad, json.dumps(message).encode("utf-8"))
    return {"v": 1, "enc": b64url(enc), "ct": b64url(ct)}


def open_json(private_key: X25519PrivateKey, info: bytes, aad: bytes, sealed: object) -> dict:
    """Open a ``{"v": 1, "enc", "ct"}`` object into a JSON object; raises ValueError."""
    if not isinstance(sealed, dict) or sealed.get("v") != 1:
        raise ValueError("not a version 1 sealed object")
    try:
        plaintext = hpke.open(private_key, b64url_decode(sealed.get("enc")), info, aad,
                              b64url_decode(sealed.get("ct")))
    except hpke.OpenError as exc:
        raise ValueError(str(exc)) from None
    message = json.loads(plaintext.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("not a JSON object")
    return message


# --- What the device keeps ---------------------------------------------------

@dataclass(frozen=True)
class PairingKeys:
    private_key: X25519PrivateKey
    code_secret: bytes
    claim_code: Optional[str] = None

    @property
    def public_key(self) -> bytes:
        return hpke.public_key_bytes(self.private_key)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)


def load_or_create_keys(directory: Optional[Path] = None,
                        claim_code: Optional[str] = None) -> PairingKeys:
    """The key pair and code secret, created when missing; ``claim_code`` is stored if given."""
    if claim_code is not None and not is_code(claim_code):
        raise ValueError("a claim code is 8 characters from 0-9 and A-Z without I, L, O and U")
    data = config.load_json(STATE_FILE, directory) or {}
    keys = None
    try:
        private = b64url_decode(data.get("private_key"))
        secret = b64url_decode(data.get("code_secret"))
        stored_claim = data.get("claim_code")
        if len(private) == 32 and len(secret) == 32:
            keys = PairingKeys(X25519PrivateKey.from_private_bytes(private), secret,
                               stored_claim if is_code(stored_claim) else None)
    except (ValueError, TypeError):
        keys = None
    if keys is not None and (claim_code is None or claim_code == keys.claim_code):
        return keys
    if keys is None:
        if data:
            log.warning("code pairing keys unreadable; making new ones")
        keys = PairingKeys(X25519PrivateKey.generate(), os.urandom(32), claim_code)
    else:
        keys = PairingKeys(keys.private_key, keys.code_secret, claim_code)
    record = {"private_key": b64url(hpke.private_key_bytes(keys.private_key)),
              "code_secret": b64url(keys.code_secret)}
    if keys.claim_code:
        record["claim_code"] = keys.claim_code
    config.save_json(STATE_FILE, record, directory)
    return keys


def delete_keys(directory: Optional[Path] = None) -> None:
    config.delete_json(STATE_FILE, directory)


# --- The run -------------------------------------------------------------------

def _interval(value: object, default: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return default
    return max(float(value), MIN_INTERVAL_S)


def _retry_after(headers: Dict[str, str]) -> float:
    try:
        return max(float(headers.get("retry-after", "")), 0.0)
    except ValueError:
        return DEFAULT_RETRY_AFTER_S


def _backoff(failures: int) -> float:
    return min(BACKOFF_MAX_S, BACKOFF_MIN_S * 2 ** max(failures - 1, 0))


def _payload_ok(payload: dict) -> bool:
    return (payload.get("action") == "provision_v2"
            and isinstance(payload.get("access_token"), str) and bool(payload["access_token"])
            and isinstance(payload.get("refresh_token"), str) and bool(payload["refresh_token"]))


class _Done(Exception):
    def __init__(self, result: Result):
        super().__init__(result.outcome.value)
        self.result = result


class CodePairing:
    """One pairing window: show the QR code and poll until paired or the window closes.

    ``clock`` is the time the one-time codes count (any steadily advancing
    clock, in seconds), ``sleep`` waits, ``transport`` does one POST, and
    ``verify`` and ``refresh`` stand for ``fetch_vms`` and the token refresh;
    tests replace them all. ``on_code`` runs whenever the QR code changes,
    ``on_status`` on each change worth telling the person about.
    """

    def __init__(
        self,
        *,
        api_root: str = muse_api.API_BASE,
        on_code: Callable[[ShownCode], None] = lambda code: None,
        on_status: Callable[[Status, Optional[float]], None] = lambda status, seconds: None,
        force: bool = False,
        timeout_s: Optional[float] = None,
        interval_s: float = DEFAULT_INTERVAL_S,
        transport: Transport = urllib_transport,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        verify: Callable[[str, str], Tuple[list, Optional[int]]] = muse_api.fetch_vms_with_status,
        refresh: Refresh = muse_api.refresh_device_token_detailed,
        claim_code: Optional[str] = None,
        directory: Optional[Path] = None,
    ):
        self.api_root = api_root.rstrip("/")
        self.on_code = on_code
        self.on_status = on_status
        self.force = force
        self.window_s = WINDOW_S if timeout_s is None else float(timeout_s)
        self.interval = max(float(interval_s), MIN_INTERVAL_S)
        self.transport = transport
        self.clock = clock
        self.sleep = sleep
        self.verify = verify
        self.refresh = refresh
        self.claim_code = claim_code
        self.directory = directory

    def run(self) -> Result:
        if config.load_json(config.PAIRING_FILE, self.directory) and not self.force:
            return Result(Outcome.ALREADY_PAIRED)
        try:
            self._sdk_token = config.sdk_token(self.directory)
        except ValueError as exc:
            return Result(Outcome.INVALID_SDK_TOKEN, str(exc))
        self._node_id = identity.load_or_create(self.directory).node_id
        self._keys = load_or_create_keys(self.directory, self.claim_code)
        self._rejected: set = set()
        try:
            return self._run()
        except _Done as done:
            return done.result
        except KeyboardInterrupt:
            log.info("code pairing: interrupted")
            return Result(Outcome.INTERRUPTED)

    # -- the loop --

    def _link(self, c: int) -> str:
        return pair_link(self._node_id, self._keys.public_key,
                         one_time_code(self._keys.code_secret, c))

    def _recent_codes(self, c: int) -> List[str]:
        codes = [one_time_code(self._keys.code_secret, n) for n in range(c, c - RECENT_CODES, -1)
                 if n >= 0]
        if self._keys.claim_code:
            codes.append(self._keys.claim_code)
        return [code for code in codes if code not in self._rejected]

    def _run(self) -> Result:
        start = self.clock()
        closes_at = start + self.window_s
        next_poll = start       # the first poll goes out right away
        shown: Optional[int] = None
        self._failures = 0
        log.info("code pairing: open for %d s, key %s", int(self.window_s), self._keys.fingerprint)
        while True:
            now = self.clock()
            if now >= closes_at:
                log.info("code pairing: window closed")
                return Result(Outcome.TIMED_OUT)
            c = counter(now)
            if c != shown:
                self.on_code(ShownCode(self._link(c), self._keys.fingerprint, closes_at - now, c))
                if shown is None:
                    self.on_status(Status.WAITING, None)
                shown = c
            if now >= next_poll:
                next_poll = now + self._poll(c)
                continue
            wake = min(next_poll, (c + 1) * STEP_S, closes_at)
            self.sleep(max(wake - now, 0.0))

    def _poll(self, c: int) -> float:
        """Poll once; returns the seconds until the next poll."""
        codes = self._recent_codes(c)
        if not codes:
            return self.interval
        body = {"node_id": self._node_id, "key_fingerprint": self._keys.fingerprint,
                "recent_otps": codes}
        if self._sdk_token:
            body["sdk_token"] = self._sdk_token
        try:
            status, data, headers = self.transport(self.api_root + POLL_PATH, body)
        except TransportError as exc:
            return self._retry(f"can't reach Muse ({exc})")
        kind = data.get("type")
        if status >= 500:
            return self._retry(f"Muse answered HTTP {status}")
        if status == 200 and "sealed" in data:
            self._failures = 0
            self._deliver(data["sealed"], data.get("otp"))
            return self.interval
        if status == 429 or kind == "rateLimited":
            self._failures = 0
            delay = max(self.interval, _retry_after(headers))
            log.warning("code pairing: rate limited; polling again in %d s", delay)
            self.on_status(Status.RATE_LIMITED, delay)
            return delay
        if kind == "devicePairUnavailable":
            log.info("code pairing: not available; use Bluetooth setup")
            raise _Done(Result(Outcome.UNAVAILABLE))
        if kind == "invalidRequest":
            detail = data.get("detail") if isinstance(data.get("detail"), str) else ""
            log.error("code pairing: Muse refused the poll: %s", detail[:200])
            raise _Done(Result(Outcome.FAILED, "Muse refused the request"
                               + (f": {detail[:200]}" if detail else "")))
        if kind == "slow_down":
            self._failures = 0
            self.interval = _interval(data.get("interval"), self.interval + SLOW_DOWN_STEP_S)
            log.info("code pairing: asked to slow down; polling every %g s", self.interval)
            self.on_status(Status.SLOW_DOWN, self.interval)
            return self.interval
        if kind == "authorization_pending":
            if self._failures:
                self.on_status(Status.WAITING, None)
            self._failures = 0
            self.interval = _interval(data.get("interval"), self.interval)
            return self.interval
        return self._retry(f"unexpected answer (HTTP {status}, "
                           f"{kind if isinstance(kind, str) else 'no type'})")

    def _retry(self, why: str) -> float:
        self._failures += 1
        delay = max(self.interval, _backoff(self._failures))
        log.warning("code pairing: %s; retrying in %d s", why, delay)
        self.on_status(Status.RETRYING, delay)
        return delay

    # -- a drop arrived --

    def _ignore(self, otp: object, why: str) -> None:
        # Anyone who saw the QR code can drop something under its code. Stop
        # presenting that code, so the next poll can reach a drop under another.
        if is_code(otp):
            self._rejected.add(otp)
        log.warning("code pairing: ignored a payload that %s; still waiting", why)
        self.on_status(Status.IGNORED, None)

    def _deliver(self, sealed: object, otp: object) -> None:
        try:
            payload = open_json(self._keys.private_key, PAYLOAD_INFO,
                                self._node_id.encode("ascii"), sealed)
        except (ValueError, UnicodeDecodeError):
            return self._ignore(otp, "didn't open")
        if not _payload_ok(payload):
            return self._ignore(otp, "isn't a token provisioning message")
        log.info("code pairing: payload opened; checking the tokens")
        self.on_status(Status.APPROVED, None)
        self._finish(payload, otp)

    def _finish(self, payload: dict, otp: object) -> None:
        response_v2 = payload.get("api_url_v2")
        if isinstance(response_v2, str) and response_v2.startswith("https://"):
            api_url_v2 = response_v2.rstrip("/")
        elif self.api_root != muse_api.API_BASE:
            api_url_v2 = self.api_root
        else:
            api_url_v2 = ""
        noise_host = payload.get("noise_host")
        if not (isinstance(noise_host, str) and re.fullmatch(r"[A-Za-z0-9.-]+(:[0-9]+)?", noise_host)):
            noise_host = ""
        username = payload.get("username")
        username = username if isinstance(username, str) else ""
        root = muse_api.api_root(api_url_v2)
        access, refresh_token = payload["access_token"], payload["refresh_token"]

        # Community gadgets: one refresh with the SDK token binds it to this device.
        if self._sdk_token:
            tokens, status, kind = self.refresh(refresh_token, self._node_id, root, self._sdk_token)
            if tokens:
                access, refresh_token = tokens["access_token"], tokens["refresh_token"]
                log.info("code pairing: SDK token recorded")
            elif kind in SDK_TOKEN_REFUSALS:
                log.warning("code pairing: Muse refused the SDK token (%s); staying unpaired", kind)
                outcome = Outcome.SDK_TOKEN_LIMIT if kind == "sdkTokenDeviceLimitReached" \
                    else Outcome.INVALID_SDK_TOKEN
                detail = ("this SDK token already pairs as many gadgets as it can"
                          if outcome is Outcome.SDK_TOKEN_LIMIT
                          else "Muse doesn't accept this SDK token; check it at gadgets.muse.ai")
                raise _Done(Result(outcome, detail))
            elif status in (401, 403):
                return self._ignore(otp, f"carried tokens Muse rejected (HTTP {status})")
            else:
                # Includes a Muse that doesn't take sdk_token on refresh yet: the
                # fetch_vms check below still vets the tokens.
                log.warning("code pairing: couldn't record the SDK token now (%s); "
                            "the service will on its next refresh", kind or status or "no answer")

        checked = False
        for attempt in range(1, VERIFY_ATTEMPTS + 1):
            vms, status = self.verify(access, root)
            if vms:
                checked = True
                break
            if status is not None and status < 500:
                return self._ignore(otp, f"carried tokens Muse rejected (HTTP {status})")
            if attempt < VERIFY_ATTEMPTS:
                self.sleep(_backoff(attempt))
        if not checked:
            log.warning("code pairing: couldn't reach Muse to check the tokens; saving them anyway")

        config.save_json(config.PAIRING_FILE, {
            "access_token": access,
            "refresh_token": refresh_token,
            "token_type": "device",
            "username": username,
            "api_url": "",
            "api_url_v2": api_url_v2,
            "noise_host": noise_host,
            "access_token_saved_at": int(time.time()),
            # Muse records the SDK token only at pairing; see Service.
            "sdk_token_hint": config.sdk_token_hint(self._sdk_token),
        }, self.directory)
        self._ack(payload, otp)
        delete_keys(self.directory)
        log.info("code pairing: paired")
        raise _Done(Result(
            Outcome.PAIRED,
            None if checked else "couldn't reach Muse to check the new device token; "
                                 "the service will keep trying",
            username or None))

    def _ack(self, payload: dict, otp: object) -> None:
        """Delete the drop. Optional and best effort: its answer doesn't matter."""
        nonce = payload.get("ack_nonce")
        if not isinstance(nonce, str) or not nonce or not is_code(otp):
            return
        body = {"node_id": self._node_id, "key_fingerprint": self._keys.fingerprint,
                "otp": otp, "ack_nonce": nonce}
        try:
            status, _, _ = self.transport(self.api_root + ACK_PATH, body)
        except TransportError as exc:
            log.warning("code pairing: acknowledgement not sent (%s)", exc)
            return
        if status == 200:
            log.info("code pairing: acknowledged")
        else:
            log.warning("code pairing: acknowledgement answered HTTP %d", status)


def pair_with_code(**kwargs) -> Result:
    """Run code pairing once; see ``CodePairing`` for the arguments."""
    return CodePairing(**kwargs).run()
