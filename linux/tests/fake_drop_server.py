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

"""A fake Muse for code pairing tests. Test scaffolding, not part of the contract.

It implements the gadget side of ``docs/code-pairing.md`` on 127.0.0.1:
``POST /device_drop/poll`` and ``POST /device_drop/ack``, plus a fake
``GET /fetch_vms`` and ``POST /device_token/refresh`` that accept only tokens
it minted. Drops are filed under (node id, key fingerprint, one-time code) and
expire after two minutes. Like the real server, it never computes or checks
one-time codes. A test-only control plane under ``/_fake/`` plays the Muse app:

- ``POST /_fake/approve``   ``{"url": "<QR link>"}``: the fake phone parses the
  link, mints tokens, seals a ``provision_v2`` payload (with ``username`` and
  ``ack_nonce``) to its key and drops it under its code (needs ``cryptography``)
- ``POST /_fake/deliver``   ``{"node_id", "key_fingerprint", "otp", "sealed",
  "ack_hash"?}``: drop what the caller sealed itself; ``ack_hash`` is
  base64url SHA-256 of the ``ack_nonce`` that may delete it
- ``POST /_fake/mint``      fake device tokens the fake endpoints accept
- ``GET  /_fake/drops``     drops waiting, and the acks received
- ``GET|POST /_fake/config`` read or change knobs, e.g. ``{"interval": 0.2}``
- ``GET  /_fake/requests``  every device request, secrets redacted
- ``POST /_fake/reset``     forget drops, tokens and the request log

Run it on its own (it prints one JSON line with the port, then serves)::

    python3 linux/tests/fake_drop_server.py --port 0

or in-process::

    with FakeDropServer(interval=0.2) as fake:
        ...  # point the device at fake.base_url; fake.approve(url=<scraped pair url>)

Everything but ``approve`` needs only the standard library.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import secrets
import signal
import sys
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field, fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PAYLOAD_INFO = b"muse-drop-v1"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
SDK_TOKEN = re.compile(r"mgst_[A-Za-z0-9_-]{43}")
REFRESH_ERRORS = {"sdkTokenDeviceLimitReached": 403, "sdkTokenInvalid": 403, "sdkTokenRevoked": 403}
REDACTED_KEYS = {"sealed", "sdk_token", "ack_nonce", "access_token", "refresh_token",
                 "recent_otps", "otp"}


def _hpke():
    """The device's HPKE module, imported from ``../src`` when not installed."""
    try:
        from musegadget import hpke
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
        from musegadget import hpke
    return hpke


def _b64url_decode(text: object) -> bytes:
    if not isinstance(text, str) or "=" in text or not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError("not unpadded base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def ack_hash(nonce: str) -> str:
    """base64url SHA-256 over the nonce's raw bytes, as the Muse app sends it."""
    try:
        raw = base64.urlsafe_b64decode(nonce + "=" * (-len(nonce) % 4))
    except (ValueError, binascii.Error):
        raw = nonce.encode("utf-8", "replace")
    return _b64url(hashlib.sha256(raw).digest())


def is_code(text: object) -> bool:
    return isinstance(text, str) and len(text) == 8 and all(ch in CROCKFORD for ch in text)


def _valid_node_id(text: object) -> bool:
    return isinstance(text, str) and bool(re.fullmatch(r"[\x21-\x7e]{1,128}", text))


def _valid_fingerprint(text: object) -> bool:
    return isinstance(text, str) and bool(re.fullmatch(r"[0-9a-f]{16}", text))


def _valid_sealed(sealed: object) -> bool:
    if not isinstance(sealed, dict) or sealed.get("v") != 1:
        return False
    try:
        return len(_b64url_decode(sealed.get("enc"))) == 32 and len(_b64url_decode(sealed.get("ct"))) >= 16
    except ValueError:
        return False


def parse_link(link: str) -> Dict[str, str]:
    _, sep, fragment = link.partition("#")
    if not sep:
        raise ValueError("no fragment")
    params = dict(urllib.parse.parse_qsl(fragment, keep_blank_values=True, strict_parsing=True))
    if params.get("v") != "1" or not all(params.get(key) for key in "nko"):
        raise ValueError("not a version 1 pairing link")
    return params


# --- State -----------------------------------------------------------------

@dataclass
class FakeConfig:
    mode: str = "manual"                 # the only mode: the fake can't see the QR code
    interval: float = 5.0                # what authorization_pending answers
    drop_ttl: float = 120.0
    slow_down_on_poll: Optional[int] = None
    slow_down_step: float = 5.0
    enforce_interval: bool = True        # slow_down for polls much faster than the interval
    rate_limit_poll: Optional[int] = None
    retry_after: int = 60
    unavailable: bool = False
    refresh_sdk_error: Optional[str] = None
    # What the fake phone puts in the payload on approve:
    username: Optional[str] = "Sam"
    with_ack: bool = True
    api_url_v2: Optional[str] = None
    noise_host: Optional[str] = None

    def update(self, changes: dict) -> None:
        known = {f.name for f in fields(self)}
        unknown = set(changes) - known
        if unknown:
            raise ValueError(f"unknown knobs: {', '.join(sorted(unknown))}")
        if changes.get("mode", "manual") != "manual":
            raise ValueError("mode must be manual")
        if changes.get("refresh_sdk_error") and changes["refresh_sdk_error"] not in REFRESH_ERRORS:
            raise ValueError(f"refresh_sdk_error must be one of {', '.join(REFRESH_ERRORS)}")
        for name, value in changes.items():
            setattr(self, name, value)


@dataclass
class _Drop:
    node_id: str
    key_fingerprint: str
    otp: str
    sealed: dict
    ack_hash: Optional[str]
    created: float
    source: str                  # "approve" or "deliver"
    delivered: int = 0


class _Problem(Exception):
    def __init__(self, status: int, kind: str, detail: str = "", headers: Optional[dict] = None,
                 **extra):
        super().__init__(kind)
        self.status, self.kind, self.detail = status, kind, detail
        self.headers = headers or {}
        self.extra = extra


@dataclass
class _Reply:
    status: int
    body: object
    content_type: str = "application/json"
    headers: Dict[str, str] = field(default_factory=dict)
    kind: Optional[str] = None


class FakeDropServer:
    """The fake Muse, in a background thread. Use ``start()``/``stop()`` or ``with``."""

    def __init__(self, port: int = 0, verbose: bool = False, **knobs):
        self.config = FakeConfig()
        self.config.update(knobs)
        self.verbose = verbose
        self._port = port
        self._lock = threading.RLock()
        self._drops: List[_Drop] = []
        self._acks: List[dict] = []
        self._access: Dict[str, str] = {}     # access token -> node id
        self._refresh: Dict[str, str] = {}    # refresh token -> node id
        self._bound: Dict[str, str] = {}      # node id -> SDK token hint, after a refresh with one
        self._polls: Dict[Tuple[str, str], int] = {}
        self._last_poll: Dict[Tuple[str, str], float] = {}
        self._poll_total = 0
        self._requests: List[dict] = []
        self._t0 = time.monotonic()
        self._httpd: Optional[ThreadingHTTPServer] = None

    # -- lifecycle --

    def start(self) -> "FakeDropServer":
        handler = type("Handler", (_Handler,), {"fake": self})
        self._httpd = ThreadingHTTPServer(("127.0.0.1", self._port), handler)
        self._httpd.daemon_threads = True
        threading.Thread(target=self._httpd.serve_forever, args=(0.05,), daemon=True,
                         name="fake-drop-server").start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    def __enter__(self) -> "FakeDropServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def port(self) -> int:
        assert self._httpd is not None, "not started"
        return self._httpd.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # -- the control plane, also callable in-process --

    def configure(self, **knobs) -> dict:
        with self._lock:
            self.config.update(knobs)
            return asdict(self.config)

    def drops(self) -> dict:
        with self._lock:
            self._expire()
            now = time.monotonic()
            return {
                "drops": [{
                    "node_id": d.node_id, "key_fingerprint": d.key_fingerprint, "otp": d.otp,
                    "source": d.source, "has_ack": d.ack_hash is not None,
                    "delivered": d.delivered,
                    "expires_in": round(max(d.created + self.config.drop_ttl - now, 0.0), 3),
                } for d in self._drops],
                "acks": [dict(a) for a in self._acks],
                "bound": dict(self._bound),
            }

    def requests(self) -> List[dict]:
        with self._lock:
            return [json.loads(json.dumps(r)) for r in self._requests]

    def reset(self) -> None:
        with self._lock:
            self._drops.clear()
            self._acks.clear()
            self._access.clear()
            self._refresh.clear()
            self._bound.clear()
            self._polls.clear()
            self._last_poll.clear()
            self._requests.clear()
            self._poll_total = 0

    def mint(self, node_id: str = "") -> dict:
        """Fake device tokens that ``/fetch_vms`` and ``/device_token/refresh`` accept."""
        with self._lock:
            tokens = {"access_token": "fake_at_" + secrets.token_urlsafe(24),
                      "refresh_token": "fake_rt_" + secrets.token_urlsafe(24)}
            self._access[tokens["access_token"]] = node_id
            self._refresh[tokens["refresh_token"]] = node_id
            return tokens

    def deliver(self, *, node_id: str, key_fingerprint: str, otp: str, sealed: dict,
                ack_hash: Optional[str] = None, source: str = "deliver") -> dict:
        with self._lock:
            if not _valid_node_id(node_id):
                raise _Problem(400, "invalidRequest", "node_id")
            if not _valid_fingerprint(key_fingerprint):
                raise _Problem(400, "invalidRequest", "key_fingerprint")
            if not is_code(otp):
                raise _Problem(400, "invalidRequest", "otp")
            if not _valid_sealed(sealed):
                raise _Problem(400, "invalidRequest", "sealed must be {v: 1, enc, ct}")
            self._drops.append(_Drop(node_id, key_fingerprint, otp, sealed, ack_hash,
                                     time.monotonic(), source))
            return {"ok": True, "node_id": node_id, "key_fingerprint": key_fingerprint, "otp": otp}

    def approve(self, url: str) -> dict:
        """Play the Muse app on a scanned QR link: mint, seal and drop."""
        try:
            params = parse_link(url)
            public_key = _b64url_decode(params["k"])
            if len(public_key) != 32:
                raise ValueError("k must be a 32-byte key")
        except ValueError as exc:
            raise _Problem(400, "invalidRequest", f"url: {exc}") from None
        hpke = _hpke()
        cfg = self.config
        with self._lock:
            tokens = self.mint(params["n"])
            payload = {"action": "provision_v2", **tokens, "token_type": "device"}
            for name in ("api_url_v2", "noise_host", "username"):
                if getattr(cfg, name) is not None:
                    payload[name] = getattr(cfg, name)
            nonce = None
            if cfg.with_ack:
                nonce = _b64url(secrets.token_bytes(16))
                payload["ack_nonce"] = nonce
            enc, ct = hpke.seal(public_key, PAYLOAD_INFO, params["n"].encode("ascii"),
                                json.dumps(payload).encode("utf-8"))
            result = self.deliver(node_id=params["n"], key_fingerprint=fingerprint(public_key),
                                  otp=params["o"], sealed={"v": 1, "enc": _b64url(enc), "ct": _b64url(ct)},
                                  ack_hash=ack_hash(nonce) if nonce else None, source="approve")
            return {**result, "tokens": tokens, "ack_nonce": nonce}

    # -- internals --

    def _expire(self) -> None:
        cutoff = time.monotonic() - self.config.drop_ttl
        self._drops = [d for d in self._drops if d.created > cutoff]

    # -- the contract --

    def handle_poll(self, body: object) -> _Reply:
        cfg = self.config
        if cfg.unavailable:
            raise _Problem(403, "devicePairUnavailable", "code pairing is off")
        if not isinstance(body, dict):
            raise _Problem(400, "invalidRequest", "body must be a JSON object")
        node_id, fp, codes = body.get("node_id"), body.get("key_fingerprint"), body.get("recent_otps")
        if not _valid_node_id(node_id):
            raise _Problem(400, "invalidRequest", "node_id")
        if not _valid_fingerprint(fp):
            raise _Problem(400, "invalidRequest", "key_fingerprint")
        if (not isinstance(codes, list) or not 1 <= len(codes) <= 8
                or not all(is_code(code) for code in codes)):
            raise _Problem(400, "invalidRequest", "recent_otps")
        token = body.get("sdk_token")
        if token is not None and not (isinstance(token, str) and SDK_TOKEN.fullmatch(token)):
            raise _Problem(400, "invalidRequest", "sdk_token")

        self._poll_total += 1
        if cfg.rate_limit_poll is not None and self._poll_total > cfg.rate_limit_poll:
            raise _Problem(429, "rateLimited", "too many polls",
                           headers={"Retry-After": str(int(cfg.retry_after))})
        key = (node_id, fp)
        now = time.monotonic()
        count = self._polls[key] = self._polls.get(key, 0) + 1
        last = self._last_poll.get(key)
        self._last_poll[key] = now
        too_fast = (cfg.enforce_interval and last is not None
                    and now - last < cfg.interval * 0.8 - 0.05)
        if too_fast or count == cfg.slow_down_on_poll:
            cfg.interval += float(cfg.slow_down_step)
            raise _Problem(400, "slow_down", "polling too fast", interval=_number(cfg.interval))

        self._expire()
        for drop in self._drops:
            if drop.node_id == node_id and drop.key_fingerprint == fp and drop.otp in codes:
                drop.delivered += 1
                return _Reply(200, {"sealed": drop.sealed, "otp": drop.otp}, kind="sealed")
        raise _Problem(400, "authorization_pending", "nothing yet", interval=_number(cfg.interval))

    def handle_ack(self, body: object) -> _Reply:
        if self.config.unavailable:
            raise _Problem(403, "devicePairUnavailable", "code pairing is off")
        if not isinstance(body, dict):
            raise _Problem(400, "invalidRequest", "body must be a JSON object")
        node_id, fp, otp, nonce = (body.get("node_id"), body.get("key_fingerprint"),
                                   body.get("otp"), body.get("ack_nonce"))
        if not (_valid_node_id(node_id) and _valid_fingerprint(fp) and is_code(otp)
                and isinstance(nonce, str) and nonce):
            raise _Problem(400, "invalidRequest", "node_id, key_fingerprint, otp and ack_nonce")
        wanted = ack_hash(nonce)
        matched = False
        for drop in list(self._drops):
            if (drop.node_id, drop.key_fingerprint, drop.otp) == (node_id, fp, otp) \
                    and drop.ack_hash is not None and secrets.compare_digest(drop.ack_hash, wanted):
                self._drops.remove(drop)   # one drop per ack
                matched = True
                break
        self._acks.append({"node_id": node_id, "key_fingerprint": fp, "otp": otp,
                           "matched": matched})
        return _Reply(200, {}, kind="acked" if matched else "ack_unmatched")

    def handle_refresh(self, authorization: str, body: object) -> _Reply:
        prefix = "Bearer hatch_refresh:"
        token = authorization[len(prefix):] if authorization.startswith(prefix) else ""
        node_id = self._refresh.get(token)
        if node_id is None or not isinstance(body, dict):
            raise _Problem(401, "unauthorized", "unknown refresh token")
        sdk_token = body.get("sdk_token")
        if sdk_token is not None and self.config.refresh_sdk_error:
            kind = self.config.refresh_sdk_error
            raise _Problem(REFRESH_ERRORS[kind], kind, "forced by the fake server")
        # Rotate: the old pair stops working.
        old_access = [a for a, n in self._access.items() if n == node_id]
        del self._refresh[token]
        for access in old_access:
            del self._access[access]
        if isinstance(sdk_token, str):
            self._bound[str(body.get("device_id"))] = sdk_token[:12]
        return _Reply(200, self.mint(node_id), kind="refreshed")

    def handle_fetch_vms(self, authorization: str) -> _Reply:
        token = authorization[len("Bearer "):] if authorization.startswith("Bearer ") else ""
        if token not in self._access:
            raise _Problem(401, "unauthorized", "unknown access token")
        return _Reply(200, {"vm_list": [{
            "vm_ws_url": "wss://vm.fake.invalid/ws",
            "vm_auth_token": "fake_vm_" + secrets.token_urlsafe(12),
            "vm_id": "fake-vm-1",
            "vm_name": "Fake Muse",
            "default": True,
        }]}, kind="vm_list")

    def log_request(self, entry: dict) -> None:
        with self._lock:
            entry["t"] = round(time.monotonic() - self._t0, 3)
            self._requests.append(entry)


def _number(value: float):
    return int(value) if float(value).is_integer() else value


def _redact(value: object) -> object:
    if isinstance(value, dict):
        return {k: ("<redacted>" if k in REDACTED_KEYS and v is not None else _redact(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


class _Handler(BaseHTTPRequestHandler):
    fake: FakeDropServer
    server_version = "FakeMuse/1"

    def log_message(self, fmt: str, *args) -> None:
        if self.fake.verbose:
            sys.stderr.write("fake_drop_server: " + (fmt % args) + "\n")

    def _read_json(self) -> object:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None

    def _send(self, reply: _Reply) -> None:
        payload = json.dumps(reply.body).encode()
        self.send_response(reply.status)
        self.send_header("Content-Type", reply.content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in reply.headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _dispatch(self, method: str) -> None:
        fake = self.fake
        path = urllib.parse.urlsplit(self.path).path
        body = self._read_json() if method == "POST" else None
        entry: dict = {"method": method, "path": path}
        if body is not None:
            entry["body"] = _redact(body)
            if isinstance(body, dict) and isinstance(body.get("recent_otps"), list):
                entry["otp_count"] = len(body["recent_otps"])
        try:
            with fake._lock:
                reply = self._route(method, path, body, entry)
        except _Problem as problem:
            reply_body = {"type": problem.kind, "title": problem.kind, "status": problem.status}
            if problem.detail:
                reply_body["detail"] = problem.detail
            reply_body.update(problem.extra)
            reply = _Reply(problem.status, reply_body, "application/problem+json",
                           problem.headers, kind=problem.kind)
        entry["status"] = reply.status
        entry["type"] = reply.kind
        if not path.startswith("/_fake/"):
            fake.log_request(entry)
        self._send(reply)

    def _route(self, method: str, path: str, body: object, entry: dict) -> _Reply:
        fake = self.fake
        auth = self.headers.get("Authorization") or ""
        if method == "POST" and path == "/device_drop/poll":
            return fake.handle_poll(body)
        if method == "POST" and path == "/device_drop/ack":
            return fake.handle_ack(body)
        if method == "POST" and path == "/device_token/refresh":
            return fake.handle_refresh(auth, body)
        if method == "GET" and path == "/fetch_vms":
            entry["authorized"] = auth[len("Bearer "):] in fake._access
            return fake.handle_fetch_vms(auth)
        if path.startswith("/_fake/"):
            return self._control(method, path[len("/_fake/"):], body)
        raise _Problem(404, "notFound", path)

    def _control(self, method: str, name: str, body: object) -> _Reply:
        fake = self.fake
        body = body if isinstance(body, dict) else {}
        if method == "GET" and name == "drops":
            return _Reply(200, fake.drops())
        if method == "GET" and name == "requests":
            return _Reply(200, fake.requests())
        if method == "GET" and name == "config":
            return _Reply(200, asdict(fake.config))
        if method == "POST" and name == "config":
            try:
                return _Reply(200, fake.configure(**body))
            except ValueError as exc:
                raise _Problem(400, "invalidRequest", str(exc)) from None
        if method == "POST" and name == "mint":
            return _Reply(200, fake.mint(str(body.get("node_id") or "")))
        if method == "POST" and name == "deliver":
            try:
                return _Reply(200, fake.deliver(
                    node_id=body.get("node_id"), key_fingerprint=body.get("key_fingerprint"),
                    otp=body.get("otp"), sealed=body.get("sealed"), ack_hash=body.get("ack_hash")))
            except TypeError:
                raise _Problem(400, "invalidRequest", "deliver fields") from None
        if method == "POST" and name == "approve":
            if not isinstance(body.get("url"), str):
                raise _Problem(400, "invalidRequest", "url")
            try:
                return _Reply(200, fake.approve(body["url"]))
            except ImportError:
                raise _Problem(501, "notAvailable", "approve needs cryptography") from None
        if method == "POST" and name == "reset":
            fake.reset()
            return _Reply(200, {"ok": True})
        raise _Problem(404, "notFound", name)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fake Muse for code pairing tests (test scaffolding, not the contract). "
                    "Prints one JSON line with the port, then serves on 127.0.0.1. "
                    "Play the Muse app with POST /_fake/approve {\"url\": <pair url>}.")
    parser.add_argument("--port", type=int, default=0, help="0 picks a free port (default)")
    parser.add_argument("--mode", choices=("manual",), default="manual",
                        help="the fake can't see the QR code: approve through /_fake/approve")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="interval authorization_pending answers (default 5)")
    parser.add_argument("--drop-ttl", type=float, default=120.0, help="seconds a drop is kept")
    parser.add_argument("--slow-down-on-poll", type=int, help="answer slow_down to the Nth poll")
    parser.add_argument("--slow-down-step", type=float, default=5.0,
                        help="seconds slow_down adds to the interval (default 5)")
    parser.add_argument("--no-enforce-interval", dest="enforce_interval", action="store_false",
                        help="don't answer slow_down to polls faster than the interval")
    parser.add_argument("--rate-limit-poll", type=int, help="answer 429 after N polls")
    parser.add_argument("--retry-after", type=int, default=60, help="Retry-After for 429 answers")
    parser.add_argument("--unavailable", action="store_true",
                        help="answer every call with 403 devicePairUnavailable")
    parser.add_argument("--refresh-sdk-error", choices=sorted(REFRESH_ERRORS),
                        help="answer refreshes that carry an SDK token with this problem type")
    parser.add_argument("--username", default="Sam",
                        help="username the fake phone puts in the payload (default Sam)")
    parser.add_argument("--no-ack", dest="with_ack", action="store_false",
                        help="the fake phone puts no ack_nonce in the payload")
    parser.add_argument("--api-url-v2", help="api_url_v2 the fake phone puts in the payload")
    parser.add_argument("--noise-host", help="noise_host the fake phone puts in the payload")
    parser.add_argument("-v", "--verbose", action="store_true", help="log requests to stderr")
    args = parser.parse_args(argv)

    knobs = vars(args).copy()
    port, verbose = knobs.pop("port"), knobs.pop("verbose")
    fake = FakeDropServer(port=port, verbose=verbose, **knobs).start()
    print(json.dumps({"port": fake.port, "base_url": fake.base_url}), flush=True)

    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    while not stopped.wait(0.5):
        pass
    fake.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
