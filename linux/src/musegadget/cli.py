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

"""``musegadget`` command line."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from musegadget import __version__, code_pairing, config, identity, muse_api
from musegadget.pair import SETUP_WINDOW_S, PairOutcome, SetupWindow, pair

log = logging.getLogger("musegadget")


def _setup_open(window: SetupWindow) -> None:
    if not window.has_sdk_token:
        print("No SDK token yet. Get one at gadgets.muse.ai and run "
              "`bash install.sh --sdk-token mgst_…`; gadgets without one will stop pairing.",
              file=sys.stderr)
    print(f"Setup open for {window.timeout_s // 60} minutes. In the Muse app, add a device")
    print(f"and choose {window.ble_name}.")


class _CodeScreen:
    """Shows the code pairing QR code, redrawn in place on a terminal when it changes.

    Every change also prints ``pair url: <url>`` on a line of its own, and the
    first one prints ``key fingerprint: <hex>``, so scripts can follow along.
    Without a terminal the QR code is printed once.
    """

    def __init__(self, stream=None):
        self.stream = stream or sys.stdout
        self.tty = self.stream.isatty()
        self.fingerprint_shown = False
        self.qr_shown = False
        self.status = ""

    def say(self, text: str = "") -> None:
        print(text, file=self.stream, flush=True)

    def code(self, code: code_pairing.ShownCode) -> None:
        from musegadget import qr

        if self.tty:
            self.stream.write("\x1b[H\x1b[2J")  # redraw from the top of the screen
        if self.tty or not self.qr_shown:
            try:
                self.say(qr.render_terminal(qr.encode(code.pair_url)))
            except ValueError:  # too long for a QR code; the link still works
                pass
            self.say()
            minutes = max(1, round(code.closes_in / 60))
            self.say("Scan the QR code with the Muse app, on a phone signed in to your Muse.")
            self.say(f"Pairing stays open for {minutes} minute{'s' if minutes != 1 else ''}. "
                     "Approve it only for a device in front of you.")
            self.qr_shown = True
        if self.tty or not self.fingerprint_shown:
            self.say(f"key fingerprint: {code.fingerprint}")
            self.fingerprint_shown = True
        self.say(f"pair url: {code.pair_url}")
        if self.tty and self.status:
            self.say(self.status)

    def show_status(self, status: code_pairing.Status, seconds: float | None) -> None:
        Status = code_pairing.Status
        self.status = {
            Status.WAITING: "Waiting for approval in the Muse app...",
            Status.SLOW_DOWN: f"Muse asked to check less often: every {seconds or 0:g} s.",
            Status.RETRYING: f"Can't reach Muse. Trying again in {seconds or 0:.0f} s.",
            Status.RATE_LIMITED: f"Muse is busy. Trying again in {seconds or 0:.0f} s.",
            Status.IGNORED: "Ignored something that didn't come from the Muse app. Still waiting...",
            Status.APPROVED: "Approved. Checking the new device token...",
        }[status]
        self.say(self.status)


def cmd_pair_code(args: argparse.Namespace) -> int:
    api_root = args.api_url or muse_api.API_BASE
    if not api_root.startswith(("https://", "http://")):
        print("--api-url must start with https://", file=sys.stderr)
        return 1
    screen = _CodeScreen()
    result = code_pairing.pair_with_code(
        api_root=api_root, on_code=screen.code, on_status=screen.show_status,
        force=args.force, timeout_s=args.timeout,
    )
    Outcome = code_pairing.Outcome
    if result.outcome is Outcome.PAIRED:
        if result.detail:
            print(f"Note: {result.detail}.", file=sys.stderr, flush=True)
        screen.say(f"Paired to {result.username}." if result.username else "Paired.")
        return 0
    again = "Run `musegadget pair --code` to try again."
    print({
        Outcome.UNAVAILABLE: "Code pairing isn't available right now. "
                             "Retry later with `musegadget pair --code`. Bluetooth stays off.",
        Outcome.INVALID_SDK_TOKEN: f"Can't pair: {result.detail}.",
        Outcome.SDK_TOKEN_LIMIT: f"Can't pair: {result.detail}.",
        Outcome.ALREADY_PAIRED: "Already paired. Run `musegadget unpair` first, or pass --force.",
        Outcome.INTERRUPTED: f"Stopped. {again}",
        Outcome.TIMED_OUT: f"Pairing closed without approval. {again}",
        Outcome.FAILED: f"Can't pair: {result.detail}.",
    }[result.outcome], file=sys.stderr, flush=True)
    return 1


def cmd_pair(args: argparse.Namespace) -> int:
    if args.code:
        return cmd_pair_code(args)
    if args.api_url:
        print("--api-url only works with --code.", file=sys.stderr)
        return 1
    timeout = SETUP_WINDOW_S if args.timeout is None else args.timeout
    result = pair(on_open=_setup_open, force=args.force, timeout_s=timeout)
    if result.outcome is PairOutcome.PAIRED:
        print("Paired.")
        return 0
    print({
        PairOutcome.ALREADY_PAIRED: "Already paired. Run `musegadget unpair` first, or pass --force.",
        PairOutcome.INVALID_SDK_TOKEN: f"Can't pair: {result.sdk_token_problem}.",
        PairOutcome.WINDOW_CLOSED: "Setup window closed without pairing.",
    }[result.outcome], file=sys.stderr)
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    from musegadget.executor import Account, Executor
    from musegadget.service import run_service

    if os.geteuid() == 0:
        if not args.run_as:
            print("Pass --run-as ACCOUNT (the account whose permissions commands get).",
                  file=sys.stderr)
            return 1
        try:
            account = Account.lookup(args.run_as)
        except KeyError:
            print(f"Account {args.run_as!r} does not exist. Create it, or pass --run-as.",
                  file=sys.stderr)
            return 1
    else:
        account = Account.current()
    try:
        sdk_token = config.sdk_token()
    except ValueError as exc:
        log.warning("running without an SDK token: %s", exc)
        sdk_token = None
    log.info("musegadget %s: commands run as %s", __version__, account.name)
    run_service(identity.load_or_create(), Executor(account), sdk_token)
    return 0


def cmd_send_user_msg(args: argparse.Namespace) -> int:
    import json
    import socket

    message = sys.stdin.read() if args.message == ["-"] else " ".join(args.message)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(90)
            sock.connect(str(config.socket_path()))
            request = {"message": message}
            if args.session_id:
                request["session_id"] = args.session_id
            sock.sendall(json.dumps(request).encode() + b"\n")
            reply = json.loads(sock.makefile("rb").readline())
    except (OSError, ValueError) as exc:
        print(f"Could not reach the musegadget service: {exc}", file=sys.stderr)
        return 1
    if not reply.get("ok"):
        print(f"Not delivered: {reply.get('error') or reply}", file=sys.stderr)
        return 1
    print("Sent to your Muse.")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    ident = identity.load_or_create()
    pairing = config.load_json(config.PAIRING_FILE)
    try:
        sdk_token = config.sdk_token_hint(config.sdk_token())
    except ValueError:
        sdk_token = "not valid"
    paired_with = (pairing or {}).get("sdk_token_hint")
    print(f"version:   {__version__}")
    print(f"node id:   {ident.node_id}")
    print(f"BLE name:  {ident.ble_name}")
    print(f"SDK token: {sdk_token}")
    if pairing is None:
        print("paired:    no")
    elif paired_with is not None and paired_with != sdk_token:
        print(f"paired:    yes, with SDK token {paired_with}; run `musegadget pair --force` to use this one")
    else:
        print("paired:    yes")
    return 0


def cmd_unpair(args: argparse.Namespace) -> int:
    config.delete_json(config.PAIRING_FILE)
    code_pairing.delete_keys()
    print("Pairing removed. The device identity is kept.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="musegadget")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    pair_parser = sub.add_parser(
        "pair", help="pair with the Muse app: Bluetooth setup, or --code without Bluetooth")
    pair_parser.add_argument("--code", action="store_true",
                             help="pair without Bluetooth: show a QR code to scan with the Muse app "
                                  "(experimental)")
    pair_parser.add_argument("--api-url", metavar="URL",
                             help=f"with --code: the Muse API root (default: {muse_api.API_BASE})")
    pair_parser.add_argument("--timeout", type=int, default=None,
                             help=f"seconds to keep Bluetooth setup open (default: {SETUP_WINDOW_S}); "
                                  "with --code, seconds pairing stays open (default: "
                                  f"{int(code_pairing.WINDOW_S)})")
    pair_parser.add_argument("--force", action="store_true", help="pair even if already paired")
    pair_parser.set_defaults(func=cmd_pair)

    run = sub.add_parser("run", help="stay connected to the Muse and serve its commands")
    run.add_argument(
        "--run-as",
        default=os.environ.get("MUSEGADGET_RUN_AS") or os.environ.get("SUDO_USER"),
        help="account whose permissions commands run with (default: the account that ran sudo)",
    )
    run.set_defaults(func=cmd_run)

    send = sub.add_parser("send-user-msg", help="send a message to your Muse from this device")
    send.add_argument("message", nargs="+", help="the message, or - to read it from stdin")
    send.add_argument("--session-id",
                     help="send to this side chat (a new id starts one) instead of the main chat")
    send.set_defaults(func=cmd_send_user_msg)

    sub.add_parser("info", help="show device identity").set_defaults(func=cmd_info)
    sub.add_parser("unpair", help="forget the saved pairing").set_defaults(func=cmd_unpair)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        return args.func(args)
    except PermissionError as exc:
        # The state directory is root-only on an installed device.
        print(f"Can't access {exc.filename or config.state_dir()}; run this with sudo.",
              file=sys.stderr)
        return 1
