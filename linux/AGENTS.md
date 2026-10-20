<!--
Copyright (c) Meta Platforms, Inc. and affiliates.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# AGENTS.md

How to work on this Linux client, test it, and deploy it to a device. See
`README.md` for a shorter human overview.

## What this is

A Python package (`musegadget`) that makes any Linux computer into a Muse
Home Link. It pairs with the Muse phone app over BLE, then holds an encrypted
Noise session to the user's Muse VM and runs the commands Muse sends it. It is
the Linux counterpart of the ESP32 firmware in `../esp32` and speaks the same
pairing and control protocols, so the same app pairs either. It can also pair
without Bluetooth, with a code (`musegadget pair --code`, experimental).

| Module | Role |
|---|---|
| `cli.py` | `musegadget pair [--code]`, `run`, `send-user-msg`, `info`, `unpair` |
| `pair.py` | `pair()`: opens BLE setup, checks and saves the pairing, prints nothing |
| `code_pairing.py` | `pair_with_code()`: code pairing without Bluetooth, as a sealed drop (`docs/code-pairing.md`), prints nothing |
| `hpke.py` | HPKE (RFC 9180) base mode for the X25519 / HKDF-SHA256 / AES-128-GCM suite that code pairing seals with |
| `qr.py` | Dependency-free QR encoder (byte mode, level M, versions 1 to 10) and terminal renderer |
| `pairing.py` | Community pairing v5: P-256 ECDH, HKDF-SHA256, AES-256-GCM, `confirm_app` |
| `ble_framing.py` | Chunked BLE framing (`0xFE`, index, total, payload) |
| `ble_setup.py` | Setup commands behind the GATT characteristics (no BlueZ dependency) |
| `ble_server.py` | BlueZ GATT peripheral and advertisement over D-Bus (GLib loop) |
| `identity.py` | Persistent identity: `homelink-xxxxxx` node id, `MuseGadgetXXXXXX` BLE name |
| `muse_api.py` | `fetch_vms` and device token refresh |
| `link_client.py` | One session: `/v1/noise` upgrade, Noise XX, `/link-control`, `/chat/stream`, `/chat/subscribe`, TTS streams |
| `service.py` | `musegadget run`: reconnect loop, token rotation, local socket |
| `muse_turn.py` | Follows one request through Muse's chat events to its replies |
| `executor.py`, `fileops.py` | The commands Muse can run, as the chosen account |
| `noise/` | Noise XX handshake, framing and service envelopes |
| `data/` | The systemd unit and the hash-pinned `requirements.lock`, shipped in the package |

## Prerequisites

- Python 3.9 or later. The package supports Debian 11 / Raspberry Pi OS
  Bullseye (Python 3.9, cryptography 3.3.2) and later, and Ubuntu 22.04 and
  later.
- [uv](https://docs.astral.sh/uv/) for tests and builds.
- For a real device: BlueZ, and `python3-dbus` and `python3-gi` from apt.
  These have no Linux wheels, so the venv must use the system interpreter
  with `--system-site-packages`. Don't point it at a uv-managed Python.

## Tests

The tests need no Bluetooth, device or network:

```sh
uv run --with pytest --with . pytest
```

To check the oldest supported versions, pin them. cryptography 3.3.2 has no
Apple Silicon wheel, so run it under an x86-64 Python on a Mac:

```sh
uv run --no-project --isolated --python cpython-3.9-macos-x86_64 \
  --with pytest --with cryptography==3.3.2 --with websockets==13.1 \
  env PYTHONPATH=src python -m pytest -q
```

The pairing tests check against the published fixtures in
`tests/vectors/link_pairing_v5.json`. `tests/test_link_client.py` runs the
client against an in-process fake VM that does a real Noise handshake.
`tests/test_code_pairing_e2e.py` runs `musegadget pair --code` against the
fake Muse in `tests/fake_drop_server.py`. `tests/test_hpke.py` checks HPKE
against the RFC 9180 A.1.1 vector and, with `--with pyhpke`, against the
`pyhpke` package. `tests/test_qr.py` compares the QR encoder with the `qrcode`
package (`--with qrcode`). Both skip those checks without the package; pyhpke
needs a newer cryptography than 3.3.2.

## Deploy to a device

Copy this directory to the device and install from it:

```sh
bash install.sh --from .            # asks before granting access
bash install.sh --from . --yes      # doesn't ask
```

Reinstalling keeps the pairing. It restarts the service, which kills any
command Muse is running at that moment, so check the log for recent `invoke`
lines first.

For a quicker loop, build a wheel and install it into the existing venv:

```sh
uv build --wheel
# on the device:
sudo /opt/musegadget/bin/uv pip install --python /opt/musegadget/venv/bin/python --no-deps --reinstall musegadget-*.whl
sudo systemctl restart musegadget
```

Installer flags: `--sdk-token TOKEN`, `--run-as USER`, `--no-pair`, `--yes`,
`--from SOURCE`, `--uninstall`, `--purge`. The installer is ShellCheck-clean;
keep it that way.

## Run and debug

```sh
sudo journalctl -u musegadget -f     # service log
sudo musegadget -v pair              # pairing, verbose
sudo musegadget info                 # identity and pairing state
```

State lives in `/var/lib/musegadget` (mode 0700): `identity.json` survives
unpairing, `pairing.json` holds the device tokens, and `code_pairing.json`
holds the code pairing key and code secret until the device pairs. The local socket is
`/run/musegadget/musegadget.sock`, owned by root and the run-as account's group.

A healthy start logs `commands run as <user>`, `Noise session established`,
`sent link.register` and `registered with the Muse`.
Each command the Muse runs logs `invoke <command>`, then how it ended, such as
`system.run ok, exit 0 in 41 ms` or `file.read failed in 3 ms`. The log
never has a command's parameters, output or error message.

## Pairing

- Community mode only: `pairing_auth: "none"`, epoch 0, policy `confirm_app`.
  A Pi has no button, so the app's own confirmation stands in for it, and BLE
  only advertises while `musegadget pair` runs.
- The BLE name is `MuseGadget` plus the last six hex digits of the identity,
  with **no hyphen**: the apps compare the text after the prefix with the text
  after `homelink-` in the node id. `get_device_info` must report
  `model: "hatch_link"`.
- The apps always scan Wi-Fi and send `provision_v2` with an SSID. When the
  device is online it offers one open network, "the current connection", and
  ignores the Wi-Fi fields it gets back. It never stores them.
- `provision_v2` carries `api_url`, which only older firmware reads (it adds
  `/hatch/`). This client ignores it and uses `api_url_v2` when newer apps
  send it, or `https://api.muse.ai`, with bare API paths either way.
- The Android app writes `negotiatedMtu - 3` bytes with no cap, and Android
  rejects writes over 512 bytes. BlueZ must have `[GATT] ExchangeMTU = 256` in
  `/etc/bluetooth/main.conf`; the installer sets it. Symptom if it's missing:
  pairing works up to Wi-Fi, then "Couldn't connect" in the app.
- Answer plaintext `get_device_info` at any time. Android re-sends it when it
  restarts a handshake on the same connection.
- GATT status 133 on the phone is usually stale Bluetooth state on the phone.
  Toggling the phone's Bluetooth clears it.

## Code pairing

`musegadget pair --code` pairs without Bluetooth, following
[`docs/code-pairing.md`](../docs/code-pairing.md). The device needs nothing
from the server to start: it shows a QR code of
`https://muse.ai/pair#v=1&n=<node id>&k=<X25519 public key>&o=<one-time code>&…`
and redraws it every 10 seconds, when the one-time code changes. The Muse app
seals the device tokens to that key (HPKE, `hpke.py`) and drops them on the
server under the node id, key fingerprint and code; the device polls
`/device_drop/poll` with its last six codes, opens the drop, and pairs. The
server only ever holds ciphertext. Muse turns code pairing on and off; when it
is off the command says to use Bluetooth setup. Linux gets online with the OS's
own networking, so there is no access point here.

- The X25519 key and the 32-byte code secret are in `code_pairing.json`,
  created when the device is unpaired and has none, kept across restarts (so
  the QR code keeps the same key), and deleted once it pairs or by
  `musegadget unpair`. The one-time code is HOTP-SHA256 over `floor(t / 10)`.
- Pairing stays open for 10 minutes (`--timeout`).
- Anyone who saw the QR code can drop something. A drop that doesn't open, isn't
  `provision_v2`, or whose tokens Muse rejects is ignored, its code is no longer
  presented, and polling goes on.
- With an SDK token, the device refreshes the new tokens once right away with
  `sdk_token`, which binds the token to it. `sdkTokenDeviceLimitReached`,
  `sdkTokenInvalid` or `sdkTokenRevoked` there leaves it unpaired. Then it
  checks the tokens with `fetch_vms`, saves `pairing.json` as Bluetooth setup
  does, acknowledges the drop, deletes the key and code secret, and prints
  `Paired to <username>`.
- It prints `key fingerprint: <hex>` once and `pair url: <link>` each time the
  link changes, on lines of their own, for scripts.
- Never log the key, the code secret, one-time codes, a drop or tokens.

To try it with no Muse or phone, run the fake Muse and play the Muse app from a
second shell with the link the command printed:

```sh
python3 tests/fake_drop_server.py --port 0 --interval 1    # prints {"port": N, "base_url": ...}
MUSEGADGET_STATE_DIR=/tmp/mg MUSEGADGET_SDK_TOKEN=mgst_… \
  musegadget pair --code --api-url http://127.0.0.1:N
curl -d '{"url": "<pair url>"}' http://127.0.0.1:N/_fake/approve
```

`/_fake/approve` mints fake tokens, seals them to the key in the link and drops
them under its code. To play the app yourself, get tokens from
`POST /_fake/mint`, seal your own payload and `POST /_fake/deliver` it.
`GET /_fake/drops` shows waiting drops, acks and bound SDK tokens;
`GET /_fake/requests` shows what the device sent, secrets redacted. `--help`
lists the knobs (`--slow-down-on-poll`, `--rate-limit-poll`,
`--refresh-sdk-error`, `--unavailable`, `--drop-ttl`, ...). The fake server is
test scaffolding, not part of the contract.

## Talking to the Muse

- Connect to `wss://<noise_host>/v1/noise?vm_id=<vm_id>` with the per-VM bearer
  from `fetch_vms` in an `Authorization` header. A 401 or 403 on the upgrade
  means fetch fresh VM credentials, not retry the same bearer.
- After the Noise handshake, open `POST /link-control` and leave the body open.
  Both directions carry JSON messages, each prefixed with a little-endian u32
  length. The device sends `link.register`, then a `link.result` for each
  `link.invoke`. `link.unpaired` means the Muse removed the device.
- Register as `platform: "linux"`, `device_family: "homehub"`. Never use family
  `link` or advertise `device.ota`: the server pushes ESP32 firmware updates to
  every `link` device.
- Messages from the device to the Muse (`musegadget send-user-msg`) go as separate
  `POST /chat/stream` requests on the same session, with `device_id` set to the
  node id and `"output_modality": "text"`. `session_id` picks the chat;
  `chat_id` is not an API field and is ignored. The response is only the ack
  (`message_id`); the reply appears in the Muse chat. Replies are text: to
  speak them, use a text-to-speech API of your choice.
- The VM accepts at most 256 KB per message from the device, so command output
  is cut at 96 KB per stream.

## Adding a command

1. Add a spec to `COMMAND_SPECS` in `executor.py`: `description`, `required`
   and `optional` parameters (each with `type` and `description`), and
   `timeout_ms` if the default 30 seconds is too short.
2. Handle it in `Executor.run`. Return `ok(payload)` or `error(message)`.
3. Anything that touches the machine should run in a child process with
   `self._child_options()`, so it runs as the chosen account and not as root.
4. Add a test in `tests/test_executor.py`.

Muse sees the new command after the service restarts and re-registers.

## Say Muse, never Hatch

Users never see the name Hatch.

- Anything a person reads says Muse, the Muse app, or the Muse's name:
  - CLI output and help
  - log lines
  - errors
  - docs
- Don't use `hatch` in a new file name or identifier. Use `muse` or
  `musegadget`. The device API client is `muse_api.py`.
- `hatch` stays only where the server or the Muse app depends on it. Don't
  rename these:
  - the host `hatch.metaaivm.com`
  - the `hatch_refresh:` auth prefix
  - pairing labels and ids such as `hatch-link-pairing-v5`, the `hatch_link`
    model and the `hatch-link:` device id, and the test vectors

## Before you hand back work

1. The tests pass, on the newest Python and on Python 3.9 with cryptography
   3.3.2 if you touched pairing or the Noise code.
2. If you changed `install.sh`, it passes ShellCheck.
3. If you deployed, the log shows `registered with the Muse` and no tracebacks.
