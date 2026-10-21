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

# Code pairing: pair a gadget without Bluetooth

**Status: experimental.** Muse turns code pairing on and off on its side. A gadget
must fall back to Bluetooth setup whenever code pairing is unavailable.

Bluetooth setup needs the phone next to the gadget: the Muse app opens an
encrypted Bluetooth session and pushes the gadget its device tokens. Code pairing
does the same push without Bluetooth, for a gadget that reaches the internet on
its own (cellular, Ethernet, or a Wi-Fi network it already knows):

1. The gadget shows a QR code with its id, its public key and a one-time code
   that changes every 10 seconds. It needs nothing from the server for this.
2. The person scans it in the Muse app and approves. The app mints the gadget's
   device tokens, **encrypts them to the gadget's key**, and drops the
   ciphertext on the Muse server, filed under the gadget's id, key fingerprint
   and the one-time code it scanned.
3. The gadget polls with its id, its key fingerprint and its last few one-time
   codes, gets the ciphertext, and opens it. A gadget behind a carrier's NAT
   can't accept connections, so it always asks.

The server stores only ciphertext it can't open, for two minutes, and never
computes or checks one-time codes: it hands a drop to whoever presents the same
gadget id, fingerprint and code, and only the gadget can open it. A photo of the
QR code goes stale within a minute, because the gadget stops presenting its old
codes.

```
gadget                               Muse                       Muse app (phone)
  | shows QR: node_id, key,            |                                 |
  | one-time code (new every 10 s)     |       person scans, approves    |
  |                                    |<--------------------------------|
  |                                    |  app mints device tokens, seals |
  |                                    |  them to the gadget's key and   |
  |                                    |  drops them, filed under        |
  |                                    |  node_id + fingerprint + code   |
  | POST /device_drop/poll             |<--------------------------------|
  | node_id, fingerprint, recent codes |                                 |
  |----------------------------------->|                                 |
  | sealed provisioning payload        |                                 |
  |<-----------------------------------|                                 |
  | open it, save the tokens           |                                 |
  | POST /device_drop/ack (optional)   |                                 |
  |----------------------------------->|                                 |
  | fetch_vms, Noise session, ... as after Bluetooth setup               |
```

What the gadget receives is the same `provision_v2` payload Bluetooth setup sends
for token-only setup, so everything after it is unchanged: the gadget stores the
tokens where Bluetooth setup stores them, refreshes them the same way, and
connects to its Muse the same way.

## Conventions

- **Base URL.** The same API root the gadget uses for its other device API calls:
  `api_url_v2` if it has one, otherwise `https://api.muse.ai`. Paths below are
  appended to it as-is.
- **Requests.** `POST`, `Content-Type: application/json`, `X-API-Version: 1.0.0`
  and a `User-Agent` that names the firmware and its version.
- **Errors.** [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) problem details
  with a `type` member. Switch on `type`, never on `title` or `detail`.
- **Encoding.** Binary values are base64url without padding (RFC 4648 §5).
- **Never log secrets.** The private key, the one-time-code secret, the sealed
  payload and the tokens never go to a log, a screen, a bug report or analytics.

## What the gadget keeps

When the gadget is unpaired and doesn't have them yet, it generates, from a
cryptographically secure random source:

- an **X25519 key pair**. `device_pubkey` is base64url of the 32-byte public key.
  Its **fingerprint** is the first 8 bytes of SHA-256 over those 32 bytes, as
  16 lowercase hex characters, e.g. `300c9c9603b92a4b`.
- a 32-byte **code secret** for the one-time codes.

It keeps both across restarts, and deletes both once it has paired (and on a
factory reset), so the next pairing starts with fresh ones. Neither ever leaves
the gadget.

## One-time codes

The code for counter `c` is HOTP ([RFC 4226](https://www.rfc-editor.org/rfc/rfc4226))
with HMAC-SHA256 and 8 Crockford base32 characters:

1. `h = HMAC-SHA256(code secret, c as an 8-byte big-endian integer)`
2. `o = h[31] & 0x0f`
3. `v` = the 5 bytes `h[o] … h[o+4]` as a big-endian 40-bit integer
4. the code is `v` as 8 characters, most significant first, 5 bits each, from
   the alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`

`c` is `floor(t / 10)`, where `t` is the gadget's own clock in seconds. Nothing
is synchronized with the server, so any clock that advances steadily works,
including one that restarts from zero at boot. A gadget whose screen redraws
slowly uses a longer step (see [Gadgets with a slow screen](#gadgets-with-a-slow-screen)).

Test vectors, for the code secret `00 01 02 … 1f` (the bytes 0 to 31):

| `c` | code |
|---|---|
| 0 | `J66JQ2A2` |
| 1 | `MG2GGDQN` |
| 179251798 | `XEPZ97F6` |
| 179251799 | `TW0NCKK8` |

## 1. Show the QR code

Show the QR code while pairing, and draw it again whenever `c` changes:

```
https://muse.ai/pair#v=1&n=<node_id>&k=<device_pubkey>&o=<code>&m=<model>&w=<wifi>&g=<mgcommands>&c=<community>
```

| Key | Value |
|---|---|
| `v` | `1` |
| `n` | The gadget's stable id, the same one it uses for device tokens (`device_id`), e.g. `homelink-ab12cd`. |
| `k` | `device_pubkey` |
| `o` | The one-time code for the current `c` |
| `m` | The model, as `get_device_info` reports it, e.g. `hatch_link` |
| `w` | Wi-Fi need: `n` none, `o` optional, `r` required |
| `g` | `1` if the gadget also serves gadget commands over Bluetooth, else `0` |
| `c` | `1` for a community gadget (built with this SDK, paired with an SDK token), else `0` |

Values are percent-encoded as in a URL query; ids made of letters, digits, `-`,
`_` and `.` need no encoding. The parameters are in the fragment so that a
browser opening the link without the Muse app never sends them to a server.
Encode the QR code in byte mode with error correction level M (version 8 for a
typical link). **Never put the SDK token in it.**

- **Screen:** show the QR code, with "Scan with the Muse app" and how long
  pairing stays open.
- **No screen:** see [Gadgets without a screen](#gadgets-without-a-screen).

## 2. Poll: `POST /device_drop/poll`

While pairing, every `interval` seconds (5 to begin with):

```json
{
  "node_id": "homelink-ab12cd",
  "key_fingerprint": "300c9c9603b92a4b",
  "recent_otps": ["TW0NCKK8", "XEPZ97F6", "…", "…", "…", "…"],
  "sdk_token": "mgst_…"
}
```

| Field | Required | Rules |
|---|---|---|
| `node_id` | yes | As in the QR code. 1 to 128 printable ASCII characters, no spaces. |
| `key_fingerprint` | yes | The fingerprint of `device_pubkey`. |
| `recent_otps` | yes | The codes for `c`, `c-1`, … `c-5`: the last 60 seconds, newest first (on a longer step, the last three steps). 1 to 8 entries (see claim stickers). |
| `sdk_token` | no | The maker's SDK token, for a community gadget. Used only to attribute and rate-limit polls. |

`200`, once the Muse app has dropped a payload filed under one of those codes:

```json
{ "sealed": { "v": 1, "enc": "…", "ct": "…" }, "otp": "XEPZ97F6" }
```

`otp` is the code the drop was filed under. Open `sealed` as described in
[The sealed payload](#the-sealed-payload). If the answer is lost, polling again
with that code still in `recent_otps` returns the same drop until it expires
(two minutes) or the gadget acknowledges it.

Other answers, by `type`:

| Status | `type` | What the gadget does |
|---|---|---|
| 400 | `authorization_pending` | Nothing for these codes yet (the same answer whether or not anything else is waiting). Poll again after `interval`. |
| 400 | `slow_down` | Too fast: use the returned `interval` from now on. |
| 400 | `invalidRequest` | A field is malformed (`detail` says which). Fix the firmware. |
| 403 | `devicePairUnavailable` | Code pairing is off. Stop and fall back to Bluetooth setup; try code pairing again after a restart. |
| 429 | `rateLimited` | Wait `Retry-After` seconds (60 if absent). |

On a transport error or a `5xx`, retry with exponential backoff from 2 to 60
seconds. Never poll from two places at once, or before the previous poll has
answered.

**Pairing stays open for 10 minutes** after the gadget boots unpaired or the
person asks to pair (a button, a command), then the gadget stops polling and
hides the QR code until asked again.

## The sealed payload

`sealed` is [HPKE](https://www.rfc-editor.org/rfc/rfc9180) in base mode,
single-shot, with the cipher suite DHKEM(X25519, HKDF-SHA256) (`0x0020`),
HKDF-SHA256 (`0x0001`) and AES-128-GCM (`0x0001`), the suite of RFC 9180
appendix A.1:

| Member | Value |
|---|---|
| `v` | `1` |
| `enc` | base64url of the 32-byte encapsulated key |
| `ct` | base64url of the ciphertext with its 16-byte tag |

- recipient key: the gadget's X25519 key
- `info`: the ASCII bytes `muse-drop-v1`
- `aad`: the ASCII bytes of `node_id`

The plaintext is UTF-8 JSON, the `provision_v2` message Bluetooth setup sends for
token-only setup:

```json
{
  "action": "provision_v2",
  "access_token": "…",
  "refresh_token": "…",
  "token_type": "device",
  "api_url_v2": "https://api.muse.ai",
  "noise_host": "hatch.metaaivm.com",
  "username": "…",
  "ack_nonce": "…"
}
```

There is no `ssid` or `password`: the gadget is already online. `api_url_v2`,
`noise_host`, `username` and `ack_nonce` are optional (`ack_nonce` is 16 random
bytes, base64url).

The QR code shows the gadget's public key, so anyone who saw it can seal
something that opens. Treat the payload as unverified until Muse accepts its
tokens (below), and ignore a drop that doesn't open, isn't valid JSON, has an
`action` other than `provision_v2`, lacks either token, or carries tokens Muse
rejects. Keep polling, and leave out of `recent_otps` the code that brought it,
so a junk drop can't shadow the real one.

## 3. After you open it

1. **Community gadgets:** refresh the device token once, with `sdk_token` in the
   refresh request next to `device_id`. That records the SDK token against the
   gadget, as pairing over Bluetooth does, so the token's device limit and
   revocation apply to it; use the tokens it returns from then on.
   - `sdkTokenDeviceLimitReached`, `sdkTokenInvalid` or `sdkTokenRevoked`: stay
     unpaired, discard the tokens and tell the maker.
   - `401` or `403`: the tokens aren't real. Ignore the drop and keep polling.
   - Anything else (including a Muse that doesn't take `sdk_token` on refresh
     yet, or no answer): keep the tokens from the payload and go on.
2. Check the tokens with `fetch_vms`, as Bluetooth setup does. A `401` or `403`
   means they aren't real: ignore the drop and keep polling.
3. Store `access_token` and `refresh_token` exactly where Bluetooth setup stores
   them, and keep refreshing them the same way, with `node_id` as the device id.
4. If the payload has `ack_nonce`, send `POST /device_drop/ack` with
   `{"node_id", "key_fingerprint", "otp", "ack_nonce"}` (`otp` as the poll
   returned it). It deletes the drop; it is optional, and its answer doesn't
   matter.
5. Delete the key pair and the code secret, stop polling, and show "Paired to
   `username`" if the payload had one, so the owner sees which account the
   gadget joined.

## Gadgets with a slow screen

An e-paper refresh takes seconds (about 15 on a 4-inch E Ink Spectra 6
panel), so a QR code that changes every 10 seconds would never stand still.
Such a gadget uses a longer step `s` (the SDK uses 45 seconds, at most 120):
`c` is `floor(t / s)`, the QR code is redrawn each step, and `recent_otps`
carries the codes of the last three steps. The server never computes codes,
so it needs nothing for this. A photographed QR code stays good for up to
three steps instead of 60 seconds.

## Gadgets without a screen

- **At the bench:** print the link (or a terminal QR code) on the serial
  console, or let a flashing tool show it, refreshed every 10 seconds.
- **Claim sticker:** at flash time, generate the key pair and an 8-character
  random **claim code** from the same alphabet, store them on the gadget, and
  print a QR code of the link with `o=<claim code>` on a sticker inside the box.
  While pairing, the gadget adds the claim code to `recent_otps`. A claim code
  doesn't expire, so the sticker is a secret: pair only after a button press or
  on first boot, and delete the claim code once paired.

## Optional transport: Wi-Fi access point (SoftAP)

A gadget with Wi-Fi but no known network can still use code pairing: it opens its
own access point (`MuseGadget-XXXXXX`, WPA2 with a per-gadget password on its
label), serves a small page at `http://192.168.4.1/` where the person picks their
Wi-Fi network from their phone's browser, joins that network, and then pairs
with a code as above. The access point carries only Wi-Fi credentials, never
Muse tokens: it is a way to get online, nothing more. The SDKs include the
interface for it, not an implementation yet.

## Testing without Muse or a phone

`linux/tests/fake_drop_server.py` implements `poll` and `ack` on `127.0.0.1`,
with a fake `fetch_vms` and refresh, and a test-only control plane under
`/_fake/` that plays the Muse app: it parses a QR link, mints fake tokens, seals
them and drops them. See its `--help`. It is test scaffolding, not part of the
contract.

## Security notes for makers

- Without Bluetooth, nothing proves the phone is next to the gadget. Someone
  who photographs the QR code could pair the gadget to their own account within
  about a minute, before the code goes stale. The Muse app asks people to
  approve only a gadget in front of them, and the gadget shows "Paired to
  `username`" afterwards; tell your users the same: scan only a code shown by a
  gadget you own, in front of you, and pair again if the name is wrong.
- Keep the private key, the code secret and any claim code in storage that
  isn't readable over the network, the serial console or a debug interface in
  production builds.
- Never put the SDK token in a QR code, a sticker or a log.
