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

**Status: experimental integration contract.** This repository implements the
Linux and portable C clients and a local test service. Production availability
requires matching Muse app and backend support; the test service is not evidence
that a production endpoint or app flow is enabled.

**This route uses no Bluetooth.** The gadget gets online independently, for
example over cellular, and all device traffic is outbound HTTPS. No Bluetooth
radio, helper, advertising or fallback is required. If the service is unavailable,
stay unpaired and let the person retry QR pairing later. The phone needs its own
internet connection; it need not share a network with the gadget.

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

An unpaired gadget generates an **X25519 key pair** from a cryptographically
secure random source if it has none. `device_pubkey` is base64url of its 32-byte
public key. Its **fingerprint** is the first 8 bytes of SHA-256 over those bytes,
as 16 lowercase hex characters, e.g. `300c9c9603b92a4b`.

It keeps the key pair across restarts, and deletes it after pairing or factory
reset. A claim sticker, if used, is stored with this key pair.

**Every new pairing window**, including after a reboot, generates a fresh
32-byte **code secret** from a cryptographically secure random source. Keep this
secret only in RAM and discard it when the window closes. Do not reload the old
secret or derive it from uptime. This prevents a reset clock from making an old
photographed code valid again. C ports must provide `random_bytes`; failure to
obtain fresh randomness must leave the device unpaired. Older persisted code
secrets (`code_secret` / `cp_otp`) are removed on migration.

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
including one that restarts from zero at boot **because each window has a fresh
secret**. Use a monotonic clock for scheduling and the pairing deadline. A
gadget whose screen redraws slowly uses a longer step (see [Gadgets with a slow screen](#gadgets-with-a-slow-screen)).

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
https://muse.ai/pair#v=1&n=<node_id>&k=<device_pubkey>&o=<code>&m=<model>&w=<wifi>&g=<mgcommands>&c=<community>[&s=<step>]
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
| `s` | Only when the code changes less often than every 10 seconds: the step, in seconds (see [Gadgets with a slow screen](#gadgets-with-a-slow-screen)). The app uses it to say how long to wait for the next code, and how long a code stays good. |

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

`otp` must match one of the codes in that poll request; ignore an answer with a
missing or unrequested code. Open `sealed` as described in
[The sealed payload](#the-sealed-payload). If the answer is lost, polling again
with that code still in `recent_otps` returns the same drop until it expires
(two minutes) or the gadget acknowledges it.

Other answers, by `type`:

| Status | `type` | What the gadget does |
|---|---|---|
| 400 | `authorization_pending` | Nothing for these codes yet (the same answer whether or not anything else is waiting). Poll again after `interval`. |
| 400 | `slow_down` | Too fast: use the returned `interval` from now on. |
| 400 | `invalidRequest` | A field is malformed (`detail` says which). Fix the firmware. |
| 403 | `devicePairUnavailable` | Stop, hide the code, and remain unpaired. Retry QR pairing on an explicit button press or command. Never enable Bluetooth. |
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

There is no `ssid` or `password`: the gadget is already online. `username` and
`ack_nonce` are optional (`ack_nonce` is 16 random bytes, base64url).

`api_url_v2` and `noise_host` are legacy optional hints, ignored on this route.
A payload cannot choose a trusted server: HPKE base mode does not authenticate
its sender. Polling, binding, verification and saved credentials use the API
root selected locally before pairing. The Noise gateway comes from trusted
client configuration. Do not follow HTTP redirects with credentials. Sandbox
endpoints must be configured on the device by its developer, never by a drop.

The QR code shows the gadget's public key, so anyone who saw it can seal
something that opens. Treat the payload as unverified until Muse accepts its
tokens (below), and ignore a drop that doesn't open, isn't valid JSON, has an
`action` other than `provision_v2`, lacks either token, or carries tokens Muse
rejects. Keep polling, and leave out of `recent_otps` the code that brought it,
so a junk drop can't shadow the real one.

## 3. After you open it

1. **Community gadgets:** refresh the device token with `sdk_token` and
   `device_id` at the trusted API root. Require a successful binding response
   with both replacement tokens before proceeding. The backend must enforce
   device-token ownership, SDK limits and revocation; accepting and ignoring an
   unknown `sdk_token` field is not sufficient support.
   - `sdkTokenDeviceLimitReached`, `sdkTokenInvalid` or `sdkTokenRevoked`: stay
     unpaired, discard the pending credentials and tell the maker.
   - `401` or `403`: ignore the drop and omit its code from subsequent polls.
   - No answer, malformed success, unsupported binding or another error:
     retain the candidate in RAM and retry with bounded backoff, within the
     pairing window. Do not mark pairing complete or bypass SDK binding.
2. Verify the tokens with `fetch_vms` at that same trusted API root. On a
   transient failure retain the **latest rotated tokens** in RAM and retry
   verification, without refreshing again or retrieving the original drop.
   On `401` or `403`, discard this candidate and resume polling for another.
   Missing verification hooks must fail closed.
3. Only after successful binding (when applicable) and verification, and before
   the window expires, persist the credentials and mark pairing successful.
   A timeout or reboot before that point leaves the gadget unpaired; a fresh
   window requires a new scan. Never acknowledge or delete keys for an
   unverified candidate. A previously working pairing must not be overwritten
   by an unverified candidate.
4. If the payload has `ack_nonce`, send `POST /device_drop/ack` with
   `{"node_id", "key_fingerprint", "otp", "ack_nonce"}`. This optional,
   best-effort request deletes the drop after credentials are safely stored.
5. Delete the key pair and the window secret, stop polling, and show the account
   name when available. A payload's `username` is only a display hint, not
   cryptographic proof of ownership.

## Muse app and backend integration

These pieces must be implemented or confirmed in the internal app/backend;
the SDK and `/_fake/*` test routes do not supply them:

- Handle the pairing URL in the app, validate its fields, display the target
  device/account and require explicit approval. Supporting the system camera
  also requires a working app/universal-link or authenticated web handoff.
- Authenticate the approving account; authorize minting tokens for the exact
  `node_id`; seal the token-only payload to the scanned key; deliver it through
  an authenticated app API. Define that production API separately from
  `/_fake/approve`, `/_fake/mint` and `/_fake/deliver`.
- Bind SDK attribution to the device with enforced limits/revocation. Validate
  device identity and account binding server-side; knowing a QR code alone is
  not manufacturer attestation or proof of physical proximity.
- Implement poll/ack, a two-minute ciphertext TTL, one pending drop per
  `(node_id, key_fingerprint, otp)` and `409 dropAlreadyDelivered` on duplicate
  delivery. Authenticate deletion with the encrypted acknowledgement nonce
  (for example by storing its hash). Rate-limit delivery as well as polling;
  prevent overwrites, account-claim races and cross-device credential reuse.
- Make refresh retries safe if a response is lost after rotating a token,
  using bounded reuse tolerance or an idempotent binding operation. The client
  cannot recover a replacement token it never received.
- Keep QR secrets, credentials and sealed payloads out of analytics and logs.
  Define unpairing, revocation and recovery without Bluetooth. Exercise the
  complete path on cellular with dropped responses, slow TLS and device resets.

For a constrained MCU, the C core's platform interface supplies HTTP, clock,
CSPRNG, X25519/AES-GCM, key/token storage and display. It has no ESP-IDF or BLE
dependency. The ESP32 adapter is an example; an STM32/BG96 adapter can reuse an
existing cellular TLS stack. Prefer connection reuse for polls, with timeouts
appropriate to that link; polling cadence starts after the prior request ends.

## Gadgets with a slow screen

An e-paper refresh takes seconds (about 15 on a 4-inch E Ink Spectra 6
panel), so a QR code that changes every 10 seconds would never stand still.
Such a gadget uses a longer step `s` (the SDK uses 45 seconds, at most 120):
`c` is `floor(t / s)`, the QR code is redrawn each step and its link carries
`s=<s>`, and `recent_otps` carries the codes of the last three steps. The server never computes codes,
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
- Keep the private key, the in-memory code secret and any claim code
  unreadable over the network, the serial console or a debug interface in
  production builds.
- Never put the SDK token in a QR code, a sticker or a log.
