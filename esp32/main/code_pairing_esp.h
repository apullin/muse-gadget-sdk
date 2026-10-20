/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

// Runs code pairing (code_pairing.h) on its own task with the ESP-IDF
// platform: HTTPS, an X25519 key and a one-time-code secret in NVS, PSA
// Crypto, the status LED or screen. Built with CONFIG_GADGET_CODE_PAIRING.
// Every call returns at once and is safe from any task; the work happens on
// the code pairing task.

#include <stdbool.h>
#include <stdint.h>

// Open the 10-minute pairing window if code pairing hasn't run yet (or was
// stopped): show the QR code and poll.
void code_pairing_esp_start_if_idle(void);
// The person asked to pair (a button press): after the window closed, an
// error or code pairing being off, open a new window. Does nothing while the
// QR code is showing.
void code_pairing_esp_restart(void);
// Stop polling and hide the QR code (Bluetooth setup finished).
void code_pairing_esp_stop(void);
// Whether the QR code is showing and the gadget polling.
bool code_pairing_esp_active(void);

// The network seam. Code pairing needs only an IP link: these default to the
// Wi-Fi manager's connected state, and are weak, so a build with another link
// (Ethernet, cellular) provides its own. net_wait_up waits at most timeout_ms
// and returns whether the link is up.
bool code_pairing_net_up(void);
bool code_pairing_net_wait_up(uint32_t timeout_ms);
