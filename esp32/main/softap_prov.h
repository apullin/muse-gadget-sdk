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

// Optional transport for code pairing: a Wi-Fi access point that gets a
// gadget with Wi-Fi but no known network online (docs/code-pairing.md,
// "Optional transport"). The gadget opens its own WPA2 access point, serves a
// small page at http://192.168.4.1/ where the person picks their network,
// and hands the credentials to on_credentials; it then joins that network
// and pairs with a code. The access point carries Wi-Fi credentials only,
// never Muse tokens.
//
// Interface only: softap_prov.c is a stub that reports ESP_ERR_NOT_SUPPORTED.

#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SOFTAP_PROV_SSID_MAX 32
#define SOFTAP_PROV_PASSWORD_MAX 64

// Called once, on the provisioning task, with the network the person chose.
// password is "" for an open network. Return true to stop the access point
// (the credentials were accepted), false to keep serving the page.
typedef bool (*softap_prov_credentials_cb_t)(const char *ssid, const char *password,
                                             void *user);

// Opens the access point (ssid, e.g. "MuseGadget-XXXXXX", and a WPA2
// password of 8 to 63 characters, e.g. printed on the gadget's label) and the
// setup page.
esp_err_t softap_prov_start(const char *ssid, const char *password,
                            softap_prov_credentials_cb_t on_credentials, void *user);
// Closes the page and the access point. Safe to call when not started.
void softap_prov_stop(void);
bool softap_prov_running(void);

#ifdef __cplusplus
}
#endif
