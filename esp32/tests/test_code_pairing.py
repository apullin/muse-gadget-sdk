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

"""Code pairing (docs/code-pairing.md): the sealed-drop state machine in
main/code_pairing.c and the HPKE in main/muse_hpke.c against a scripted
platform and a fake drop server, and how the firmware wires them in under
CONFIG_GADGET_CODE_PAIRING.

The HPKE vector checks need the host's libcrypto (found with
`pkg-config libcrypto`; `libssl-dev` on Debian or Ubuntu) and skip without it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "main"
VECTORS = ROOT / "tests" / "vectors" / "code_pairing_hpke.json"


def _cc_command() -> list[str]:
    cmd = shlex.split(os.environ.get("CC", "cc"))
    if not cmd or shutil.which(cmd[0]) is None:
        raise unittest.SkipTest("C compiler not available")
    return cmd


def _sanitizer_flags(cc: list[str], tmp: Path) -> list[str]:
    probe = tmp / "asan_probe"
    flags = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    proc = subprocess.run(
        [*cc, "-x", "c", "-std=c11", *flags, "-o", str(probe), "-"],
        input=b"int main(void) { return 0; }\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        return []
    run = subprocess.run(
        [str(probe)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1"},
    )
    return flags if run.returncode == 0 else []


def _libcrypto_flags() -> tuple[list[str], list[str]]:
    if shutil.which("pkg-config") is None:
        return [], []
    cflags = subprocess.run(["pkg-config", "--cflags", "libcrypto"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    libs = subprocess.run(["pkg-config", "--libs", "libcrypto"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if cflags.returncode != 0 or libs.returncode != 0:
        return [], []
    return ["-DHAVE_LIBCRYPTO", *shlex.split(cflags.stdout)], shlex.split(libs.stdout)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class CodePairingHarnessTest(unittest.TestCase):
    """Each scenario runs in the C harness; see tests/code_pairing_harness.c."""

    binary: Path
    env: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        cc = _cc_command()
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls._tmp.name)
        cls.binary = tmp / "code_pairing_harness"
        sanitizer_flags = _sanitizer_flags(cc, tmp)
        crypto_cflags, crypto_libs = _libcrypto_flags()
        compile_cmd = [
            *cc,
            "-include",
            str(ROOT / "tests" / "host_compat.h"),
            "-std=c11",
            "-D_GNU_SOURCE",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-g",
            "-O1",
            *sanitizer_flags,
            *crypto_cflags,
            "-I",
            str(ROOT / "tests" / "link_fakes"),
            "-I",
            str(MAIN),
            str(ROOT / "tests" / "code_pairing_harness.c"),
            str(MAIN / "code_pairing.c"),
            str(MAIN / "muse_hpke.c"),
            str(ROOT / "tests" / "link_fakes" / "cJSON.c"),
            *crypto_libs,
            "-o",
            str(cls.binary),
        ]
        proc = subprocess.run(
            compile_cmd, cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if proc.returncode != 0:
            cls._tmp.cleanup()
            raise AssertionError(proc.stdout + proc.stderr)
        cls.env = os.environ.copy()
        # The harness checks for leaks with mallinfo2(); glibc's per-thread
        # cache would count freed blocks as in use.
        cls.env["GLIBC_TUNABLES"] = "glibc.malloc.tcache_count=0"
        if sanitizer_flags:
            cls.env["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
            cls.env["UBSAN_OPTIONS"] = "halt_on_error=1"

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _run(self, scenario: str) -> str:
        proc = subprocess.run(
            [str(self.binary), scenario, str(VECTORS)], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn(f"ok {scenario}", proc.stdout)
        return proc.stdout

    def test_every_scenario_is_run(self) -> None:
        proc = subprocess.run(
            [str(self.binary), "--list"], text=True, stdout=subprocess.PIPE, check=True
        )
        listed = set(proc.stdout.split())
        tested = {
            name[len("test_"):]
            for name in dir(self)
            if name.startswith("test_") and name != "test_every_scenario_is_run"
        }
        self.assertEqual(listed - tested, set())

    def test_otp_vectors(self) -> None:
        self._run("otp_vectors")

    def test_link(self) -> None:
        self._run("link")

    def test_happy_path(self) -> None:
        self._run("happy_path")

    def test_pending_then_drop(self) -> None:
        self._run("pending_then_drop")

    def test_stale_code(self) -> None:
        self._run("stale_code")

    def test_slow_step(self) -> None:
        self._run("slow_step")

    def test_wrong_fingerprint_or_code(self) -> None:
        self._run("wrong_fingerprint_or_code")

    def test_junk_ignored(self) -> None:
        self._run("junk_ignored")

    def test_binding_refresh(self) -> None:
        self._run("binding_refresh")

    def test_slow_down(self) -> None:
        self._run("slow_down")

    def test_rate_limited(self) -> None:
        self._run("rate_limited")

    def test_unavailable(self) -> None:
        self._run("unavailable")

    def test_transport_backoff(self) -> None:
        self._run("transport_backoff")

    def test_network_down(self) -> None:
        self._run("network_down")

    def test_reboot_keeps_keys(self) -> None:
        self._run("reboot_keeps_keys")

    def test_keys_erased_after_pairing(self) -> None:
        self._run("keys_erased_after_pairing")

    def test_window(self) -> None:
        self._run("window")

    def test_verify(self) -> None:
        self._run("verify")

    def test_security(self) -> None:
        self._run("security")

    def test_claim_code(self) -> None:
        self._run("claim_code")

    def test_early_counter(self) -> None:
        self._run("early_counter")

    def test_stop(self) -> None:
        self._run("stop")

    def test_encodings(self) -> None:
        self._run("encodings")

    def test_state_names(self) -> None:
        self._run("state_names")

    def test_hpke_vectors(self) -> None:
        out = self._run("hpke_vectors")
        if "skip hpke_vectors" in out:
            self.skipTest("libcrypto not found (pkg-config libcrypto)")


class CodePairingVectorsTest(unittest.TestCase):
    """The fixture and the harness's expected values, recomputed here."""

    def test_fingerprint_vector(self) -> None:
        harness = (ROOT / "tests" / "code_pairing_harness.c").read_text()
        self.assertIn(f'"{hashlib.sha256(bytes(range(32))).digest()[:8].hex()}"', harness)

    def test_otp_vectors(self) -> None:
        # The contract's table, recomputed from its definition.
        crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

        def otp(counter: int) -> str:
            h = hmac.new(bytes(range(32)), counter.to_bytes(8, "big"), hashlib.sha256).digest()
            o = h[31] & 0x0F
            v = int.from_bytes(h[o:o + 5], "big")
            return "".join(crockford[(v >> (35 - 5 * i)) & 31] for i in range(8))

        want = {0: "J66JQ2A2", 1: "MG2GGDQN", 179251798: "XEPZ97F6", 179251799: "TW0NCKK8"}
        harness = (ROOT / "tests" / "code_pairing_harness.c").read_text()
        data = json.loads(VECTORS.read_text())
        for counter, code in want.items():
            self.assertEqual(otp(counter), code)
            self.assertIn(f'{{{counter}, "{code}"}}', harness)
            self.assertEqual(data["otps"][str(counter)], code)

    def test_fixture_is_consistent(self) -> None:
        data = json.loads(VECTORS.read_text())
        pk = base64.urlsafe_b64decode(data["device_pk"] + "=")
        self.assertEqual(len(pk), 32)
        self.assertEqual(data["fingerprint"], hashlib.sha256(pk).digest()[:8].hex())
        for vector in data["payloads"]:
            self.assertEqual(vector["info"], "muse-drop-v1")
            self.assertEqual(vector["aad"], data["node_id"])
            self.assertEqual(json.loads(vector["pt"])["action"], "provision_v2")


class CodePairingSourceContractTest(unittest.TestCase):
    """The pure state machine stays portable, and its wiring stays optional."""

    def test_core_has_no_platform_dependencies(self) -> None:
        for name in ("code_pairing.c", "code_pairing.h", "muse_hpke.c", "muse_hpke.h"):
            source = (MAIN / name).read_text()
            includes = re.findall(r'#include\s+[<"]([^>"]+)[>"]', source)
            for inc in includes:
                self.assertNotRegex(inc, r"^(esp_|freertos|nvs|mbedtls|psa|sdkconfig)",
                                    f"{name} includes {inc}")

    def test_platform_seam_names(self) -> None:
        header = (MAIN / "code_pairing.h").read_text()
        for member in ("http_post_json", "now_ms", "random_bytes", "load_keys",
                       "erase_keys", "net_up", "net_wait_up", "show_code",
                       "show_status", "log", "save_tokens", "bind_tokens",
                       "verify_tokens"):
            self.assertRegex(header, rf"\(\*{member}\)\(", member)
        self.assertIn("const muse_hpke_ops_t *hpke;", header)

    def test_option_guards_the_build_and_the_app_hook(self) -> None:
        kconfig = (MAIN / "Kconfig.projbuild").read_text()
        self.assertRegex(kconfig, r"config GADGET_CODE_PAIRING\n\s+bool")
        block = kconfig[kconfig.index("config GADGET_CODE_PAIRING\n"):]
        self.assertRegex(block.split("config ", 2)[1], r"default n")
        cmake = (MAIN / "CMakeLists.txt").read_text()
        self.assertRegex(
            cmake,
            r'if\(CONFIG_GADGET_CODE_PAIRING\)\n\s+list\(APPEND GADGET_SRCS\s+'
            r'"code_pairing.c"\s+"code_pairing_esp.c"\s+"muse_hpke.c"',
        )
        app = (MAIN / "app.c").read_text()
        for use in re.finditer(r"code_pairing_esp_\w+\(", app):
            before = app[:use.start()]
            opened = before.count("#if CONFIG_GADGET_CODE_PAIRING")
            closed = len(re.findall(r"#endif  // CONFIG_GADGET_CODE_PAIRING", before))
            self.assertGreater(opened, closed, f"unguarded {use.group(0)}")

    def test_ble_setup_stops_code_pairing(self) -> None:
        app = (MAIN / "app.c").read_text()
        start = app.index("static bool complete_setup_and_stop_ble(")
        body = app[start:app.index("\n}\n", start)]
        self.assertIn("code_pairing_esp_stop()", body)

    def test_code_pairing_blocks_bluetooth_start_and_preserves_network_setup(self) -> None:
        for name, signature in (("app.c", "static void start_ble_setup_server_if_needed(void)"),
                                ("ble_server.c", "void ble_server_start(")):
            source = (MAIN / name).read_text()
            body = source[source.index(signature):]
            self.assertRegex(body, r"(?s)^[^{]+\{\s*#if CONFIG_GADGET_CODE_PAIRING\n"
                                   r"[^#]*?return;\s*#endif")
        kconfig = (MAIN / "Kconfig.projbuild").read_text()
        persistent = kconfig[kconfig.index("config HOMEHUB_BLE_PERSISTENT\n"):]
        self.assertIn("!GADGET_CODE_PAIRING", persistent.split("default", 1)[0])
        app = (MAIN / "app.c").read_text()
        self.assertIn("#elif CONFIG_GADGET_CODE_PAIRING\n#define WIFI_WITHOUT_PAIRING 1", app)
        self.assertIn("#if !CONFIG_GADGET_CODE_PAIRING\n        } else if (setup_complete", app)

    def test_factory_reset_deletes_the_keys(self) -> None:
        store = (MAIN / "config_store.c").read_text()
        pairing = store[store.index("bool config_clear_pairing(void)"):]
        pairing = pairing[:pairing.index("\n}\n")]
        setup = store[store.index("bool config_clear_setup(void)"):]
        setup = setup[:setup.index("\n}\n")]
        for key in ("cp_key", "cp_otp"):
            self.assertIn(f'"{key}"', setup)
            self.assertNotIn(f'"{key}"', pairing)

    def test_no_secrets_in_glue_logs(self) -> None:
        glue = (MAIN / "code_pairing_esp.c").read_text()
        for call in re.finditer(r"ESP_LOG\w\(TAG,(.*?)\);", glue, re.S):
            args = call.group(1)
            for secret in ("secret", "access", "refresh", "priv", "claim", "sdk_token",
                           "plaintext", "sealed", "otp", "nonce"):
                self.assertNotIn(secret, args, call.group(0))


if __name__ == "__main__":
    unittest.main()
