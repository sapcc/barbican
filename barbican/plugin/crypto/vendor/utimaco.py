# Copyright (c) 2026 SAP SE
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import tempfile

from barbican.common import utils
from barbican.plugin.crypto.vendor import base

LOG = utils.getLogger(__name__)

_DEFAULT_PKCS11_LIBRARY_PATH = "/opt/hsm/lib/pkcs11.so"


def render_utimaco_cfg(endpoints, fallback_interval=0, logpath=None):
    """Render a Utimaco PKCS#11 cfg file for the given endpoints.

    Emits one `[HSMCluster]` block whose `Devices` line lists every
    endpoint ordered by ascending `order`.

    `fallback_interval` controls the driver's cluster behavior
    (CryptoServer SDK PKCS#11 Developer's Guide):
      * 0 (default) -> load-balancing mode: requests are spread across
        all devices in the cluster.
      * N > 0       -> failover mode: devices are tried in priority
        order; after a device fails, the driver retries it every N
        seconds to fall back to it.
    """
    ordered = sorted(endpoints, key=lambda ep: ep["order"])
    pairs = [f"{ep['port']}@{ep['host']}" for ep in ordered]
    if len(pairs) == 1:
        devices_value = pairs[0]
    else:
        devices_value = "{ " + " ".join(pairs) + " }"
    return (
        "[Global]\n"
        f"Logpath = {logpath or tempfile.gettempdir()}\n"
        "Logging = 4\n"
        "SlotMultiSession = true\n"
        "SlotCount = 10\n"
        f"FallbackInterval = {int(fallback_interval)}\n"
        "\n"
        "[HSMCluster]\n"
        f"Devices = {devices_value}\n"
    )


class UtimacoValidator(base.VendorValidator):
    """Utimaco: serial-only slot resolution + cfg rewrite before PKCS#11."""

    def validate_args(self, args):
        if not getattr(args, "token_serial_number", None):
            raise ValueError(
                "Utimaco onboarding requires --token-serial-number"
            )

    def validate_keys(self, endpoints, args, library_path=None):
        # Lazy import: pkcs11 pulls in the vendor library at import time
        # on some hosts, which the unit tests should not require.
        from barbican.plugin.crypto import pkcs11

        lib = library_path or _DEFAULT_PKCS11_LIBRARY_PATH
        cfg_content = render_utimaco_cfg(endpoints)
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".cfg", delete=False, prefix="hsm_"
        )
        try:
            tmp.write(cfg_content)
            tmp.close()
            os.environ["CS_PKCS11_R3_CFG"] = tmp.name
            p11 = pkcs11.PKCS11(
                library_path=lib,
                login_passphrase=args.password,
                token_serial_number=args.token_serial_number,
                token_labels=None,
                encryption_mechanism="CKM_AES_CBC",
                hmac_mechanism="CKM_SHA256_HMAC",
                key_wrap_mechanism="CKM_AES_CBC_PAD",
            )
            session = p11.get_session()
            try:
                for label, kind in [
                    (args.mkek_label, "MKEK"),
                    (args.hmac_label, "HMAC"),
                ]:
                    handle = p11.get_key_handle("CKK_AES", label, session)
                    if handle is None:
                        raise RuntimeError(
                            f"{kind} key '{label}' not found on HSM"
                        )
                    LOG.info(
                        "%s key '%s' found on HSM (handle=%s)",
                        kind, label, handle,
                    )
            finally:
                p11.return_session(session)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
