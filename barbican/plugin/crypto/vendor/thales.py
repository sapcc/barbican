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

from barbican.common import utils
from barbican.plugin.crypto.vendor import base

LOG = utils.getLogger(__name__)

_DEFAULT_PKCS11_LIBRARY_PATH = "/opt/hsm/lib/pkcs11.so"


class ThalesValidator(base.VendorValidator):
    """Thales: direct PKCS#11 lookup; driver picks slot/label/serial."""

    def validate_args(self, args):
        if not any([
            getattr(args, "token_serial_number", None),
            getattr(args, "slot_id", None),
            getattr(args, "token_label", None),
        ]):
            raise ValueError(
                "Thales onboarding requires at least one of "
                "--token-serial-number, --slot-id, or --token-label"
            )

    def validate_keys(self, endpoints, args, library_path=None):
        from barbican.plugin.crypto import pkcs11

        lib = library_path or _DEFAULT_PKCS11_LIBRARY_PATH
        slot_id = args.slot_id
        if slot_id is not None:
            slot_id = int(slot_id)
        token_labels = [args.token_label] if args.token_label else None
        p11 = pkcs11.PKCS11(
            library_path=lib,
            login_passphrase=args.password,
            token_serial_number=getattr(args, "token_serial_number", None),
            token_labels=token_labels,
            slot_id=slot_id,
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
