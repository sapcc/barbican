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

import argparse
import os
from unittest import mock

from barbican.plugin.crypto.vendor import thales
from barbican.tests import utils


class WhenValidatingThalesArgs(utils.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.validator = thales.ThalesValidator()

    def test_rejects_when_no_identifier_present(self):
        args = argparse.Namespace(
            token_serial_number=None, slot_id=None, token_label=None,
        )
        self.assertRaises(ValueError, self.validator.validate_args, args)

    def test_accepts_any_identifier(self):
        for present in ("token_serial_number", "slot_id", "token_label"):
            kwargs = dict(
                token_serial_number=None, slot_id=None, token_label=None,
            )
            kwargs[present] = "x"
            self.validator.validate_args(argparse.Namespace(**kwargs))

    def test_build_metadata_is_none(self):
        self.assertIsNone(
            self.validator.build_metadata(argparse.Namespace(), [])
        )


class WhenValidatingThalesKeys(utils.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.validator = thales.ThalesValidator()
        self.endpoints = [{"host": "h", "port": 1792, "order": 0}]
        self.args = argparse.Namespace(
            password="pw",
            token_serial_number=None,
            slot_id=3,
            token_label="tok",
            mkek_label="mkek",
            hmac_label="hmac",
        )

    def test_opens_pkcs11_without_rewriting_cfg(self):
        """Thales path never touches CS_PKCS11_R3_CFG.

        Expected: PKCS11 ctor receives slot_id/token_labels/
        token_serial_number from args; no CS_PKCS11_R3_CFG env mutation
        occurs; both key labels are looked up.
        """
        before = os.environ.get("CS_PKCS11_R3_CFG")
        captured = {}

        class FakePKCS11:
            def __init__(fake_self, **kwargs):
                captured["ctor"] = kwargs
                captured["env"] = os.environ.get("CS_PKCS11_R3_CFG")

            def get_session(fake_self):
                return object()

            def return_session(fake_self, _):
                captured["returned"] = True

            def get_key_handle(fake_self, _ckk, label, _session):
                captured.setdefault("labels", []).append(label)
                return 7

        with mock.patch(
            "barbican.plugin.crypto.pkcs11.PKCS11", FakePKCS11
        ):
            self.validator.validate_keys(self.endpoints, self.args)

        self.assertEqual(captured["ctor"]["slot_id"], 3)
        self.assertEqual(captured["ctor"]["token_labels"], ["tok"])
        self.assertIsNone(captured["ctor"]["token_serial_number"])
        # Env variable untouched compared to before the call.
        self.assertEqual(captured["env"], before)
        self.assertEqual(captured["labels"], ["mkek", "hmac"])
        self.assertTrue(captured["returned"])
