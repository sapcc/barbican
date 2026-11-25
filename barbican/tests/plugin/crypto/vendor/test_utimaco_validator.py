# Copyright (c) 2025 SAP SE
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

from barbican.plugin.crypto.vendor import utimaco
from barbican.tests import utils


class WhenRenderingUtimacoCfg(utils.BaseTestCase):

    def test_endpoints_ordered_by_order_field(self):
        endpoints = [
            {"host": "h2", "port": 4002, "order": 1},
            {"host": "h1", "port": 4001, "order": 0},
        ]
        cfg = utimaco.render_utimaco_cfg(endpoints)
        self.assertIn("Devices = { 4001@h1 4002@h2 }\n", cfg)
        self.assertIn("[HSMCluster]", cfg)
        self.assertIn("[Global]", cfg)
        self.assertIn("FallbackInterval = 0\n", cfg)

    def test_single_endpoint(self):
        cfg = utimaco.render_utimaco_cfg(
            [{"host": "10.0.0.1", "port": 4001, "order": 0}]
        )
        self.assertIn("Devices = 4001@10.0.0.1\n", cfg)

    def test_custom_logpath(self):
        cfg = utimaco.render_utimaco_cfg(
            [{"host": "h", "port": 1, "order": 0}], logpath="/var/log/hsm"
        )
        self.assertIn("Logpath = /var/log/hsm\n", cfg)

    def test_failover_interval_sets_mode(self):
        """fallback_interval > 0 selects failover mode per vendor docs."""
        cfg = utimaco.render_utimaco_cfg(
            [{"host": "h", "port": 1, "order": 0}], fallback_interval=30
        )
        self.assertIn("FallbackInterval = 30\n", cfg)


class WhenValidatingUtimacoArgs(utils.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.validator = utimaco.UtimacoValidator()

    def test_requires_token_serial_number(self):
        args = argparse.Namespace(token_serial_number=None)
        self.assertRaises(ValueError, self.validator.validate_args, args)

    def test_accepts_when_serial_present(self):
        args = argparse.Namespace(token_serial_number="SER123")
        self.validator.validate_args(args)  # does not raise

    def test_build_metadata_is_none_by_default(self):
        args = argparse.Namespace(token_serial_number="SER")
        self.assertIsNone(self.validator.build_metadata(args, []))


class WhenValidatingUtimacoKeys(utils.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.validator = utimaco.UtimacoValidator()
        self.endpoints = [{"host": "h", "port": 4001, "order": 0}]
        self.args = argparse.Namespace(
            password="pw",
            token_serial_number="SER",
            mkek_label="mkek",
            hmac_label="hmac",
        )

    def test_writes_cfg_and_opens_pkcs11_with_serial(self):
        """Utimaco path writes a cfg file and drives PKCS11 by serial.

        Expected: CS_PKCS11_R3_CFG points at a file whose contents match
        render_utimaco_cfg(); PKCS11 is constructed with
        token_serial_number but no token_labels/slot_id; both key labels
        are looked up; the temp cfg is removed after.
        """
        captured = {}

        class FakeSession:
            pass

        class FakePKCS11:
            def __init__(fake_self, **kwargs):
                captured["ctor"] = kwargs
                cfg_path = os.environ["CS_PKCS11_R3_CFG"]
                with open(cfg_path) as fh:
                    captured["cfg_contents"] = fh.read()
                captured["cfg_path"] = cfg_path

            def get_session(fake_self):
                return FakeSession()

            def return_session(fake_self, _):
                captured["returned"] = True

            def get_key_handle(fake_self, _ckk, label, _session):
                captured.setdefault("labels", []).append(label)
                return 42

        with mock.patch(
            "barbican.plugin.crypto.pkcs11.PKCS11", FakePKCS11
        ):
            self.validator.validate_keys(self.endpoints, self.args)

        self.assertEqual(captured["ctor"]["token_serial_number"], "SER")
        self.assertIsNone(captured["ctor"]["token_labels"])
        self.assertEqual(
            captured["cfg_contents"],
            utimaco.render_utimaco_cfg(self.endpoints),
        )
        # Temp cfg is deleted after validate_keys returns.
        self.assertFalse(os.path.exists(captured["cfg_path"]))
        self.assertEqual(captured["labels"], ["mkek", "hmac"])
        self.assertTrue(captured["returned"])

    def test_missing_key_raises(self):
        class FakePKCS11:
            def __init__(fake_self, **kwargs):
                pass

            def get_session(fake_self):
                return object()

            def return_session(fake_self, _):
                pass

            def get_key_handle(fake_self, _ckk, _label, _session):
                return None

        with mock.patch(
            "barbican.plugin.crypto.pkcs11.PKCS11", FakePKCS11
        ):
            self.assertRaises(
                RuntimeError,
                self.validator.validate_keys, self.endpoints, self.args,
            )
