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
import base64
import os
from unittest import mock

import fixtures

from barbican.cmd import token_config_create
from barbican.plugin.crypto import hsm_config_key
from barbican.tests import utils

TEST_KEY = b"\x01" * hsm_config_key.KEY_LEN
TEST_KEY_B64 = base64.b64encode(TEST_KEY)
TEST_PIN = "sup3r-secret-pin"


class WhenParsingEndpoints(utils.BaseTestCase):

    def test_parses_full_triple(self):
        self.assertEqual(
            token_config_create._parse_endpoint(
                "host=10.0.0.1,port=4001,order=0"
            ),
            {"host": "10.0.0.1", "port": 4001, "order": 0},
        )

    def test_rejects_missing_key(self):
        self.assertRaises(
            ValueError,
            token_config_create._parse_endpoint, "host=h,port=1",
        )

    def test_rejects_unknown_key(self):
        self.assertRaises(
            ValueError,
            token_config_create._parse_endpoint,
            "host=h,port=1,order=0,foo=bar",
        )

    def test_rejects_non_int_port(self):
        self.assertRaises(
            ValueError,
            token_config_create._parse_endpoint,
            "host=h,port=nope,order=0",
        )

    def test_rejects_negative_order(self):
        self.assertRaises(
            ValueError,
            token_config_create._parse_endpoint,
            "host=h,port=1,order=-1",
        )

    def test_rejects_empty_host(self):
        self.assertRaises(
            ValueError,
            token_config_create._parse_endpoint,
            "host=,port=1,order=0",
        )

    def test_build_endpoints_rejects_duplicate_order(self):
        args = argparse.Namespace(endpoint=[
            "host=a,port=1,order=0",
            "host=b,port=2,order=0",
        ])
        self.assertRaises(
            ValueError, token_config_create._build_endpoints, args
        )

    def test_build_endpoints_requires_at_least_one(self):
        args = argparse.Namespace(endpoint=[])
        self.assertRaises(
            ValueError, token_config_create._build_endpoints, args
        )


class WhenCheckingConnectivity(utils.BaseTestCase):

    def test_succeeds_when_all_reachable(self):
        endpoints = [
            {"host": "h1", "port": 1, "order": 0},
            {"host": "h2", "port": 2, "order": 1},
        ]
        conn = mock.MagicMock()
        with mock.patch(
            "socket.create_connection", return_value=conn
        ) as fake:
            token_config_create._check_connectivity(endpoints)
        self.assertEqual(fake.call_count, 2)

    def test_raises_listing_all_unreachable(self):
        endpoints = [
            {"host": "h1", "port": 1, "order": 0},
            {"host": "h2", "port": 2, "order": 1},
        ]
        with mock.patch(
            "socket.create_connection", side_effect=OSError("boom")
        ):
            exc = self.assertRaises(
                RuntimeError,
                token_config_create._check_connectivity, endpoints,
            )
        self.assertIn("h1:1", str(exc))
        self.assertIn("h2:2", str(exc))

    def test_raises_if_any_endpoint_unreachable(self):
        endpoints = [
            {"host": "h1", "port": 1, "order": 0},
            {"host": "h2", "port": 2, "order": 1},
        ]
        conn = mock.MagicMock()

        def side_effect(addr, timeout):
            if addr[0] == "h2":
                raise OSError("down")
            return conn

        with mock.patch(
            "socket.create_connection", side_effect=side_effect
        ):
            exc = self.assertRaises(
                RuntimeError,
                token_config_create._check_connectivity, endpoints,
            )
        self.assertIn("h2:2", str(exc))
        self.assertNotIn("h1:1", str(exc))


class BaseFlowTest(utils.BaseTestCase):
    """Shared fixtures for the create_token_config flow tests."""

    vendor_type = "utimaco"

    def setUp(self):
        super().setUp()
        self.tmpdir = self.useFixture(fixtures.TempDir()).path
        self.key_path = os.path.join(self.tmpdir, "hsm-config-key")
        with open(self.key_path, "wb") as f:
            f.write(TEST_KEY_B64)

        # Stub out every external step so only create logic runs.
        for target in ("_setup_database", "_check_connectivity",
                       "_get_secret_store_by_id",
                       "_set_project_preferred_store"):
            self.useFixture(fixtures.MockPatchObject(
                token_config_create, target))

        # Replace the vendor validator with a no-op mock.
        self.validator = mock.Mock()
        self.validator.build_metadata.return_value = None
        patcher = mock.patch.dict(
            token_config_create.vendor_pkg.VALIDATORS,
            {self.vendor_type: self.validator},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        project = mock.Mock(id="project-uuid")
        self.useFixture(fixtures.MockPatchObject(
            token_config_create.resources, "get_or_create_project",
            return_value=project))

        self.repo = mock.Mock()
        self.repo.get_by_project_id.return_value = None
        self.repo.create_from.side_effect = lambda obj: obj
        self.useFixture(fixtures.MockPatchObject(
            token_config_create.repositories,
            "get_project_token_config_repository",
            return_value=self.repo))
        self.useFixture(fixtures.MockPatchObject(
            token_config_create.repositories, "commit"))
        self.useFixture(fixtures.MockPatchObject(
            token_config_create.repositories, "rollback"))

    def _args(self, **overrides):
        base = dict(
            vendor_type=self.vendor_type,
            external_project_id="proj",
            endpoint=["host=10.0.0.1,port=4001,order=0"],
            token_label=None,
            slot_id=None,
            password=TEST_PIN,
            token_config_id=None,
            token_serial_number="SER123",
            mkek_label="mkek",
            hmac_label="hmac",
            secret_store_id="store-1",
            library_path=None,
            config_key_path=self.key_path,
            skip_hsm_checks=False,
            debug=False,
        )
        base.update(overrides)
        return argparse.Namespace(**base)


class WhenCreatingTokenConfig(BaseFlowTest):
    """Vendor-neutral write path.

    Validators are dispatched, endpoints are normalized from CLI
    strings, and the PIN is encrypted before reaching the DB.
    """

    def test_pin_is_encrypted_not_plaintext(self):
        """A valid config key encrypts the PIN into an envelope on write.

        Expected: the credentials persisted to the repo are an AES-256-GCM
        envelope that decrypts back to the PIN, and the plaintext PIN
        never appears in the stored value.
        """
        token_config_create.create_token_config(self._args())

        self.assertTrue(self.repo.create_from.called)
        stored = self.repo.create_from.call_args[0][0].credentials
        self.assertEqual(hsm_config_key.ALG, stored["alg"])
        self.assertNotIn("password", stored)
        self.assertNotIn(TEST_PIN, stored["ciphertext"])
        self.assertEqual(
            TEST_PIN, hsm_config_key.decrypt_pin(stored, TEST_KEY))

    def test_missing_key_aborts_before_db_write(self):
        args = self._args(config_key_path=os.path.join(self.tmpdir, "nope"))
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          token_config_create.create_token_config, args)
        self.assertFalse(self.repo.create_from.called)

    def test_invalid_key_aborts_before_db_write(self):
        bad_path = os.path.join(self.tmpdir, "bad-key")
        with open(bad_path, "wb") as f:
            f.write(base64.b64encode(b"\x01" * 16))
        args = self._args(config_key_path=bad_path)
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          token_config_create.create_token_config, args)
        self.assertFalse(self.repo.create_from.called)

    def test_endpoints_normalized_onto_row(self):
        """CLI --endpoint strings are parsed into the model shape."""
        args = self._args(endpoint=[
            "host=10.0.0.1,port=4001,order=0",
            "host=10.0.0.2,port=4002,order=1",
        ])
        token_config_create.create_token_config(args)
        row = self.repo.create_from.call_args[0][0]
        self.assertEqual(row.endpoints, [
            {"host": "10.0.0.1", "port": 4001, "order": 0},
            {"host": "10.0.0.2", "port": 4002, "order": 1},
        ])
        self.assertEqual(row.vendor_type, "utimaco")

    def test_vendor_validator_dispatched(self):
        """Validators are called with parsed endpoints + args."""
        token_config_create.create_token_config(self._args())
        self.validator.validate_args.assert_called_once()
        self.validator.validate_keys.assert_called_once()
        call_endpoints = self.validator.validate_keys.call_args[0][0]
        self.assertEqual(call_endpoints[0]["host"], "10.0.0.1")

    def test_unknown_vendor_type_rejected(self):
        args = self._args(vendor_type="acme")
        self.assertRaises(
            ValueError,
            token_config_create.create_token_config, args,
        )
        self.assertFalse(self.repo.create_from.called)

    def test_skip_hsm_checks_bypasses_connectivity_and_key_lookup(self):
        token_config_create.create_token_config(
            self._args(skip_hsm_checks=True)
        )
        token_config_create._check_connectivity.assert_not_called()
        self.validator.validate_keys.assert_not_called()

    def test_idempotent_when_row_exists(self):
        """Existing row short-circuits the flow before any HSM work."""
        existing = mock.Mock(id="existing-uuid")
        self.repo.get_by_project_id.return_value = existing
        token_config_create.create_token_config(self._args())
        self.assertFalse(self.repo.create_from.called)
        token_config_create._check_connectivity.assert_not_called()
        self.validator.validate_keys.assert_not_called()

    def test_vendor_metadata_persisted_when_validator_returns_dict(self):
        self.validator.build_metadata.return_value = {"foo": "bar"}
        token_config_create.create_token_config(self._args())
        row = self.repo.create_from.call_args[0][0]
        self.assertEqual(row.vendor_metadata, {"foo": "bar"})
