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

from barbican.cmd import cloudhsms_create
from barbican.plugin.crypto import hsm_config_key
from barbican.tests import utils

TEST_KEY = b"\x01" * hsm_config_key.KEY_LEN
TEST_KEY_B64 = base64.b64encode(TEST_KEY)
TEST_PIN = "sup3r-secret-pin"


class WhenCreatingHSMPartition(utils.BaseTestCase):
    """Write-path glue: the CU-PIN is encrypted before it reaches the DB."""

    def setUp(self):
        super().setUp()
        self.tmpdir = self.useFixture(fixtures.TempDir()).path
        self.key_path = os.path.join(self.tmpdir, "hsm-config-key")
        with open(self.key_path, "wb") as f:
            f.write(TEST_KEY_B64)

        # Stub out every external step so only the create logic runs.
        for target in ("_setup_database", "_check_connectivity",
                       "_validate_hsm_keys", "_get_secret_store_by_id",
                       "_set_project_preferred_store"):
            self.useFixture(fixtures.MockPatchObject(cloudhsms_create, target))

        project = mock.Mock(id="project-uuid")
        self.useFixture(fixtures.MockPatchObject(
            cloudhsms_create.resources, "get_or_create_project",
            return_value=project))

        self.repo = mock.Mock()
        self.repo.get_by_project_id.return_value = None
        self.repo.create_from.side_effect = lambda obj: obj
        self.useFixture(fixtures.MockPatchObject(
            cloudhsms_create.repositories,
            "get_hsm_partition_config_repository",
            return_value=self.repo))
        self.useFixture(fixtures.MockPatchObject(
            cloudhsms_create.repositories, "commit"))
        self.useFixture(fixtures.MockPatchObject(
            cloudhsms_create.repositories, "rollback"))

    def _args(self, **overrides):
        base = dict(
            external_project_id="proj",
            device_ip="10.0.0.1",
            container_id=1,
            token_serial_number="SER123",
            password=TEST_PIN,
            mkek_label="mkek",
            hmac_label="hmac",
            secret_store_id="store-1",
            config_key_path=self.key_path,
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_pin_is_encrypted_not_plaintext(self):
        """A valid config key encrypts the PIN into an envelope on write.

        Expected: the credentials persisted to the repo are an AES-256-GCM
        envelope that decrypts back to the PIN, and the plaintext PIN never
        appears in the stored value.
        """
        cloudhsms_create.create_hsm_partition(self._args())

        self.assertTrue(self.repo.create_from.called)
        stored = self.repo.create_from.call_args[0][0].credentials
        self.assertEqual(hsm_config_key.ALG, stored["alg"])
        self.assertNotIn("password", stored)
        self.assertNotIn(TEST_PIN, stored["ciphertext"])
        self.assertEqual(
            TEST_PIN, hsm_config_key.decrypt_pin(stored, TEST_KEY))

    def test_missing_key_aborts_before_db_write(self):
        """A missing config key fails hard before any row is created.

        Expected: ``HSMConfigKeyError`` and the repo's create_from is never
        called, so no partial row is persisted.
        """
        args = self._args(config_key_path=os.path.join(self.tmpdir, "nope"))
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          cloudhsms_create.create_hsm_partition, args)
        self.assertFalse(self.repo.create_from.called)

    def test_invalid_key_aborts_before_db_write(self):
        """A wrong-length config key fails hard before any row is created.

        Expected: ``HSMConfigKeyError`` and no call to create_from.
        """
        bad_path = os.path.join(self.tmpdir, "bad-key")
        with open(bad_path, "wb") as f:
            f.write(base64.b64encode(b"\x01" * 16))
        args = self._args(config_key_path=bad_path)
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          cloudhsms_create.create_hsm_partition, args)
        self.assertFalse(self.repo.create_from.called)
