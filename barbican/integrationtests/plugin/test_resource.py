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

import base64
import json
import subprocess
import unittest
from argparse import Namespace
from enum import StrEnum

from barbican.cmd.hsm_partition_create import create_hsm_partition
from barbican.common import config, resources
from barbican.model import models, repositories
from barbican.model.models import States
from barbican.plugin.crypto import hsm_partition_crypto, p11_crypto, pkcs11
from barbican.plugin.resources import store_secret


class HSMVendor(StrEnum):
    THALES = "thales_hsm"
    UTIMACO = "utimaco_hsm"


class CryptoPlugin(StrEnum):
    THALES = "thales_hsm_crypto"
    UTIMACO = "utimaco_hsm_crypto"


class HSMCryptoPlugin(StrEnum):
    THALES = "barbican.plugin.crypto.hsm_partition_crypto.ThalesHSMPartitionCryptoPlugin"
    UTIMACO = "barbican.plugin.crypto.hsm_partition_crypto.UtimacoHSMPartitionCryptoPlugin"


hsm_vendor_to_plugin_mapping = {
    HSMVendor.THALES: CryptoPlugin.THALES,
    HSMVendor.UTIMACO: CryptoPlugin.UTIMACO,
}


class WhenTestingPluginResourceWithSoftHSM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not cls.is_softhsm_available():
            raise unittest.SkipTest("SoftHSM not found!")

        # Load global configs
        cls.conf = config.CONF
        cls.conf.set_override(
            "connection", "sqlite:///:memory:", group="database"
        )
        cls.conf.set_override("db_auto_create", True)

        # Register crypto plugin vendors
        p11_crypto.register_opts(cls.conf)
        hsm_partition_crypto.register_opts_for_hsm_vendors(cls.conf)

        # Generate mkek and hmac keys using `p11_crypto_plugin` configs
        # ToDo: Note: `p11_crypto_plugin` configs are required
        cls.pkcs11 = pkcs11.PKCS11(
            library_path=cls.conf.p11_crypto_plugin.library_path,
            login_passphrase=cls.conf.p11_crypto_plugin.login,
            rw_session=cls.conf.p11_crypto_plugin.rw_session,
            slot_id=int(cls.conf.p11_crypto_plugin.slot_id),
            encryption_mechanism=cls.conf.p11_crypto_plugin.encryption_mechanism,
            hmac_mechanism=cls.conf.p11_crypto_plugin.hmac_mechanism,
            key_wrap_mechanism=cls.conf.p11_crypto_plugin.key_wrap_mechanism,
            token_serial_number=cls.conf.p11_crypto_plugin.token_serial_number,
            token_labels=cls.conf.p11_crypto_plugin.token_labels,
        )
        cls.gen_mkek()
        cls.gen_hmac()

        # Setup DB and tables with secret stores
        # ToDo: Note: Initialization of secret stores are based on `p11_crypto_plugin` configs
        repositories.setup_database_engine_and_factory(
            initialize_secret_stores=True
        )
        repositories.start()

        # Initialize repositories
        cls.secret_stores_repo = repositories.get_secret_stores_repository()
        cls.project_store_repo = (
            repositories.get_project_secret_store_repository()
        )
        cls.hsm_partition_configs_repo = (
            repositories.get_hsm_partition_config_repository()
        )
        cls.kek_data_repo = repositories.get_kek_datum_repository()
        cls.secret_meta_repo = repositories.get_secret_meta_repository()
        cls.encrypted_data_repo = repositories.get_encrypted_datum_repository()

    @classmethod
    def tearDownClass(cls):
        # Delete mkek and hmac keys using `p11_crypto_plugin` configs
        cls.delete_key(cls.conf.p11_crypto_plugin.mkek_label)
        cls.delete_key(cls.conf.p11_crypto_plugin.hmac_label)

    @classmethod
    def is_softhsm_available(cls) -> bool:
        try:
            result = subprocess.run(
                ["softhsm2-util", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    @classmethod
    def delete_key(cls, label: str):
        try:
            subprocess.run(
                [
                    "pkcs11-tool",
                    "--module",
                    cls.conf.p11_crypto_plugin.library_path,
                    "--slot",
                    str(cls.conf.p11_crypto_plugin.slot_id),
                    "--pin",
                    str(cls.conf.p11_crypto_plugin.login),
                    "--delete-object",
                    "--label",
                    label,
                    "--type",
                    "secrkey",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    @classmethod
    def gen_mkek(cls):
        session = cls.pkcs11.get_session()
        label_exists = cls.does_label_exist(
            "CKK_AES", cls.conf.p11_crypto_plugin.mkek_label, session
        )
        if label_exists:
            return

        cls.pkcs11.generate_key(
            key_type="CKK_AES",
            key_length=cls.conf.p11_crypto_plugin.mkek_length,
            mechanism="CKM_AES_KEY_GEN",
            session=session,
            key_label=cls.conf.p11_crypto_plugin.mkek_label,
            encrypt=True,
            wrap=True,
            master_key=True,
        )
        cls.pkcs11.return_session(session)

    @classmethod
    def gen_hmac(cls):
        session = cls.pkcs11.get_session()
        label_exists = cls.does_label_exist(
            cls.conf.p11_crypto_plugin.hmac_key_type,
            cls.conf.p11_crypto_plugin.hmac_label,
            session,
        )
        if label_exists:
            return

        cls.pkcs11.generate_key(
            key_type=cls.conf.p11_crypto_plugin.hmac_key_type,
            key_length=32,
            mechanism=cls.conf.p11_crypto_plugin.hmac_keygen_mechanism,
            session=session,
            key_label=cls.conf.p11_crypto_plugin.hmac_label,
            sign=True,
            master_key=True,
        )
        cls.pkcs11.return_session(session)

    @classmethod
    def does_label_exist(cls, key_type: str, label: str, session: int) -> bool:
        key_handle = cls.pkcs11.get_key_handle(key_type, label, session)
        if key_handle:
            return True
        return False

    def _create_project_secret_store_mapping(
            self, project_name: str, hsm_vendor: HSMVendor
    ) -> models.Project:
        # Create project in DB
        # ToDo: Note: Project name must not contain (-) hyphens
        project = resources.get_or_create_project(project_name)

        # Create HSM partition config in DB
        # ToDo: Refactor in a proper way with repository
        # ToDo: Note: Some of the options are not present in HSM crypto plugin
        args = Namespace(
            external_project_id=project.external_id,
            token_label="",
            slot_id=self.conf.p11_crypto_plugin.slot_id,
            library_path=self.conf.p11_crypto_plugin.library_path,
            password=self.conf.p11_crypto_plugin.login,
            partition_id=None,
            partition_label="",
        )
        create_hsm_partition(args)

        # Create project to secret store mapping in DB
        vendor_plugin = hsm_vendor_to_plugin_mapping[hsm_vendor]
        project_secret_store = None
        secret_stores = self.secret_stores_repo.get_all()
        for secret_store in secret_stores:
            if secret_store.crypto_plugin == vendor_plugin:
                project_secret_store = secret_store

        if not project_secret_store:
            raise unittest.SkipTest(
                f"Secret store for plugin {vendor_plugin.value} not found!"
            )

        self.project_store_repo.create_or_update_for_project(
            project.id, project_secret_store.id
        )
        return project

    def test_secret_store_count_matches_config(self):
        secret_stores = self.secret_stores_repo.get_all()

        SECRET_STORE_PREFIX = "secretstore"
        EXPECTED_SECTION_PARTS = 2

        secret_store_config_count = 0
        config_sections = self.conf.list_all_sections()
        for section in config_sections:
            if (
                    section.startswith(SECRET_STORE_PREFIX)
                    and len(section.split(":")) == EXPECTED_SECTION_PARTS
            ):
                secret_store_config_count += 1

        self.assertEqual(
            len(secret_stores),
            secret_store_config_count,
            f"Expected {secret_store_config_count} secret stores from config, "
            f"but found {len(secret_stores)} in database",
        )

    def test_store_secret_creates_secret(self):
        ALGORITHM = "AES"
        BIT_LENGTH = 256
        MODE = "CBC"
        MECHANISM = "CKM_AES_CBC"
        KEY_WRAP_MECHANISM = "CKM_AES_CBC_PAD"
        SECRET_TYPE = "passphrase"
        CONTENT_TYPE = "application/octet-stream"
        CONTENT_ENCODING = "base64"
        MKEK_LABEL = "mkek"
        HMAC_LABEL = "hmac"
        PROJECT_NAME = "testproject"

        project = self._create_project_secret_store_mapping(
            project_name=PROJECT_NAME, hsm_vendor=HSMVendor.UTIMACO
        )

        # Create a new secret
        spec = {
            "algorithm": ALGORITHM,
            "bit_length": BIT_LENGTH,
            "mode": MODE,
            "secret_type": SECRET_TYPE,
        }
        new_secret, _ = store_secret(
            unencrypted_raw=base64.b64encode(b"ABCDEFABCDEFABCDEFABCDEF"),
            content_type_raw=CONTENT_TYPE,
            content_encoding=CONTENT_ENCODING,
            secret_model=models.Secret(spec),
            project_model=project,
        )

        # Check secret values
        self.assertEqual(new_secret.algorithm, ALGORITHM)
        self.assertEqual(new_secret.bit_length, BIT_LENGTH)
        self.assertEqual(new_secret.mode, MODE)
        self.assertEqual(new_secret.secret_type, SECRET_TYPE)
        self.assertEqual(new_secret.status, States.ACTIVE)

        # Check encrypted data values
        encrypted_data = new_secret.encrypted_data[0]
        self.assertEqual(encrypted_data.content_type, CONTENT_TYPE)
        self.assertIsNotNone(encrypted_data.cypher_text)
        self.assertIsNotNone(encrypted_data.kek_meta_extended)
        self.assertEqual(encrypted_data.status, States.ACTIVE)

        kek_meta_extended = json.loads(encrypted_data.kek_meta_extended)
        self.assertIsNotNone(kek_meta_extended["iv"])
        self.assertEqual(kek_meta_extended["mechanism"], MECHANISM)

        # Check kek data values
        kek_data = encrypted_data.kek_meta_project
        self.assertEqual(kek_data.algorithm, ALGORITHM)
        self.assertEqual(kek_data.bit_length, BIT_LENGTH)
        self.assertTrue(kek_data.kek_label.startswith(f"project-{PROJECT_NAME}-key-"))
        self.assertEqual(kek_data.mode, MODE)
        self.assertIsNotNone(kek_data.plugin_meta)
        self.assertEqual(kek_data.plugin_name,HSMCryptoPlugin.UTIMACO.value)
        self.assertEqual(kek_data.status, States.ACTIVE)

        plugin_meta = json.loads(kek_data.plugin_meta)
        self.assertIsNotNone(plugin_meta["iv"])
        self.assertIsNotNone(plugin_meta["wrapped_key"])
        self.assertIsNotNone(plugin_meta["hmac"])
        self.assertEqual(plugin_meta["mkek_label"], MKEK_LABEL)
        self.assertEqual(plugin_meta["hmac_label"], HMAC_LABEL)
        self.assertEqual(plugin_meta["key_wrap_mechanism"], KEY_WRAP_MECHANISM)

        # Check secret store metadata values
        secret_store_metadata = new_secret.secret_store_metadata
        self.assertEqual(secret_store_metadata["plugin_name"].value,
                         "barbican.plugin.store_crypto.StoreCryptoAdapterPlugin")
        self.assertEqual(secret_store_metadata["content_type"].value, CONTENT_TYPE)
