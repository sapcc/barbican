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

from argparse import Namespace
import base64
from enum import StrEnum
import json
from pathlib import Path
import subprocess
import unittest

import pytest

from barbican.cmd.hsm_partition_create import create_hsm_partition
from barbican.common import config
from barbican.common import exception
from barbican.common import resources
from barbican.common.utils import is_multiple_backends_enabled
from barbican.model import models
from barbican.model import repositories
from barbican.plugin.crypto import hsm_partition_crypto
from barbican.plugin.crypto import p11_crypto
from barbican.plugin.crypto import pkcs11
from barbican.plugin.interface.secret_store import StorePluginNotAvailableOrMisconfigured  # noqa: E501
from barbican.plugin.resources import delete_secret
from barbican.plugin.resources import get_secret
from barbican.plugin.resources import store_secret


class HSMVendor(StrEnum):
    THALES = "thales_hsm"
    UTIMACO = "utimaco_hsm"


class CryptoPlugin(StrEnum):
    THALES = "thales_hsm_crypto"
    UTIMACO = "utimaco_hsm_crypto"


class HSMCryptoPlugin(StrEnum):
    THALES = "barbican.plugin.crypto.hsm_partition_crypto.ThalesHSMPartitionCryptoPlugin"  # noqa: E501
    UTIMACO = "barbican.plugin.crypto.hsm_partition_crypto.UtimacoHSMPartitionCryptoPlugin"  # noqa: E501


hsm_vendor_to_plugin_mapping = {
    HSMVendor.THALES: CryptoPlugin.THALES,
    HSMVendor.UTIMACO: CryptoPlugin.UTIMACO,
}

hsm_vendor_to_hsm_plugin_mapping = {
    HSMVendor.THALES: HSMCryptoPlugin.THALES,
    HSMVendor.UTIMACO: HSMCryptoPlugin.UTIMACO,
}


class TestPluginResourceWithSoftHSM:
    @classmethod
    def setup_class(cls):
        if not cls.is_softhsm_available():
            raise unittest.SkipTest("SoftHSM not found!")

        # Load test configs
        test_config_file = (
            Path(__file__).parent.parent.resolve() / "barbican.conf.test"
        )
        config.parse_args(config.CONF, default_config_files=[test_config_file])
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
            encryption_mechanism=cls.conf.p11_crypto_plugin.encryption_mechanism,  # noqa: E501
            hmac_mechanism=cls.conf.p11_crypto_plugin.hmac_mechanism,
            key_wrap_mechanism=cls.conf.p11_crypto_plugin.key_wrap_mechanism,
            token_serial_number=cls.conf.p11_crypto_plugin.token_serial_number,
            token_labels=cls.conf.p11_crypto_plugin.token_labels,
        )
        cls.gen_mkek()
        cls.gen_hmac()

        # Setup DB and tables with secret stores
        # ToDo: Note: Init of secret stores is based on `p11_crypto_plugin` configs  # noqa: E501
        repositories.setup_database_engine_and_factory(
            initialize_secret_stores=True
        )
        repositories.start()

        # Initialize repositories
        cls.secret_stores_repo = repositories.get_secret_stores_repository()
        cls.project_store_repo = (
            repositories.get_project_secret_store_repository()
        )
        cls.secret_repo = repositories.get_secret_repository()

    @classmethod
    def teardown_class(cls):
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
        """Secret stores count from the DB matches with the conf if multiple

        secret stores option is enabled
        """
        if not is_multiple_backends_enabled():
            raise unittest.SkipTest(
                "Multiple secret stores option is not enabled!"
            )

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

        assert len(secret_stores) == secret_store_config_count, (
            f"Expected {secret_store_config_count} secret stores from "
            f"config, but found {len(secret_stores)} in database"
        )

    @pytest.mark.parametrize(
        "project_name, hsm_vendor",
        [
            ("testproject_utimaco", HSMVendor.UTIMACO),
            ("testproject_thales", HSMVendor.THALES),
        ],
    )
    def test_store_secret_creates_secret(self, project_name, hsm_vendor):
        """Creates a new secret"""
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
        PROJECT_NAME = project_name

        project = self._create_project_secret_store_mapping(
            project_name=PROJECT_NAME, hsm_vendor=hsm_vendor
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
        assert new_secret.algorithm == ALGORITHM
        assert new_secret.bit_length == BIT_LENGTH
        assert new_secret.mode == MODE
        assert new_secret.secret_type == SECRET_TYPE
        assert new_secret.status == models.States.ACTIVE

        # Check encrypted data values
        encrypted_data = new_secret.encrypted_data[0]
        assert encrypted_data.content_type == CONTENT_TYPE
        assert encrypted_data.cypher_text is not None
        assert encrypted_data.kek_meta_extended is not None
        assert encrypted_data.status == models.States.ACTIVE

        kek_meta_extended = json.loads(encrypted_data.kek_meta_extended)
        assert kek_meta_extended["iv"] is not None
        assert kek_meta_extended["mechanism"] == MECHANISM

        # Check kek data values
        kek_data = encrypted_data.kek_meta_project
        assert kek_data.algorithm == ALGORITHM
        assert kek_data.bit_length == BIT_LENGTH
        assert (
            kek_data.kek_label.startswith(f"project-{PROJECT_NAME}-key-")
            is True
        )
        assert kek_data.mode == MODE
        assert kek_data.plugin_meta is not None
        assert (
            kek_data.plugin_name
            == hsm_vendor_to_hsm_plugin_mapping[hsm_vendor]
        )
        assert kek_data.status == models.States.ACTIVE

        plugin_meta = json.loads(kek_data.plugin_meta)
        assert plugin_meta["iv"] is not None
        assert plugin_meta["wrapped_key"] is not None
        assert plugin_meta["hmac"] is not None
        assert plugin_meta["mkek_label"] == MKEK_LABEL
        assert plugin_meta["hmac_label"] == HMAC_LABEL
        assert plugin_meta["key_wrap_mechanism"] == KEY_WRAP_MECHANISM

        # Check secret store metadata values
        secret_store_metadata = new_secret.secret_store_metadata
        assert (
            secret_store_metadata["plugin_name"].value
            == "barbican.plugin.store_crypto.StoreCryptoAdapterPlugin"
        )
        assert secret_store_metadata["content_type"].value == CONTENT_TYPE

    def test_get_secret_returns_secret(self):
        """Retrieves the raw secret if present"""
        ALGORITHM = "AES"
        BIT_LENGTH = 256
        MODE = "CBC"
        SECRET_TYPE = "passphrase"
        CONTENT_TYPE = "application/octet-stream"
        CONTENT_ENCODING = "base64"
        PROJECT_NAME = "testproject"

        project = self._create_project_secret_store_mapping(
            project_name=PROJECT_NAME, hsm_vendor=HSMVendor.UTIMACO
        )

        # Create a new secret
        raw_secret = b"ABCDEFABCDEFABCDEFABCDEF"
        spec = {
            "algorithm": ALGORITHM,
            "bit_length": BIT_LENGTH,
            "mode": MODE,
            "secret_type": SECRET_TYPE,
        }
        new_secret, _ = store_secret(
            unencrypted_raw=base64.b64encode(raw_secret),
            content_type_raw=CONTENT_TYPE,
            content_encoding=CONTENT_ENCODING,
            secret_model=models.Secret(spec),
            project_model=project,
        )

        # Retrieve the newly created secret
        retrieved_raw_secret = get_secret(
            requesting_content_type=CONTENT_TYPE,
            secret_model=new_secret,
            project_model=project,
        )
        assert raw_secret == retrieved_raw_secret

    def test_get_secret_raises_exception(self):
        """Raises exception if the secret is not present"""
        ALGORITHM = "AES"
        BIT_LENGTH = 256
        MODE = "CBC"
        SECRET_TYPE = "passphrase"
        CONTENT_TYPE = "application/octet-stream"
        PROJECT_NAME = "testproject2"

        project = self._create_project_secret_store_mapping(
            project_name=PROJECT_NAME, hsm_vendor=HSMVendor.UTIMACO
        )

        # Retrieve a secret which is not present
        spec = {
            "algorithm": ALGORITHM,
            "bit_length": BIT_LENGTH,
            "mode": MODE,
            "secret_type": SECRET_TYPE,
        }
        with pytest.raises(StorePluginNotAvailableOrMisconfigured):
            get_secret(
                requesting_content_type=CONTENT_TYPE,
                secret_model=models.Secret(spec),
                project_model=project,
            )

    def test_delete_secret_deletes_secret(self):
        """Deletes secret if present"""
        ALGORITHM = "AES"
        BIT_LENGTH = 256
        MODE = "CBC"
        SECRET_TYPE = "passphrase"
        CONTENT_TYPE = "application/octet-stream"
        CONTENT_ENCODING = "base64"
        PROJECT_NAME = "testproject3"

        project = self._create_project_secret_store_mapping(
            project_name=PROJECT_NAME, hsm_vendor=HSMVendor.UTIMACO
        )

        # Create a new secret
        raw_secret = b"ABCDEFABCDEFABCDEFABCDEF"
        spec = {
            "algorithm": ALGORITHM,
            "bit_length": BIT_LENGTH,
            "mode": MODE,
            "secret_type": SECRET_TYPE,
        }
        new_secret, _ = store_secret(
            unencrypted_raw=base64.b64encode(raw_secret),
            content_type_raw=CONTENT_TYPE,
            content_encoding=CONTENT_ENCODING,
            secret_model=models.Secret(spec),
            project_model=project,
        )

        # Delete the newly created secret
        delete_secret(secret_model=new_secret, project_id=project.external_id)

        # Verify that the secret is not present
        with pytest.raises(exception.NotFound):
            self.secret_repo.get_secret_by_id(new_secret.id)

    def test_delete_secret_raises_exception(self):
        """Raises exception if the secret is not present"""
        ALGORITHM = "AES"
        BIT_LENGTH = 256
        MODE = "CBC"
        SECRET_TYPE = "passphrase"
        PROJECT_NAME = "testproject4"

        project = self._create_project_secret_store_mapping(
            project_name=PROJECT_NAME, hsm_vendor=HSMVendor.UTIMACO
        )

        # Delete a secret which is not present
        spec = {
            "algorithm": ALGORITHM,
            "bit_length": BIT_LENGTH,
            "mode": MODE,
            "secret_type": SECRET_TYPE,
        }
        with pytest.raises(exception.NotFound):
            delete_secret(
                secret_model=models.Secret(spec),
                project_id=project.external_id,
            )
