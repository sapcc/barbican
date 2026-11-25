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

import os
import tempfile
import threading
from unittest import mock

from barbican.common import config
from barbican.common import exception
from barbican import i18n as u

from barbican.model.models import KEKDatum
from barbican.model.models import ProjectTokenConfig
from barbican.plugin.crypto.base import KEKMetaDTO
from barbican.plugin.crypto.base import ResponseDTO
from barbican.plugin.crypto import multitenant_p11_crypto as mt_p11
from barbican.plugin.crypto import p11_crypto
from barbican.tests import utils
from oslo_config import cfg


def _utimaco_token_config(**overrides):
    """Build a Utimaco ProjectTokenConfig fixture with sensible defaults."""
    defaults = dict(
        project_id="test_project_id",
        vendor_type="utimaco",
        endpoints=[{"host": "10.0.0.1", "port": 4009, "order": 0}],
        mkek_label="mkek",
        hmac_label="hmac",
        token_serial_number="016df7f4be_0001",
        slot_id=None,
        token_label=None,
        credentials={"password": "test_password"},
        vendor_metadata=None,
    )
    defaults.update(overrides)
    return ProjectTokenConfig(**defaults)


def _thales_token_config(**overrides):
    defaults = dict(
        project_id="test_project_id",
        vendor_type="thales",
        endpoints=[{"host": "10.0.0.2", "port": 1792, "order": 0}],
        mkek_label="mkek",
        hmac_label="hmac",
        token_serial_number=None,
        slot_id="100",
        token_label="test_token_label",
        credentials={"password": "test_password"},
        vendor_metadata=None,
    )
    defaults.update(overrides)
    return ProjectTokenConfig(**defaults)


class PluginOperationThread(threading.Thread):

    def __init__(self, index, results):
        threading.Thread.__init__(self)
        self.index = index
        self.results = results
        self.plugin = mt_p11.MultitenantP11CryptoPlugin()
        self.plugin._configure_pkcs11 = mock.MagicMock()

    def run(self):
        with mock.patch.object(p11_crypto.P11CryptoPlugin,
                               "encrypt") as mock_encrypt:
            mock_encrypt.return_value = ResponseDTO(
                cypher_text=f"cypher_text_{self.index}".encode("utf-8"),
                kek_meta_extended=('{"iv":"AAAA",'
                                   '"mechanism":"CKM_AES_CBC",'
                                   '"key_wrap_mechanism":"CKM_AES_CBC_PAD"}'),
            )

            self.results[self.index] = self.plugin.encrypt(
                encrypt_dto=mock.MagicMock(),
                kek_meta_dto=mock.MagicMock(),
                project_id=f"project_{self.index}",
            )


class WhenTestingMultitenantP11CryptoPlugin(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingMultitenantP11CryptoPlugin, self).setUp()

        self.conf = config.new_config()
        self.conf.register_group(
            mt_p11.multitenant_p11_crypto_plugin_group)
        self.conf.register_opts(
            mt_p11.multitenant_p11_crypto_plugin_opts,
            group=mt_p11.multitenant_p11_crypto_plugin_group,
        )

        self.pkcs11 = mock.Mock()
        self.plugin_name = "TestMultitenantP11CryptoPlugin"
        self.project_id = "test_project_id"
        self.token_config_id = "test_token_config_id"
        self.slot_id = "100"
        self.token_label = "test_token_label"
        self.library_path = "test_library_path"
        self.login = "test_password"
        self.cypher_text = b"cypher_text"
        self.kek_meta_extended = ('{"iv":"AAAA",'
                                  '"mechanism":"CKM_AES_CBC",'
                                  '"key_wrap_mechanism":"CKM_AES_CBC_PAD"}')

        self.conf.multitenant_p11_crypto_plugin.plugin_name = self.plugin_name
        self.conf.multitenant_p11_crypto_plugin.default_token_config_id = (
            self.token_config_id
        )
        self.conf.multitenant_p11_crypto_plugin.library_path = (
            self.library_path
        )

    def test_init_with_global_conf(self):
        store_plugin_name = "default"
        section_name = "multitenant_p11_crypto_plugin"

        plugin = mt_p11.MultitenantP11CryptoPlugin()

        self.assertEqual(section_name, plugin.section_name)
        self.assertEqual(store_plugin_name, plugin.store_plugin_name)

    def test_init_with_given_conf(self):
        store_plugin_name = "given_test_store_plugin"
        section_name = (
            f"multitenant_p11_crypto_plugin:{store_plugin_name}"
        )

        plugin_group = cfg.OptGroup(name=section_name)
        self.conf.register_group(plugin_group)
        self.conf.register_opts(
            mt_p11.multitenant_p11_crypto_plugin_opts,
            group=plugin_group)

        plugin = mt_p11.MultitenantP11CryptoPlugin(
            conf=self.conf, store_plugin_name=store_plugin_name)

        self.assertEqual(section_name, plugin.section_name)
        self.assertEqual(store_plugin_name, plugin.store_plugin_name)

    def test_init_with_dynamic_conf(self):
        store_plugin_name = "dynamic_test_store_plugin"
        section_name = (
            f"multitenant_p11_crypto_plugin:{store_plugin_name}"
        )

        plugin = mt_p11.MultitenantP11CryptoPlugin(
            conf=self.conf, store_plugin_name=store_plugin_name)

        self.assertEqual(section_name, plugin.section_name)
        self.assertEqual(store_plugin_name, plugin.store_plugin_name)

    def test_get_token_config_raises_error_without_project_id(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin()

        self.assertRaises(
            ValueError, plugin._get_token_config_for_project, None
        )

    def test_get_token_config_specific_mapping(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)

        plugin.project_token_config_repo = mock.MagicMock()
        plugin.project_token_config_repo.get_by_project_id.return_value = (
            _thales_token_config(
                project_id=self.project_id,
                slot_id=self.slot_id,
                token_label=self.token_label,
            )
        )

        token_config = plugin._get_token_config_for_project(self.project_id)

        self.assertEqual(self.project_id, token_config.project_id)
        self.assertEqual(self.slot_id, token_config.slot_id)
        self.assertEqual(self.token_label, token_config.token_label)

    def test_get_token_config_default_mapping(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)

        plugin.project_token_config_repo = mock.MagicMock()
        plugin.project_token_config_repo.get_by_project_id.return_value = (
            _thales_token_config(
                project_id=self.project_id,
                slot_id=self.slot_id,
                token_label=self.token_label,
            )
        )

        token_config = plugin._get_token_config_for_project(self.project_id)

        self.assertEqual(self.project_id, token_config.project_id)
        self.assertEqual(self.slot_id, token_config.slot_id)
        self.assertEqual(self.token_label, token_config.token_label)

    def test_get_token_config_raises_error_for_no_mapping(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)

        plugin.project_token_config_repo = mock.MagicMock()
        plugin.project_token_config_repo.get_by_project_id.side_effect = (
            exception.NotFound("Token config not found"))
        plugin.project_token_config_repo.get.side_effect = exception.NotFound(
            "Token config not found")

        self.assertRaises(
            ValueError,
            plugin._get_token_config_for_project,
            self.project_id,
        )

    def test_configure_pkcs11_is_already_configured(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)
        plugin.current_project_id = self.project_id
        plugin.pkcs11 = mock.MagicMock()
        plugin._get_token_config_for_project = mock.MagicMock()
        plugin._create_pkcs11 = mock.MagicMock()

        plugin._configure_pkcs11(self.project_id)

        self.assertEqual(
            0, plugin._get_token_config_for_project.call_count
        )
        self.assertEqual(0, plugin._create_pkcs11.call_count)

    def test_configure_pkcs11_raises_error_for_no_token_config_mapping(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)
        plugin.project_token_config_repo = mock.MagicMock()
        plugin.project_token_config_repo.get_by_project_id.side_effect = (
            exception.NotFound("Token config not found"))
        plugin.project_token_config_repo.get.side_effect = exception.NotFound(
            "Token config not found")

        self.assertRaises(ValueError, plugin._configure_pkcs11,
                          self.project_id)

    def test_configure_pkcs11_thales(self):
        """Thales dispatch: no cfg rewrite; slot/token_label resolved."""
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)
        plugin._get_token_config_for_project = mock.MagicMock(
            return_value=_thales_token_config(
                project_id=self.project_id,
                slot_id=self.slot_id,
                token_label=self.token_label,
            )
        )
        plugin._create_pkcs11 = mock.MagicMock(return_value=self.pkcs11)
        plugin._decrypt_pin = mock.MagicMock(return_value=self.login)
        utimaco = mt_p11.VENDOR_BACKENDS["utimaco"]
        with mock.patch.object(utimaco, "_generate_cfg") as mock_gen:
            os.environ.pop("CS_PKCS11_R3_CFG", None)
            plugin._configure_pkcs11(self.project_id)

            self.assertEqual(self.login, plugin.login)
            self.assertEqual(int(self.slot_id), plugin.slot_id)
            self.assertEqual([self.token_label], plugin.token_labels)
            self.assertIsNone(plugin.token_serial_number)
            self.assertNotIn("CS_PKCS11_R3_CFG", os.environ)
            self.assertEqual(1, plugin._create_pkcs11.call_count)
            mock_gen.assert_not_called()

    def test_configure_pkcs11_utimaco(self):
        """Utimaco dispatch: backend._generate_cfg is called with the row."""
        token_config = _utimaco_token_config(
            project_id=self.project_id,
            mkek_label="part-mkek",
            hmac_label="part-hmac",
        )
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)
        plugin._get_token_config_for_project = mock.MagicMock(
            return_value=token_config
        )
        plugin._create_pkcs11 = mock.MagicMock(return_value=self.pkcs11)
        plugin._decrypt_pin = mock.MagicMock(return_value=self.login)
        utimaco = mt_p11.VENDOR_BACKENDS["utimaco"]
        with mock.patch.object(
            utimaco, "_generate_cfg",
            return_value="/tmp/utimaco/cs_pkcs11_R3.cfg",
        ) as mock_gen:
            os.environ.pop("CS_PKCS11_R3_CFG", None)
            plugin._configure_pkcs11(self.project_id)

            self.assertEqual("016df7f4be_0001", plugin.token_serial_number)
            self.assertIsNone(plugin.slot_id)
            self.assertIsNone(plugin.token_labels)
            self.assertEqual("part-mkek", plugin.mkek_label)
            self.assertEqual("part-hmac", plugin.hmac_label)
            mock_gen.assert_called_once_with(token_config)

    def test_configure_pkcs11_unsupported_vendor_raises(self):
        """Defensive runtime guard against unknown vendor_type."""
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)
        # Use a mock stand-in for the row — the model-level @validates
        # decorator rejects unknown vendor_types on real ORM assignment,
        # which is exactly the invariant this guard defends against at
        # runtime (defense in depth for existing corrupted rows).
        token_config = mock.MagicMock(
            vendor_type="futurevendor",
            credentials={"password": "p"},
            token_serial_number="s",
            slot_id=None,
            token_label=None,
            mkek_label="mkek",
            hmac_label="hmac",
            vendor_metadata=None,
            endpoints=[{"host": "h", "port": 1, "order": 0}],
        )
        plugin._get_token_config_for_project = mock.MagicMock(
            return_value=token_config
        )
        plugin._create_pkcs11 = mock.MagicMock(return_value=self.pkcs11)
        plugin._decrypt_pin = mock.MagicMock(return_value=self.login)

        self.assertRaises(
            exception.BarbicanException,
            plugin._configure_pkcs11,
            self.project_id,
        )

    def test_configure_pkcs11_utimaco_writes_cfg_from_endpoints(self):
        """End-to-end: Utimaco endpoint list renders as Devices lines."""
        token_config = _utimaco_token_config(
            project_id=self.project_id,
            endpoints=[
                {"host": "10.246.244.60", "port": 4000, "order": 0},
            ],
        )
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)
        plugin._get_token_config_for_project = mock.MagicMock(
            return_value=token_config
        )
        plugin._create_pkcs11 = mock.MagicMock(return_value=self.pkcs11)
        plugin._decrypt_pin = mock.MagicMock(return_value=self.login)

        with tempfile.TemporaryDirectory() as tmp:
            fixed_cfg = os.path.join(tmp, "cs_pkcs11_R3.cfg")
            with mock.patch.object(
                mt_p11.UtimacoBackend,
                "_CFG_PATH",
                fixed_cfg,
            ):
                plugin._configure_pkcs11(self.project_id)

                self.assertTrue(os.path.exists(fixed_cfg))
                with open(fixed_cfg) as f:
                    content = f.read()
                self.assertIn("Devices = 4000@10.246.244.60", content)

    def test_configure_pkcs11_utimaco_multi_endpoint_ha(self):
        """Multiple endpoints emit one comma-separated Devices line.

        Entries are ordered by the ``order`` field.
        """
        token_config = _utimaco_token_config(
            project_id=self.project_id,
            endpoints=[
                # Intentionally out of order to confirm sort-by-order.
                {"host": "10.0.0.2", "port": 4010, "order": 1},
                {"host": "10.0.0.1", "port": 4009, "order": 0},
            ],
        )
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)
        plugin._get_token_config_for_project = mock.MagicMock(
            return_value=token_config
        )
        plugin._create_pkcs11 = mock.MagicMock(return_value=self.pkcs11)
        plugin._decrypt_pin = mock.MagicMock(return_value=self.login)

        with tempfile.TemporaryDirectory() as tmp:
            fixed_cfg = os.path.join(tmp, "cs_pkcs11_R3.cfg")
            with mock.patch.object(
                mt_p11.UtimacoBackend,
                "_CFG_PATH",
                fixed_cfg,
            ):
                plugin._configure_pkcs11(self.project_id)

                with open(fixed_cfg) as f:
                    content = f.read()

        self.assertEqual(1, content.count("[HSMCluster]"))
        # One Devices line listing all cluster members, ordered by `order`.
        self.assertEqual(1, content.count("Devices ="))
        self.assertIn(
            "Devices = { 4009@10.0.0.1 4010@10.0.0.2 }", content
        )

    def test_get_plugin_name_for_default_store_plugin_name(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin(conf=self.conf)

        self.assertEqual(self.plugin_name, plugin.get_plugin_name())

    def test_get_plugin_name_for_given_store_plugin_name(self):
        store_plugin_name = "test_store_plugin"
        plugin_group_name = (
            f"multitenant_p11_crypto_plugin:{store_plugin_name}"
        )

        plugin_group = cfg.OptGroup(name=plugin_group_name)
        self.conf.register_group(plugin_group)
        self.conf.register_opts(
            mt_p11.multitenant_p11_crypto_plugin_opts,
            group=plugin_group)

        self.conf[plugin_group_name].plugin_name = self.plugin_name

        plugin = mt_p11.MultitenantP11CryptoPlugin(
            conf=self.conf, store_plugin_name=store_plugin_name)

        self.assertEqual(self.plugin_name, plugin.get_plugin_name())

    def test_encrypt(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin()

        plugin._configure_pkcs11 = mock.MagicMock()

        with mock.patch.object(p11_crypto.P11CryptoPlugin,
                               "encrypt") as mock_encrypt:
            mock_encrypt.return_value = ResponseDTO(
                cypher_text=self.cypher_text,
                kek_meta_extended=self.kek_meta_extended,
            )

            response_dto = plugin.encrypt(
                encrypt_dto=mock.MagicMock(),
                kek_meta_dto=mock.MagicMock(),
                project_id=self.project_id,
            )

        self.assertEqual(1, plugin._configure_pkcs11.call_count)
        self.assertEqual(1, mock_encrypt.call_count)
        self.assertEqual(self.cypher_text, response_dto.cypher_text)
        self.assertEqual(self.kek_meta_extended,
                         response_dto.kek_meta_extended)

    def test_encrypt_with_multi_threads(self):
        results = [None] * 10

        # Setup 10 threads to call encrypt() at same time
        for i in range(10):
            t = PluginOperationThread(i, results)
            t.start()

        # Verify all threads return corresponding response
        for i in range(10):
            self.assertEqual(f"cypher_text_{i}".encode("utf-8"),
                             results[i].cypher_text)

    def test_encrypt_raises_error_for_misconfigured_token_config(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin()
        plugin._configure_pkcs11 = mock.MagicMock()
        plugin._configure_pkcs11.side_effect = ValueError(
            u._("No token config mapping found for project"))

        self.assertRaises(
            ValueError,
            plugin.encrypt,
            mock.MagicMock(),
            mock.MagicMock(),
            self.project_id,
        )

    def test_decrypt(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin()

        plugin._configure_pkcs11 = mock.MagicMock()

        with mock.patch.object(p11_crypto.P11CryptoPlugin,
                               "decrypt") as mock_decrypt:
            mock_decrypt.return_value = b"0"

            pt = plugin.decrypt(
                decrypt_dto=mock.MagicMock(),
                kek_meta_dto=mock.MagicMock(),
                kek_meta_extended=mock.MagicMock(),
                project_id=self.project_id,
            )

        self.assertEqual(1, plugin._configure_pkcs11.call_count)
        self.assertEqual(1, mock_decrypt.call_count)
        self.assertEqual(b"0", pt)

    def test_decrypt_raises_error_for_misconfigured_token_config(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin()
        plugin._configure_pkcs11 = mock.MagicMock()
        plugin._configure_pkcs11.side_effect = ValueError(
            u._("No token config mapping found for project"))

        self.assertRaises(
            ValueError,
            plugin.decrypt,
            mock.MagicMock(),
            mock.MagicMock(),
            mock.MagicMock(),
            self.project_id,
        )

    def test_bind_kek_metadata(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin()

        plugin._configure_pkcs11 = mock.MagicMock()
        kek_datum = KEKDatum(
            kek_label=(
                f"project-{self.project_id}-key-"
                "9f4d7025-ea84-454f-8b3a-3e9bb594c777"
            )
        )
        kek_meta_dto = KEKMetaDTO(kek_datum)

        with mock.patch.object(p11_crypto.P11CryptoPlugin,
                               "bind_kek_metadata") as mock_bind_kek_metadata:
            plugin.bind_kek_metadata(kek_meta_dto)

        plugin._configure_pkcs11.assert_called_once_with(self.project_id)
        self.assertEqual(1, mock_bind_kek_metadata.call_count)

    def test_bind_kek_metadata_has_no_project_id(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin()

        plugin._configure_pkcs11 = mock.MagicMock()
        kek_datum = KEKDatum()
        kek_meta_dto = KEKMetaDTO(kek_datum)

        with mock.patch.object(p11_crypto.P11CryptoPlugin,
                               "bind_kek_metadata") as mock_bind_kek_metadata:
            plugin.bind_kek_metadata(kek_meta_dto)

        plugin._configure_pkcs11.assert_called_once_with("default")
        self.assertEqual(1, mock_bind_kek_metadata.call_count)

    def test_generate_symmetric(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin()

        plugin._configure_pkcs11 = mock.MagicMock()

        with mock.patch.object(
                p11_crypto.P11CryptoPlugin,
                "generate_symmetric") as mock_generate_symmetric:
            mock_generate_symmetric.return_value = ResponseDTO(
                cypher_text=self.cypher_text,
                kek_meta_extended=self.kek_meta_extended,
            )

            response_dto = plugin.generate_symmetric(
                generate_dto=mock.MagicMock(),
                kek_meta_dto=mock.MagicMock(),
                project_id=self.project_id,
            )

        self.assertEqual(1, plugin._configure_pkcs11.call_count)
        self.assertEqual(1, mock_generate_symmetric.call_count)
        self.assertEqual(self.cypher_text, response_dto.cypher_text)
        self.assertEqual(self.kek_meta_extended,
                         response_dto.kek_meta_extended)

    def test_generate_symmetric_raises_error_for_misconfigured_token(self):
        plugin = mt_p11.MultitenantP11CryptoPlugin()
        plugin._configure_pkcs11 = mock.MagicMock()
        plugin._configure_pkcs11.side_effect = ValueError(
            u._("No token config mapping found for project"))

        self.assertRaises(
            ValueError,
            plugin.generate_symmetric,
            mock.MagicMock(),
            mock.MagicMock(),
            self.project_id,
        )

    def test_generate_utimaco_cfg(self):
        backend = mt_p11.UtimacoBackend()

        with tempfile.TemporaryDirectory() as tmp:
            fixed_cfg = os.path.join(tmp, "cs_pkcs11_R3.cfg")
            with mock.patch.object(
                mt_p11.UtimacoBackend,
                "_CFG_PATH",
                fixed_cfg,
            ):
                token_config = _utimaco_token_config(
                    endpoints=[
                        {"host": "10.246.244.60", "port": 4000, "order": 0},
                    ],
                )
                cfg_path = backend._generate_cfg(token_config)

            self.assertEqual(fixed_cfg, cfg_path)
            self.assertTrue(os.path.exists(cfg_path))
            with open(cfg_path) as f:
                content = f.read()
            self.assertIn("[Global]", content)
            self.assertIn("SlotCount = 10", content)
            self.assertIn("[HSMCluster]", content)
            self.assertIn("Devices = 4000@10.246.244.60", content)
