# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

import threading
from unittest import mock

from barbican.common import utils as common_utils
from barbican.plugin.crypto import base
from barbican.plugin.crypto import hsm_partition_crypto
from barbican.plugin.crypto import manager as cm
from barbican.tests import utils


class MyThread(threading.Thread):
    def __init__(self, index, results):
        threading.Thread.__init__(self)
        self.index = index
        self.results = results

    def run(self):
        self.results[self.index] = cm.get_manager()


class WhenTestingManager(utils.BaseTestCase):

    def setUp(self):
        super(WhenTestingManager, self).setUp()

        self.plugin_returned = mock.MagicMock()
        self.plugin_type = base.PluginSupportTypes.ENCRYPT_DECRYPT
        self.plugin_returned.supports.return_value = True
        self.plugin_name = common_utils.generate_fullname_for(
            self.plugin_returned)
        self.plugin_loaded = mock.MagicMock(obj=self.plugin_returned)
        self.manager = cm.get_manager()
        self.manager.extensions = [self.plugin_loaded]

    def test_can_override_enabled_plugins(self):
        """Verify can override default configuration for plugin selection."""
        # Reset manager singleton otherwise we have test execution
        # order problems
        cm._PLUGIN_MANAGER = None

        cm.CONF.set_override(
            "enabled_crypto_plugins",
            ['foo_plugin'],
            group='crypto')

        manager_to_test = cm.get_manager()

        self.assertIsInstance(
            manager_to_test, cm._CryptoPluginManager)

        self.assertListEqual(['foo_plugin'],
                             manager_to_test._names)

    def test_get_plugin_store_generate(self):
        self.assertEqual(
            self.plugin_returned,
            self.manager.get_plugin_store_generate(self.plugin_type))

    def test_raises_error_with_wrong_plugin_type(self):
        self.plugin_returned.supports.return_value = False
        self.assertRaises(
            base.CryptoPluginUnsupportedOperation,
            self.manager.get_plugin_store_generate,
            self.plugin_type)

    def test_raises_error_with_no_active_store_generate_plugin(self):
        self.manager.extensions = []
        self.assertRaises(
            base.CryptoPluginNotFound,
            self.manager.get_plugin_store_generate,
            self.plugin_type)

    def test_get_plugin_retrieve(self):
        self.assertEqual(
            self.plugin_returned,
            self.manager.get_plugin_retrieve(self.plugin_name))

    def test_raises_error_with_wrong_plugin_name(self):
        self.assertRaises(
            base.CryptoPluginUnsupportedOperation,
            self.manager.get_plugin_retrieve,
            'other-name')

    def test_raises_error_with_no_active_plugin_name(self):
        self.manager.extensions = []
        self.assertRaises(
            base.CryptoPluginNotFound,
            self.manager.get_plugin_retrieve,
            self.plugin_name)

    def test_get_manager_with_multi_threads(self):
        self.manager.extensions = []
        self.manager = None
        results = [None] * 10
        # setup 10 threads to call get_manager() at same time
        for i in range(10):
            t = MyThread(i, results)
            t.start()
        # verify all threads return one and same plugin manager
        for i in range(10):
            self.assertIsInstance(results[i], cm._CryptoPluginManager)
            self.assertEqual(results[0], results[i])


class WhenTestingPluginName(utils.BaseTestCase):
    """get_plugin_name() distinguishes HSMPartition instances by config."""

    def test_non_hsm_plugin_falls_back_to_fullname(self):
        plugin = mock.MagicMock()
        self.assertEqual(
            common_utils.generate_fullname_for(plugin),
            cm.get_plugin_name(plugin),
        )

    def test_hsm_partition_plugin_uses_configured_name(self):
        plugin = mock.MagicMock(
            spec=hsm_partition_crypto.HSMPartitionCryptoPlugin)
        plugin.conf = mock.MagicMock(legacy_plugin_name=None)
        plugin.get_plugin_name.return_value = "utimaco_hsm_42"

        self.assertEqual("utimaco_hsm_42", cm.get_plugin_name(plugin))

    def test_hsm_partition_plugin_prefers_legacy_name(self):
        plugin = mock.MagicMock(
            spec=hsm_partition_crypto.HSMPartitionCryptoPlugin)
        plugin.conf = mock.MagicMock(
            legacy_plugin_name=(
                "barbican.plugin.crypto.hsm_partition_crypto."
                "UtimacoHSMPartitionCryptoPlugin"
            )
        )
        plugin.get_plugin_name.return_value = "utimaco_hsm_1"

        self.assertEqual(
            "barbican.plugin.crypto.hsm_partition_crypto."
            "UtimacoHSMPartitionCryptoPlugin",
            cm.get_plugin_name(plugin),
        )

    def test_two_hsm_instances_have_distinct_identity(self):
        a = mock.MagicMock(
            spec=hsm_partition_crypto.HSMPartitionCryptoPlugin)
        a.conf = mock.MagicMock(legacy_plugin_name=None)
        a.get_plugin_name.return_value = "utimaco_hsm"
        b = mock.MagicMock(
            spec=hsm_partition_crypto.HSMPartitionCryptoPlugin)
        b.conf = mock.MagicMock(legacy_plugin_name=None)
        b.get_plugin_name.return_value = "utimaco_hsm_2"

        self.assertNotEqual(cm.get_plugin_name(a), cm.get_plugin_name(b))


class WhenTestingApplianceInstantiation(utils.BaseTestCase):
    """Manager instantiates one HSMPartitionCryptoPlugin per plugin_names."""

    def _fake_plugin(self, plugin_name):
        inst = mock.MagicMock(
            spec=hsm_partition_crypto.HSMPartitionCryptoPlugin)
        inst.conf = mock.MagicMock(legacy_plugin_name=None)
        inst.get_plugin_name.return_value = plugin_name
        return inst

    def test_get_plugin_retrieve_routes_to_correct_instance(self):
        util_1 = self._fake_plugin("utimaco_hsm")
        util_2 = self._fake_plugin("utimaco_hsm_2")

        manager = cm.get_manager()
        original_extensions = manager.extensions
        try:
            manager.extensions = [
                mock.MagicMock(obj=util_1),
                mock.MagicMock(obj=util_2),
            ]

            self.assertIs(util_1, manager.get_plugin_retrieve("utimaco_hsm"))
            self.assertIs(util_2, manager.get_plugin_retrieve("utimaco_hsm_2"))
        finally:
            manager.extensions = original_extensions

    def test_duplicate_appliance_name_raises(self):
        fake_a = self._fake_plugin("ignored_1")
        fake_b = self._fake_plugin("ignored_2")

        mgr = cm.get_manager()
        original_extensions = list(mgr.extensions)
        try:
            with mock.patch(
                "barbican.plugin.crypto.hsm_partition_crypto.CONF"
            ) as mock_conf, mock.patch(
                "barbican.plugin.crypto.hsm_partition_crypto"
                ".HSMPartitionCryptoPlugin",
                side_effect=[fake_a, fake_b],
            ):
                mock_conf.hsm_partition_crypto_plugins.plugin_names = [
                    "shared_appliance", "shared_appliance"]
                self.assertRaises(
                    ValueError,
                    mgr._instantiate_hsm_partition_plugins,
                    (), {},
                )
        finally:
            mgr.extensions = original_extensions
