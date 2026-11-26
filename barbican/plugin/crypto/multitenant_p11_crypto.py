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

from oslo_config import cfg

from barbican.common import config
from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u
from barbican.model import repositories
from barbican.plugin.crypto import hsm_config_key
from barbican.plugin.crypto import p11_crypto
from barbican.plugin.crypto.vendor import utimaco as utimaco_vendor

LOG = utils.getLogger(__name__)
CONF = config.new_config()

# Register the multitenant PKCS#11 crypto plugin instance list.
multitenant_p11_crypto_plugins_group = cfg.OptGroup(
    name="multitenant_p11_crypto_plugins",
    title="Multitenant PKCS#11 Crypto Plugin Instances",
)
multitenant_p11_crypto_plugins_opts = [
    cfg.ListOpt(
        "plugin_names",
        default=[],
        help=u._(
            "List of multitenant PKCS#11 crypto plugin instance names. "
            "Each name here must have a matching "
            "[multitenant_p11_crypto_plugin:<name>] section carrying its "
            "plugin_name (used as the routing identity) and vendor "
            "library configuration. Each entry becomes one "
            "MultitenantP11CryptoPlugin instance; distinct entries do not "
            "need to map to distinct physical HSMs."
        ),
    ),
]

# Register multitenant PKCS#11 plugin options
multitenant_p11_crypto_plugin_group = cfg.OptGroup(
    name="multitenant_p11_crypto_plugin",
    title="Multitenant PKCS#11 Crypto Plugin Options",
)
multitenant_p11_crypto_plugin_opts = [
    cfg.StrOpt(
        "library_path",
        help=u._("Path to vendor library"),
    ),
    cfg.StrOpt(
        "plugin_name",
        help=u._("User friendly plugin name"),
        default="Multitenant PKCS#11 Crypto Plugin",
    ),
    cfg.StrOpt(
        "legacy_plugin_name",
        default=None,
        help=u._(
            "Routing identity written to kek_data.plugin_name for this "
            "plugin instance. Set only when inheriting data from a "
            "pre-rename deployment that stored a different identifier "
            "(typically the Python class path of the pre-rename plugin "
            "subclass). Leave unset for new plugin instances; the "
            "configured plugin_name is used instead."
        ),
    ),
    cfg.StrOpt(
        "default_token_config_id",
        help=u._("Default token config ID if no project mapping exists"),
        default=None,
    ),
    cfg.StrOpt(
        "mkek_label", help=u._("Master KEK label (as stored in the HSM)")
    ),
    cfg.IntOpt(
        "mkek_length",
        default=32,
        min=1,
        help=u._("Master KEK length in bytes."),
    ),
    cfg.StrOpt(
        "hmac_label", help=u._("Master HMAC Key label (as stored in the HSM)")
    ),
    cfg.BoolOpt(
        "rw_session", help=u._("Flag for Read/Write Sessions"), default=True
    ),
    cfg.IntOpt(
        "pkek_length", help=u._("Project KEK length in bytes."), default=32
    ),
    cfg.IntOpt(
        "pkek_cache_ttl",
        help=u._("Project KEK Cache Time To Live, in seconds"),
        default=900,
    ),
    cfg.IntOpt(
        "pkek_cache_limit",
        help=u._("Project KEK Cache Item Limit"),
        default=100,
    ),
    cfg.StrOpt(
        "encryption_mechanism",
        help=u._("Secret encryption mechanism"),
        default="CKM_AES_CBC",
        deprecated_name="algorithm",
    ),
    cfg.StrOpt("hmac_key_type", help=u._("HMAC Key Type"), default="CKK_AES"),
    cfg.StrOpt(
        "hmac_keygen_mechanism",
        help=u._(
            "HMAC Key Generation Algorithm used to create the master HMAC Key."
        ),
        default="CKM_AES_KEY_GEN",
    ),
    cfg.StrOpt(
        "hmac_mechanism",
        help=u._("HMAC algorithm used to sign encrypted data."),
        default="CKM_SHA256_HMAC",
        deprecated_name="hmac_keywrap_mechanism",
    ),
    cfg.StrOpt(
        "key_wrap_mechanism",
        help=u._("Key Wrapping algorithm used to wrap Project KEKs."),
        default="CKM_AES_CBC_PAD",
    ),
    cfg.BoolOpt(
        "key_wrap_generate_iv",
        help=u._("Generate IVs for Key Wrapping mechanism."),
        default=True,
    ),
    cfg.StrOpt(
        "seed_file",
        help=u._("File to pull entropy for seeding RNG"),
        default="",
    ),
    cfg.IntOpt(
        "seed_length",
        help=u._("Amount of data to read from file for seed"),
        default=32,
    ),
    cfg.BoolOpt(
        "aes_gcm_generate_iv",
        help=u._("Generate IVs for CKM_AES_GCM mechanism."),
        default=True,
        deprecated_name="generate_iv",
    ),
    cfg.BoolOpt(
        "always_set_cka_sensitive",
        help=u._(
            "Always set CKA_SENSITIVE=CK_TRUE "
            "including CKA_EXTRACTABLE=CK_TRUE keys."
        ),
        default=True,
    ),
    cfg.BoolOpt(
        "os_locking_ok",
        help=u._(
            "Enable CKF_OS_LOCKING_OK flag when initializing the "
            "PKCS#11 client library."
        ),
        default=False,
    ),
    cfg.StrOpt(
        "config_key_path",
        default="/mnt/secrets/hsm-config-key",
        help=u._(
            "Path to the base64 file holding the 32-byte AES-256 HSM config "
            "key used to decrypt the stored CU-PIN at rest. Barbican never "
            "generates this key; login fails if it is missing or invalid."
        ),
    ),
]


# Register per-instance config sections
def register_opts_for_multitenant_p11_plugin_instances(conf):
    """Register a config section per configured plugin instance.

    Reads [multitenant_p11_crypto_plugins] plugin_names from `conf` and
    registers a [multitenant_p11_crypto_plugin:<name>] group for each.
    """
    plugin_names = conf.multitenant_p11_crypto_plugins.plugin_names

    for name in plugin_names:
        # Construct the section name
        section_name = f"multitenant_p11_crypto_plugin:{name}"

        # Create a new option group for this plugin instance
        instance_group = cfg.OptGroup(
            name=section_name,
            title=f"Multitenant PKCS#11 Crypto Plugin Options for {name}",
        )

        # Register the group and options
        conf.register_group(instance_group)
        conf.register_opts(
            multitenant_p11_crypto_plugin_opts, group=instance_group
        )

        LOG.debug(
            f"Registered multitenant PKCS#11 plugin instance configuration "
            f"section: {section_name}"
        )


# Register [multitenant_p11_crypto_plugins] first, then parse args so the
# plugin_names list is readable, then register a section per listed name.
CONF.register_group(multitenant_p11_crypto_plugins_group)
CONF.register_opts(
    multitenant_p11_crypto_plugins_opts,
    group=multitenant_p11_crypto_plugins_group,
)

CONF.register_group(multitenant_p11_crypto_plugin_group)
CONF.register_opts(
    multitenant_p11_crypto_plugin_opts,
    group=multitenant_p11_crypto_plugin_group,
)
config.parse_args(CONF)

# Now that CONF is parsed, iterate the plugin instance list.
register_opts_for_multitenant_p11_plugin_instances(CONF)


def list_opts():
    yield multitenant_p11_crypto_plugins_group, \
        multitenant_p11_crypto_plugins_opts
    # Per-instance [multitenant_p11_crypto_plugin:<name>] sections use the
    # same options as below; they are registered at parse-time from the
    # plugin_names list and cannot be enumerated statically here.
    yield multitenant_p11_crypto_plugin_group, \
        multitenant_p11_crypto_plugin_opts


class VendorBackend:
    """Per-vendor hook for token-identifier resolution + cfg rewrite."""

    def apply(self, plugin, token_config):
        raise NotImplementedError


class UtimacoBackend(VendorBackend):
    """Utimaco: serial-only resolution plus per-request cfg rewrite."""

    # Path the Utimaco PKCS#11 library was initialized with. The library
    # caches CS_PKCS11_R3_CFG at C_Initialize and ignores later env
    # changes, so we rewrite this file in place for every token switch.
    _CFG_PATH = os.environ.get(
        "CS_PKCS11_R3_CFG",
        os.path.join(tempfile.gettempdir(), "utimaco", "cs_pkcs11_R3.cfg")
    )

    def apply(self, plugin, token_config):
        plugin.token_serial_number = token_config.token_serial_number
        plugin.slot_id = None
        plugin.token_labels = None
        cfg_path = self._generate_cfg(token_config)
        LOG.info(
            "_configure_pkcs11 wrote Utimaco cfg path=%s endpoints=%s",
            cfg_path, token_config.endpoints,
        )

    def _generate_cfg(self, token_config):
        """Rewrite the Utimaco PKCS#11 cfg in place and return its path.

        Emits a single comma-separated `Devices = port@host,...` line in
        a `[HSMCluster]` block so the Utimaco driver can fail over
        between peers. Entries are ordered by ascending `order`.
        """
        cfg_content = utimaco_vendor.render_utimaco_cfg(
            token_config.endpoints
        )
        cfg_path = self._CFG_PATH
        os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
        with open(cfg_path, "w") as f:
            f.write(cfg_content)
        LOG.debug(
            "Rewrote Utimaco cfg at %s:\n%s", cfg_path, cfg_content
        )
        return cfg_path


class ThalesBackend(VendorBackend):
    """Thales backend: pass all three identifiers to the driver.

    The PKCS#11 driver resolves them in priority order
    (serial → label → slot_id). No cfg rewrite.
    """

    def apply(self, plugin, token_config):
        plugin.token_serial_number = token_config.token_serial_number
        plugin.slot_id = (
            int(token_config.slot_id) if token_config.slot_id else None
        )
        plugin.token_labels = (
            [token_config.token_label]
            if token_config.token_label else None
        )
        # TODO(rakib): Thales-specific cfg rewrite (for multi-tenancy).


VENDOR_BACKENDS = {
    "utimaco": UtimacoBackend(),
    "thales": ThalesBackend(),
}


class MultitenantP11CryptoPlugin(p11_crypto.P11CryptoPlugin):
    """Multitenant PKCS#11 crypto plugin.

    Inherits from P11CryptoPlugin. Adds per-project token-config
    resolution: each project is mapped to its own HSM token (slot /
    partition / container, depending on the vendor) with isolated keys
    and credentials, and the underlying PKCS#11 library is reconfigured
    on each project switch.
    """

    def __init__(
        self, conf=None, ffi=None, pkcs11=None, store_plugin_name=None
    ):
        """Initialize plugin using dynamic config.

        This uses dynamic config based on secret store name.
        """

        # Use the global CONF if none provided
        if conf is None:
            conf = CONF

        # Store name of the secret store that uses this plugin
        self.store_plugin_name = store_plugin_name or "default"

        # Build section name based on secret store
        self.section_name = (
            f"multitenant_p11_crypto_plugin:{self.store_plugin_name}"
        )

        # If this is a default instance (no specific store), use base config
        if self.store_plugin_name == "default":
            self.section_name = "multitenant_p11_crypto_plugin"

        # Make sure PKCS11 object is available
        self.pkcs11 = None

        # Get config for this section
        try:
            self.conf = conf[self.section_name]
            LOG.info(
                f"Using multitenant PKCS#11 configuration section: "
                f"{self.section_name}"
            )
        except (cfg.NoSuchGroupError, cfg.NoSuchOptError):
            # Section doesn't exist - create a new one dynamically
            LOG.warning(
                f"No config found for {self.section_name}, "
                "registering dynamically"
            )
            group = cfg.OptGroup(
                name=self.section_name,
                title=f"Multitenant PKCS#11 Crypto Plugin Options for "
                f"{self.store_plugin_name}",
            )
            conf.register_group(group)
            conf.register_opts(
                multitenant_p11_crypto_plugin_opts, group=group
            )
            self.conf = conf[self.section_name]

        # Initialize basic attributes from config
        self.library_path = self.conf.library_path
        self.login = None
        self.rw_session = self.conf.rw_session
        self.slot_id = None
        self.token_labels = None
        self.token_serial_number = None
        self.seed_file = self.conf.seed_file
        self.seed_length = self.conf.seed_length

        # Crypto configuration
        self.encryption_mechanism = self.conf.encryption_mechanism
        self.encryption_gen_iv = self.conf.aes_gcm_generate_iv
        self.cka_sensitive = self.conf.always_set_cka_sensitive
        self.mkek_key_type = "CKK_AES"  # Optional: make configurable
        self.mkek_length = self.conf.mkek_length
        self.mkek_label = self.conf.mkek_label
        self.hmac_key_type = self.conf.hmac_key_type
        self.hmac_label = self.conf.hmac_label
        self.hmac_mechanism = self.conf.hmac_mechanism
        self.key_wrap_mechanism = self.conf.key_wrap_mechanism
        self.key_wrap_gen_iv = self.conf.key_wrap_generate_iv
        self.os_locking_ok = self.conf.os_locking_ok
        self.config_key_path = self.conf.config_key_path
        self.pkek_length = self.conf.pkek_length
        self.pkek_cache_ttl = self.conf.pkek_cache_ttl
        self.pkek_cache_limit = self.conf.pkek_cache_limit

        # Initialize repository interfaces
        self.project_token_config_repo = (
            repositories.get_project_token_config_repository()
        )

        # Runtime variables
        self.current_project_id = None
        self.current_token_config = None

    def _get_token_config_for_project(self, project_id):
        """Get token configuration for a project."""

        if project_id is None:
            raise ValueError(
                "No token config mapping found for the project "
                "and no valid default token config is configured"
            )

        # Check for project-specific token config
        try:
            return self.project_token_config_repo.get_by_project_id(project_id)
        except Exception as e:
            LOG.warning(
                f"Error finding default token config: {e}, "
                f"{type(e).__name__}"
            )

        # Fall back to default if configured
        if self.conf.default_token_config_id:
            try:
                return self.project_token_config_repo.get(
                    self.conf.default_token_config_id
                )
            except exception.NotFound:
                LOG.warning(
                    f"Default token config ID "
                    f"{self.conf.default_token_config_id} not found"
                )
                pass

        # Nothing found
        raise ValueError(
            u._(
                "No token config mapping found for the project "
                "and no valid default token config is configured"
            )
        )

    def _decrypt_pin(self, credentials):
        """Decrypt the stored CU-PIN envelope; fail hard, no fallback.

        Loads the mounted HSM config key and decrypts the {v, alg, nonce,
        ciphertext} envelope. A missing/invalid key (HSMConfigKeyError) or a
        GCM tag mismatch / malformed envelope (HSMCredentialDecryptionError)
        propagates so the plugin refuses HSM login rather than proceeding with
        a bad PIN. A legacy plaintext {"password": ...} row has no envelope
        version and is rejected as malformed by decrypt_pin.
        """
        key = hsm_config_key.load_config_key(self.config_key_path)
        return hsm_config_key.decrypt_pin(credentials, key)

    def _configure_pkcs11(self, project_id):
        """Configure PKCS11 for the specified project if needed."""

        LOG.info(
            "_configure_pkcs11 START project=%s current=%s pkcs11_set=%s",
            project_id, self.current_project_id,
            self.pkcs11 is not None,
        )

        if project_id == self.current_project_id and self.pkcs11 is not None:
            LOG.debug("Already configured for project %s, skipping",
                      project_id)
            return

        token_config = self._get_token_config_for_project(project_id)
        metadata = token_config.vendor_metadata or {}

        self.current_project_id = project_id
        self.current_token_config = token_config
        self.login = self._decrypt_pin(token_config.credentials)

        # Per-row MKEK/HMAC label overrides.
        self.mkek_label = (
            token_config.mkek_label
            or metadata.get("mkek_label")
            or self.conf.mkek_label
        )
        self.hmac_label = (
            token_config.hmac_label
            or metadata.get("hmac_label")
            or self.conf.hmac_label
        )

        # Vendor dispatch via the backend registry.
        try:
            backend = VENDOR_BACKENDS[token_config.vendor_type]
        except KeyError:
            raise exception.BarbicanException(
                u._(
                    "Unsupported vendor_type {vendor_type!r} on token "
                    "config for project {project_id}"
                ).format(
                    vendor_type=token_config.vendor_type,
                    project_id=project_id,
                )
            )
        backend.apply(self, token_config)

        LOG.debug(
            "Token config: vendor_type=%s, slot_id=%s, token_label=%s, "
            "token_serial_number=%s, mkek_label=%s, hmac_label=%s, "
            "endpoints=%s",
            token_config.vendor_type, self.slot_id, self.token_labels,
            self.token_serial_number, self.mkek_label, self.hmac_label,
            token_config.endpoints,
        )

        # Finalize the existing library before re-init. Without this, the
        # next C_Initialize returns 0x191 (CKR_CRYPTOKI_ALREADY_INITIALIZED,
        # silently tolerated) and the library stays bound to the previous
        # device, so _get_slot_id can't find the new token's serial.
        if self.pkcs11 is not None:
            LOG.info("_configure_pkcs11 finalizing before re-init")
            self.pkcs11.finalize()
            self.pkcs11 = None

        self.pkcs11 = self._create_pkcs11(None)
        self._configure_object_cache()
        LOG.info(
            "_configure_pkcs11 END project=%s slot_id=%s",
            project_id, getattr(self.pkcs11, "slot_id", None),
        )

    def get_plugin_name(self):
        """Gets user-friendly plugin name."""
        return self.conf.plugin_name

    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        self._configure_pkcs11(project_id)
        return super(MultitenantP11CryptoPlugin, self).encrypt(
            encrypt_dto, kek_meta_dto, project_id
        )

    def decrypt(
        self, decrypt_dto, kek_meta_dto, kek_meta_extended, project_id
    ):
        self._configure_pkcs11(project_id)
        return super(MultitenantP11CryptoPlugin, self).decrypt(
            decrypt_dto, kek_meta_dto, kek_meta_extended, project_id
        )

    def bind_kek_metadata(self, kek_meta_dto):
        LOG.debug(
            "bind_kek_metadata called with kek_label: %s",
            kek_meta_dto.kek_label,
        )
        # Extract project_id from the kek_label in kek_meta_dto
        # The format is "project-{external_id}-key-{uuid}"
        try:
            label_parts = kek_meta_dto.kek_label.split("-")
            if len(label_parts) >= 4 and label_parts[0] == "project":
                project_id = label_parts[1]
            else:
                # If we can't determine project_id, use default token config
                LOG.warning(
                    "Cannot determine project_id from kek_label: %s, "
                    "using default token config",
                    kek_meta_dto.kek_label,
                )
                project_id = "default"
        except (AttributeError, IndexError):
            LOG.warning(
                "Invalid kek_label format, using default token config"
            )
            project_id = "default"

        self._configure_pkcs11(project_id)
        return super(MultitenantP11CryptoPlugin, self).bind_kek_metadata(
            kek_meta_dto
        )

    def generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
        self._configure_pkcs11(project_id)
        return super(MultitenantP11CryptoPlugin, self).generate_symmetric(
            generate_dto, kek_meta_dto, project_id
        )
