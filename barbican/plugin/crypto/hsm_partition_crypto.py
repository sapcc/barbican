from oslo_config import cfg
from barbican import i18n as u
from barbican.model import repositories
from barbican.plugin.crypto import base as c
from barbican.plugin.crypto import p11_crypto
from barbican.common import config
from barbican.plugin.crypto import pkcs11

CONF = config.new_config()

# First register all p11_crypto plugin options (from p11_crypto.py)
p11_crypto_plugin_group = cfg.OptGroup(name='p11_crypto_plugin',
                                       title="PKCS11 Crypto Plugin Options")
p11_crypto_plugin_opts = [
    cfg.StrOpt('library_path',
               help=u._('Path to vendor PKCS11 library')),
    cfg.StrOpt('token_serial_number',
               help=u._('Token serial number used to identify the token to be '
                        'used.')),
    cfg.ListOpt('token_labels',
                default=[],
                help=u._('List of labels for one or more tokens to be used. '
                         'Typically this is a single label, but some HSM '
                         'devices may require more than one label for Load '
                         'Balancing or High Availability configurations.')),
    cfg.StrOpt('login',
               help=u._('Password (PIN) to login to PKCS11 session'),
               secret=True),
    cfg.StrOpt('mkek_label',
               help=u._('Master KEK label (as stored in the HSM)')),
    cfg.IntOpt('mkek_length',
               default=32,
               min=1,
               help=u._('Master KEK length in bytes.')),
    cfg.StrOpt('hmac_label',
               help=u._('Master HMAC Key label (as stored in the HSM)')),
    cfg.IntOpt('slot_id',
               help=u._('(Optional) HSM Slot ID that contains the token '
                        'device to be used.'),
               default=1),
    cfg.BoolOpt('rw_session',
                help=u._('Flag for Read/Write Sessions'),
                default=True),
    cfg.IntOpt('pkek_length',
               help=u._('Project KEK length in bytes.'),
               default=32),
    cfg.IntOpt('pkek_cache_ttl',
               help=u._('Project KEK Cache Time To Live, in seconds'),
               default=900),
    cfg.IntOpt('pkek_cache_limit',
               help=u._('Project KEK Cache Item Limit'),
               default=100),
    cfg.StrOpt('encryption_mechanism',
               help=u._('Secret encryption mechanism'),
               default='CKM_AES_CBC', deprecated_name='algorithm'),
    cfg.StrOpt('hmac_key_type',
               help=u._('HMAC Key Type'),
               default='CKK_AES'),
    cfg.StrOpt('hmac_keygen_mechanism',
               help=u._('HMAC Key Generation Algorithm used to create the '
                        'master HMAC Key.'),
               default='CKM_AES_KEY_GEN'),
    cfg.StrOpt('hmac_mechanism',
               help=u._('HMAC algorithm used to sign encrypted data.'),
               default='CKM_SHA256_HMAC',
               deprecated_name='hmac_keywrap_mechanism'),
    cfg.StrOpt('key_wrap_mechanism',
               help=u._('Key Wrapping algorithm used to wrap Project KEKs.'),
               default='CKM_AES_CBC_PAD'),
    cfg.BoolOpt('key_wrap_generate_iv',
                help=u._('Generate IVs for Key Wrapping mechanism.'),
                default=True),
    cfg.StrOpt('seed_file',
               help=u._('File to pull entropy for seeding RNG'),
               default=''),
    cfg.IntOpt('seed_length',
               help=u._('Amount of data to read from file for seed'),
               default=32),
    cfg.StrOpt('plugin_name',
               help=u._('User friendly plugin name'),
               default='PKCS11 HSM'),
    cfg.BoolOpt('aes_gcm_generate_iv',
                help=u._('Generate IVs for CKM_AES_GCM mechanism.'),
                default=True, deprecated_name='generate_iv'),
    cfg.BoolOpt('always_set_cka_sensitive',
                help=u._('Always set CKA_SENSITIVE=CK_TRUE including '
                         'CKA_EXTRACTABLE=CK_TRUE keys.'),
                default=True),
    cfg.BoolOpt('os_locking_ok',
                help=u._('Enable CKF_OS_LOCKING_OK flag when initializing the '
                         'PKCS#11 client library.'),
                default=False),
]

CONF.register_group(p11_crypto_plugin_group)
CONF.register_opts(p11_crypto_plugin_opts, group='p11_crypto_plugin')

# Then register hsm partition plugin options
hsm_partition_crypto_plugin_group = cfg.OptGroup(name='hsm_partition_crypto_plugin',
                                               title="HSM Partition Crypto Plugin Options")
hsm_partition_crypto_plugin_opts = [
    cfg.StrOpt('plugin_name',
               help=u._('User friendly plugin name'),
               default='HSM Partition Crypto Plugin'),
    cfg.StrOpt('partition_id',
               help=u._('ID of the HSM partition to use'),
               default=None),
]

CONF.register_group(hsm_partition_crypto_plugin_group)
CONF.register_opts(hsm_partition_crypto_plugin_opts, group=hsm_partition_crypto_plugin_group)
config.parse_args(CONF)

def list_opts():
    yield hsm_partition_crypto_plugin_group, hsm_partition_crypto_plugin_opts
    yield p11_crypto_plugin_group, p11_crypto_plugin_opts


class HSMPartitionCryptoPlugin(p11_crypto.P11CryptoPlugin):
    """PKCS11 crypto plugin for HSMaaS. Inherits from P11CryptoPlugin

    This plugin extends the base PKCS11 plugin to support per-project HSM 
    partitions. Each project is mapped to its own HSM partition with isolated
    keys and credentials.
    """
    
    def __init__(self, conf=None, ffi=None, pkcs11=None):
        """Initialize plugin using standard P11CryptoPlugin init."""
        # Always use our module-level CONF if no config is provided
        if conf is None:
            conf = CONF

        # Make sure p11_crypto_plugin group is accessible
        if not hasattr(conf, 'p11_crypto_plugin'):
            # Register p11 options if not already registered
            p11_crypto.register_opts(conf)

        # Store partition-specific config
        self.hsm_partition_conf = conf.hsm_partition_crypto_plugin
    
        super(HSMPartitionCryptoPlugin, self).__init__(conf, ffi=ffi, pkcs11=pkcs11)

    def _create_pkcs11(self, ffi=None):
        """Override PKCS11 creation to use partition config.
        
        Gets HSM partition configuration from database and uses it to 
        initialize PKCS11 connection.
        """
        # Get partition config from database
        hsm_partition_config_repo = repositories.get_hsm_partition_repository()
        partition_config = hsm_partition_config_repo.get_by_id(self.hsm_partition_conf.partition_id)
        if not partition_config:
            raise ValueError(u._("HSM partition configuration not found"))

        # Handle seed file same as parent
        seed_random_buffer = None
        if self.seed_file:
            with open(self.seed_file, 'rb') as f:
                seed_random_buffer = f.read(self.seed_length)

        # Create PKCS11 instance with partition config
        return pkcs11.PKCS11(
            library_path=partition_config.credentials['library_path'],
            login_passphrase=partition_config.credentials['password'],
            slot_id=partition_config.slot_id,
            token_labels=partition_config.token_label,
            seed_random_buffer=seed_random_buffer,
            # encryption_mechanism=self.encryption_mechanism,
            # encryption_gen_iv=self.encryption_gen_iv,
            # hmac_mechanism=self.hmac_mechanism,
            # key_wrap_mechanism=self.key_wrap_mechanism,
            # key_wrap_gen_iv=self.key_wrap_gen_iv,
            # always_set_cka_sensitive=self.always_set_cka_sensitive,
            os_locking_ok=self.os_locking_ok,
            ffi=ffi
        )
