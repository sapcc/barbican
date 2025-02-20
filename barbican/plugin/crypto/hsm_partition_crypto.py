from oslo_config import cfg
from barbican import i18n as u
from barbican.model import repositories
from barbican.plugin.crypto import base as c
from barbican.plugin.crypto import p11_crypto
from barbican.common import config
from barbican.plugin.crypto import pkcs11
from barbican.common import utils

LOG = utils.getLogger(__name__)
CONF = config.new_config()

# Register hsm partition plugin options
hsm_partition_crypto_plugin_group = cfg.OptGroup(name='hsm_partition_crypto_plugin',
                                               title="HSM Partition Crypto Plugin Options")
hsm_partition_crypto_plugin_opts = [
    cfg.StrOpt('plugin_name',
               help=u._('User friendly plugin name'),
               default='HSM Partition Crypto Plugin'),
    cfg.StrOpt('partition_id',
               help=u._('ID of the HSM partition to use'),
               default=None),
    cfg.StrOpt('mkek_label',
               help=u._('Master KEK label (as stored in the HSM)')),
    cfg.IntOpt('mkek_length',
               default=32,
               min=1,
               help=u._('Master KEK length in bytes.')),
    cfg.StrOpt('hmac_label',
               help=u._('Master HMAC Key label (as stored in the HSM)')),
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

CONF.register_group(hsm_partition_crypto_plugin_group)
CONF.register_opts(hsm_partition_crypto_plugin_opts, group=hsm_partition_crypto_plugin_group)
config.parse_args(CONF)

def list_opts():
    yield hsm_partition_crypto_plugin_group, hsm_partition_crypto_plugin_opts

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

        # Initialize basic attributes that parent needs
        self.library_path = None
        self.login = None
        self.rw_session = self.hsm_partition_conf.rw_session
        self.slot_id = None
        self.token_labels = None
        self.token_serial_number = None
        self.seed_file = self.hsm_partition_conf.seed_file
        self.seed_length = self.hsm_partition_conf.seed_length

        # Encryption related configs from parent
        self.encryption_mechanism = self.hsm_partition_conf.encryption_mechanism
        self.encryption_gen_iv = self.hsm_partition_conf.aes_gcm_generate_iv
        self.cka_sensitive = self.hsm_partition_conf.always_set_cka_sensitive
        self.mkek_key_type = 'CKK_AES'  # TODO: Make this also configurable
        self.mkek_length = self.hsm_partition_conf.mkek_length
        self.mkek_label = self.hsm_partition_conf.mkek_label
        self.hmac_key_type = self.hsm_partition_conf.hmac_key_type
        self.hmac_label = self.hsm_partition_conf.hmac_label
        self.hmac_mechanism = self.hsm_partition_conf.hmac_mechanism
        self.key_wrap_mechanism = self.hsm_partition_conf.key_wrap_mechanism
        self.key_wrap_gen_iv = self.hsm_partition_conf.key_wrap_generate_iv
        self.os_locking_ok = self.hsm_partition_conf.os_locking_ok
        self.pkek_length = self.hsm_partition_conf.pkek_length
        self.pkek_cache_ttl = self.hsm_partition_conf.pkek_cache_ttl
        self.pkek_cache_limit = self.hsm_partition_conf.pkek_cache_limit

        # Create PKCS11 instance
        self.pkcs11 = pkcs11 or self._create_pkcs11(ffi)
    
        # Configure object cache same as parent
        self._configure_object_cache()
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

        # Set instance attributes needed by parent class
        self.library_path = partition_config.credentials['library_path']
        self.login = partition_config.credentials['password']
        self.slot_id = int(partition_config.slot_id)
        self.token_labels = ([partition_config.token_label] if partition_config.token_label else None)

        # Handle seed file same as parent
        seed_random_buffer = None
        if self.seed_file:
            with open(self.seed_file, 'rb') as f:
                seed_random_buffer = f.read(self.seed_length)

         # Validate configuration
        if not self.library_path:
            raise ValueError(u._("library_path not found in partition credentials"))
        if not self.login:
            raise ValueError(u._("password not found in partition credentials"))
        if not self.slot_id:
            raise ValueError(u._("slot_id not found in partition configuration"))

        LOG.debug("Initializing PKCS11 for partition %s with token label %s on slot %s",
                partition_config.partition_label,
                partition_config.token_label,
                self.slot_id)

        # Create PKCS11 instance with partition config
        return pkcs11.PKCS11(
            library_path=self.library_path,
            login_passphrase=self.login,
            slot_id=self.slot_id,
            token_labels=self.token_labels,
            rw_session=self.rw_session,
            seed_random_buffer=seed_random_buffer,
            encryption_mechanism=self.encryption_mechanism,
            encryption_gen_iv=self.encryption_gen_iv,
            always_set_cka_sensitive=self.cka_sensitive,
            hmac_mechanism=self.hmac_mechanism,
            key_wrap_mechanism=self.key_wrap_mechanism,
            key_wrap_gen_iv=self.key_wrap_gen_iv,
            os_locking_ok=self.os_locking_ok,
            ffi=ffi
        )
