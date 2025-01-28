# TODO: Implement me
class HSMPartitionCryptoPlugin(P11CryptoPlugin):
    """PKCS11 crypto plugin for HSMaaS. Inherits from P11CryptoPlugin"""
    
    def __init__(self, conf=None):
        super(P11CryptoPlugin, self).__init__()
        self.conf = conf
        self._hsm_sessions = {}
    
    def _get_session(self, project_id):
        """Get HSM session for customer's partition."""
        if project_id in self._hsm_sessions:
            return self._hsm_sessions[project_id]
            
        # Get customer's partition config from their selected store
        store_plugin = get_project_secret_store(project_id)
        if not isinstance(store_plugin, HSMPartitionStore):
            raise ValueError("Project not configured with HSM partition")
            
        partition_config = store_plugin.get_config()
        
        # Initialize session with customer's partition
        session = self._init_hsm_session(partition_config)
        self._hsm_sessions[project_id] = session
        return session

    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        """Encrypt using customer's HSM partition."""
        session = self._get_session(project_id)
        # Perform encryption using customer's partition
