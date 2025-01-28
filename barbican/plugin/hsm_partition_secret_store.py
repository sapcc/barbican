# SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Greenhouse contributors
# SPDX-License-Identifier: Apache-2.0

"""
An implementation of the SecretStore that uses HSM partitions as a backend.
"""

class HSMPartitionStore(secret_store.SecretStorePluginBase):
    """Stores HSM partition access configurations for HSMaaS."""
    
    def __init__(self, conf=None):
        super(HSMPartitionStore, self).__init__()
        self.conf = conf
        self.partition_repo = HSMPartitionConfigRepo()

    # TODO: Implement me
    def store_secret(self, secret_dto):
        """Store secret in HSM partition."""
        # First, get partition config
        partition_config = self.partition_repo.get_by_id(
            secret_dto.partition_id
        )
        if not partition_config:
            raise Exception("HSM partition not found")

        # Store secret using HSM session
        hsm_session = self._get_hsm_session(partition_config)
        key_label = self._store_in_hsm(hsm_session, secret_dto)

        # Create mapping
        mapping = models.HSMPartitionSecret(
            secret_id=secret_dto.id,
            partition_id=partition_config.id,
            hsm_key_label=key_label
        )
        HSMPartitionSecretRepo().create_from(mapping)

        return secret_dto.id

    # TODO: Implement me
    def get_secret(self, secret_metadata):
        """Retrieve secret from HSM partition."""
        mapping = HSMPartitionSecretRepo().get_by_secret_id(
            secret_metadata.id
        )
        if not mapping:
            raise Exception("Secret not found in HSM")

        partition_config = self.partition_repo.get_by_id(
            mapping.partition_id
        )
        
        # Retrieve from HSM
        hsm_session = self._get_hsm_session(partition_config)
        return self._get_from_hsm(
            hsm_session, 
            mapping.hsm_key_label
        )
