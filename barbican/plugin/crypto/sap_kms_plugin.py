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
import os
from oslo_log import log as logging
from cryptography.fernet import Fernet
from barbican.plugin.crypto import base as cbase

LOG = logging.getLogger(__name__)
LOG.debug("Initializing SAPKMSCryptoPlugin module: %s", __name__)


class SAPKMSCryptoPlugin(cbase.CryptoPluginBase):
    """Minimal Fernet-based CryptoPlugin for demo/dev.

    * encrypt()/decrypt(): uses a single Fernet key from env/config (per-process)
    * generate_symmetric(): returns random key material (bytes) encrypted with Fernet
    * bind_kek_metadata(): records a label per project (no real per-project KEK)

    WARNING: This is for local testing only.
    """

    def __init__(self):
        super().__init__()
        LOG.debug("SAPKMSCryptoPlugin instance created")

    # ---- Helper: get Fernet from env/config ----
    def _fernet(self, gtid_scoped_kek) -> Fernet:
        LOG.debug("Preparing Fernet instance (gtid_scoped_kek provided=%s)", bool(gtid_scoped_kek))
        key = gtid_scoped_kek or os.environ.get("SAP_KMS_FERNET_KEY")
        if not key:
            # Generate ephemeral key for dev only; do not log the key material.
            key = Fernet.generate_key().decode("utf-8")
            os.environ["SAP_KMS_FERNET_KEY"] = key
            LOG.warning("No SAP_KMS_FERNET_KEY configured; generated an ephemeral key (INSECURE FOR PRODUCTION)")
        try:
            f = Fernet(key.encode("utf-8"))
            LOG.debug("Fernet instance initialized successfully")
            return f
        except Exception:
            LOG.exception("Failed to initialize Fernet instance")
            raise

    # --- Metadata helpers ---
    def _load_sap_gtid_to_kek_mapping(self, sap_gtid: str) -> dict:
        LOG.debug("Loading SAP GTID to KEK mapping for sap_gtid=%s", sap_gtid)
        # 1) file mapping (optional)
        path = os.environ.get("PROJECT_METADATA_FILE")
        if path and os.path.exists(path):
            try:
                LOG.debug("Attempting to load PROJECT_METADATA_FILE from %s", path)
                with open(path, "r") as fh:
                    data = json.load(fh)
                if sap_gtid in data and isinstance(data[sap_gtid], dict):
                    LOG.debug("Found mapping for sap_gtid=%s in metadata file", sap_gtid)
                    return data[sap_gtid]
                LOG.debug("No entry for sap_gtid=%s in metadata file", sap_gtid)
            except Exception:
                LOG.warning("Unable to read PROJECT_METADATA_FILE at %s", path, exc_info=True)

        # 2) nothing configured
        LOG.debug("No KEK mapping available for sap_gtid=%s; returning empty mapping", sap_gtid)
        return {}

    def _get_sap_gtid(self, kek_meta_dto: cbase.KEKMetaDTO) -> str | None:
        """Resolve 'sap_gtid' from persisted plugin_meta, with possible runtime override."""
        has_meta = bool(kek_meta_dto and getattr(kek_meta_dto, "plugin_meta", None))
        LOG.debug("_get_sap_gtid called; plugin_meta_present=%s", has_meta)
        meta = {}
        if has_meta:
            try:
                meta = json.loads(kek_meta_dto.plugin_meta)
            except Exception:
                LOG.debug("plugin_meta not valid JSON; ignoring persisted value", exc_info=True)
                meta = {}

        val = meta.get("sap_gtid")
        LOG.debug("_get_sap_gtid resolved sap_gtid=%s", val)
        return val

    # ---- Required API ----

    def get_plugin_name(self) -> str:
        LOG.info("SAPKMSCryptoPlugin loaded")
        return "sap_kms_crypto"

    def supports(self, type_enum, algorithm=None, bit_length=None, mode=None) -> bool:
        LOG.debug("supports called with type=%s algorithm=%s bit_length=%s mode=%s",
                  type_enum, algorithm, bit_length, mode)
        supported = type_enum in (
            cbase.PluginSupportTypes.ENCRYPT_DECRYPT,
            cbase.PluginSupportTypes.SYMMETRIC_KEY_GENERATION,
        )
        LOG.debug("supports result=%s", supported)
        return supported

    def bind_kek_metadata(self, kek_meta_dto: cbase.KEKMetaDTO) -> cbase.KEKMetaDTO:
        LOG.debug("bind_kek_metadata called; incoming kek_label=%s", getattr(kek_meta_dto, "kek_label", None))
        kek_meta_dto.plugin_name = self.get_plugin_name()
        if not kek_meta_dto.kek_label:
            kek_meta_dto.kek_label = "sap-kms-fernet"
            LOG.debug("No kek_label provided; defaulted to 'sap-kms-fernet'")
        LOG.debug("bind_kek_metadata returning kek_label=%s plugin_name=%s",
                  kek_meta_dto.kek_label, kek_meta_dto.plugin_name)
        return kek_meta_dto

    def encrypt(
        self,
        encrypt_dto: cbase.EncryptDTO,
        kek_meta_dto: cbase.KEKMetaDTO,
        project_id: str,
    ) -> cbase.ResponseDTO:
        LOG.debug("encrypt called for project_id=%s", project_id)
        unencrypted = encrypt_dto.unencrypted
        if not isinstance(unencrypted, bytes):
            LOG.error("encrypt received invalid payload type: %s", type(unencrypted))
            raise ValueError(
                u._(
                    'Unencrypted data must be a byte type, but was '
                    '{unencrypted_type}'
                ).format(
                    unencrypted_type=type(unencrypted)
                )
            )

        sap_gtid = self._get_sap_gtid(kek_meta_dto)
        mapping = self._load_sap_gtid_to_kek_mapping(sap_gtid=sap_gtid)
        LOG.debug("Encryption selection resolved; sap_gtid=%s mapping_present=%s",
                  sap_gtid, bool(mapping))

        try:
            f = self._fernet(mapping.get("kek"))
            ciphertext = f.encrypt(unencrypted)
            LOG.info("Encryption completed for project_id=%s; ciphertext_size=%d bytes",
                     project_id, len(ciphertext))
        except Exception:
            LOG.exception("Encryption operation failed for project_id=%s", project_id)
            raise

        resp = cbase.ResponseDTO(cypher_text=ciphertext, kek_meta_extended=sap_gtid)
        LOG.debug("encrypt returning ResponseDTO with kek_meta_extended=%s", sap_gtid)
        return resp

    def decrypt(
        self,
        decrypt_dto: cbase.DecryptDTO,
        kek_meta_dto: cbase.KEKMetaDTO,
        kek_meta_extended: str,
        project_id: str,
    ) -> bytes:
        LOG.debug("decrypt called for project_id=%s sap_gtid=%s", project_id, kek_meta_extended)
        mapping = self._load_sap_gtid_to_kek_mapping(sap_gtid=kek_meta_extended)
        LOG.debug("Decryption mapping present=%s", bool(mapping))
        try:
            f = self._fernet(mapping.get("kek"))
            plaintext = f.decrypt(decrypt_dto.encrypted)
            LOG.info("Decryption completed for project_id=%s; plaintext_size=%d bytes",
                     project_id, len(plaintext))
            return plaintext
        except Exception:
            LOG.exception("Decryption operation failed for project_id=%s", project_id)
            raise

    def generate_symmetric(
        self,
        generate_dto: cbase.GenerateDTO,
        kek_meta_dto: cbase.KEKMetaDTO,
        project_id: str,
    ) -> cbase.ResponseDTO:
        LOG.debug("generate_symmetric called for project_id=%s algorithm=%s bit_length=%s mode=%s",
                  project_id, generate_dto.algorithm, generate_dto.bit_length, generate_dto.mode)
        n_bits = generate_dto.bit_length or 256
        if n_bits % 8 != 0 or n_bits <= 0:
            LOG.error("Invalid bit_length=%s requested", n_bits)
            raise ValueError("bit_length must be a positive multiple of 8")
        try:
            raw = os.urandom(n_bits // 8)
            f = self._fernet(None)
            ciphertext = f.encrypt(raw)
            LOG.info("Generated symmetric key and encrypted it; ciphertext_size=%d bytes", len(ciphertext))
            return cbase.ResponseDTO(cypher_text=ciphertext, kek_meta_extended=None)
        except Exception:
            LOG.exception("generate_symmetric operation failed for project_id=%s", project_id)
            raise

    def generate_asymmetric(
        self,
        generate_dto: cbase.GenerateDTO,
        kek_meta_dto: cbase.KEKMetaDTO,
        project_id: str,
    ):
        LOG.error("Asymmetric key generation is not supported by SAPKMSCryptoPlugin")
        raise NotImplementedError("Asymmetric key generation not supported by SAPKMSCryptoPlugin")
