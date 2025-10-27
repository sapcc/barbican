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

import copy
import json
import base64
from oslo_log import log as logging

from barbican.plugin.crypto import base as crypto_base
from barbican.plugin.store_crypto import StoreCryptoAdapterPlugin
from barbican.plugin import store_crypto as sc
from barbican.model import repositories as repos

from barbican.plugin.crypto.sap_kms_plugin import SAPKMSCryptoPlugin

LOG = logging.getLogger(__name__)
LOG.debug("Loaded PerSecretKEKStoreAdapter module: %s", __name__)
DEFAULT_KEK_META_KEY = "kek-ref"

class PerSecretKEKStoreAdapter(StoreCryptoAdapterPlugin):
    """Secret-store adapter that honors a per-secret KEK selector via user-metadata,
    hard-wired to ToyCryptoPlugin (dev/testing only)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Hard-code the delegate crypto engine
        self.encrypting_plugin = SAPKMSCryptoPlugin()
        self._metadata_key = DEFAULT_KEK_META_KEY
        LOG.info("Initialized PerSecretKEKStoreAdapter using %s; metadata_key=%s",
                 type(self.encrypting_plugin).__name__, self._metadata_key)

    def _extract_user_metadata(self, context):
        """Return user metadata as a dict; always re-load from DB by secret id."""
        secret = getattr(context, "secret_model", None)
        secret_id = getattr(secret, "id", None)
        LOG.debug("Extracting user metadata for secret_model=%s secret_id=%s",
                  type(secret).__name__ if secret is not None else None, secret_id)
        meta = {}

        # 1) Preferred: repository read (fresh DB state)
        try:
            meta_repo = repos.get_secret_user_meta_repository()
            rows = None
            get1 = getattr(meta_repo, "get_metadata_for_secret", None)
            get2 = getattr(meta_repo, "get_metadata_by_secret_id", None)
            LOG.debug("Repository metadata methods available: get_metadata_for_secret=%s get_metadata_by_secret_id=%s",
                      bool(get1), bool(get2))

            if secret_id and callable(get1):
                rows = get1(secret_id)
                LOG.debug("Repository returned %s rows for secret_id=%s", len(rows) if rows else 0, secret_id)
            elif secret_id and callable(get2):
                rows = get2(secret_id)
                LOG.debug("Repository returned %s rows for secret_id=%s", len(rows) if rows else 0, secret_id)

            if isinstance(rows, dict):
                meta.update(rows)
            elif rows:
                meta.update({
                    getattr(r, "key", ""): getattr(r, "value", None)
                    for r in rows if getattr(r, "key", None)
                })
        except Exception:
            LOG.exception("Failed to read user metadata from repository for secret_id=%s", secret_id)

        # 2) Fallback: relationship on the loaded model (may be empty due to lazy-load)
        if not meta:
            LOG.debug("Repository metadata empty; attempting relationship fallback for secret_id=%s", secret_id)
            try:
                rel = getattr(secret, "user_metadata", None) or []
                items = [m for m in rel]  # force lazy load
                meta.update({
                    getattr(m, "key", ""): getattr(m, "value", None)
                    for m in items if getattr(m, "key", None)
                })
            except Exception:
                LOG.exception("Relationship fallback failed when loading user metadata for secret_id=%s", secret_id)

        # 3) Normalize keys so 'kek-ref' and 'kek_ref' both work
        norm = {(k or "").lower().replace("_", "-"): v for k, v in meta.items() if k}
        if "kek-ref" in norm:
            meta["kek-ref"] = norm["kek-ref"]

        LOG.debug("User metadata loaded for secret_id=%s: raw=%r normalized=%r", secret_id, meta, norm)
        return meta

    @staticmethod
    def _with_transient_override(kek_meta_dto, sap_gtid):
        """Copy KEK meta and add secret_kek_ref into plugin_meta (transient hint)."""
        LOG.debug("Applying transient plugin_meta override; sap_gtid=%s", sap_gtid)
        tmp = copy.deepcopy(kek_meta_dto)
        try:
            pm = json.loads(tmp.plugin_meta) if tmp.plugin_meta else {}
            LOG.debug("Parsed existing plugin_meta: %s", pm)
        except Exception:
            LOG.debug("Existing plugin_meta not parseable JSON; initializing new plugin_meta")
            pm = {}
        if sap_gtid:
            pm["sap_gtid"] = sap_gtid
        if pm:
            tmp.plugin_meta = json.dumps(pm)
        LOG.debug("Updated transient plugin_meta=%s", tmp.plugin_meta)
        return tmp

    # Barbican 7.1 calls: store_plugin.store_secret(secret_dto, context)
    def store_secret(self, secret_dto, context):
        LOG.debug("store_secret invoked for project=%s secret_model=%s",
                  getattr(context, "project_model", None), getattr(context, "secret_model", None))
        # 1) Resolve/create KEK backing objects (per-project binding etc.)
        kek_datum_model, kek_meta_dto = sc._find_or_create_kek_objects(
            self.encrypting_plugin, context.project_model
        )
        LOG.debug("Obtained KEK datum id=%s plugin_meta=%s",
                  getattr(kek_datum_model, "id", None), getattr(kek_meta_dto, "plugin_meta", None))

        # 2) Read caller-provided KEK selector (e.g., "kek-ref")
        meta = self._extract_user_metadata(context)
        LOG.debug("User metadata for secret=%s: %r",
                  getattr(getattr(context, "secret_model", None), "id", "?"), meta)
        sap_gtid = meta.get("sap_gtid") or meta.get("prefix-gtid")
        LOG.debug("Resolved sap_gtid=%s for encryption selection", sap_gtid)

        # 3) Inject transient override for the crypto plugin
        kek_meta_for_encrypt = self._with_transient_override(kek_meta_dto, sap_gtid)
        LOG.debug("Transient plugin_meta prepared for encryption")

        # 4) Decode base64 secret payload
        try:
            secret_bytes = base64.b64decode(secret_dto.secret)
            LOG.debug("Decoded secret payload: %d bytes", len(secret_bytes))
        except Exception:
            LOG.exception("Failed to decode base64 secret payload for secret_model=%s",
                          getattr(context, "secret_model", None))
            raise

        # 5) Perform encryption via delegate plugin
        try:
            response_dto = self.encrypting_plugin.encrypt(
                crypto_base.EncryptDTO(secret_bytes),
                kek_meta_for_encrypt,
                getattr(context.project_model, "external_id", None),
            )
            LOG.info("Encryption completed for secret_id=%s; kek_meta_extended=%s",
                     getattr(context.secret_model, "id", None),
                     getattr(response_dto, "kek_meta_extended", None))
        except Exception:
            LOG.exception("Encryption failed for secret_id=%s", getattr(context.secret_model, "id", None))
            raise

        # 6) Persist ciphertext + kek_meta_extended
        try:
            result = sc._store_secret_and_datum(
                context, context.secret_model, kek_datum_model, response_dto
            )
            LOG.info("Persisted encrypted datum for secret_id=%s", getattr(context.secret_model, "id", None))
            return result
        except Exception:
            LOG.exception("Failed to persist encrypted datum for secret_id=%s", getattr(context.secret_model, "id", None))
            raise

    def generate_symmetric_key(self, key_spec, context):
        """Generate a symmetric key.

        :param key_spec: KeySpec that contains details on the type of key to
        generate
        :param context: StoreCryptoContext for secret
        :returns: a dictionary that contains metadata about the key
        """
        LOG.info("generate_symmetric invoked: alg=%s bit_length=%s mode=%s project=%s",
                 getattr(key_spec, "alg", None),
                 getattr(key_spec, "bit_length", None),
                 getattr(key_spec, "mode", None),
                 getattr(context, "project_model", None))

        try:
            kek_datum_model, kek_meta_dto = sc._find_or_create_kek_objects(
                self.encrypting_plugin, context.project_model
            )
            LOG.debug("KEK binding ready for project %s (plugin_meta=%s)",
                      getattr(context.project_model, "external_id", None),
                      getattr(kek_meta_dto, "plugin_meta", None))
        except Exception:
            LOG.exception("Failed to obtain or create KEK binding for project %s",
                          getattr(context.project_model, "external_id", None))
            raise

        generate_dto = crypto_base.GenerateDTO(key_spec.alg,
                                        key_spec.bit_length,
                                        key_spec.mode, None)
        LOG.debug("Prepared GenerateDTO: alg=%s bit_length=%s mode=%s",
                  key_spec.alg, key_spec.bit_length, key_spec.mode)

        try:
            response_dto = self.encrypting_plugin.generate_symmetric(
                generate_dto, kek_meta_dto, context.project_model.external_id)
            LOG.info("Symmetric key generation completed for project=%s", getattr(context.project_model, "external_id", None))
        except Exception:
            LOG.exception("Symmetric key generation failed for project %s",
                          getattr(context.project_model, "external_id", None))
            raise

        try:
            result = sc._store_secret_and_datum(
                context, context.secret_model, kek_datum_model, response_dto
            )
            LOG.info("Persisted generated key datum for secret_id=%s", getattr(context.secret_model, "id", None))
            return result
        except Exception:
            LOG.exception("Failed to persist generated key datum for secret_id=%s", getattr(context.secret_model, "id", None))
            raise
