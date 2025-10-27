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
import base64
import pytest

# Import the real class from your repo
from barbican.plugin.crypto.sap_kms_plugin import SAPKMSCryptoPlugin

# Tiny stand-ins for Barbican DTOs
class EncryptDTO:
    def __init__(self, unencrypted: bytes):
        self.unencrypted = unencrypted

class DecryptDTO:
    def __init__(self, encrypted: bytes):
        self.encrypted = encrypted

class KEKMetaDTO:
    def __init__(self, plugin_meta: str | None = None, kek_label: str | None = None, plugin_name: str | None = None):
        self.plugin_meta = plugin_meta
        self.kek_label = kek_label
        self.plugin_name = plugin_name

def dto_with_gtid(gtid: str | None):
    import json
    return KEKMetaDTO(plugin_meta=(json.dumps({"sap_gtid": gtid}) if gtid else None))

def test_encrypt_decrypt_env_key(tmp_env, monkeypatch):
    # Arrange: set an explicit env key (stable across process)
    monkeypatch.setenv("SAP_KMS_FERNET_KEY", "s7H0y1jzvH8vE9aJt4nK0mPLgSQc5m2cMcb3XQ8s1BY=")
    p = SAPKMSCryptoPlugin()
    dto = EncryptDTO(b"test")

    # Act
    enc = p.encrypt(dto, dto_with_gtid(None), project_id="proj")
    dec = p.decrypt(DecryptDTO(enc.cypher_text), dto_with_gtid(None), enc.kek_meta_extended, "proj")

    # Assert
    assert dec == b"test"
    assert enc.kek_meta_extended is None  # because no sap_gtid was used

def test_encrypt_decrypt_with_mapping(tmp_env, monkeypatch, mapping_file):
    # Arrange: use mapping file + gtid to pick scoped key
    monkeypatch.setenv("PROJECT_METADATA_FILE", mapping_file)
    # Do NOT set SAP_KMS_FERNET_KEY to ensure mapping is used
    p = SAPKMSCryptoPlugin()
    dto = EncryptDTO(b"alpha")
    kek_meta = dto_with_gtid("GTID-123")

    # Act
    enc = p.encrypt(dto, kek_meta, "proj")
    # The kek_meta_extended should carry sap_gtid (as simple string in current code)
    assert enc.kek_meta_extended == "GTID-123"

    dec = p.decrypt(DecryptDTO(enc.cypher_text), kek_meta, enc.kek_meta_extended, "proj")
    assert dec == b"alpha"

def test_encrypt_rejects_non_bytes(tmp_env):
    p = SAPKMSCryptoPlugin()
    with pytest.raises(ValueError):
        p.encrypt(EncryptDTO("not-bytes"), dto_with_gtid(None), "proj")  # type: ignore

def test_generate_symmetric_default_bits(tmp_env, monkeypatch):
    # Arrange
    monkeypatch.setenv("SAP_KMS_FERNET_KEY", "s7H0y1jzvH8vE9aJt4nK0mPLgSQc5m2cMcb3XQ8s1BY=")
    p = SAPKMSCryptoPlugin()

    class GenerateDTO:
        def __init__(self, alg=None, bit_length=None, mode=None, passphrase=None):
            self.algorithm = alg
            self.bit_length = bit_length
            self.mode = mode
            self.passphrase = passphrase

    # Act
    resp = p.generate_symmetric(GenerateDTO(bit_length=None), dto_with_gtid(None), "proj")

    # Assert: just ensure ciphertext is non-empty and decryptable with env key
    assert isinstance(resp.cypher_text, (bytes, bytearray))
    # Basic decrypt check
    f = p._fernet(None)
    f.decrypt(resp.cypher_text)  # should not raise

def test_ephemeral_key_dev_mode(tmp_env, monkeypatch):
    # When no key provided, plugin generates ephemeral (dev) key and still works
    # NOTE: this relies on current behavior that auto-generates a key; if you
    # later guard this behind ALLOW_EPHEMERAL_KEY, set the env here accordingly.
    p = SAPKMSCryptoPlugin()
    enc = p.encrypt(EncryptDTO(b"x"), dto_with_gtid(None), "proj")
    dec = p.decrypt(DecryptDTO(enc.cypher_text), dto_with_gtid(None), enc.kek_meta_extended, "proj")
    assert dec == b"x"
