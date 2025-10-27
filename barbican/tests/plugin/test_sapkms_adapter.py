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
#
import json
import base64
import types
import pytest

from barbican.plugin.sap_kms_adapter import PerSecretKEKStoreAdapter

# Minimal fakes for Barbican pieces the adapter touches

class FakeSecretModel:
    def __init__(self, id_=None, user_metadata=None):
        self.id = id_
        self.user_metadata = user_metadata or []  # list of objects with key/value

class FakeUserMeta:
    def __init__(self, key, value):
        self.key = key
        self.value = value

class FakeProjectModel:
    def __init__(self, external_id="proj-ext"):
        self.external_id = external_id

class FakeContext:
    def __init__(self, secret_model=None, project_model=None):
        self.secret_model = secret_model or FakeSecretModel()
        self.project_model = project_model or FakeProjectModel()

class FakeSecretDTO:
    def __init__(self, secret_bytes: bytes):
        # adapter expects base64-encoded string
        self.secret = base64.b64encode(secret_bytes).decode("ascii")

# Patch points in modules the adapter imports
@pytest.fixture(autouse=True)
def patch_repos(monkeypatch):
    """Patch repos.get_secret_user_meta_repository to return controlled metadata."""
    class FakeRepo:
        def get_metadata_for_secret(self, secret_id):
            return []  # default: nothing in DB

    monkeypatch.setattr("barbican.plugin.sap_kms_adapter.repos.get_secret_user_meta_repository", lambda: FakeRepo())
    yield

@pytest.fixture
def patched_crypto(monkeypatch):
    """Patch the underlying crypto plugin used by the adapter to a trivial fake."""
    class FakeCrypto:
        def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
            # echo-like cipher: prepend a marker to allow verifying flow
            ct = b"CT:" + encrypt_dto.unencrypted
            # Return object with cypher_text + kek_meta_extended
            Resp = types.SimpleNamespace
            # propagate sap_gtid from kek_meta_dto.plugin_meta to check path
            sap_gtid = None
            try:
                meta = json.loads(kek_meta_dto.plugin_meta) if kek_meta_dto.plugin_meta else {}
                sap_gtid = meta.get("sap_gtid")
            except Exception:
                sap_gtid = None
            return Resp(cypher_text=ct, kek_meta_extended=sap_gtid)

        def generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
            Resp = types.SimpleNamespace
            return Resp(cypher_text=b"GEN:deadbeef", kek_meta_extended=None)

    # Replace the class construction inside the adapter module
    monkeypatch.setattr("barbican.plugin.sap_kms_adapter.SAPKMSCryptoPlugin", FakeCrypto)
    yield

@pytest.fixture
def patch_store_crypto(monkeypatch):
    """Patch store_crypto helpers the adapter calls to avoid DB persistence."""
    # sc._find_or_create_kek_objects -> returns (kek_datum_model, kek_meta_dto)
    class FakeKEKDatum:
        id = "kek-datum-id"

    class FakeKEKMetaDTO:
        def __init__(self):
            self.plugin_meta = None
            self.kek_label = None
            self.plugin_name = None

    def fake_find_or_create(plugin, project_model):
        return FakeKEKDatum(), FakeKEKMetaDTO()

    # sc._store_secret_and_datum -> just returns a sentinel
    def fake_store(context, secret_model, kek_datum_model, response_dto):
        return {"stored": True, "len": len(response_dto.cypher_text), "kek_meta_extended": response_dto.kek_meta_extended}

    monkeypatch.setattr("barbican.plugin.sap_kms_adapter.sc._find_or_create_kek_objects", fake_find_or_create)
    monkeypatch.setattr("barbican.plugin.sap_kms_adapter.sc._store_secret_and_datum", fake_store)
    yield

def test_store_secret_no_user_metadata(patched_crypto, patch_store_crypto):
    adapter = PerSecretKEKStoreAdapter()
    ctx = FakeContext(secret_model=FakeSecretModel(id_="S1"))
    dto = FakeSecretDTO(b"abcd")

    result = adapter.store_secret(dto, ctx)
    assert result["stored"] is True
    assert result["len"] == len(b"CT:abcd")
    # No gtid provided, so kek_meta_extended should be None
    assert result["kek_meta_extended"] is None

def test_store_secret_with_sap_gtid_on_relationship(patched_crypto, patch_store_crypto):
    adapter = PerSecretKEKStoreAdapter()
    # Simulate controller attaching user metadata to the secret model before store
    meta = [FakeUserMeta("sap_gtid", "GTID-123")]
    ctx = FakeContext(secret_model=FakeSecretModel(id_="S2", user_metadata=meta))
    dto = FakeSecretDTO(b"ping")

    result = adapter.store_secret(dto, ctx)
    assert result["stored"] is True
    assert result["kek_meta_extended"] == "GTID-123"  # flowed through transient plugin_meta

def test_store_secret_base64_error_is_logged_and_raised(patched_crypto, patch_store_crypto):
    adapter = PerSecretKEKStoreAdapter()
    ctx = FakeContext(secret_model=FakeSecretModel(id_="S3"))
    bad = FakeSecretDTO(b"ok")
    # corrupt the base64 payload
    bad.secret = "%%%NOT-BASE64%%%"

    with pytest.raises(Exception):
        adapter.store_secret(bad, ctx)

def test_generate_symmetric_flow(patched_crypto, patch_store_crypto):
    adapter = PerSecretKEKStoreAdapter()

    class KeySpec:
        def __init__(self, alg="AES", bit_length=256, mode=None):
            self.alg = alg
            self.bit_length = bit_length
            self.mode = mode

    ctx = FakeContext(secret_model=FakeSecretModel(id_="S4"))
    out = adapter.generate_symmetric_key(KeySpec(), ctx)
    assert out["stored"] is True
    assert out["len"] == len(b"GEN:deadbeef")
