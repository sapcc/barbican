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
import os

import fixtures

from barbican.plugin.crypto import hsm_config_key
from barbican.tests import utils

TEST_KEY = b"\x01" * hsm_config_key.KEY_LEN
TEST_KEY_B64 = base64.b64encode(TEST_KEY)
TEST_PIN = "sup3r-secret-pin"


class WhenLoadingConfigKey(utils.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.tmpdir = self.useFixture(fixtures.TempDir()).path

    def _write_key_file(self, contents):
        path = os.path.join(self.tmpdir, "hsm-config-key")
        with open(path, "wb") as f:
            f.write(contents)
        return path

    def test_loads_valid_base64_key(self):
        """A file holding base64 of 32 raw bytes decodes to those 32 bytes.

        Expected: ``load_config_key`` returns the decoded key unchanged.
        """
        path = self._write_key_file(TEST_KEY_B64)
        self.assertEqual(TEST_KEY, hsm_config_key.load_config_key(path))

    def test_loads_key_with_trailing_newline(self):
        """A trailing newline in the key file is tolerated.

        Mounted secrets often end in a newline. Expected: the newline is
        stripped before decoding and the correct 32-byte key is returned.
        """
        path = self._write_key_file(TEST_KEY_B64 + b"\n")
        self.assertEqual(TEST_KEY, hsm_config_key.load_config_key(path))

    def test_empty_path_fails_hard(self):
        """An empty or None key path is refused rather than silently ignored.

        Expected: ``HSMConfigKeyError`` for both ``""`` and ``None`` so the
        caller never proceeds without a configured key.
        """
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          hsm_config_key.load_config_key, "")
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          hsm_config_key.load_config_key, None)

    def test_missing_file_fails_hard(self):
        """A path that does not exist on disk is a hard failure.

        Expected: ``HSMConfigKeyError`` (no fallback to a generated key).
        """
        path = os.path.join(self.tmpdir, "does-not-exist")
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          hsm_config_key.load_config_key, path)

    def test_empty_file_fails_hard(self):
        """A file with only whitespace holds no key and is refused.

        Expected: ``HSMConfigKeyError`` rather than decoding to empty bytes.
        """
        path = self._write_key_file(b"   \n")
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          hsm_config_key.load_config_key, path)

    def test_non_base64_file_fails_hard(self):
        """Contents that are not valid base64 are refused.

        Expected: ``HSMConfigKeyError`` instead of a partial/garbage key.
        """
        path = self._write_key_file(b"not valid base64 !!!")
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          hsm_config_key.load_config_key, path)

    def test_wrong_length_key_fails_hard(self):
        """A key that decodes to a length other than 32 bytes is refused.

        Here a 16-byte key is supplied. Expected: ``HSMConfigKeyError``,
        since AES-256 requires exactly 32 bytes.
        """
        short = base64.b64encode(b"\x01" * 16)
        path = self._write_key_file(short)
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          hsm_config_key.load_config_key, path)


class WhenEncryptingAndDecryptingPin(utils.BaseTestCase):

    def test_round_trip(self):
        """Encrypting then decrypting with the same key recovers the PIN.

        Expected: ``decrypt_pin`` returns the exact original plaintext.
        """
        env = hsm_config_key.encrypt_pin(TEST_PIN, TEST_KEY)
        self.assertEqual(TEST_PIN, hsm_config_key.decrypt_pin(env, TEST_KEY))

    def test_envelope_shape(self):
        """The envelope has the expected versioned, JSON-safe structure.

        Expected: ``v``/``alg`` match the module constants; ``nonce`` and
        ``ciphertext`` are base64 strings; the nonce is 12 bytes; and the
        plaintext PIN never appears inside the ciphertext field.
        """
        env = hsm_config_key.encrypt_pin(TEST_PIN, TEST_KEY)
        self.assertEqual(hsm_config_key.ENVELOPE_VERSION, env["v"])
        self.assertEqual(hsm_config_key.ALG, env["alg"])
        # Binary fields are base64 strings so the dict is JSON-safe.
        self.assertIsInstance(env["nonce"], str)
        self.assertIsInstance(env["ciphertext"], str)
        nonce = base64.b64decode(env["nonce"], validate=True)
        self.assertEqual(hsm_config_key.NONCE_LEN, len(nonce))
        # Plaintext PIN must never appear in the stored envelope.
        self.assertNotIn(TEST_PIN, env["ciphertext"])

    def test_nonce_is_random_per_call(self):
        """Each encryption draws a fresh nonce.

        Encrypting the same PIN with the same key twice must not reuse the
        nonce (GCM nonce reuse is catastrophic). Expected: differing nonces
        and, consequently, differing ciphertexts.
        """
        a = hsm_config_key.encrypt_pin(TEST_PIN, TEST_KEY)
        b = hsm_config_key.encrypt_pin(TEST_PIN, TEST_KEY)
        self.assertNotEqual(a["nonce"], b["nonce"])
        self.assertNotEqual(a["ciphertext"], b["ciphertext"])

    def test_tampered_ciphertext_refuses(self):
        """A flipped ciphertext byte fails the GCM authentication tag.

        Expected: ``HSMCredentialDecryptionError`` so a tampered row can
        never yield a usable PIN.
        """
        env = hsm_config_key.encrypt_pin(TEST_PIN, TEST_KEY)
        raw = bytearray(base64.b64decode(env["ciphertext"]))
        raw[0] ^= 0xFF
        env["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
        self.assertRaises(hsm_config_key.HSMCredentialDecryptionError,
                          hsm_config_key.decrypt_pin, env, TEST_KEY)

    def test_wrong_key_refuses(self):
        """Decrypting with a different key fails authentication.

        Expected: ``HSMCredentialDecryptionError`` rather than garbage
        plaintext, since the GCM tag will not verify under the wrong key.
        """
        env = hsm_config_key.encrypt_pin(TEST_PIN, TEST_KEY)
        other = b"\x02" * hsm_config_key.KEY_LEN
        self.assertRaises(hsm_config_key.HSMCredentialDecryptionError,
                          hsm_config_key.decrypt_pin, env, other)

    def test_malformed_envelope_refuses(self):
        """Structurally invalid envelopes are rejected before decryption.

        Covers a missing envelope, missing fields, an unsupported version,
        an unsupported algorithm, and non-base64 fields. Expected:
        ``HSMCredentialDecryptionError`` in every case.
        """
        for bad in ({}, {"v": 1}, {"v": 2, "alg": hsm_config_key.ALG},
                    {"v": 1, "alg": "other"},
                    {"v": 1, "alg": hsm_config_key.ALG,
                     "nonce": "!!!", "ciphertext": "!!!"}):
            self.assertRaises(hsm_config_key.HSMCredentialDecryptionError,
                              hsm_config_key.decrypt_pin, bad, TEST_KEY)

    def test_encrypt_rejects_bad_key(self):
        """Encrypting with a key of the wrong length is refused up front.

        Expected: ``HSMConfigKeyError`` rather than producing an envelope
        under an invalid (non-256-bit) key.
        """
        self.assertRaises(hsm_config_key.HSMConfigKeyError,
                          hsm_config_key.encrypt_pin, TEST_PIN, b"short")


class WhenDetectingLegacyRows(utils.BaseTestCase):

    def test_legacy_plaintext_detected(self):
        """A pre-encryption row ``{"password": ...}`` is flagged as legacy.

        Expected: ``is_legacy_plaintext`` returns True so the read path can
        fall back to the plaintext PIN with a warning.
        """
        self.assertTrue(
            hsm_config_key.is_legacy_plaintext({"password": "x"}))

    def test_encrypted_envelope_not_legacy(self):
        """A real encrypted envelope is not treated as legacy plaintext.

        Expected: ``is_legacy_plaintext`` returns False because the envelope
        carries a version (``v``) key.
        """
        env = hsm_config_key.encrypt_pin(TEST_PIN, TEST_KEY)
        self.assertFalse(hsm_config_key.is_legacy_plaintext(env))

    def test_non_dict_not_legacy(self):
        """Non-dict or empty-dict credentials are not legacy plaintext.

        Expected: ``is_legacy_plaintext`` returns False for ``None``, a
        string, and an empty dict (none carry a ``password`` key).
        """
        self.assertFalse(hsm_config_key.is_legacy_plaintext(None))
        self.assertFalse(hsm_config_key.is_legacy_plaintext("x"))
        self.assertFalse(hsm_config_key.is_legacy_plaintext({}))
