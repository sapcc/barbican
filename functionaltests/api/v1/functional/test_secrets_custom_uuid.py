# Copyright 2026 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

"""sapcc-custom: functional tests for caller-supplied secret UUID."""

from oslo_utils import uuidutils
from testtools import testcase

from functionaltests.api import base
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import secret_models
from functionaltests.common import config


CONF = config.get_config()
admin_a = CONF.rbac_users.admin_a


def _make_v4_uuid():
    """Return a fresh canonical lowercase v4 UUID string."""
    return uuidutils.generate_uuid()


class SecretsCustomUUIDTestCase(base.TestCase):
    """sapcc-custom: end-to-end caller-supplied secret UUID feature."""

    def setUp(self):
        super(SecretsCustomUUIDTestCase, self).setUp()
        self.behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.base_payload = {
            'name': 'custom-uuid-test',
            'algorithm': 'aes',
            'bit_length': 256,
            'mode': 'cbc',
            'secret_type': 'symmetric',
        }

    def tearDown(self):
        self.behaviors.delete_all_created_secrets()
        super(SecretsCustomUUIDTestCase, self).tearDown()

    @testcase.attr('positive')
    def test_create_secret_with_custom_uuid(self):
        """The caller-supplied UUID is honoured and echoed back."""
        custom_uuid = _make_v4_uuid()
        model = secret_models.SecretModel(id=custom_uuid, **self.base_payload)

        resp, secret_ref = self.behaviors.create_secret(
            model, user_name=admin_a)
        self.assertEqual(201, resp.status_code)
        self.assertTrue(secret_ref.endswith(custom_uuid),
                        msg='secret_ref %s does not end with %s' %
                            (secret_ref, custom_uuid))

        get_resp = self.behaviors.get_secret_metadata(
            secret_ref, user_name=admin_a)
        self.assertEqual(200, get_resp.status_code)

    @testcase.attr('negative')
    def test_create_secret_with_active_duplicate_uuid_conflicts(self):
        """In-project active duplicate -> 409, original row untouched."""
        custom_uuid = _make_v4_uuid()
        first = secret_models.SecretModel(id=custom_uuid, **self.base_payload)
        resp1, ref1 = self.behaviors.create_secret(first, user_name=admin_a)
        self.assertEqual(201, resp1.status_code)

        second = secret_models.SecretModel(id=custom_uuid, **self.base_payload)
        resp2, _ = self.behaviors.create_secret(second, user_name=admin_a)
        self.assertEqual(409, resp2.status_code)

        # The original row must still be readable.
        get_resp = self.behaviors.get_secret_metadata(
            ref1, user_name=admin_a)
        self.assertEqual(200, get_resp.status_code)

    @testcase.attr('positive')
    def test_recreate_after_soft_delete_with_same_uuid(self):
        """Deleting a custom-UUID secret and POSTing it again must succeed."""
        custom_uuid = _make_v4_uuid()
        first = secret_models.SecretModel(id=custom_uuid, **self.base_payload)
        resp1, ref1 = self.behaviors.create_secret(first, user_name=admin_a)
        self.assertEqual(201, resp1.status_code)

        del_resp = self.behaviors.delete_secret(ref1, user_name=admin_a)
        self.assertEqual(204, del_resp.status_code)

        replacement = secret_models.SecretModel(
            id=custom_uuid, **self.base_payload)
        resp2, ref2 = self.behaviors.create_secret(
            replacement, user_name=admin_a)
        self.assertEqual(201, resp2.status_code)
        self.assertTrue(ref2.endswith(custom_uuid))

    @testcase.attr('negative')
    def test_create_secret_with_invalid_uuid_format_is_rejected(self):
        """Non-RFC4122-v4 strings are rejected by the validator."""
        for bad in ['not-a-uuid',
                    'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',  # uppercase
                    '550e8400-e29b-11d4-a716-446655440000',  # v1
                    '']:
            model = secret_models.SecretModel(id=bad, **self.base_payload)
            resp, _ = self.behaviors.create_secret(model, user_name=admin_a)
            self.assertEqual(
                400, resp.status_code,
                msg='UUID %r should have been rejected with 400, got %d'
                    % (bad, resp.status_code))
