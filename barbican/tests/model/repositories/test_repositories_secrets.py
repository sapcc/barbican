# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime

import fixtures
from oslo_utils import timeutils
import testtools

from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.plugin.interface import secret_store as ss
from barbican.tests import database_utils
from barbican.tests import fixture
from barbican.tests import utils


@utils.parameterized_test_case
class WhenTestingSecretRepository(database_utils.RepositoryTestCase):

    dataset_for_filter_tests = {
        'query_by_name': {
            'secret_1_dict': dict(name="name1"),
            'secret_2_dict': dict(name="name2"),
            'query_dict': dict(name="name1")
        },
        'query_by_algorithm': {
            'secret_1_dict': dict(algorithm="algorithm1"),
            'secret_2_dict': dict(algorithm="algorithm2"),
            'query_dict': dict(alg="algorithm1")
        },
        'query_by_mode': {
            'secret_1_dict': dict(mode="mode1"),
            'secret_2_dict': dict(mode="mode2"),
            'query_dict': dict(mode="mode1")
        },
        'query_by_bit_length': {
            'secret_1_dict': dict(bit_length=1024),
            'secret_2_dict': dict(bit_length=2048),
            'query_dict': dict(bits=1024)
        },
        'query_by_secret_type': {
            'secret_1_dict': dict(secret_type=ss.SecretType.SYMMETRIC),
            'secret_2_dict': dict(secret_type=ss.SecretType.OPAQUE),
            'query_dict': dict(secret_type=ss.SecretType.SYMMETRIC)
        },
    }

    def setUp(self):
        super(WhenTestingSecretRepository, self).setUp()
        self.repo = repositories.SecretRepo()

    def test_get_secret_list(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        secret = self.repo.create_from(secret_model, session=session)

        session.commit()

        secrets, offset, limit, total = self.repo.get_secret_list(
            "my keystone id",
            session=session,
        )

        self.assertEqual([secret.id], [s.id for s in secrets])
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_secret_by_id(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        secret = self.repo.create_from(secret_model, session=session)

        session.commit()

        db_secret = self.repo.get_secret_by_id(secret.id)
        self.assertIsNotNone(db_secret)

    def test_should_raise_notfound_exception(self):
        self.assertRaises(exception.NotFound, self.repo.get_secret_by_id,
                          "invalid_id", suppress_exception=False)

    def test_should_suppress_notfound_exception(self):
        self.assertIsNone(self.repo.get_secret_by_id("invalid_id",
                                                     suppress_exception=True))

    @utils.parameterized_dataset(dataset_for_filter_tests)
    def test_get_secret_list_with_filter(self, secret_1_dict, secret_2_dict,
                                         query_dict):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_1_dict['project_id'] = project.id
        secret1 = self.repo.create_from(
            models.Secret(secret_1_dict),
            session=session,
        )
        secret_2_dict['project_id'] = project.id
        secret2 = self.repo.create_from(
            models.Secret(secret_2_dict),
            session=session,
        )

        session.commit()

        secrets, offset, limit, total = self.repo.get_secret_list(
            "my keystone id",
            session=session,
            **query_dict
        )
        resulting_secret_ids = [s.id for s in secrets]
        self.assertIn(secret1.id, resulting_secret_ids)
        self.assertNotIn(secret2.id, resulting_secret_ids)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(1, total)

    def test_get_by_create_date_nothing(self):
        session = self.repo.get_session()
        secrets, offset, limit, total = self.repo.get_secret_list(
            "my keystone id",
            bits=1024,
            session=session,
            suppress_exception=True
        )

        self.assertEqual([], secrets)
        self.assertEqual(0, offset)
        self.assertEqual(10, limit)
        self.assertEqual(0, total)

    def test_do_entity_name(self):
        self.assertEqual("Secret", self.repo._do_entity_name())

    def test_should_raise_no_result_found(self):
        session = self.repo.get_session()

        self.assertRaises(
            exception.NotFound,
            self.repo.get_secret_list,
            "my keystone id",
            session=session,
            suppress_exception=False)

    def test_should_get_count_zero(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        session.commit()
        count = self.repo.get_count(project.id, session=session)

        self.assertEqual(0, count)

    def test_should_get_count_one(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        self.repo.create_from(secret_model, session=session)

        session.commit()
        count = self.repo.get_count(project.id, session=session)

        self.assertEqual(1, count)

    def test_should_get_count_one_after_delete(self):
        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        self.repo.create_from(secret_model, session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        self.repo.create_from(secret_model, session=session)

        session.commit()
        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(2, count)

        self.repo.delete_entity_by_id(secret_model.id, "my keystone id",
                                      session=session)
        session.commit()

        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(1, count)

    def test_should_get_count_one_after_expiration(self):
        current_time = timeutils.utcnow()
        tomorrow = current_time + datetime.timedelta(days=1)
        yesterday = current_time - datetime.timedelta(days=1)

        session = self.repo.get_session()

        project = models.Project()
        project.external_id = "my keystone id"
        project.save(session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        secret_model.expiration = tomorrow
        self.repo.create_from(secret_model, session=session)

        secret_model = models.Secret()
        secret_model.project_id = project.id
        secret_model.expiration = yesterday
        self.repo.create_from(secret_model, session=session)

        session.commit()

        count = self.repo.get_count(project.id, session=session)
        self.assertEqual(2, count)


class WhenTestingQueryFilters(testtools.TestCase,
                              fixtures.TestWithFixtures):

    def setUp(self):
        super(WhenTestingQueryFilters, self).setUp()
        self._session_fixture = self.useFixture(fixture.SessionQueryFixture())
        self.session = self._session_fixture.Session()
        self.query = self.session.query(models.Secret)
        self.repo = repositories.SecretRepo()

    def test_data_includes_six_secrets(self):
        self.assertEqual(6, len(self.query.all()))

    def test_sort_by_name_defaults_ascending(self):
        query = self.repo._build_sort_filter_query(self.query, 'name')
        secrets = query.all()
        self.assertEqual('A', secrets[0].name)

    def test_sort_by_name_desc(self):
        query = self.repo._build_sort_filter_query(self.query, 'name:desc')
        secrets = query.all()
        self.assertEqual('F', secrets[0].name)

    def test_sort_by_created_asc(self):
        query = self.repo._build_sort_filter_query(self.query, 'created:asc')
        secrets = query.all()
        self.assertEqual('A', secrets[0].name)

    def test_sort_by_updated_desc(self):
        query = self.repo._build_sort_filter_query(self.query, 'updated:desc')
        secrets = query.all()
        self.assertEqual('F', secrets[0].name)

    def test_filter_by_created_on_new_years(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            '2016-01-01T00:00:00'
        )
        secrets = query.all()
        self.assertEqual(1, len(secrets))
        self.assertEqual('A', secrets[0].name)

    def test_filter_by_created_after_march(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            'gt:2016-03-01T00:00:00'
        )
        secrets = query.all()
        self.assertEqual(3, len(secrets))

    def test_filter_by_created_on_or_after_march(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            'gte:2016-03-01T00:00:00'
        )
        secrets = query.all()
        self.assertEqual(4, len(secrets))

    def test_filter_by_created_before_march(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            'lt:2016-03-01T00:00:00'
        )
        secrets = query.all()
        self.assertEqual(2, len(secrets))

    def test_filter_by_created_on_or_before_march(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            'lte:2016-03-01T00:00:00'
        )
        secrets = query.all()
        self.assertEqual(3, len(secrets))

    def test_filter_by_created_between_march_and_may_inclusive(self):
        query = self.repo._build_date_filter_query(
            self.query, 'created_at',
            'gte:2016-03-01T00:00:00,lte:2016-05-01T00:00:00'
        )
        secrets = query.all()
        secret_names = [s.name for s in secrets]

        self.assertEqual(3, len(secrets))
        self.assertIn('C', secret_names)
        self.assertIn('D', secret_names)
        self.assertIn('E', secret_names)


class WhenTestingSecretRepoCustomUUID(database_utils.RepositoryTestCase):
    """sapcc-custom: tests for caller-supplied UUID path in SecretRepo."""

    # sapcc-custom: canonical lowercase RFC 4122 v4 UUID used across all
    # tests in this class.  Must satisfy models._SAPCC_CUSTOM_UUID_V4_RE
    # since models.Secret now re-validates caller-supplied ids.
    CUSTOM_UUID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'

    def setUp(self):
        super(WhenTestingSecretRepoCustomUUID, self).setUp()
        self.repo = repositories.SecretRepo()

    def _make_project(self, session, external_id='recovery-test-project'):
        project = models.Project()
        project.external_id = external_id
        project.save(session=session)
        return project

    def test_create_secret_with_custom_uuid(self):
        session = self.repo.get_session()
        project = self._make_project(session)

        secret_model = models.Secret()
        secret_model.id = self.CUSTOM_UUID
        secret_model.project_id = project.id
        created = self.repo.create_from(secret_model, session=session)
        session.commit()

        self.assertEqual(self.CUSTOM_UUID, created.id)
        fetched = self.repo.get_secret_by_id(self.CUSTOM_UUID, session=session)
        self.assertIsNotNone(fetched)
        self.assertEqual(self.CUSTOM_UUID, fetched.id)

    def test_create_secret_with_custom_uuid_after_soft_delete(self):
        """Recreating a deleted key with the same UUID must succeed."""
        session = self.repo.get_session()
        project = self._make_project(session)

        # Create and then soft-delete a secret with the target UUID.
        original = models.Secret()
        original.id = self.CUSTOM_UUID
        original.project_id = project.id
        self.repo.create_from(original, session=session)
        session.commit()

        self.repo.delete_entity_by_id(self.CUSTOM_UUID,
                                      'recovery-test-project',
                                      session=session)
        session.commit()

        # Re-creating with the same UUID should succeed.
        replacement = models.Secret()
        replacement.id = self.CUSTOM_UUID
        replacement.project_id = project.id
        replacement.name = 'recovered-key'
        created = self.repo.create_from(replacement, session=session)
        session.commit()

        self.assertEqual(self.CUSTOM_UUID, created.id)
        fetched = self.repo.get_secret_by_id(self.CUSTOM_UUID, session=session)
        self.assertEqual('recovered-key', fetched.name)

    def test_create_secret_with_custom_uuid_raises_if_active(self):
        """In-project active duplicate raises HTTP-409 SecretIdConflict."""
        session = self.repo.get_session()
        project = self._make_project(session)

        existing = models.Secret()
        existing.id = self.CUSTOM_UUID
        existing.project_id = project.id
        self.repo.create_from(existing, session=session)
        session.commit()

        duplicate = models.Secret()
        duplicate.id = self.CUSTOM_UUID
        duplicate.project_id = project.id
        err = self.assertRaises(
            exception.SecretIdConflict,
            self.repo.create_from,
            duplicate,
            session=session,
        )
        # status_code attribute confirms HTTP 409 mapping at the
        # controller layer.
        self.assertEqual(409, err.status_code)

    def test_custom_uuid_requires_project_id(self):
        """An entity.id without project_id must be rejected.

        Defence in depth: scoping the duplicate-id lookup is only safe when a
        project_id is present, so the repo must refuse to proceed without
        one.
        """
        secret_model = models.Secret()
        secret_model.id = self.CUSTOM_UUID
        # project_id deliberately not set
        self.assertRaises(
            exception.Invalid,
            self.repo.create_from,
            secret_model,
        )

    def test_custom_uuid_collision_in_other_project_is_isolated(self):
        """Cross-project collision -> SecretIdNotAvailable (no info leak)."""
        # Use a fresh session for B so the DB PK constraint fires (not the
        # ORM identity map, which would short-circuit before the DB).
        session_a = self.repo.get_session()
        project_a = self._make_project(session_a, external_id='proj-a')
        project_a_id = project_a.id
        a_secret = models.Secret()
        a_secret.id = self.CUSTOM_UUID
        a_secret.project_id = project_a_id
        self.repo.create_from(a_secret, session=session_a)
        session_a.commit()
        session_a.close()

        session_b = self.repo.get_session()
        session_b.expunge_all()
        project_b = self._make_project(session_b, external_id='proj-b')
        session_b.commit()

        b_secret = models.Secret()
        b_secret.id = self.CUSTOM_UUID
        b_secret.project_id = project_b.id

        err = self.assertRaises(
            exception.SecretIdNotAvailable,
            self.repo.create_from,
            b_secret,
            session=session_b,
        )
        self.assertEqual(409, err.status_code)
        # No UUID / SQL internals leak in the error.
        err_text = str(err)
        self.assertNotIn(self.CUSTOM_UUID, err_text)
        self.assertNotIn('Duplicate', err_text)
        self.assertNotIn('PRIMARY', err_text)
        self.assertNotIn(self.CUSTOM_UUID, err.client_message)

        # Project A's row is untouched.
        session_b.rollback()
        verify_session = self.repo.get_session()
        verify_session.expunge_all()
        a_after = self.repo.get_secret_by_id(self.CUSTOM_UUID,
                                             session=verify_session)
        self.assertIsNotNone(a_after)
        self.assertEqual(project_a_id, a_after.project_id)
        self.assertFalse(a_after.deleted)

    def test_custom_uuid_uppercase_is_normalised_to_lowercase(self):
        """Mixed-case UUIDs are canonicalised lowercase by the model."""
        session = self.repo.get_session()
        project = self._make_project(session)
        secret_model = models.Secret(
            parsed_request={'id': self.CUSTOM_UUID.upper()},
        )
        secret_model.project_id = project.id
        created = self.repo.create_from(secret_model, session=session)
        session.commit()
        self.assertEqual(self.CUSTOM_UUID, created.id)
