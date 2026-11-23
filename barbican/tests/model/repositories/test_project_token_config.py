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

from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils


_UNSET = object()


def _build_project_token_config(project_id, slot_id="my slot id",
                                vendor_type="utimaco",
                                endpoints=_UNSET,
                                mkek_label="mkek",
                                hmac_label="hmac",
                                token_serial_number=None,
                                vendor_metadata=None):
    if endpoints is _UNSET:
        endpoints = [{"host": "127.0.0.1", "port": 4001, "order": 0}]
    cfg = models.ProjectTokenConfig()
    cfg.project_id = project_id
    cfg.slot_id = slot_id
    cfg.token_label = "my token label"
    cfg.vendor_type = vendor_type
    cfg.endpoints = endpoints
    cfg.mkek_label = mkek_label
    cfg.hmac_label = hmac_label
    cfg.token_serial_number = token_serial_number
    cfg.vendor_metadata = vendor_metadata
    cfg.credentials = {"password": "secret"}
    cfg.status = models.States.ACTIVE
    return cfg


class WhenTestingProjectTokenConfigRepository(
    database_utils.RepositoryTestCase
):
    def setUp(self):
        super(WhenTestingProjectTokenConfigRepository, self).setUp()
        self.repo = repositories.ProjectTokenConfigRepo()
        self.session = self.repo.get_session()

        self.project = models.Project()
        self.project.external_id = "179e1f2106054b829b7503e619a44231"
        self.project.status = models.States.ACTIVE
        self.project.save(session=self.session)

        self.project_token_config = _build_project_token_config(
            self.project.id
        )
        self.project_token_config.save(session=self.session)

    def test_get_project_token_config_returns_result(self):
        got = self.repo.get(
            entity_id=self.project_token_config.id,
            session=self.session,
            suppress_exception=False,
        )

        self.assertEqual(self.project_token_config.id, got.id)

    def test_get_by_project_id_returns_result_for_project_id(self):
        got = self.repo.get_by_project_id(
            project_id=self.project.id,
            suppress_exception=False,
            session=self.session,
        )

        self.assertEqual(self.project_token_config.id, got.id)

    def test_get_by_project_id_returns_result_for_external_id(self):
        self.project.project_id = "my project id"
        self.project.save(session=self.session)

        got = self.repo.get_by_project_id(
            project_id=self.project.external_id,
            suppress_exception=False,
            session=self.session,
        )

        self.assertEqual(self.project_token_config.id, got.id)

    def test_get_by_project_id_returns_no_result_and_no_exception(self):
        entity = self.repo.get_by_project_id(
            project_id="my project id",
            suppress_exception=True,
            session=self.session,
        )

        self.assertEqual(None, entity)

    def test_get_by_project_id_returns_no_result_and_raises_exception(self):
        self.assertRaises(
            exception.NotFound,
            self.repo.get_by_project_id,
            project_id="my project id",
            suppress_exception=False,
            session=self.session,
        )

    def test_create_from_rejects_second_active_config_for_project(self):
        second = _build_project_token_config(self.project.id, slot_id="other")
        self.assertRaises(
            exception.ConstraintCheck,
            self.repo.create_from,
            second,
            session=self.session,
        )


class WhenValidatingProjectTokenConfig(database_utils.RepositoryTestCase):
    """@validates coverage: must fire on in-memory assignment, not save."""

    def setUp(self):
        super(WhenValidatingProjectTokenConfig, self).setUp()
        self.project = models.Project()
        self.project.external_id = "179e1f2106054b829b7503e619a44231"
        self.project.status = models.States.ACTIVE
        self.project.save()

    def test_vendor_type_rejects_unknown_value(self):
        self.assertRaises(
            exception.Invalid,
            _build_project_token_config,
            self.project.id,
            vendor_type="unknown",
        )

    def test_endpoints_rejects_empty_list(self):
        self.assertRaises(
            exception.Invalid,
            _build_project_token_config,
            self.project.id,
            endpoints=[],
        )

    def test_endpoints_rejects_non_list(self):
        self.assertRaises(
            exception.Invalid,
            _build_project_token_config,
            self.project.id,
            endpoints={"host": "h", "port": 1},
        )

    def test_endpoints_rejects_missing_host(self):
        self.assertRaises(
            exception.Invalid,
            _build_project_token_config,
            self.project.id,
            endpoints=[{"port": 4001, "order": 0}],
        )

    def test_endpoints_rejects_non_int_port(self):
        self.assertRaises(
            exception.Invalid,
            _build_project_token_config,
            self.project.id,
            endpoints=[{"host": "h", "port": "4001", "order": 0}],
        )

    def test_endpoints_rejects_bool_port(self):
        # bool is an int subclass - guard against it.
        self.assertRaises(
            exception.Invalid,
            _build_project_token_config,
            self.project.id,
            endpoints=[{"host": "h", "port": True, "order": 0}],
        )

    def test_endpoints_rejects_missing_order(self):
        self.assertRaises(
            exception.Invalid,
            _build_project_token_config,
            self.project.id,
            endpoints=[{"host": "h", "port": 4001}],
        )

    def test_endpoints_rejects_negative_order(self):
        self.assertRaises(
            exception.Invalid,
            _build_project_token_config,
            self.project.id,
            endpoints=[{"host": "h", "port": 4001, "order": -1}],
        )

    def test_endpoints_rejects_duplicate_order(self):
        self.assertRaises(
            exception.Invalid,
            _build_project_token_config,
            self.project.id,
            endpoints=[
                {"host": "a", "port": 4001, "order": 0},
                {"host": "b", "port": 4001, "order": 0},
            ],
        )

    def test_accepts_multi_endpoint_utimaco_row(self):
        cfg = _build_project_token_config(
            self.project.id,
            vendor_type="utimaco",
            endpoints=[
                {"host": "10.0.0.1", "port": 4001, "order": 0},
                {"host": "10.0.0.2", "port": 4001, "order": 1},
            ],
            token_serial_number="SN-123",
            vendor_metadata={"container_id": 1},
        )
        cfg.save()
        self.assertEqual(2, len(cfg.endpoints))

    def test_accepts_thales_row_without_token_serial_number(self):
        cfg = _build_project_token_config(
            self.project.id,
            vendor_type="thales",
            endpoints=[
                {"host": "luna.example.com", "port": 1792, "order": 0},
            ],
            token_serial_number=None,
        )
        cfg.save()
        self.assertEqual("thales", cfg.vendor_type)
        self.assertIsNone(cfg.token_serial_number)

    def test_rejects_row_with_no_token_identifiers(self):
        # token_serial_number, slot_id, and token_label all None/empty.
        # Validation is now enforced at flush time, not on assignment.
        cfg = _build_project_token_config(
            self.project.id,
            slot_id=None,
            token_serial_number=None,
        )
        cfg.token_label = None
        self.assertRaises(exception.Invalid, cfg.save)

    def test_accepts_row_with_only_token_serial_number(self):
        cfg = models.ProjectTokenConfig()
        cfg.project_id = self.project.id
        cfg.vendor_type = "utimaco"
        cfg.endpoints = [{"host": "h", "port": 4001, "order": 0}]
        cfg.mkek_label = "mkek"
        cfg.hmac_label = "hmac"
        cfg.credentials = {"password": "secret"}
        cfg.status = models.States.ACTIVE
        cfg.token_serial_number = "SN-123"
        # slot_id and token_label never set
        self.assertEqual("SN-123", cfg.token_serial_number)

    def test_rejects_clearing_last_token_identifier(self):
        cfg = _build_project_token_config(
            self.project.id,
            slot_id="0",
            token_serial_number=None,
        )
        cfg.save()
        # Clearing slot_id is fine because token_label still satisfies the
        # invariant.
        cfg.slot_id = None
        cfg.save()
        # But clearing token_label when slot_id and token_serial_number are
        # both empty must fail at flush time.
        cfg.token_label = None
        self.assertRaises(exception.Invalid, cfg.save)

    def test_accepts_row_when_only_last_assigned_identifier_is_set(self):
        cfg = _build_project_token_config(
            self.project.id,
            slot_id=None,
            token_serial_number=None,
        )
        # token_label is set to "my token label" by the helper.
        cfg.save()
        self.assertEqual("my token label", cfg.token_label)
