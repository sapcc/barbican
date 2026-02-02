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


class WhenTestingHSMPartitionConfigRepository(
    database_utils.RepositoryTestCase
):
    def setUp(self):
        super(WhenTestingHSMPartitionConfigRepository, self).setUp()
        self.repo = repositories.HSMPartitionConfigRepo()
        self.session = self.repo.get_session()

        self.project = models.Project()
        self.project.external_id = "my external id"
        self.project.status = models.States.ACTIVE
        self.project.save(session=self.session)

        self.hsm_partition_config = models.HSMPartitionConfig()
        self.hsm_partition_config.project_id = self.project.id
        self.hsm_partition_config.slot_id = "my slot id"
        self.hsm_partition_config.token_label = "my token label"
        self.hsm_partition_config.partition_label = "my partition label"
        self.hsm_partition_config.credentials = "{}"
        self.hsm_partition_config.status = models.States.ACTIVE
        self.hsm_partition_config.save(session=self.session)

    def test_get_hsm_partition_config_returns_result(self):
        hsm_partition_config_get = self.repo.get(
            entity_id=self.hsm_partition_config.id,
            session=self.session,
            suppress_exception=False,
        )

        self.assertEqual(
            self.hsm_partition_config.id, hsm_partition_config_get.id
        )

    def test_get_by_project_id_returns_result_for_project_id(self):
        hsm_partition_config_get = self.repo.get_by_project_id(
            project_id=self.project.id,
            suppress_exception=False,
            session=self.session,
        )

        self.assertEqual(
            self.hsm_partition_config.id, hsm_partition_config_get.id
        )

    def test_get_by_project_id_returns_result_for_external_id(self):
        self.project.project_id = "my project id"
        self.project.save(session=self.session)

        hsm_partition_config_get = self.repo.get_by_project_id(
            project_id=self.project.external_id,
            suppress_exception=False,
            session=self.session,
        )

        self.assertEqual(
            self.hsm_partition_config.id, hsm_partition_config_get.id
        )

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
