from barbican.common import exception
from barbican.model import models
from barbican.model import repositories
from barbican.tests import database_utils

# TODO: Fix tests here
class WhenTestingProjectHSMPartitionRepository(database_utils.RepositoryTestCase):
    def setUp(self):
        super(WhenTestingProjectHSMPartitionRepository, self).setUp()
        self.repo = repositories.ProjectHSMPartitionRepo()
        
        # Create test project
        self.project_repo = repositories.ProjectRepo()
        self.project = models.Project()
        self.project.external_id = 'test_keystone_id'
        self.project_repo.create_from(self.project)

        # Create test HSM partition config
        self.partition_repo = repositories.HSMPartitionConfigRepo()
        self.partition = models.HSMPartitionConfig()
        self.partition.slot_id = '1'
        self.partition.token_label = 'test_token'
        self.partition.partition_label = 'test_partition'
        self.partition.credentials = '{"pin": "123456"}'
        self.partition_repo.create_from(self.partition)

    def test_should_create_retrieve_mapping(self):
        session = self.repo.get_session()

        # Create mapping
        mapping = models.ProjectHSMPartition(
            project_id=self.project.id,
            partition_id=self.partition.id
        )
        self.repo.create_from(mapping, session=session)
        
        # Verify creation
        self.assertIsNotNone(mapping.id)
        self.assertEqual(models.States.ACTIVE, mapping.status)

        # Test retrieval
        retrieved = self.repo.get_by_project_id(self.project.id)
        self.assertEqual(mapping.id, retrieved.id)
        self.assertEqual(self.partition.id, retrieved.partition_id)

    def test_should_create_or_update_mapping(self):
        # Create initial mapping
        mapping = self.repo.create_or_update_for_project(
            self.project.id,
            self.partition.id
        )
        self.assertEqual(self.partition.id, mapping.partition_id)

        # Create another partition
        partition2 = models.HSMPartitionConfig()
        partition2.slot_id = '2'
        partition2.token_label = 'test_token2'
        partition2.partition_label = 'test_partition2'
        partition2.credentials = '{"pin": "654321"}'
        self.partition_repo.create_from(partition2)

        # Update mapping to point to new partition
        updated = self.repo.create_or_update_for_project(
            self.project.id,
            partition2.id
        )
        self.assertEqual(partition2.id, updated.partition_id)
        self.assertEqual(mapping.id, updated.id)  # Same mapping, different partition

    def test_should_raise_not_found(self):
        self.assertRaises(
            exception.NotFound,
            self.repo.get_by_project_id,
            "non-existent-project-id",
            suppress_exception=False
        )

    def test_should_suppress_not_found(self):
        retrieved = self.repo.get_by_project_id(
            "non-existent-project-id",
            suppress_exception=True
        )
        self.assertIsNone(retrieved)
