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


"""
Command-line utility for creating HSM partition configurations
and mapping them to projects in the Barbican database.
"""

import uuid

from oslo_utils import timeutils

from barbican.common import resources
from barbican.common import utils
from barbican.model import models
from barbican.model import repositories

# Initialize logging and configuration
CONF = repositories.CONF
LOG = utils.getLogger(__name__)


def _setup_database():
    """Initialize database connection."""
    LOG.debug("Initializing database connection")
    repositories.setup_database_engine_and_factory()
    repositories.start()


def create_hsm_partition(args):
    if hasattr(args, "debug") and args.debug:
        LOG.logger.setLevel("DEBUG")

    _setup_database()

    """Create HSM partition configuration and map to project."""

    # Step 1: Fetch or create project based on external_id
    project = resources.get_or_create_project(args.external_project_id)
    LOG.debug("Got project with id: %s", project.id)

    # Step 2: Check if HSM partition config already exists for the project
    hsm_partition_config_repo = (
        repositories.get_hsm_partition_config_repository()
    )
    existing_config = hsm_partition_config_repo.get_by_project_id(
        project.id, suppress_exception=True
    )

    if existing_config:
        LOG.info(
            "HSM partition config already exists for project %s",
            project.external_id,
        )
        return existing_config

    # Step 3: Create new HSM partition config for the project
    hsm_partition_config_obj = models.HSMPartitionConfig()
    # Always set the id explicitly for HSMPartitionConfig
    hsm_partition_config_obj.id = (
        getattr(args, "partition_id", None) or str(uuid.uuid4())
    )
    hsm_partition_config_obj.created_at = timeutils.utcnow()
    hsm_partition_config_obj.updated_at = timeutils.utcnow()
    hsm_partition_config_obj.project_id = project.id
    # partition_label / token_label / slot_id are needed by Thales only
    hsm_partition_config_obj.partition_label = (
        getattr(args, "partition_label", None) or ""
    )
    hsm_partition_config_obj.token_label = (
        getattr(args, "token_label", None) or ""
    )
    hsm_partition_config_obj.slot_id = (
        getattr(args, "slot_id", None) if getattr(args, "slot_id", None)
        is not None else 0
    )
    hsm_partition_config_obj.credentials = {"password": args.password}
    hsm_partition_config_obj.status = models.States.ACTIVE
    hsm_partition_config_obj.deleted = False

    metadata = {}
    if getattr(args, "device_ip", None):
        metadata["device_ip"] = args.device_ip
    if getattr(args, "token_serial_number", None):
        metadata["token_serial_number"] = args.token_serial_number
    if getattr(args, "container_id", None) is not None:
        metadata["container_id"] = args.container_id
    if getattr(args, "mkek_label", None):
        metadata["mkek_label"] = args.mkek_label
    if getattr(args, "hmac_label", None):
        metadata["hmac_label"] = args.hmac_label
    if metadata:
        hsm_partition_config_obj.partition_metadata = metadata

    try:
        hsm_partition_config = hsm_partition_config_repo.create_from(
            hsm_partition_config_obj
        )
        repositories.commit()
    except Exception:
        repositories.rollback()
        return None
    else:
        LOG.debug(
            "Created HSM partition config with id: %s", hsm_partition_config.id
        )

        LOG.info("Successfully created HSM partition configuration:")
        LOG.info(
            "  Project ID: %s (External ID: %s)",
            project.id,
            args.external_project_id,
        )
        LOG.info(
            "  Partition ID: %s (Label: %s)",
            hsm_partition_config.id,
            args.partition_label,
        )
        return hsm_partition_config
