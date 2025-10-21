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
    """Create HSM partition configuration and map to project."""
    if hasattr(args, "debug") and args.debug:
        LOG.logger.setLevel("DEBUG")

    _setup_database()

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
        # If requested, still ensure preferred secret store mapping
        if getattr(args, "secret_store_id", None):
            _ensure_preferred_secret_store(project.id, args.secret_store_id)
        return existing_config

    # Step 3: Create new HSM partition config for the project
    hsm_partition_config_obj = models.HSMPartitionConfig()
    # Always set the id explicitly for HSMPartitionConfig
    hsm_partition_config_obj.id = args.partition_id or str(uuid.uuid4())
    hsm_partition_config_obj.created_at = timeutils.utcnow()
    hsm_partition_config_obj.updated_at = timeutils.utcnow()
    hsm_partition_config_obj.project_id = project.id
    hsm_partition_config_obj.partition_label = args.partition_label or ""
    hsm_partition_config_obj.token_label = args.token_label
    hsm_partition_config_obj.slot_id = (
        str(args.slot_id) if args.slot_id is not None else ""
    )
    creds = {}
    if hasattr(args, "password") and args.password:
        creds["password"] = args.password
    hsm_partition_config_obj.credentials = creds
    hsm_partition_config_obj.status = models.States.ACTIVE
    hsm_partition_config_obj.deleted = False

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
            "Created HSM partition config with id: %s",
            hsm_partition_config.id,
        )

        LOG.info("Successfully created HSM partition configuration:")
        LOG.info(
            "  Project ID: %s (External ID: %s)",
            project.id,
            project.external_id,
        )
        LOG.info(
            "  Partition ID: %s (Label: %s)",
            hsm_partition_config.id,
            args.partition_label,
        )

        # Step 4 (optional): Preferred secret store mapping
        # (API-equivalent of POST /secret-stores/{id}/preferred)
        if getattr(args, "secret_store_id", None):
            _ensure_preferred_secret_store(project.id, args.secret_store_id)

        return hsm_partition_config


# To implement later
# a project external_id uuid is generated even if the project does not exist

# def _get_project_by_external_id(external_id: str):
#     session = repositories.get_session()
#     return (
#         session.query(models.Project)
#         .filter(
#             models.Project.external_id == external_id,
#             models.Project.deleted == False,  # noqa: E712
#         )
#         .one_or_none()
#     )


def _ensure_preferred_secret_store(
    project_id: str,
    secret_store_id: str,
) -> None:
    """Create or update project_secret_store to mark the preferred store
    (ORM path).
    """
    LOG.info(
        "Ensuring preferred secret store for project %s -> %s",
        project_id,
        secret_store_id,
    )

    now = timeutils.utcnow()
    session = repositories.get_session()
    pss_repo = repositories.get_project_secret_store_repository()

    try:
        # Check if mapping already exists
        existing_pss = (
            session.query(models.ProjectSecretStore)
            .filter(
                models.ProjectSecretStore.project_id == project_id,
                models.ProjectSecretStore.deleted == False,
            )
            .one_or_none()
        )

        if existing_pss:
            LOG.debug("Updating existing project_secret_store mapping")
            existing_pss.secret_store_id = secret_store_id
            if hasattr(existing_pss, "status"):
                existing_pss.status = models.States.ACTIVE
            if hasattr(existing_pss, "updated_at"):
                existing_pss.updated_at = now
            pss_repo.save(existing_pss)
        else:
            LOG.debug("Creating new project_secret_store mapping")

            # Required fields only
            # (id must be None — repo assigns automatically)
            pss = models.ProjectSecretStore(
                project_id=project_id,
                secret_store_id=secret_store_id,
            )

            # Optional attributes (set after init)
            if hasattr(pss, "created_at"):
                pss.created_at = now
            if hasattr(pss, "updated_at"):
                pss.updated_at = now
            if hasattr(pss, "deleted"):
                pss.deleted = False
            if hasattr(pss, "deleted_at"):
                pss.deleted_at = None
            if hasattr(pss, "status"):
                pss.status = models.States.ACTIVE

            pss_repo.create_from(pss)

        repositories.commit()
        LOG.info("Preferred secret store set successfully.")
    except Exception as ex:
        LOG.exception(
            "Failed to upsert project_secret_store via repository: %s",
            ex,
        )
        repositories.rollback()
