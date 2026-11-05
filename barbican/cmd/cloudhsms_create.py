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

Steps performed:
  1. Validate required arguments
  2. Check TCP connectivity to the HSM device
  3. Validate MKEK key exists on HSM
  4. Validate HMAC key exists on HSM
  5. Resolve (or create) the Barbican project record
  6. Skip if HSM partition config already exists for the project
  7. Create the HSM partition config row
  8. Look up the target secret store by ID
  9. Set the project preferred secret store
 10. Commit and report
"""

import os
import socket
import tempfile
import uuid

from oslo_utils import timeutils

from barbican.common import resources
from barbican.common import utils
from barbican.model import models
from barbican.model import repositories

CONF = repositories.CONF
LOG = utils.getLogger(__name__)

_DEFAULT_PKCS11_LIBRARY_PATH = "/opt/hsm/lib/pkcs11.so"


def _setup_database():
    LOG.debug("Initializing database connection")
    repositories.setup_database_engine_and_factory()
    repositories.start()


# ---------------------------------------------------------------------------
# Step 2: TCP connectivity
# ---------------------------------------------------------------------------

def _check_connectivity(device_ip, container_id, timeout=5):
    port = 4000 + int(container_id)
    try:
        socket.create_connection((device_ip, port), timeout=timeout).close()
    except (socket.timeout, OSError) as exc:
        raise RuntimeError(
            f"Cannot reach HSM device at {device_ip}:{port}: {exc}"
        )
    LOG.info("Connectivity OK: %s:%d", device_ip, port)


# ---------------------------------------------------------------------------
# Steps 3–4: PKCS11 key existence
# ---------------------------------------------------------------------------

def _build_hsm_cfg(device_ip, container_id):
    port = 4000 + int(container_id)
    tmp_dir = tempfile.gettempdir()
    content = (
        "[Global]\n"
        f"Logpath = {tmp_dir}\n"
        "Logging = 4\n"
        "SlotMultiSession = true\n"
        "SlotCount = 10\n"
        "\n"
        "[HSMCluster]\n"
        f"Devices = {port}@{device_ip}\n"
    )
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".cfg", delete=False, prefix="hsm_"
    )
    f.write(content)
    f.close()
    return f.name


def _validate_hsm_keys(device_ip, container_id, token_serial_number,
                       password, mkek_label, hmac_label,
                       library_path=None):
    from barbican.plugin.crypto import pkcs11

    lib = library_path or _DEFAULT_PKCS11_LIBRARY_PATH
    cfg_path = _build_hsm_cfg(device_ip, container_id)
    try:
        os.environ["CS_PKCS11_R3_CFG"] = cfg_path
        p11 = pkcs11.PKCS11(
            library_path=lib,
            login_passphrase=password,
            token_serial_number=token_serial_number,
            token_labels=None,
            encryption_mechanism="CKM_AES_CBC",
            hmac_mechanism="CKM_SHA256_HMAC",
            key_wrap_mechanism="CKM_AES_CBC_PAD",
        )
        session = p11.get_session()
        try:
            for label, kind in [(mkek_label, "MKEK"), (hmac_label, "HMAC")]:
                handle = p11.get_key_handle("CKK_AES", label, session)
                if handle is None:
                    raise RuntimeError(
                        f"{kind} key '{label}' not found on HSM"
                    )
                LOG.info("%s key '%s' found on HSM (handle=%s)",
                         kind, label, handle)
        finally:
            p11.return_session(session)
    finally:
        os.unlink(cfg_path)


# ---------------------------------------------------------------------------
# Steps 8–9: secret store lookup and preferred store assignment
# ---------------------------------------------------------------------------

def _get_secret_store_by_id(store_id):
    secret_stores_repo = repositories.get_secret_stores_repository()
    try:
        return secret_stores_repo.get(store_id)
    except Exception:
        stores = secret_stores_repo.get_all()
        available = ", ".join(f"{s.name}={s.id}" for s in stores) or "(none)"
        raise RuntimeError(
            f"Secret store '{store_id}' not found. Available: {available}"
        )


def _set_project_preferred_store(project_id, secret_store_id):
    pss_repo = repositories.get_project_secret_store_repository()
    pss_repo.create_or_update_for_project(project_id, secret_store_id)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def create_hsm_partition(args):
    if hasattr(args, "debug") and args.debug:
        LOG.logger.setLevel("DEBUG")

    _setup_database()

    # Step 1: Validate required arguments
    required = [
        "external_project_id",
        "device_ip",
        "container_id",
        "token_serial_number",
        "password",
        "mkek_label",
        "hmac_label",
    ]
    missing = [
        name for name in required
        if not getattr(args, name, None) and getattr(args, name, None) != 0
    ]
    if missing:
        raise ValueError(f"Missing required arguments: {', '.join(missing)}")

    # Step 2: TCP connectivity check
    LOG.info("[ Step 2 ] Checking connectivity to %s (container_id=%d)...",
             args.device_ip, args.container_id)
    _check_connectivity(args.device_ip, args.container_id)

    # Steps 3–4: Key existence on HSM
    LOG.info("[ Steps 3-4 ] Validating MKEK '%s' and HMAC '%s' on HSM...",
             args.mkek_label, args.hmac_label)
    _validate_hsm_keys(
        args.device_ip,
        args.container_id,
        args.token_serial_number,
        args.password,
        args.mkek_label,
        args.hmac_label,
        library_path=getattr(args, "library_path", None),
    )

    # Step 5: Resolve project
    LOG.info("[ Step 5 ] Resolving project %s...", args.external_project_id)
    project = resources.get_or_create_project(args.external_project_id)
    LOG.debug("Barbican project id: %s", project.id)

    # Step 6: Check if partition config already exists
    hsm_partition_config_repo = (
        repositories.get_hsm_partition_config_repository()
    )
    existing_config = hsm_partition_config_repo.get_by_project_id(
        project.id, suppress_exception=True
    )

    if existing_config:
        LOG.info(
            "[ Step 6-7 ] HSM partition config already exists (%s), skipping",
            existing_config.id,
        )
        partition_config = existing_config
    else:
        # Step 7: Create partition config
        LOG.info("[ Step 7 ] Creating HSM partition config...")
        obj = models.HSMPartitionConfig()
        obj.id = getattr(args, "partition_id", None) or str(uuid.uuid4())
        obj.created_at = timeutils.utcnow()
        obj.updated_at = timeutils.utcnow()
        obj.project_id = project.id
        obj.partition_label = getattr(args, "partition_label", None) or ""
        obj.token_label = getattr(args, "token_label", None) or ""
        obj.slot_id = (
            args.slot_id if getattr(args, "slot_id", None) is not None else 0
        )
        obj.credentials = {"password": args.password}
        obj.status = models.States.ACTIVE
        obj.deleted = False

        metadata = {}
        for field in ("device_ip", "token_serial_number", "container_id",
                      "mkek_label", "hmac_label"):
            val = getattr(args, field, None)
            if val is not None:
                metadata[field] = val
        if metadata:
            obj.partition_metadata = metadata

        try:
            partition_config = hsm_partition_config_repo.create_from(obj)
            repositories.commit()
        except Exception:
            repositories.rollback()
            raise

        LOG.info("Created HSM partition config %s", partition_config.id)

    # Step 8: Look up target secret store
    store_id = getattr(args, "secret_store_id", None)
    if not store_id:
        raise ValueError("Missing required argument: secret_store_id")
    LOG.info("[ Step 8 ] Looking up secret store '%s'...", store_id)
    store = _get_secret_store_by_id(store_id)
    LOG.debug("Found secret store: %s (%s)", store.name, store.id)

    # Step 9: Set project preferred secret store
    LOG.info("[ Step 9 ] Setting preferred secret store for project %s...",
             args.external_project_id)
    try:
        _set_project_preferred_store(project.id, store.id)
        repositories.commit()
    except Exception:
        repositories.rollback()
        raise

    # Step 10: Report
    LOG.info("[ Step 10 ] Done.")
    LOG.info("  Project:        %s  (internal: %s)",
             args.external_project_id, project.id)
    LOG.info("  Partition cfg:  %s", partition_config.id)
    LOG.info("  Secret store:   %s  (%s)", store.name, store.id)

    return partition_config
