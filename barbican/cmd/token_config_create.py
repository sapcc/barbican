# Copyright (c) 2026 SAP SE
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
Command-line utility for registering a project token config in the
Barbican database. The CLI is vendor-neutral; per-vendor validation
lives in `barbican.plugin.crypto.vendor`.

Steps performed:
  1. Validate required arguments (common + vendor-specific)
  2. Parse and validate endpoints
  3. Resolve (or create) the Barbican project record
  4. Short-circuit if a project token config already exists
  5. Check TCP connectivity to every endpoint
  6. Validate MKEK + HMAC keys exist on the HSM
     (steps 5-6 are both skipped by --skip-hsm-checks)
  7. Create the project token config row
  8. Look up the target secret store by ID
  9. Set the project preferred secret store
 10. Commit and report
"""

import socket
import uuid

from oslo_utils import timeutils

from barbican.common import resources
from barbican.common import utils
from barbican.model import models
from barbican.model import repositories
from barbican.plugin.crypto import hsm_config_key
from barbican.plugin.crypto import vendor as vendor_pkg

CONF = repositories.CONF
LOG = utils.getLogger(__name__)

_DEFAULT_CONFIG_KEY_PATH = "/mnt/secrets/hsm-config-key"
_COMMON_REQUIRED_ARGS = (
    "vendor_type",
    "external_project_id",
    "password",
    "mkek_label",
    "hmac_label",
    "secret_store_id",
)


def _setup_database():
    LOG.debug("Initializing database connection")
    repositories.setup_database_engine_and_factory()
    repositories.start()


# ---------------------------------------------------------------------------
# Endpoint parsing
# ---------------------------------------------------------------------------

_ENDPOINT_KEYS = {"host", "port", "order"}


def _parse_endpoint(raw):
    """Parse one `host=H,port=P,order=O` argument into a dict.

    Raises ValueError on any malformed/unknown/missing key.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"Invalid --endpoint value: {raw!r}")

    parsed = {}
    for part in raw.split(","):
        if "=" not in part:
            raise ValueError(
                f"Invalid --endpoint segment {part!r}: expected key=value"
            )
        key, _, value = part.partition("=")
        key = key.strip()
        value = value.strip()
        if key not in _ENDPOINT_KEYS:
            raise ValueError(
                f"Unknown --endpoint key {key!r}; expected one of "
                f"{sorted(_ENDPOINT_KEYS)}"
            )
        if key in parsed:
            raise ValueError(f"Duplicate --endpoint key {key!r}")
        parsed[key] = value

    missing = _ENDPOINT_KEYS - parsed.keys()
    if missing:
        raise ValueError(
            f"--endpoint {raw!r} missing keys: {sorted(missing)}"
        )

    host = parsed["host"]
    if not host:
        raise ValueError(f"--endpoint {raw!r} has empty host")
    try:
        port = int(parsed["port"])
    except ValueError:
        raise ValueError(
            f"--endpoint {raw!r} port must be an integer"
        )
    try:
        order = int(parsed["order"])
    except ValueError:
        raise ValueError(
            f"--endpoint {raw!r} order must be an integer"
        )
    if order < 0:
        raise ValueError(
            f"--endpoint {raw!r} order must be non-negative"
        )
    return {"host": host, "port": port, "order": order}


def _build_endpoints(args):
    raw_list = getattr(args, "endpoint", None) or []
    if not raw_list:
        raise ValueError(
            "At least one --endpoint host=H,port=P,order=O is required"
        )
    endpoints = [_parse_endpoint(r) for r in raw_list]

    seen_orders = set()
    for ep in endpoints:
        if ep["order"] in seen_orders:
            raise ValueError(
                f"Duplicate endpoint order={ep['order']}; order values "
                "must be unique across all --endpoint arguments"
            )
        seen_orders.add(ep["order"])
    return endpoints


# ---------------------------------------------------------------------------
# Connectivity
# ---------------------------------------------------------------------------

def _check_connectivity(endpoints, timeout=5):
    unreachable = []
    for ep in endpoints:
        try:
            socket.create_connection(
                (ep["host"], ep["port"]), timeout=timeout
            ).close()
            LOG.info("Connectivity OK: %s:%d", ep["host"], ep["port"])
        except (socket.timeout, OSError) as exc:
            unreachable.append(f"{ep['host']}:{ep['port']} ({exc})")
    if unreachable:
        raise RuntimeError(
            "Cannot reach HSM endpoint(s): " + ", ".join(unreachable)
        )


# ---------------------------------------------------------------------------
# Secret-store wiring
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

def create_token_config(args):
    if getattr(args, "debug", False):
        LOG.logger.setLevel("DEBUG")

    _setup_database()

    # Step 1: validate required args (common + vendor-specific).
    LOG.info("[ Step 1 ] Validating arguments...")
    missing = [
        name for name in _COMMON_REQUIRED_ARGS
        if not getattr(args, name, None)
    ]
    if missing:
        raise ValueError(f"Missing required arguments: {', '.join(missing)}")

    try:
        validator = vendor_pkg.VALIDATORS[args.vendor_type]
    except KeyError:
        raise ValueError(
            f"Unknown --vendor-type {args.vendor_type!r}; expected one of "
            f"{sorted(vendor_pkg.VALIDATORS)}"
        )

    validator.validate_args(args)

    # Step 2: parse + validate endpoints
    LOG.info("[ Step 2 ] Parsing endpoints...")
    endpoints = _build_endpoints(args)

    # Step 3: Resolve project
    LOG.info("[ Step 3 ] Resolving project %s...", args.external_project_id)
    project = resources.get_or_create_project(args.external_project_id)
    LOG.debug("Barbican project id: %s", project.id)

    # Step 4: Short-circuit if a token config already exists for the project.
    project_token_config_repo = (
        repositories.get_project_token_config_repository()
    )
    existing_config = project_token_config_repo.get_by_project_id(
        project.id, suppress_exception=True
    )

    if existing_config:
        LOG.info(
            "[ Step 4 ] Project token config already exists (%s), "
            "skipping HSM checks and row creation",
            existing_config.id,
        )
        token_config = existing_config
    else:
        # Steps 5-6: TCP connectivity + MKEK/HMAC key existence on HSM.
        # Both require a reachable HSM, so --skip-hsm-checks gates them as
        # a pair for pre-provisioning configs before the HSM is live.
        if getattr(args, "skip_hsm_checks", False):
            LOG.warning(
                "[ Steps 5-6 ] Skipping HSM connectivity and key checks "
                "(--skip-hsm-checks)"
            )
        else:
            LOG.info(
                "[ Step 5 ] Checking connectivity to %d endpoint(s)...",
                len(endpoints),
            )
            _check_connectivity(endpoints)
            LOG.info(
                "[ Step 6 ] Validating MKEK '%s' and HMAC '%s' on HSM...",
                args.mkek_label, args.hmac_label,
            )
            validator.validate_keys(
                endpoints, args,
                library_path=getattr(args, "library_path", None),
            )

        # Load the HSM config key first and encrypt the PIN before any DB
        # write. If the key is missing or invalid this fails hard here, so
        # we never persist a partial row (and never fall back to plaintext).
        config_key_path = (
            getattr(args, "config_key_path", None) or _DEFAULT_CONFIG_KEY_PATH
        )
        config_key = hsm_config_key.load_config_key(config_key_path)

        LOG.info("[ Step 7 ] Creating project token config...")
        obj = models.ProjectTokenConfig()
        obj.id = (
            getattr(args, "token_config_id", None) or str(uuid.uuid4())
        )
        obj.created_at = timeutils.utcnow()
        obj.updated_at = timeutils.utcnow()
        obj.project_id = project.id
        obj.credentials = hsm_config_key.encrypt_pin(
            args.password, config_key
        )
        obj.status = models.States.ACTIVE
        obj.deleted = False

        obj.vendor_type = args.vendor_type
        obj.mkek_label = args.mkek_label
        obj.hmac_label = args.hmac_label
        obj.endpoints = endpoints

        # Set token_serial_number first so the cross-field validator on
        # slot_id / token_label has at least one identifier to see.
        obj.token_serial_number = getattr(args, "token_serial_number", None)
        obj.token_label = getattr(args, "token_label", None)
        slot = getattr(args, "slot_id", None)
        obj.slot_id = str(slot) if slot is not None else None

        metadata = validator.build_metadata(args, endpoints)
        if metadata:
            obj.vendor_metadata = metadata

        try:
            token_config = project_token_config_repo.create_from(obj)
            repositories.commit()
        except Exception:
            repositories.rollback()
            raise

        LOG.info("Created project token config %s", token_config.id)

    # Step 8: Look up target secret store
    store_id = args.secret_store_id
    LOG.info("[ Step 8 ] Looking up secret store '%s'...", store_id)
    store = _get_secret_store_by_id(store_id)
    LOG.debug("Found secret store: %s (%s)", store.name, store.id)

    # Step 9: Set project preferred secret store
    LOG.info(
        "[ Step 9 ] Setting preferred secret store for project %s...",
        args.external_project_id,
    )
    try:
        _set_project_preferred_store(project.id, store.id)
        repositories.commit()
    except Exception:
        repositories.rollback()
        raise

    # Step 10: Report
    LOG.info("[ Step 10 ] Done.")
    LOG.info(
        "  Project:        %s  (internal: %s)",
        args.external_project_id, project.id,
    )
    LOG.info("  Token config:   %s", token_config.id)
    LOG.info("  Secret store:   %s  (%s)", store.name, store.id)

    return token_config
