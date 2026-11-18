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

"""add project token configs

Revision ID: f03174aade89
Revises: 3afe6ad4bc3d
Create Date: 2026-11-17 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = "f03174aade89"
down_revision = "3afe6ad4bc3d"

from alembic import op
import sqlalchemy as sa

import barbican


def upgrade():
    op.create_table(
        "project_token_configs",
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("vendor_type", sa.String(length=32), nullable=False),
        sa.Column(
            "endpoints", barbican.model.models.JsonBlob(), nullable=False
        ),
        sa.Column("mkek_label", sa.String(length=255), nullable=False),
        sa.Column("hmac_label", sa.String(length=255), nullable=False),
        sa.Column(
            "token_serial_number", sa.String(length=64), nullable=True
        ),
        sa.Column("slot_id", sa.String(length=255), nullable=True),
        sa.Column("token_label", sa.String(length=255), nullable=True),
        sa.Column(
            "credentials", barbican.model.models.JsonBlob(), nullable=False
        ),
        sa.Column(
            "vendor_metadata",
            barbican.model.models.JsonBlob(),
            nullable=True,
        ),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.Column("deleted", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_project_token_configs_project_id"),
        "project_token_configs",
        ["project_id"],
        unique=False,
    )