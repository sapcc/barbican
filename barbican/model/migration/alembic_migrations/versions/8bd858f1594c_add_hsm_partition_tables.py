# Copyright 2025 OpenStack Foundation
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
#
"""add_hsm_partition_tables
Revision ID: 8bd858f1594c
Revises: 8c74e2d7f1ff
Create Date: 2025-01-28 15:29:47.405153
"""
# revision identifiers, used by Alembic.
revision = '8bd858f1594c'
down_revision = '8c74e2d7f1ff'

from alembic import op
import sqlalchemy as sa
from sqlalchemy import types as sql_types

class JsonBlob(sql_types.TypeDecorator):
    """JsonBlob is custom type for fields which need to store JSON text."""
    impl = sa.Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return value

def upgrade():
    # Create hsm_partition_configs table
    op.create_table(
        'hsm_partition_configs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('project_id', sa.String(36), nullable=False),
        sa.Column('slot_id', sa.String(255), nullable=False),
        sa.Column('token_label', sa.String(255), nullable=False),
        sa.Column('partition_label', sa.String(255), nullable=False),
        sa.Column('credentials', JsonBlob(), nullable=False),
        sa.Column('partition_metadata', JsonBlob(), nullable=True),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('deleted', sa.Boolean, nullable=False, default=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE', onupdate='CASCADE', name='fk_hsm_project_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
        mysql_collate='utf8_general_ci'
    )

    # Create hsm_partition_secrets table
    op.create_table(
        'hsm_partition_secrets',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('secret_id', sa.String(36), nullable=False),
        sa.Column('partition_id', sa.String(36), nullable=False),
        sa.Column('hsm_key_label', sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'], ondelete='CASCADE', onupdate='CASCADE', name='fk_hsm_secret_id'),
        sa.ForeignKeyConstraint(['partition_id'], ['hsm_partition_configs.id'], ondelete='CASCADE', onupdate='CASCADE', name='fk_hsm_partition_id'),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
        mysql_collate='utf8_general_ci'
    )

def downgrade():
    # Drop tables in reverse order
    op.drop_table('hsm_partition_secrets')
    op.drop_table('hsm_partition_configs')

