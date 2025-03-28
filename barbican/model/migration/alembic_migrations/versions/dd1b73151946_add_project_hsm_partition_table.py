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

"""add_project_hsm_partition_table

Revision ID: dd1b73151946
Revises: 8bd858f1594c
Create Date: 2025-02-20 15:34:18.876176

"""

# revision identifiers, used by Alembic.
revision = 'dd1b73151946'
down_revision = '8bd858f1594c'

from alembic import op
import sqlalchemy as sa

def upgrade():
    # Create project_hsm_partitions table for project-partition mappings
    op.create_table(
        'project_hsm_partitions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('deleted', sa.Boolean, nullable=False, default=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('project_id', sa.String(36), nullable=False),
        sa.Column('partition_id', sa.String(36), nullable=False),

        # Ensure one partition per project
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name="project_id_fk"),
        sa.ForeignKeyConstraint(['partition_id'], ['hsm_partition_configs.id'], name="hsm_partition_config_id_fk"),
        sa.UniqueConstraint('project_id', name='_project_hsm_partition_uc'),
        mysql_engine='InnoDB'
    )

# def downgrade():
#     op.drop_table('project_hsm_partitions')
