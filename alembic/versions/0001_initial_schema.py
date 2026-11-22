"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-11-17 09:37:35.823901
"""
from alembic import op
import sqlalchemy as sa


revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('tasks',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('owner', sa.String(length=64), nullable=False),
    sa.Column('filename', sa.String(length=255), nullable=True),
    sa.Column('sha256', sa.String(length=64), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('verdict', sa.String(length=16), nullable=True),
    sa.Column('malware_score', sa.Float(), nullable=True),
    sa.Column('model_version', sa.String(length=64), nullable=True),
    sa.Column('shap_data', sa.Text(), nullable=True),
    sa.Column('features', sa.Text(), nullable=True),
    sa.Column('apk_info', sa.Text(), nullable=True),
    sa.Column('report_status', sa.String(length=16), nullable=True),
    sa.Column('llm_report', sa.Text(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('cached_from', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('tasks', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_tasks_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_tasks_owner'), ['owner'], unique=False)
        batch_op.create_index(batch_op.f('ix_tasks_sha256'), ['sha256'], unique=False)



def downgrade():
    with op.batch_alter_table('tasks', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_tasks_sha256'))
        batch_op.drop_index(batch_op.f('ix_tasks_owner'))
        batch_op.drop_index(batch_op.f('ix_tasks_created_at'))

    op.drop_table('tasks')
