"""Add is_secret

Revision ID: 093034fc60a1
Revises: b295b033364d
Create Date: 2019-08-23 02:24:57.771560

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '093034fc60a1'
down_revision = 'b295b033364d'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'challenges',
        sa.Column('is_secret', sa.Boolean(), nullable=False, default=True),
    )
    pass


def downgrade():
    op.drop_column('challenges', 'is_secret')
