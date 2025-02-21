"""Added Assignment model

Revision ID: 114537357f5b
Revises: 372e6f8fd521
Create Date: 2025-02-21 15:56:52.485775

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '114537357f5b'
down_revision = '372e6f8fd521'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('assignment',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('classroom_id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('due_date', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['classroom_id'], ['classroom.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('assignment')
    # ### end Alembic commands ###
