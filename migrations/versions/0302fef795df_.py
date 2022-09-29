"""empty message

Revision ID: 0302fef795df
Revises: ebcadb77387f
Create Date: 2022-09-25 12:30:48.905851

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0302fef795df'
down_revision = 'ebcadb77387f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('about_me', sa.String(length=140), nullable=True))
    op.add_column('users', sa.Column('last_seen', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'last_seen')
    op.drop_column('users', 'about_me')
    # ### end Alembic commands ###
