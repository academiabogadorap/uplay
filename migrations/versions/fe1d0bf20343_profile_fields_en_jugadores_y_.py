"""profile fields en jugadores y solicitudes_alta"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# Reemplazá por tus IDs reales si Alembic te los generó
revision = 'profile_fields_jugadores_solicitudes'
down_revision = '0c5cc4f22c58'  # <-- ÚLTIMA REVISION QUE TENÉS APLICADA
branch_labels = None
depends_on = None


def column_missing(bind, table_name, column_name):
    insp = inspect(bind)
    cols = [c['name'] for c in insp.get_columns(table_name) or []]
    return column_name not in cols


def upgrade():
    bind = op.get_bind()

    # --- jugadores ---
    if column_missing(bind, 'jugadores', 'pais'):
        op.add_column('jugadores', sa.Column('pais', sa.Text(), nullable=True))
    if column_missing(bind, 'jugadores', 'provincia'):
        op.add_column('jugadores', sa.Column('provincia', sa.Text(), nullable=True))
    if column_missing(bind, 'jugadores', 'ciudad'):
        op.add_column('jugadores', sa.Column('ciudad', sa.Text(), nullable=True))
    if column_missing(bind, 'jugadores', 'fecha_nacimiento'):
        op.add_column('jugadores', sa.Column('fecha_nacimiento', sa.Date(), nullable=True))

    # --- solicitudes_alta ---
    if column_missing(bind, 'solicitudes_alta', 'pais'):
        op.add_column('solicitudes_alta', sa.Column('pais', sa.Text(), nullable=True))
    if column_missing(bind, 'solicitudes_alta', 'provincia'):
        op.add_column('solicitudes_alta', sa.Column('provincia', sa.Text(), nullable=True))
    if column_missing(bind, 'solicitudes_alta', 'ciudad'):
        op.add_column('solicitudes_alta', sa.Column('ciudad', sa.Text(), nullable=True))
    if column_missing(bind, 'solicitudes_alta', 'fecha_nacimiento'):
        op.add_column('solicitudes_alta', sa.Column('fecha_nacimiento', sa.Date(), nullable=True))


def downgrade():
    bind = op.get_bind()

    # Para SQLite, hacemos drops condicionales y por batch para mayor compatibilidad
    insp = inspect(bind)
    def has_col(table, col):
        return any(c['name'] == col for c in insp.get_columns(table) or [])

    # --- jugadores ---
    with op.batch_alter_table('jugadores') as batch:
        if has_col('jugadores', 'fecha_nacimiento'):
            batch.drop_column('fecha_nacimiento')
        if has_col('jugadores', 'ciudad'):
            batch.drop_column('ciudad')
        if has_col('jugadores', 'provincia'):
            batch.drop_column('provincia')
        if has_col('jugadores', 'pais'):
            batch.drop_column('pais')

    # --- solicitudes_alta ---
    with op.batch_alter_table('solicitudes_alta') as batch:
        if has_col('solicitudes_alta', 'fecha_nacimiento'):
            batch.drop_column('fecha_nacimiento')
        if has_col('solicitudes_alta', 'ciudad'):
            batch.drop_column('ciudad')
        if has_col('solicitudes_alta', 'provincia'):
            batch.drop_column('provincia')
        if has_col('solicitudes_alta', 'pais'):
            batch.drop_column('pais')
