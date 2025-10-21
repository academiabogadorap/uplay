"""ensure partidos.creado_por_desafio_id exists

Revision ID: 0c5cc4f22c58
Revises: 4a2b01d7b8ff
Create Date: 2025-10-21 13:34:56.381938
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = '0c5cc4f22c58'
down_revision = '4a2b01d7b8ff'
branch_labels = None
depends_on = None


# ---------------------------
# Helpers tolerantes (SQLite)
# ---------------------------
def _is_sqlite():
    bind = op.get_bind()
    return bind.dialect.name == "sqlite"


def _sqlite_has_column(table: str, col: str) -> bool:
    bind = op.get_bind()
    rows = bind.execute(text(f"PRAGMA table_info('{table}')")).fetchall()
    # (cid, name, type, notnull, dflt_value, pk) → tomamos la segunda columna
    names = { (r[1] if len(r) > 1 else r["name"]) for r in rows }
    return col in names


def upgrade():
    """
    Garantiza que la columna partidos.creado_por_desafio_id exista.
    - En SQLite: usa ALTER TABLE ... ADD COLUMN si falta.
    - En otros motores: inspecciona y agrega con batch_alter_table si falta.
    """
    if _is_sqlite():
        if not _sqlite_has_column("partidos", "creado_por_desafio_id"):
            op.execute("ALTER TABLE partidos ADD COLUMN creado_por_desafio_id INTEGER")
    else:
        bind = op.get_bind()
        insp = sa.inspect(bind)
        cols = [c["name"] for c in insp.get_columns("partidos")]
        if "creado_por_desafio_id" not in cols:
            with op.batch_alter_table("partidos") as batch_op:
                batch_op.add_column(sa.Column("creado_por_desafio_id", sa.Integer(), nullable=True))


def downgrade():
    """
    Best-effort:
    - En SQLite NO dropeamos columna (costoso/limitado).
    - En otros motores intentamos dropearla si existe.
    """
    if not _is_sqlite():
        bind = op.get_bind()
        insp = sa.inspect(bind)
        cols = [c["name"] for c in insp.get_columns("partidos")]
        if "creado_por_desafio_id" in cols:
            with op.batch_alter_table("partidos") as batch_op:
                try:
                    batch_op.drop_column("creado_por_desafio_id")
                except Exception:
                    # si el motor/estado no lo permite, ignoramos
                    pass
