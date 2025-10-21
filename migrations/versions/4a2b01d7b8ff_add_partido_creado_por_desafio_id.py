"""Add Partido.creado_por_desafio_id

Revision ID: 4a2b01d7b8ff
Revises: 9aa002123d8c
Create Date: 2025-10-19 18:05:42.750136
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = '4a2b01d7b8ff'
down_revision = '9aa002123d8c'
branch_labels = None
depends_on = None


# -------------------------------------------------------------------
# Helpers “a prueba de balas” (especialmente para SQLite)
# -------------------------------------------------------------------
def _is_sqlite():
    bind = op.get_bind()
    return bind.dialect.name == "sqlite"


def _sqlite_index_names(table_name: str):
    """
    Devuelve el set de nombres de índices de una tabla en SQLite.
    """
    bind = op.get_bind()
    rows = bind.execute(text(f"PRAGMA index_list('{table_name}')")).fetchall()
    names = set()
    for r in rows:
        # PRAGMA index_list cols varían según versión: (seq, name, unique, origin?, partial?)
        # tomamos la segunda columna o la key 'name'
        try:
            names.add(r[1])
        except Exception:
            try:
                names.add(r["name"])
            except Exception:
                pass
    return names


def _sqlite_has_index(table: str, index_name: str) -> bool:
    return index_name in _sqlite_index_names(table)


def _sqlite_drop_index_if_exists(index_name: str):
    op.execute(f"DROP INDEX IF EXISTS {index_name}")


def _sqlite_has_column(table: str, col: str) -> bool:
    bind = op.get_bind()
    rows = bind.execute(text(f"PRAGMA table_info('{table}')")).fetchall()
    cols = { (r[1] if len(r) > 1 else r["name"]) for r in rows }
    return col in cols


def _sqlite_create_index_if_not_exists(index_name: str, table: str, columns: list, unique: bool = False):
    cols_sql = ", ".join(columns)
    uq = "UNIQUE " if unique else ""
    op.execute(f"CREATE {uq}INDEX IF NOT EXISTS {index_name} ON {table} ({cols_sql})")


# -------------------------------------------------------------------
# Upgrade
# -------------------------------------------------------------------
def upgrade():
    # --- jugadores: drop index ux_jugadores_email si existe ---
    # En tu traza el nombre aparece literal como 'ux_jugadores_email'
    j_idx = "ux_jugadores_email"
    if _is_sqlite():
        if _sqlite_has_index("jugadores", j_idx):
            _sqlite_drop_index_if_exists(j_idx)
    else:
        # Para otros motores intentamos por batch y toleramos que no exista
        try:
            with op.batch_alter_table('jugadores', schema=None) as batch_op:
                batch_op.drop_index(j_idx)  # nombre explícito
        except Exception:
            pass

    # --- partido_resultado_propuesto: drop ix_prp_creado_en si existe ---
    prp_idx = "ix_prp_creado_en"
    if _is_sqlite():
        if _sqlite_has_index("partido_resultado_propuesto", prp_idx):
            _sqlite_drop_index_if_exists(prp_idx)
    else:
        try:
            with op.batch_alter_table('partido_resultado_propuesto', schema=None) as batch_op:
                batch_op.drop_index(prp_idx)
        except Exception:
            pass

    # --- partidos: add column + drop múltiples índices si existen ---
    # Agregar columna creado_por_desafio_id sólo si no existe (SQLite no tiene DDL transaccional)
    if _is_sqlite():
        if not _sqlite_has_column("partidos", "creado_por_desafio_id"):
            with op.batch_alter_table('partidos', schema=None) as batch_op:
                batch_op.add_column(sa.Column('creado_por_desafio_id', sa.Integer(), nullable=True))
    else:
        with op.batch_alter_table('partidos', schema=None) as batch_op:
            batch_op.add_column(sa.Column('creado_por_desafio_id', sa.Integer(), nullable=True))

    # Índices potencialmente presentes (dependen de estados previos)
    partidos_drop_idxs = [
        "ix_partidos_creador",
        "ix_partidos_estado",
        "ix_partidos_resultado_propuesto_en",
        "ix_partidos_rival1",
        "ix_partidos_rival2",
    ]
    if _is_sqlite():
        for idx in partidos_drop_idxs:
            if _sqlite_has_index("partidos", idx):
                _sqlite_drop_index_if_exists(idx)
    else:
        try:
            with op.batch_alter_table('partidos', schema=None) as batch_op:
                for idx in partidos_drop_idxs:
                    try:
                        batch_op.drop_index(idx)
                    except Exception:
                        pass
        except Exception:
            pass

    # --- torneos_participantes: create ix_torneos_participantes_inscripcion_id si no existe ---
    tpart_idx = "ix_torneos_participantes_inscripcion_id"
    if _is_sqlite():
        _sqlite_create_index_if_not_exists(
            tpart_idx, "torneos_participantes", ["inscripcion_id"], unique=False
        )
    else:
        try:
            with op.batch_alter_table('torneos_participantes', schema=None) as batch_op:
                batch_op.create_index(tpart_idx, ['inscripcion_id'], unique=False)
        except Exception:
            pass

    # --- torneos_partidos: create índices/constraint si no existen ---
    tp_prog_idx = "ix_torneos_partidos_programado"
    tp_torneo_estado_idx = "ix_torneos_partidos_torneo_estado"
    uq_grupo_partido_ab = "uq_grupo_partido_ab"

    if _is_sqlite():
        _sqlite_create_index_if_not_exists(tp_prog_idx, "torneos_partidos", ["programado_en"], unique=False)
        _sqlite_create_index_if_not_exists(tp_torneo_estado_idx, "torneos_partidos", ["torneo_id", "estado"], unique=False)
        # UNIQUE constraint (en SQLite se materializa como índice unique):
        # Intentamos crearla y si existe, ignoramos el error.
        try:
            with op.batch_alter_table('torneos_partidos', schema=None) as batch_op:
                batch_op.create_unique_constraint(uq_grupo_partido_ab, ['grupo_id', 'participante_a_id', 'participante_b_id'])
        except Exception:
            pass
    else:
        try:
            with op.batch_alter_table('torneos_partidos', schema=None) as batch_op:
                batch_op.create_index(tp_prog_idx, ['programado_en'], unique=False)
                batch_op.create_index(tp_torneo_estado_idx, ['torneo_id', 'estado'], unique=False)
                batch_op.create_unique_constraint(uq_grupo_partido_ab, ['grupo_id', 'participante_a_id', 'participante_b_id'])
        except Exception:
            pass


# -------------------------------------------------------------------
# Downgrade (best-effort, también tolerante)
# -------------------------------------------------------------------
def downgrade():
    # --- torneos_partidos: drop constraint e índices ---
    uq_grupo_partido_ab = "uq_grupo_partido_ab"
    tp_torneo_estado_idx = "ix_torneos_partidos_torneo_estado"
    tp_prog_idx = "ix_torneos_partidos_programado"

    try:
        with op.batch_alter_table('torneos_partidos', schema=None) as batch_op:
            try:
                batch_op.drop_constraint(uq_grupo_partido_ab, type_='unique')
            except Exception:
                pass
            try:
                batch_op.drop_index(tp_torneo_estado_idx)
            except Exception:
                pass
            try:
                batch_op.drop_index(tp_prog_idx)
            except Exception:
                pass
    except Exception:
        # fallback SQLite
        if _is_sqlite():
            _sqlite_drop_index_if_exists(tp_torneo_estado_idx)
            _sqlite_drop_index_if_exists(tp_prog_idx)

    # --- torneos_participantes: drop index ---
    tpart_idx = "ix_torneos_participantes_inscripcion_id"
    try:
        with op.batch_alter_table('torneos_participantes', schema=None) as batch_op:
            try:
                batch_op.drop_index(tpart_idx)
            except Exception:
                pass
    except Exception:
        if _is_sqlite():
            _sqlite_drop_index_if_exists(tpart_idx)

    # --- partidos: revertir adiciones ---
    try:
        with op.batch_alter_table('partidos', schema=None) as batch_op:
            # recrear índices básicos (best-effort)
            for idx, cols in [
                ("ix_partidos_rival2", ["rival2_id"]),
                ("ix_partidos_rival1", ["rival1_id"]),
                ("ix_partidos_resultado_propuesto_en", ["resultado_propuesto_en"]),
                ("ix_partidos_estado", ["estado"]),
                ("ix_partidos_creador", ["creador_id"]),
            ]:
                try:
                    batch_op.create_index(idx, cols, unique=False)
                except Exception:
                    pass
            # drop columna (si existe)
            try:
                batch_op.drop_column('creado_por_desafio_id')
            except Exception:
                pass
    except Exception:
        # SQLite fallback para índices:
        if _is_sqlite():
            # recrear índices si los necesitas estrictamente (opcional)
            pass
        # drop columna en SQLite es más delicado; lo dejamos best-effort.

    # --- partido_resultado_propuesto: recrear ix_prp_creado_en ---
    try:
        with op.batch_alter_table('partido_resultado_propuesto', schema=None) as batch_op:
            try:
                batch_op.create_index('ix_prp_creado_en', ['creado_en'], unique=False)
            except Exception:
                pass
    except Exception:
        # SQLite fallback si fuera necesario
        pass

    # --- jugadores: recrear ux_jugadores_email (unique, con WHERE en SQLite) ---
    try:
        with op.batch_alter_table('jugadores', schema=None) as batch_op:
            try:
                # Nota: en SQLite, Alembic permite pasar sqlite_where
                batch_op.create_index(
                    'ux_jugadores_email',
                    ['email'],
                    unique=True,
                    sqlite_where=sa.text('email IS NOT NULL')
                )
            except Exception:
                pass
    except Exception:
        # SQLite fallback si hiciera falta:
        if _is_sqlite():
            # CREATE UNIQUE INDEX IF NOT EXISTS ux_jugadores_email ON jugadores(email)
            # WHERE email IS NOT NULL;  (SQLite soporta WHERE en índices desde hace tiempo)
            op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_jugadores_email ON jugadores (email) WHERE email IS NOT NULL")
