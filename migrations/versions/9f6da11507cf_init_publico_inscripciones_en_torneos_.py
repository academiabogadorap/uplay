"""init: publico/inscripciones en torneos + pareja_key/estado/timestamps en inscripciones

Revision ID: 9f6da11507cf
Revises: 
Create Date: 2025-10-13 09:59:47.672026

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9f6da11507cf'
down_revision = None
branch_labels = None
depends_on = None


def _sqlite_columns(table_name: str):
    """Devuelve set con nombres de columnas existentes en SQLite."""
    bind = op.get_bind()
    rows = bind.exec_driver_sql(f"PRAGMA table_info('{table_name}')").fetchall()
    return {r[1] for r in rows}  # (cid, name, type, notnull, dflt_value, pk)


def _safe_create_index(idx_name: str, table: str, cols: list[str], unique: bool = False):
    """Crea índice en SQLite solo si no existe; en otros motores usa Alembic."""
    bind = op.get_bind()
    if bind.dialect.name == 'sqlite':
        unique_sql = "UNIQUE" if unique else ""
        cols_sql = ", ".join([f'"{c}"' for c in cols])
        op.execute(f'CREATE {unique_sql} INDEX IF NOT EXISTS "{idx_name}" ON "{table}" ({cols_sql})')
    else:
        op.create_index(idx_name, table, cols, unique=unique)


def upgrade():
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == 'sqlite'

    # --- Limpieza defensiva por si quedaron tablas temporales de intentos previos
    if is_sqlite:
        op.execute('DROP TABLE IF EXISTS "_alembic_tmp_desafios"')
        op.execute('DROP TABLE IF EXISTS "_alembic_tmp_torneos"')
        op.execute('DROP TABLE IF EXISTS "_alembic_tmp_torneos_inscripciones"')
        op.execute('DROP TABLE IF EXISTS "_alembic_tmp_partidos"')
        op.execute('DROP TABLE IF EXISTS "_alembic_tmp_jugadores"')
        op.execute('DROP TABLE IF EXISTS "_alembic_tmp_partido_resultado_propuesto"')
        op.execute('DROP TABLE IF EXISTS "_alembic_tmp_partido_abierto_jugadores"')

    # ---------------------------
    # DESAFIOS
    # ---------------------------
    # En SQLite salteamos cambios de tipo para evitar recreaciones.
    if not is_sqlite:
        with op.batch_alter_table('desafios', schema=None) as batch_op:
            batch_op.alter_column(
                'rival1_acepto',
                existing_type=sa.INTEGER(),
                type_=sa.Boolean(),
                existing_nullable=False,
                existing_server_default=sa.text('0'),
            )
            batch_op.alter_column(
                'rival2_acepto',
                existing_type=sa.INTEGER(),
                type_=sa.Boolean(),
                existing_nullable=False,
                existing_server_default=sa.text('0'),
            )

    # ---------------------------
    # JUGADORES
    # ---------------------------
    with op.batch_alter_table('jugadores', schema=None) as batch_op:
        if not is_sqlite:
            batch_op.alter_column(
                'activo',
                existing_type=sa.INTEGER(),
                type_=sa.Boolean(),
                existing_nullable=False,
                existing_server_default=sa.text('1'),
            )
            batch_op.alter_column(
                'is_admin',
                existing_type=sa.INTEGER(),
                type_=sa.Boolean(),
                existing_nullable=False,
                existing_server_default=sa.text('0'),
            )
            batch_op.alter_column(
                'pin',
                existing_type=sa.TEXT(),
                type_=sa.String(length=10),
                existing_nullable=False,
                existing_server_default=sa.text("'0000'"),
            )
        # El índice puede o no existir; intentamos y si falla, seguimos.
        try:
            batch_op.drop_index(batch_op.f('ux_jugadores_email'), sqlite_where=sa.text('email IS NOT NULL'))
        except Exception:
            pass

    # ---------------------------
    # PARTIDO_ABIERTO_JUGADORES
    # ---------------------------
    if not is_sqlite:
        with op.batch_alter_table('partido_abierto_jugadores', schema=None) as batch_op:
            batch_op.create_foreign_key(
                'fk_paj_partner_pref_id_jugadores',
                'jugadores',
                ['partner_pref_id'],
                ['id'],
            )

    # ---------------------------
    # PARTIDO_RESULTADO_PROPUESTO
    # ---------------------------
    with op.batch_alter_table('partido_resultado_propuesto', schema=None) as batch_op:
        try:
            batch_op.drop_index(batch_op.f('ix_prp_creado_en'))
        except Exception:
            pass

    # ---------------------------
    # PARTIDOS
    # ---------------------------
    if not is_sqlite:
        with op.batch_alter_table('partidos', schema=None) as batch_op:
            batch_op.alter_column('rival1_acepto', existing_type=sa.INTEGER(), type_=sa.Boolean(), existing_nullable=True)
            batch_op.alter_column('rival2_acepto', existing_type=sa.INTEGER(), type_=sa.Boolean(), existing_nullable=True)
            batch_op.alter_column('resultado_propuesto_sets_text', existing_type=sa.TEXT(), type_=sa.String(length=100), existing_nullable=True)
            for idx in (
                batch_op.f('ix_partidos_creador'),
                batch_op.f('ix_partidos_estado'),
                batch_op.f('ix_partidos_resultado_propuesto_en'),
                batch_op.f('ix_partidos_rival1'),
                batch_op.f('ix_partidos_rival2'),
            ):
                try:
                    batch_op.drop_index(idx)
                except Exception:
                    pass

        with op.batch_alter_table('partidos', schema=None) as batch_op:
            batch_op.create_foreign_key('fk_partidos_companero_id_jugadores', 'jugadores', ['companero_id'], ['id'])
            batch_op.create_foreign_key('fk_partidos_rival2_id_jugadores', 'jugadores', ['rival2_id'], ['id'])
            batch_op.create_foreign_key('fk_partidos_rechazo_ultimo_por_id_jugadores', 'jugadores', ['rechazo_ultimo_por_id'], ['id'])
            batch_op.create_foreign_key('fk_partidos_creador_id_jugadores', 'jugadores', ['creador_id'], ['id'])
            batch_op.create_foreign_key('fk_partidos_resultado_propuesto_por_id_jugadores', 'jugadores', ['resultado_propuesto_por_id'], ['id'])
            batch_op.create_foreign_key('fk_partidos_rival1_id_jugadores', 'jugadores', ['rival1_id'], ['id'])

    # ---------------------------
    # TORNEOS
    # ---------------------------
    if is_sqlite:
        cols = _sqlite_columns('torneos')
        if 'es_publico' not in cols:
            op.execute("ALTER TABLE torneos ADD COLUMN es_publico BOOLEAN NOT NULL DEFAULT 1")
        if 'inscripciones_abiertas' not in cols:
            op.execute("ALTER TABLE torneos ADD COLUMN inscripciones_abiertas BOOLEAN NOT NULL DEFAULT 1")

        # índices (idempotentes)
        _safe_create_index(op.f('ix_torneos_es_publico'), 'torneos', ['es_publico'], unique=False)
        _safe_create_index(op.f('ix_torneos_inscripciones_abiertas'), 'torneos', ['inscripciones_abiertas'], unique=False)
        _safe_create_index('ix_torneos_publicos_cat', 'torneos', ['es_publico', 'categoria_id'], unique=False)
        # En SQLite no cambiamos tipos de columnas legacy.
    else:
        with op.batch_alter_table('torneos', schema=None) as batch_op:
            batch_op.add_column(sa.Column('es_publico', sa.Boolean(), nullable=False, server_default=sa.text('1')))
            batch_op.add_column(sa.Column('inscripciones_abiertas', sa.Boolean(), nullable=False, server_default=sa.text('1')))
            batch_op.alter_column('formato', existing_type=sa.VARCHAR(length=20), type_=sa.String(length=10), existing_nullable=False)
            batch_op.alter_column('tipo', existing_type=sa.VARCHAR(length=20), nullable=False, existing_server_default=sa.text("'AMERICANO'"))
            batch_op.alter_column('inscripcion_libre', existing_type=sa.BOOLEAN(), nullable=False, existing_server_default=sa.text('1'))
            batch_op.alter_column('permite_playoff_desde', existing_type=sa.VARCHAR(length=20), nullable=False, existing_server_default=sa.text("'ZONAS'"))
            batch_op.alter_column('reglas_json', existing_type=sa.TEXT(), type_=sa.JSON(), existing_nullable=True)
            batch_op.alter_column('updated_at', existing_type=sa.DATETIME(), nullable=False)
            batch_op.create_index(batch_op.f('ix_torneos_es_publico'), ['es_publico'], unique=False)
            batch_op.create_index(batch_op.f('ix_torneos_inscripciones_abiertas'), ['inscripciones_abiertas'], unique=False)
            batch_op.create_index('ix_torneos_publicos_cat', ['es_publico', 'categoria_id'], unique=False)
            batch_op.alter_column('es_publico', server_default=None)
            batch_op.alter_column('inscripciones_abiertas', server_default=None)

    # ---------------------------
    # TORNEOS_INSCRIPCIONES
    # ---------------------------
    if is_sqlite:
        cols = _sqlite_columns('torneos_inscripciones')

        if 'estado' not in cols:
            op.execute("ALTER TABLE torneos_inscripciones ADD COLUMN estado VARCHAR(15) NOT NULL DEFAULT 'ACTIVA'")
        if 'baja_motivo' not in cols:
            op.execute("ALTER TABLE torneos_inscripciones ADD COLUMN baja_motivo VARCHAR(120)")
        if 'created_at' not in cols:
            op.execute("ALTER TABLE torneos_inscripciones ADD COLUMN created_at DATETIME")
            op.execute("UPDATE torneos_inscripciones SET created_at = COALESCE(created_at, datetime('now'))")
        if 'updated_at' not in cols:
            op.execute("ALTER TABLE torneos_inscripciones ADD COLUMN updated_at DATETIME")
            op.execute("UPDATE torneos_inscripciones SET updated_at = COALESCE(updated_at, datetime('now'))")
        if 'pareja_key' not in cols:
            op.execute("ALTER TABLE torneos_inscripciones ADD COLUMN pareja_key VARCHAR(50)")

        # índices y unique (idempotentes)
        _safe_create_index('ix_insc_j1', 'torneos_inscripciones', ['jugador1_id'])
        _safe_create_index('ix_insc_j2', 'torneos_inscripciones', ['jugador2_id'])
        _safe_create_index('ix_insc_torneo', 'torneos_inscripciones', ['torneo_id'])
        _safe_create_index(op.f('ix_torneos_inscripciones_pareja_key'), 'torneos_inscripciones', ['pareja_key'])
        # unique compuesto
        try:
            op.create_unique_constraint('uq_torneo_pareja_key', 'torneos_inscripciones', ['torneo_id', 'pareja_key'])
        except Exception:
            pass
    else:
        with op.batch_alter_table('torneos_inscripciones', schema=None) as batch_op:
            batch_op.add_column(sa.Column('estado', sa.String(length=15), nullable=False, server_default='ACTIVA'))
            batch_op.add_column(sa.Column('baja_motivo', sa.String(length=120), nullable=True))
            batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')))
            batch_op.add_column(sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')))
            batch_op.add_column(sa.Column('pareja_key', sa.String(length=50), nullable=True))
            batch_op.create_index('ix_insc_j1', ['jugador1_id'], unique=False)
            batch_op.create_index('ix_insc_j2', ['jugador2_id'], unique=False)
            batch_op.create_index('ix_insc_torneo', ['torneo_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_torneos_inscripciones_pareja_key'), ['pareja_key'], unique=False)
            batch_op.create_unique_constraint('uq_torneo_pareja_key', ['torneo_id', 'pareja_key'])
            batch_op.alter_column('estado', server_default=None)
            batch_op.alter_column('created_at', server_default=None)
            batch_op.alter_column('updated_at', server_default=None)


def downgrade():
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == 'sqlite'

    # TORNEOS_INSCRIPCIONES
    if is_sqlite:
        # Borramos índices/constraints si existen (idempotente)
        try:
            op.drop_constraint('uq_torneo_pareja_key', 'torneos_inscripciones', type_='unique')
        except Exception:
            pass
        for idx in (
            op.f('ix_torneos_inscripciones_pareja_key'),
            'ix_insc_torneo',
            'ix_insc_j2',
            'ix_insc_j1',
        ):
            try:
                op.drop_index(idx, table_name='torneos_inscripciones')
            except Exception:
                pass
        # No drop column en SQLite (requeriría recrear tabla)
    else:
        with op.batch_alter_table('torneos_inscripciones', schema=None) as batch_op:
            batch_op.drop_constraint('uq_torneo_pareja_key', type_='unique')
            batch_op.drop_index(batch_op.f('ix_torneos_inscripciones_pareja_key'))
            batch_op.drop_index('ix_insc_torneo')
            batch_op.drop_index('ix_insc_j2')
            batch_op.drop_index('ix_insc_j1')
            batch_op.drop_column('pareja_key')
            batch_op.drop_column('updated_at')
            batch_op.drop_column('created_at')
            batch_op.drop_column('baja_motivo')
            batch_op.drop_column('estado')

    # TORNEOS
    if is_sqlite:
        for idx in (
            'ix_torneos_publicos_cat',
            op.f('ix_torneos_inscripciones_abiertas'),
            op.f('ix_torneos_es_publico'),
        ):
            try:
                op.drop_index(idx, table_name='torneos')
            except Exception:
                pass
        # No drop columns en SQLite
    else:
        with op.batch_alter_table('torneos', schema=None) as batch_op:
            batch_op.drop_index('ix_torneos_publicos_cat')
            batch_op.drop_index(batch_op.f('ix_torneos_inscripciones_abiertas'))
            batch_op.drop_index(batch_op.f('ix_torneos_es_publico'))
            batch_op.alter_column('updated_at', existing_type=sa.DATETIME(), nullable=True)
            batch_op.alter_column('reglas_json', existing_type=sa.JSON(), type_=sa.TEXT(), existing_nullable=True)
            batch_op.alter_column('permite_playoff_desde', existing_type=sa.VARCHAR(length=20), nullable=True, existing_server_default=sa.text("'ZONAS'"))
            batch_op.alter_column('inscripcion_libre', existing_type=sa.BOOLEAN(), nullable=True, existing_server_default=sa.text('1'))
            batch_op.alter_column('tipo', existing_type=sa.VARCHAR(length=20), nullable=True, existing_server_default=sa.text("'AMERICANO'"))
            batch_op.alter_column('formato', existing_type=sa.String(length=10), type_=sa.VARCHAR(length=20), existing_nullable=False)
            batch_op.drop_column('inscripciones_abiertas')
            batch_op.drop_column('es_publico')

    # PARTIDOS (downgrade solo fuera de SQLite)
    if not is_sqlite:
        with op.batch_alter_table('partidos', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_partidos_rival2'), ['rival2_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_partidos_rival1'), ['rival1_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_partidos_resultado_propuesto_en'), ['resultado_propuesto_en'], unique=False)
            batch_op.create_index(batch_op.f('ix_partidos_estado'), ['estado'], unique=False)
            batch_op.create_index(batch_op.f('ix_partidos_creador'), ['creador_id'], unique=False)
            batch_op.alter_column('resultado_propuesto_sets_text', existing_type=sa.String(length=100), type_=sa.TEXT(), existing_nullable=True)
            batch_op.alter_column('rival2_acepto', existing_type=sa.Boolean(), type_=sa.INTEGER(), existing_nullable=True)
            batch_op.alter_column('rival1_acepto', existing_type=sa.Boolean(), type_=sa.INTEGER(), existing_nullable=True)

    # PARTIDO_ABIERTO_JUGADORES
    if not is_sqlite:
        with op.batch_alter_table('partido_abierto_jugadores', schema=None) as batch_op:
            batch_op.drop_constraint('fk_paj_partner_pref_id_jugadores', type_='foreignkey')

    # PARTIDO_RESULTADO_PROPUESTO
    with op.batch_alter_table('partido_resultado_propuesto', schema=None) as batch_op:
        try:
            batch_op.create_index(batch_op.f('ix_prp_creado_en'), ['creado_en'], unique=False)
        except Exception:
            pass

    # JUGADORES
    with op.batch_alter_table('jugadores', schema=None) as batch_op:
        try:
            batch_op.create_index(batch_op.f('ux_jugadores_email'), ['email'], unique=1, sqlite_where=sa.text('email IS NOT NULL'))
        except Exception:
            pass
        if not is_sqlite:
            batch_op.alter_column('pin', existing_type=sa.String(length=10), type_=sa.TEXT(), existing_nullable=False, existing_server_default=sa.text("'0000'"))
            batch_op.alter_column('is_admin', existing_type=sa.Boolean(), type_=sa.INTEGER(), existing_nullable=False, existing_server_default=sa.text('0'))
            batch_op.alter_column('activo', existing_type=sa.Boolean(), type_=sa.INTEGER(), existing_nullable=False, existing_server_default=sa.text('1'))
