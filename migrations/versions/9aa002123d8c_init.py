"""init

Revision ID: 9aa002123d8c
Revises: 9f6da11507cf
Create Date: 2025-10-15 13:25:02.255306
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9aa002123d8c'
down_revision = '9f6da11507cf'
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _col_exists(table, col):
    insp = _inspector()
    return col in {c['name'] for c in insp.get_columns(table)}


def _idx_exists(table, name):
    insp = _inspector()
    return name in {i['name'] for i in insp.get_indexes(table)}


def _uq_exists(table, name):
    insp = _inspector()
    return name in {u['name'] for u in insp.get_unique_constraints(table)}


def upgrade():
    # DESAFIOS: casteo INTEGER -> BOOLEAN
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

    # JUGADORES
    with op.batch_alter_table('jugadores', schema=None) as batch_op:
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
        # dropear índice solo si existe (nombre generado con f())
        idx_name = 'ux_jugadores_email'
        if _idx_exists('jugadores', idx_name):
            batch_op.drop_index(idx_name, sqlite_where=sa.text('email IS NOT NULL'))

    # PARTIDO_ABIERTO_JUGADORES: FK para partner_pref_id
    with op.batch_alter_table('partido_abierto_jugadores', schema=None) as batch_op:
        # nombre explícito para evitar problemas en downgrade
        batch_op.create_foreign_key(
            'fk_paj_partner_pref',
            'jugadores',
            ['partner_pref_id'],
            ['id'],
        )

    # PRP: índice opcional
    with op.batch_alter_table('partido_resultado_propuesto', schema=None) as batch_op:
        idx_name = 'ix_prp_creado_en'
        if _idx_exists('partido_resultado_propuesto', idx_name):
            batch_op.drop_index(idx_name)

    # PARTIDOS
    with op.batch_alter_table('partidos', schema=None) as batch_op:
        batch_op.alter_column(
            'rival1_acepto',
            existing_type=sa.INTEGER(),
            type_=sa.Boolean(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            'rival2_acepto',
            existing_type=sa.INTEGER(),
            type_=sa.Boolean(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            'resultado_propuesto_sets_text',
            existing_type=sa.TEXT(),
            type_=sa.String(length=100),
            existing_nullable=True,
        )

        # dropear índices solo si existen
        for idx in [
            'ix_partidos_creador',
            'ix_partidos_estado',
            'ix_partidos_resultado_propuesto_en',
            'ix_partidos_rival1',
            'ix_partidos_rival2',
        ]:
            if _idx_exists('partidos', idx):
                batch_op.drop_index(idx)

        # FKs con nombres explícitos
        batch_op.create_foreign_key('fk_partidos_res_prop_por', 'jugadores', ['resultado_propuesto_por_id'], ['id'])
        batch_op.create_foreign_key('fk_partidos_rival1', 'jugadores', ['rival1_id'], ['id'])
        batch_op.create_foreign_key('fk_partidos_rival2', 'jugadores', ['rival2_id'], ['id'])
        batch_op.create_foreign_key('fk_partidos_creador', 'jugadores', ['creador_id'], ['id'])
        batch_op.create_foreign_key('fk_partidos_companero', 'jugadores', ['companero_id'], ['id'])
        batch_op.create_foreign_key('fk_partidos_rechazo_ultimo_por', 'jugadores', ['rechazo_ultimo_por_id'], ['id'])

    # TORNEOS
    with op.batch_alter_table('torneos', schema=None) as batch_op:
        batch_op.alter_column(
            'formato',
            existing_type=sa.VARCHAR(length=20),
            type_=sa.String(length=10),
            existing_nullable=False,
        )
        batch_op.alter_column(
            'tipo',
            existing_type=sa.VARCHAR(length=20),
            nullable=False,
            existing_server_default=sa.text("'AMERICANO'"),
        )
        batch_op.alter_column(
            'inscripcion_libre',
            existing_type=sa.BOOLEAN(),
            nullable=False,
            existing_server_default=sa.text('1'),
        )
        batch_op.alter_column(
            'permite_playoff_desde',
            existing_type=sa.VARCHAR(length=20),
            nullable=False,
            existing_server_default=sa.text("'ZONAS'"),
        )
        batch_op.alter_column(
            'reglas_json',
            existing_type=sa.TEXT(),
            type_=sa.JSON(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            'updated_at',
            existing_type=sa.DATETIME(),
            nullable=False,
        )

        # Solo dropear columnas si existen en esta base (Render no las tiene)
        if _col_exists('torneos', 'limite_jugadores'):
            batch_op.drop_column('limite_jugadores')
        if _col_exists('torneos', 'limite_parejas'):
            batch_op.drop_column('limite_parejas')

    # TORNEOS_INSCRIPCIONES
    with op.batch_alter_table('torneos_inscripciones', schema=None) as batch_op:
        batch_op.alter_column('created_at', existing_type=sa.DATETIME(), nullable=False)
        batch_op.alter_column('updated_at', existing_type=sa.DATETIME(), nullable=False)
        if not _uq_exists('torneos_inscripciones', 'uq_torneo_pareja_key'):
            batch_op.create_unique_constraint('uq_torneo_pareja_key', ['torneo_id', 'pareja_key'])


def downgrade():
    # TORNEOS_INSCRIPCIONES
    with op.batch_alter_table('torneos_inscripciones', schema=None) as batch_op:
        if _uq_exists('torneos_inscripciones', 'uq_torneo_pareja_key'):
            batch_op.drop_constraint('uq_torneo_pareja_key', type_='unique')
        batch_op.alter_column('updated_at', existing_type=sa.DATETIME(), nullable=True)
        batch_op.alter_column('created_at', existing_type=sa.DATETIME(), nullable=True)

    # TORNEOS
    with op.batch_alter_table('torneos', schema=None) as batch_op:
        # re-crear columnas sólo si no existen (idempotente)
        if not _col_exists('torneos', 'limite_parejas'):
            batch_op.add_column(sa.Column('limite_parejas', sa.INTEGER(), nullable=True))
        if not _col_exists('torneos', 'limite_jugadores'):
            batch_op.add_column(sa.Column('limite_jugadores', sa.INTEGER(), nullable=True))

        batch_op.alter_column('updated_at', existing_type=sa.DATETIME(), nullable=True)
        batch_op.alter_column('reglas_json', existing_type=sa.JSON(), type_=sa.TEXT(), existing_nullable=True)
        batch_op.alter_column('permite_playoff_desde', existing_type=sa.VARCHAR(length=20), nullable=True, existing_server_default=sa.text("'ZONAS'"))
        batch_op.alter_column('inscripcion_libre', existing_type=sa.BOOLEAN(), nullable=True, existing_server_default=sa.text('1'))
        batch_op.alter_column('tipo', existing_type=sa.VARCHAR(length=20), nullable=True, existing_server_default=sa.text("'AMERICANO'"))
        batch_op.alter_column('formato', existing_type=sa.String(length=10), type_=sa.VARCHAR(length=20), existing_nullable=False)

    # PARTIDOS
    with op.batch_alter_table('partidos', schema=None) as batch_op:
        for fk in [
            'fk_partidos_res_prop_por',
            'fk_partidos_rival1',
            'fk_partidos_rival2',
            'fk_partidos_creador',
            'fk_partidos_companero',
            'fk_partidos_rechazo_ultimo_por',
        ]:
            try:
                batch_op.drop_constraint(fk, type_='foreignkey')
            except Exception:
                pass

        # recrear índices
        for name, cols in [
            ('ix_partidos_rival2', ['rival2_id']),
            ('ix_partidos_rival1', ['rival1_id']),
            ('ix_partidos_resultado_propuesto_en', ['resultado_propuesto_en']),
            ('ix_partidos_estado', ['estado']),
            ('ix_partidos_creador', ['creador_id']),
        ]:
            if not _idx_exists('partidos', name):
                batch_op.create_index(name, cols, unique=False)

        batch_op.alter_column('resultado_propuesto_sets_text', existing_type=sa.String(length=100), type_=sa.TEXT(), existing_nullable=True)
        batch_op.alter_column('rival2_acepto', existing_type=sa.Boolean(), type_=sa.INTEGER(), existing_nullable=True)
        batch_op.alter_column('rival1_acepto', existing_type=sa.Boolean(), type_=sa.INTEGER(), existing_nullable=True)

    # PRP
    with op.batch_alter_table('partido_resultado_propuesto', schema=None) as batch_op:
        if not _idx_exists('partido_resultado_propuesto', 'ix_prp_creado_en'):
            batch_op.create_index('ix_prp_creado_en', ['creado_en'], unique=False)

    # PARTIDO_ABIERTO_JUGADORES
    with op.batch_alter_table('partido_abierto_jugadores', schema=None) as batch_op:
        try:
            batch_op.drop_constraint('fk_paj_partner_pref', type_='foreignkey')
        except Exception:
            pass

    # JUGADORES
    with op.batch_alter_table('jugadores', schema=None) as batch_op:
        if not _idx_exists('jugadores', 'ux_jugadores_email'):
            batch_op.create_index('ux_jugadores_email', ['email'], unique=1, sqlite_where=sa.text('email IS NOT NULL'))
        batch_op.alter_column('pin', existing_type=sa.String(length=10), type_=sa.TEXT(), existing_nullable=False, existing_server_default=sa.text("'0000'"))
        batch_op.alter_column('is_admin', existing_type=sa.Boolean(), type_=sa.INTEGER(), existing_nullable=False, existing_server_default=sa.text('0'))
        batch_op.alter_column('activo', existing_type=sa.Boolean(), type_=sa.INTEGER(), existing_nullable=False, existing_server_default=sa.text('1'))

    # DESAFIOS
    with op.batch_alter_table('desafios', schema=None) as batch_op:
        batch_op.alter_column('rival2_acepto', existing_type=sa.Boolean(), type_=sa.INTEGER(), existing_nullable=False, existing_server_default=sa.text('0'))
        batch_op.alter_column('rival1_acepto', existing_type=sa.Boolean(), type_=sa.INTEGER(), existing_nullable=False, existing_server_default=sa.text('0'))
