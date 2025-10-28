from flask import current_app
import logging
from logging.config import fileConfig

from alembic import context
from sqlalchemy import text

# --- Alembic config & logging ---
config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)
logger = logging.getLogger("alembic.env")


# --- Helpers para URL/engine de la app ---
def _get_db_ext():
    return current_app.extensions["migrate"].db

def get_engine():
    try:
        # Flask-SQLAlchemy < 3  (o Alchemical)
        return _get_db_ext().get_engine()
    except (TypeError, AttributeError):
        # Flask-SQLAlchemy >= 3
        return _get_db_ext().engine

def get_engine_url() -> str:
    eng = get_engine()
    try:
        # URL “limpia” para alembic (con % escapado)
        return eng.url.render_as_string(hide_password=False).replace("%", "%%")
    except AttributeError:
        return str(eng.url).replace("%", "%%")


# ¡Clave!: forzar que Alembic use la misma URL que tu app
try:
    config.set_main_option("sqlalchemy.url", get_engine_url())
except Exception as e:
    logger.warning("[env.py] No se pudo setear sqlalchemy.url desde app: %s", e)

target_db = _get_db_ext()

def get_metadata():
    # Compatible con multimetadata de Flask-Migrate
    if hasattr(target_db, "metadatas"):
        return target_db.metadatas.get(None, target_db.metadata)
    return target_db.metadata


# --- Limpieza de tablas temporales en SQLite ---
def _cleanup_sqlite_tmp_tables(connection):
    """
    Borra cualquier tabla temporal (prefijo _alembic_tmp_) que haya quedado
    de corridas interrumpidas. Solo aplica a SQLite.
    """
    try:
        if connection.dialect.name == "sqlite":
            res = connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '_alembic_tmp_%'"
            )
            for (tname,) in res.fetchall():
                connection.exec_driver_sql(f"DROP TABLE IF EXISTS {tname}")
                logger.info("[env.py] DROP %s", tname)
    except Exception as e:
        logger.warning("[env.py] Limpieza _alembic_tmp_ falló: %s", e)


# --- Offline ---
def run_migrations_offline():
    """Run migrations in 'offline' mode'."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=get_metadata(),
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# --- Online ---
def run_migrations_online():
    """Run migrations in 'online' mode'."""

    def process_revision_directives(ctx, revision, directives):
        # Evitar crear revisiones vacías
        if getattr(config.cmd_opts, "autogenerate", False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info("No changes in schema detected.")

    conf_args = dict(current_app.extensions["migrate"].configure_args or {})
    conf_args.setdefault("process_revision_directives", process_revision_directives)
    conf_args.setdefault("compare_type", True)
    conf_args.setdefault("compare_server_default", True)

    connectable = get_engine()

    with connectable.connect() as connection:
        # Limpieza preventiva
        _cleanup_sqlite_tmp_tables(connection)

        # Forzar batch en SQLite para ALTER TABLE seguros
        if connection.dialect.name == "sqlite":
            conf_args = {**conf_args, "render_as_batch": True}

        context.configure(
            connection=connection,
            target_metadata=get_metadata(),
            **conf_args,
        )

        # Limpieza adicional justo antes de migrar
        _cleanup_sqlite_tmp_tables(connection)

        with context.begin_transaction():
            context.run_migrations()


# --- Entry point ---
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
