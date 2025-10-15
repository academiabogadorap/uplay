import logging
from logging.config import fileConfig

from flask import current_app
from alembic import context
from sqlalchemy import text

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')


def get_engine():
    try:
        # this works with Flask-SQLAlchemy<3 and Alchemical
        return current_app.extensions['migrate'].db.get_engine()
    except (TypeError, AttributeError):
        # this works with Flask-SQLAlchemy>=3
        return current_app.extensions['migrate'].db.engine


def get_engine_url():
    try:
        return get_engine().url.render_as_string(hide_password=False).replace('%', '%%')
    except AttributeError:
        return str(get_engine().url).replace('%', '%%')


# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
config.set_main_option('sqlalchemy.url', get_engine_url())
target_db = current_app.extensions['migrate'].db


def get_metadata():
    if hasattr(target_db, 'metadatas'):
        return target_db.metadatas[None]
    return target_db.metadata


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
            rows = res.fetchall()
            if rows:
                for (tname,) in rows:
                    connection.exec_driver_sql(f"DROP TABLE IF EXISTS {tname}")
                    logger.info("[env.py] DROP %s", tname)
    except Exception as e:
        logger.warning("[env.py] Limpieza _alembic_tmp_ falló: %s", e)


def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")

    # En offline no tenemos conexión, así que no podemos limpiar tablas aquí.
    # La limpieza se hace en online (al tener connection).
    context.configure(
        url=url,
        target_metadata=get_metadata(),
        literal_binds=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode."""
    # this callback is used to prevent an auto-migration from being generated
    # when there are no changes to the schema
    # reference: http://alembic.zzzcomputing.com/en/latest/cookbook.html
    def process_revision_directives(context_, revision, directives):
        if getattr(config.cmd_opts, 'autogenerate', False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info('No changes in schema detected.')

    conf_args = current_app.extensions['migrate'].configure_args
    if conf_args.get("process_revision_directives") is None:
        conf_args["process_revision_directives"] = process_revision_directives

    connectable = get_engine()

    with connectable.connect() as connection:
        # Limpieza preventiva antes de configurar el contexto
        _cleanup_sqlite_tmp_tables(connection)

        # Si es SQLite, forzamos batch mode
        if connection.dialect.name == "sqlite":
            # respetamos flags existentes y solo imponemos render_as_batch=True
            conf_args = {**conf_args, "render_as_batch": True}

        context.configure(
            connection=connection,
            target_metadata=get_metadata(),
            **conf_args
        )

        # Limpieza adicional justo antes de correr migraciones (por si algo creó tmp nuevamente)
        _cleanup_sqlite_tmp_tables(connection)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
