from __future__ import annotations

# ============================================================
# 📦 IMPORTS ESTÁNDAR
# ============================================================
import os
import logging
from sqlalchemy import text
from flask import Flask, jsonify
from flask_migrate import Migrate

# ============================================================
# 🔌 EXTENSIONES CENTRALIZADAS
# ============================================================
from extensions import db, mail, csrf

# ============================================================
# ⚙️ CONFIGURACIONES Y CONSTANTES
# ============================================================
from utils.constants import AUTOCRON_ENABLED, BASE_DIR
from utils.email_utils import send_mail

# ============================================================
# 🚀 INICIALIZAR APLICACIÓN
# ============================================================
app = Flask(__name__)
from datetime import datetime

def localdt(value, fmt="%Y-%m-%d %H:%M"):
    if not value:
        return ""
    try:
        return value.strftime(fmt)
    except Exception:
        return str(value)

app.jinja_env.filters["localdt"] = localdt


# 🕓 Filtro Jinja para fechas locales

app.config.from_object("config.Config")

# Configuración de base de datos
DB_URL = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(BASE_DIR, "torneo_padel.db")}')
if DB_URL.startswith('postgres://'):
    DB_URL = DB_URL.replace('postgres://', 'postgresql://', 1)

# Inicializar extensiones
db.init_app(app)
mail.init_app(app)
csrf.init_app(app)
migrate = Migrate(app, db)

# ============================================================
# 🧾 LOGGING
# ============================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================
# 🧱 ALTERACIONES DE TABLAS (AUTOUPGRADE SUAVE)
# ============================================================
with app.app_context():
    try:
        insp = db.inspect(db.engine)
        if 'solicitudes_alta' in insp.get_table_names():
            cols_sa = [c['name'] for c in insp.get_columns('solicitudes_alta')]

            def add_col_if_missing_sa(col_name, col_type):
                if col_name not in cols_sa:
                    db.session.execute(
                        db.text(f"ALTER TABLE solicitudes_alta ADD COLUMN {col_name} {col_type}")
                    )
                    db.session.commit()
                    logger.info(f"✅ Columna agregada: {col_name} ({col_type})")
                    cols_sa.append(col_name)

            add_col_if_missing_sa('pais', 'TEXT')
            add_col_if_missing_sa('provincia', 'TEXT')
            add_col_if_missing_sa('ciudad', 'TEXT')
            add_col_if_missing_sa('fecha_nacimiento', 'TEXT')
            add_col_if_missing_sa('resuelto_en', 'TEXT')
        else:
            logger.warning("⚠️ Tabla 'solicitudes_alta' aún no existe. Saltando ALTER TABLE.")
    except Exception as e:
        logger.exception("[ALTER solicitudes_alta] Error aplicando columnas")

# ============================================================
# 🔗 IMPORTAR MODELOS Y BLUEPRINTS
# ============================================================
from models import *
from routes import (
    main_routes,
    admin_routes,
    torneo_routes,
    desafio_routes,
    jugador_routes,
    abiertos_routes,
)

from routes.partido_routes import partido_bp
# Registrar los blueprints (ajustados a los nombres nuevos)
app.register_blueprint(main_routes.main_bp)
app.register_blueprint(admin_routes.admin_bp)
app.register_blueprint(torneo_routes.torneo_bp)
app.register_blueprint(desafio_routes.desafio_bp)
app.register_blueprint(jugador_routes.jugador_bp)
app.register_blueprint(abiertos_routes.abiertos_bp)
app.register_blueprint(partido_bp)

# ============================================================
# 🌐 CONTEXTO GLOBAL PARA PLANTILLAS
# ============================================================
from utils.helpers import get_current_jugador

try:
    from flask_wtf.csrf import generate_csrf
except ImportError:
    # Fallback si Flask-WTF no está instalado
    def generate_csrf():
        return ""

@app.context_processor
def inject_globals():
    """Variables globales disponibles en todas las plantillas."""
    return dict(
        current_jugador=get_current_jugador(),
        csrf_token=generate_csrf,
    )

# ============================================================
# 🌱 SEED OPCIONAL DE ADMINISTRADOR
# ============================================================
with app.app_context():
    from models import Jugador
    if not Jugador.query.first():
        admin = Jugador(
            nombre_completo="ADMINISTRADOR",
            email="admin@uplay.com",
            pin="1111",
            es_admin=True,
            activo=True,
            puntos=999,
        )
        db.session.add(admin)
        db.session.commit()
        logger.info("✅ Administrador creado: ADMINISTRADOR / PIN 1111")

# ============================================================
# 🩺 RUTA DE SALUD / TEST
# ============================================================
@app.route("/healthz")
def healthz():
    return jsonify(status="ok", database=bool(db.engine))

# ============================================================
# 🚀 EJECUCIÓN PRINCIPAL
# ============================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)


# ============================================================
# 🕓 Filtro Jinja para fechas locales
# ============================================================
from datetime import datetime


