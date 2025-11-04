import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SECRET_KEY = os.getenv("SECRET_KEY", "dev-key-cambiar")
DB_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'torneo.db')}")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
