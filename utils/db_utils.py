def emitir_codigo(email: str, minutos: int = MINUTOS_VIGENCIA_PIN) -> str:
    """
    Genera un PIN de 6 dígitos (string, conserva ceros a la izquierda),
    lo guarda/actualiza en la tabla codigos_login y devuelve el PIN.
    La expiración se setea en la DB con CURRENT_TIMESTAMP para evitar problemas de TZ.
    """
    email = (email or "").strip().lower()
    code = str(random.randint(0, 999999)).zfill(6)

    # Usamos la DB para calcular expira: datetime(CURRENT_TIMESTAMP, '+N minutes')
    delta = f"+{int(minutos)} minutes"

    db.session.execute(text("""
        INSERT INTO codigos_login(email, code, expira, usado)
        VALUES (:email, :code, datetime(CURRENT_TIMESTAMP, :delta), 0)
        ON CONFLICT(email) DO UPDATE SET
            code   = excluded.code,
            expira = datetime(CURRENT_TIMESTAMP, :delta),
            usado  = 0
    """), {"email": email, "code": code, "delta": delta})
    db.session.commit()
    return code




# ---- SQLite: auto-migración mínima para 'torneos' ----
def ensure_torneos_schema():
    """
    Agrega a la tabla 'torneos' las columnas que exige el modelo si faltan.
    Idempotente: corre en cada arranque sin romper nada.
    """
    from sqlalchemy import text
    with app.app_context():
        insp = db.inspect(db.engine)
        if 'torneos' not in insp.get_table_names():
            return  # aún no existe; create_all la creará

        cols = {c['name'] for c in insp.get_columns('torneos')}
        stmts = []

        if 'tipo' not in cols:
            stmts.append("ALTER TABLE torneos ADD COLUMN tipo VARCHAR(20) DEFAULT 'AMERICANO'")
        if 'inscripcion_libre' not in cols:
            stmts.append("ALTER TABLE torneos ADD COLUMN inscripcion_libre BOOLEAN DEFAULT 1")
        if 'cupo_max' not in cols:
            stmts.append("ALTER TABLE torneos ADD COLUMN cupo_max INTEGER")
        if 'permite_playoff_desde' not in cols:
            # default alineado con tu modelo ('ZONAS')
            stmts.append("ALTER TABLE torneos ADD COLUMN permite_playoff_desde VARCHAR(20) DEFAULT 'ZONAS'")
        if 'reglas_json' not in cols:
            # en SQLite lo guardamos como TEXT (JSON lo maneja SQLAlchemy)
            stmts.append("ALTER TABLE torneos ADD COLUMN reglas_json TEXT")
        if 'fecha_inicio' not in cols:
            stmts.append("ALTER TABLE torneos ADD COLUMN fecha_inicio DATE")
        if 'sede' not in cols:
            stmts.append("ALTER TABLE torneos ADD COLUMN sede VARCHAR(120)")
        if 'notas' not in cols:
            stmts.append("ALTER TABLE torneos ADD COLUMN notas TEXT")
        if 'updated_at' not in cols:
            stmts.append("ALTER TABLE torneos ADD COLUMN updated_at DATETIME")

        for sql in stmts:
            db.session.execute(text(sql))
        if stmts:
            db.session.commit()

def build_pareja_key(torneo: Torneo, j1_id: int, j2_id: int | None) -> str:
    """
    Clave única por torneo para evitar inscripciones duplicadas.
    S: singles -> S:<j1>
    D: dobles  -> D:<min>-<max> (ordenada)
    """
    if torneo.es_dobles():
        if not j2_id:
            raise ValueError("Este torneo es de dobles: faltó jugador2_id")
        a, b = sorted([int(j1_id), int(j2_id)])
        return f"D:{a}-{b}"
    else:
        return f"S:{int(j1_id)}"

def conteo_inscriptos(torneo_id: int) -> int:
    return db.session.query(func.count(TorneoInscripcion.id))\
        .filter(TorneoInscripcion.torneo_id == torneo_id)\
        .scalar() or 0

def send_mail(
