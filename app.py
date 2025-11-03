from __future__ import annotations

# --- Stdlib ---
import os
import logging
import smtplib, ssl
import secrets
import string
import re, time
import unicodedata
import hmac
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo
from itertools import islice
from typing import Optional, List, Tuple

# --- Flask & Extensiones ---
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort, jsonify, current_app
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.routing import BuildError

# --- SQLAlchemy ---
import sqlalchemy as sa
from sqlalchemy import (
    and_, or_, exists, select, text, func,
    CheckConstraint, UniqueConstraint, Index, event
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (
    column_property, joinedload, load_only, synonym
)
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.orm.exc import NoResultFound



AUTOCRON_ENABLED = os.getenv('AUTOCRON_ENABLED', '0').lower() in ('1','true','yes','on')
_last_autocierre_run = {'ts': None}


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

AUTOCRON_TOKEN = globals().get("AUTOCRON_TOKEN", "changeme-autocron-token")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# --- Throttle/cooldown simple en memoria por proceso (opcional) ---
_OLVIDE_PIN_COOLDOWN = {}  # dict[email] = epoch_last_request
_COOLDOWN_SECONDS = 60  # p.ej., 60s por email


app = Flask(__name__)

csrf = CSRFProtect()
csrf.init_app(app)

# SECRET_KEY desde entorno; fallback para desarrollo local
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-cambiala-mas-tarde')

# DB: usa DATABASE_URL si existe (Postgres en el futuro), si no SQLite local
DB_URL = os.getenv('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'torneo.db'))
if DB_URL.startswith('postgres://'):
    DB_URL = DB_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ← NUEVO: conectar Flask-Migrate (una sola línea)
migrate = Migrate(app, db)

# --- Migraciones/ALTERs idempotentes (SQLite) para solicitudes_alta ---
with app.app_context():
    try:
        cols_sa = [r[1] for r in db.session.execute(db.text("PRAGMA table_info(solicitudes_alta)")).all()]

        def add_col_if_missing_sa(col_name, col_type):
            if col_name not in cols_sa:
                db.session.execute(db.text(f"ALTER TABLE solicitudes_alta ADD COLUMN {col_name} {col_type}"))
                db.session.commit()
                cols_sa.append(col_name)

        add_col_if_missing_sa('pais',             'TEXT')
        add_col_if_missing_sa('provincia',        'TEXT')
        add_col_if_missing_sa('ciudad',           'TEXT')
        add_col_if_missing_sa('fecha_nacimiento', 'TEXT')
        add_col_if_missing_sa('resuelto_en',      'TEXT')  # por si faltara en algún deploy

    except Exception:
        import logging
        logging.exception("[ALTER solicitudes_alta] Error aplicando columnas")

# --- bootstrap tabla codigos_login (idempotente) ---
from sqlalchemy import text

def _ensure_codigos_login_table():
    DDL = """
    CREATE TABLE IF NOT EXISTS codigos_login (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      email   TEXT NOT NULL UNIQUE,
      code    TEXT NOT NULL,
      expira  TIMESTAMP NOT NULL,
      usado   INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_codigos_login_expira ON codigos_login(expira);
    """
    for stmt in DDL.strip().split(";"):
        s = stmt.strip()
        if s:
            db.session.execute(text(s))
    db.session.commit()

with app.app_context():
    _ensure_codigos_login_table()

# --- Helper: emitir código de login (6 dígitos + expira) ---
import random

MINUTOS_VIGENCIA_PIN = 20  # podés ajustar

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
    subject: str,
    body: str | None,
    to: list[str] | str | None = None,          # list o str
    html_body: str | None = None,
    from_email: str | None = None,
    inline_logo_path: str | None = None,
    inline_logo_cid: str = "uplaylogo",
    inline_images: dict[str, str] | None = None,
    cc: list[str] | str | None = None,          # NUEVO
    bcc: list[str] | str | None = None,         # NUEVO
    reply_to: str | None = None,                # NUEVO
    **kwargs
) -> bool:
    """
    Envío SMTP con saneo de credenciales (strip/espacios) y logging de diagnóstico.
    Compatibilidad:
      - acepta to_addrs= o recipients= (alias de to)
      - ahora soporta CC/BCC/Reply-To (sin romper llamadas viejas)
    """
    import os, ssl, smtplib, logging, mimetypes, unicodedata
    from email.message import EmailMessage
    try:
        from flask import current_app
    except Exception:
        current_app = None

    # --- MODO DEBUG LOCAL (solo imprime) ---
    if os.getenv("RENDER") is None:  # si no estamos en Render
        print("\n==================== EMAIL DEBUG UPLAY ====================")
        print(f"🧾 Asunto: {subject}")
        print(f"📤 Para: {to}")
        if html_body:
            print("💬 HTML:\n", html_body)
        elif body:
            print("💬 Texto:\n", body)
        print("===========================================================\n")
        return True

    # Logger seguro
    try:
        logger = current_app.logger  # type: ignore[union-attr]
    except Exception:
        logger = logging.getLogger(__name__)

    # --- Normalización destinatarios principales y alias viejos ---
    recipients = to or kwargs.get("to_addrs") or kwargs.get("recipients") or []
    if isinstance(recipients, str):
        recipients = [recipients]
    to_clean = [str(t).strip() for t in recipients if t and str(t).strip()]

    # CC / BCC (opcionales)
    def _norm_list(val):
        if not val:
            return []
        if isinstance(val, str):
            return [val.strip()] if val.strip() else []
        return [str(x).strip() for x in val if x and str(x).strip()]

    cc_clean  = _norm_list(cc)
    bcc_clean = _norm_list(bcc)

    # --- Cargar y SANEAR env vars (evita 535 por espacios ocultos)
    host = (os.getenv("SMTP_HOST", "") or "").strip()
    port = int((os.getenv("SMTP_PORT", "587") or "587").strip())
    user = (os.getenv("SMTP_USER", "") or "").strip()
    pwd  = (os.getenv("SMTP_PASS", "") or "").strip()

    # eliminar espacios internos (p. ej. App Password con espacios)
    pwd = pwd.replace(" ", "")
    # normalizar unicode
    user = unicodedata.normalize("NFKC", user)
    pwd  = unicodedata.normalize("NFKC", pwd)

    use_tls = (os.getenv("SMTP_TLS", "1") or "1").strip() == "1"
    use_ssl = (os.getenv("SMTP_SSL", "0") or "0").strip() == "1"

    sender_env = (os.getenv("SMTP_FROM") or "").strip()
    sender = from_email or sender_env or (user or "")

    # Validaciones mínimas
    if not host or not port or not sender or not (to_clean or cc_clean or bcc_clean):
        logger.warning(
            "SMTP: faltan variables o destinatarios. host=%r port=%r sender=%r to=%r cc=%r bcc=%r",
            host, port, sender, to_clean, cc_clean, bcc_clean
        )
        return False

    # --- Mensaje
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    if to_clean:
        msg["To"] = ", ".join(to_clean)
    if cc_clean:
        msg["Cc"] = ", ".join(cc_clean)
    if reply_to:
        msg["Reply-To"] = reply_to

    texto_plano = (body or "").strip() or " "
    msg.set_content(texto_plano)

    html_part = None
    if html_body:
        msg.add_alternative(html_body, subtype="html")
        for part in msg.iter_parts():
            try:
                if part.get_content_type() == "text/html":
                    html_part = part
                    break
            except Exception:
                continue

    def _attach_inline(path: str, cid: str):
        nonlocal html_part
        if not (path and html_part):
            return
        try:
            mime_type, _ = mimetypes.guess_type(path)
            maintype, subtype = ("image", "png")
            if mime_type and "/" in mime_type:
                m_maintype, m_subtype = mime_type.split("/", 1)
                if m_maintype == "image" and m_subtype:
                    maintype, subtype = m_maintype, m_subtype
            with open(path, "rb") as f:
                img_bytes = f.read()
            html_part.add_related(img_bytes, maintype=maintype, subtype=subtype, cid=f"<{cid}>")
            logger.info("SMTP: imagen inline embebida cid=%s desde %s (%s/%s)", cid, path, maintype, subtype)
        except Exception as e:
            logger.warning("SMTP: no pude adjuntar inline (%s -> cid=%s): %s", path, cid, e)

    if inline_logo_path and html_part:
        _attach_inline(inline_logo_path, inline_logo_cid)
    if inline_images and html_part:
        for cid, path in inline_images.items():
            if cid and path:
                _attach_inline(path, cid)

    # --- DEBUG
    try:
        logger.info(
            "SMTP debug: host=%r port=%r TLS=%r SSL=%r user=%r from=%r pass_len=%d to=%s cc=%s bcc=%s",
            host, port, use_tls, use_ssl, user, sender, len(pwd or ""), to_clean, cc_clean, bcc_clean
        )
    except Exception:
        pass

    # --- Envío
    try:
        if use_ssl and use_tls:
            logger.warning("SMTP: TLS y SSL habilitados a la vez; desactivando TLS.")
            use_tls = False

        all_rcpts = [*to_clean, *cc_clean, *bcc_clean]

        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as server:
                if user:
                    server.login(user, pwd)
                resp = server.send_message(msg, from_addr=sender, to_addrs=all_rcpts)
        else:
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.ehlo()
                if use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()
                if user:
                    server.login(user, pwd)
                resp = server.send_message(msg, from_addr=sender, to_addrs=all_rcpts)

        if resp:
            logger.error("SMTP: fallos por destinatario: %s", resp)
            return False

        logger.info("SMTP: envío OK a to=%s cc=%s bcc=%s", to_clean, cc_clean, bcc_clean)
        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.exception("SMTP auth error: %s", e)
        return False
    except smtplib.SMTPConnectError as e:
        logger.exception("SMTP connect error: %s", e)
        return False
    except smtplib.SMTPException as e:
        logger.exception("SMTP error: %s", e)
        return False
    except Exception as e:
        logger.exception("SMTP error inesperado: %s", e)
        return False




def get_or_404(model, pk):
    """
    Reemplazo 2.x-friendly de Model.query.get_or_404().
    Usa la API moderna: db.session.get(Model, pk) y aborta con 404 si no existe.
    """
    obj = db.session.get(model, pk)
    if obj is None:
        abort(404)
    return obj

# ==== Helpers de autenticación / permisos (torneos) ====

def _require_login():
    """
    Requiere que exista un jugador logueado. Si no, 403.
    Devuelve el objeto Jugador actual.
    """
    j = get_current_jugador()
    if not j:
        abort(403)
    return j

def _lado_flag_dict(partido: "TorneoPartido", jugador_id: int) -> dict[str, bool]:
    """
    Devuelve un dict {'A': bool, 'B': bool} indicando si el jugador_id pertenece
    al lado A y/o B del partido. Usa primero la tabla de LADOS (insc1/insc2) y
    si no encuentra, cae al participante_a/participante_b (fallback).
    """
    flags = {'A': False, 'B': False}

    try:
        # 1) Preferimos la tabla de lados si está poblada
        lados = getattr(partido, "lados", None) or []
        if lados:
            Ins = globals().get('TorneoInscripcion')
            if Ins:
                for l in lados:
                    lado = (getattr(l, "lado", "") or "").upper()
                    if lado not in ("A", "B"):
                        continue
                    for insc_id in (getattr(l, "insc1_id", None), getattr(l, "insc2_id", None)):
                        if not insc_id:
                            continue
                        insc = db.session.get(Ins, insc_id)
                        if not insc:
                            continue
                        if jugador_id in [insc.jugador1_id, insc.jugador2_id]:
                            flags[lado] = True
        # 2) Fallback: si no hay lados, usamos los participantes A/B
        if not any(flags.values()):
            def players_from_part(tp):
                if not tp:
                    return []
                # intentamos derivar jugadores desde la inscripción del participante
                Ins = globals().get('TorneoInscripcion')
                insc = getattr(tp, "inscripcion", None)
                if not insc and Ins and getattr(tp, "inscripcion_id", None):
                    insc = db.session.get(Ins, tp.inscripcion_id)
                if insc:
                    return [x for x in (getattr(insc, "jugador1_id", None),
                                        getattr(insc, "jugador2_id", None)) if x]
                return []

            a_players = players_from_part(getattr(partido, "participante_a", None))
            b_players = players_from_part(getattr(partido, "participante_b", None))
            flags['A'] = jugador_id in a_players
            flags['B'] = jugador_id in b_players
    except Exception:
        # En caso de cualquier rareza, no romper
        pass

    return flags


def _require_participante(partido: "TorneoPartido", jugador_id: int | None = None) -> None:
    """
    Exige que el jugador actual participe en el partido. Si no, 403.
    Opcionalmente podés pasar jugador_id; si es None toma el actual.
    """
    j = get_current_jugador() if jugador_id is None else db.session.get(Jugador, int(jugador_id))
    if not j:
        abort(403)

    try:
        # Usamos el método robusto del modelo (ya contempla lados y participantes)
        if hasattr(partido, "jugador_participa") and partido.jugador_participa(int(j.id)):
            return
    except Exception:
        # Si algo falló arriba, hacemos un chequeo mínimo por lados
        flags = _lado_flag_dict(partido, int(j.id))
        if flags['A'] or flags['B']:
            return

    abort(403)


def db_first_or_404(query):
    """
    Equivalente 2.x-friendly de Model.query.first_or_404().
    Recibe una query ya construida (ORM/Query).
    """
    obj = query.first()
    if obj is None:
        abort(404)
    return obj


def _extraer_email_desde_request(req):
    """
    Devuelve el email desde JSON/FORM/ARGS aceptando las claves:
    'email', 'mail', 'correo'. Normaliza Unicode, remueve espacios
    invisibles/zero-width y devuelve en minúsculas.
    """
    def _first_str(*vals):
        # toma el primer string no vacío; si es lista/tupla, mira su primer str
        for v in vals:
            if v is None:
                continue
            if isinstance(v, (list, tuple)):
                for x in v:
                    if isinstance(x, str) and x.strip():
                        return x
            elif isinstance(v, str) and v.strip():
                return v
        return ""

    def _sanitize(s: str) -> str:
        # normaliza, quita ZWSP/ZWJ/ZWNJ/NBSP y recorta
        if not s:
            return ""
        s = unicodedata.normalize("NFKC", s)
        invisibles = {
            "\u200B",  # ZERO WIDTH SPACE
            "\u200C",  # ZERO WIDTH NON-JOINER
            "\u200D",  # ZERO WIDTH JOINER
            "\u2060",  # WORD JOINER
            "\u00A0",  # NO-BREAK SPACE
        }
        for ch in invisibles:
            s = s.replace(ch, " ")
        s = " ".join(s.split())  # colapsa múltiples espacios
        return s.strip().lower()

    keys = ("email", "mail", "correo")

    data = {}
    if req.is_json:
        # tolerante a JSON inválido
        data = (req.get_json(silent=True) or {}) if isinstance(req.get_json(silent=True) or {}, dict) else {}

    # orden de búsqueda: JSON → FORM → ARGS
    cand = _first_str(
        *[ (data.get(k) if isinstance(data, dict) else None) for k in keys ],
        *[ req.form.get(k) for k in keys ],
        *[ req.args.get(k) for k in keys ],
    )

    return _sanitize(cand)



def _inactivar_parejas_de(jugador_id: int):
    """Inactiva (o elimina si no existe flag) todas las parejas donde participa el jugador."""
    parejas = db.session.query(Pareja).filter(
        or_(Pareja.jugador1_id == jugador_id, Pareja.jugador2_id == jugador_id)
    ).all()
    for p in parejas:
        if hasattr(Pareja, 'activa'):
            p.activa = False
        else:
            db.session.delete(p)  # fallback si tu modelo Pareja no tiene 'activa'

def _normalize_spaces(s: str) -> str:
    """Colapsa espacios múltiples y recorta extremos."""
    return " ".join((s or "").split())

def normalize_name_upper(s: str) -> str:
    """
    Devuelve el nombre en MAYÚSCULAS, con espacios normalizados.
    Si querés remover acentos visualmente, descomentá el bloque NFD.
    """
    s = _normalize_spaces(s)
    # --- opcional: remover tildes/acentos visualmente ---
    # s = unicodedata.normalize("NFD", s)
    # s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")
    # s = unicodedata.normalize("NFC", s)
    return s.upper()

def normalize_phone_e164(cc: str, local: str) -> str:
    """
    Devuelve teléfono en formato E.164: +<código_pais><número_local_sin_separadores>
    Reglas útiles para Argentina (+54):
      - Si local empieza con '0', eliminarlo.
      - Si (tras quitar 0) empieza con '15', eliminar '15' (móviles).
      - (Opcional) forzar '9' en móviles -> comentado abajo.
    """
    cc_digits = _DIGITS_RE.sub("", f"{cc or ''}")
    local_digits = _DIGITS_RE.sub("", f"{local or ''}")

    if not cc_digits:
        raise ValueError("Código de país vacío")
    if not local_digits:
        raise ValueError("Número local vacío")

    if cc_digits == "54":
        if local_digits.startswith("0"):
            local_digits = local_digits[1:]
        if local_digits.startswith("15"):
            local_digits = local_digits[2:]
        # --- Opcional: forzar +549 para móviles ---
        # if not local_digits.startswith("9") and 9 <= len(local_digits) <= 11:
        #     local_digits = "9" + local_digits

    return f"+{cc_digits}{local_digits}"

# ===== Servicios: generación de fixtures (stubs MVP) =====

def _crear_participantes_desde_inscripciones(torneo: Torneo) -> list[TorneoParticipante]:
    # Crea participantes (1 por inscripción) si no existen
    existentes = {p.inscripcion_id for p in torneo.participantes}
    nuevos = []
    for ins in torneo.inscripciones:
        if ins.confirmado and ins.id not in existentes:
            p = TorneoParticipante(torneo_id=torneo.id, inscripcion_id=ins.id)
            db.session.add(p)
            nuevos.append(p)
    if nuevos:
        db.session.commit()
    return list(torneo.participantes)  # refrescado


def generar_fixture_americano(torneo_id: int, zonas: int | None = None, ida_y_vuelta: bool = False):
    """
    Genera fixture AMERICANO según formato del torneo:
      - DOBLES  -> parejas fijas (round-robin por grupos o general)
      - SINGLES -> parejas rotativas 2v2 (usa generar_fixture_americano_individual)
    """
    t = get_or_404(Torneo, torneo_id)

    # Solo aplica a tipo AMERICANO
    if not t.es_americano():
        raise ValueError("Este generador es solo para torneos de tipo AMERICANO.")

    # ---- AMERICANO INDIVIDUAL (SINGLES; parejas rotativas 2v2) ----
    if t.es_americano_individual():
        res = generar_fixture_americano_individual(t.id, ida_y_vuelta=ida_y_vuelta)
        if not res.get("ok"):
            raise ValueError(res.get("msg", "No se pudo generar el fixture SINGLES."))
        return int(res.get("partidos_creados", 0))

    # ---- AMERICANO EN PAREJAS (DOBLES; parejas fijas) ----
    # Tomamos SOLO inscripciones activas/confirmadas con jugador2_id (dobles).
    insc_q = (db.session.query(TorneoInscripcion)
              .filter(
                  TorneoInscripcion.torneo_id == t.id,
                  TorneoInscripcion.estado == 'ACTIVA',
                  (TorneoInscripcion.confirmado.is_(True) if hasattr(TorneoInscripcion, 'confirmado') else True),
                  TorneoInscripcion.jugador2_id.isnot(None)  # requisito: pareja fija
              ))

    # Orden estable (seed si existe, luego created_at/id)
    if hasattr(TorneoInscripcion, 'seed'):
        insc_q = insc_q.order_by(
            (db.nulls_last(TorneoInscripcion.seed.asc()) if hasattr(db, 'nulls_last') else TorneoInscripcion.seed.asc()),
            (TorneoInscripcion.created_at.asc() if hasattr(TorneoInscripcion, 'created_at') else TorneoInscripcion.id.asc()),
        )
    else:
        insc_q = insc_q.order_by(
            (TorneoInscripcion.created_at.asc() if hasattr(TorneoInscripcion, 'created_at') else TorneoInscripcion.id.asc()),
        )

    insc = insc_q.all()
    if not insc:
        raise ValueError("No hay inscripciones de DOBLES activas/confirmadas para generar el fixture.")

    # Asegurar TorneoParticipante 1–a–1 por cada inscripción (tu helper)
    participantes = []
    for i in insc:
        p = _inscripcion_to_participante(t, i)
        participantes.append(p)

    # Fase única (LIGA) y armado de grupos
    fase = _get_or_create_fase_unica(t)

    cant_zonas = int(zonas) if (zonas and zonas > 1) else 1
    participantes.sort(key=lambda x: (getattr(x, 'seed', None) is None, getattr(x, 'seed', 10**9), x.id))

    grupos = []
    if cant_zonas == 1:
        g = _get_or_create_grupo(t, fase, "GENERAL", 1)
        grupos.append((g, [p.id for p in participantes]))
    else:
        repartidas = _repartir_en_zonas(participantes, cant_zonas)
        for idx, zona_list in enumerate(repartidas, start=1):
            g = _get_or_create_grupo(t, fase, f"ZONA {idx}", idx)
            grupos.append((g, [p.id for p in zona_list]))

    # Crear partidos (round-robin), ida y vuelta opcional
    partidos_creados = 0
    for g, ids in grupos:
        if len(ids) < 2:
            continue

        rounds = _round_robin_pairs(ids)
        jornada = 1
        for pares in rounds:
            for (a, b) in pares:
                _crear_partido_rr(t, g, a, b, jornada)
                partidos_creados += 1
            jornada += 1

        if ida_y_vuelta:
            for pares in rounds:
                for (a, b) in pares:
                    _crear_partido_rr(t, g, b, a, jornada)
                    partidos_creados += 1
                jornada += 1

    db.session.commit()
    return partidos_creados

def generar_playoff_directo(torneo_id: int) -> int:
    t = get_or_404(Torneo, torneo_id)

    participantes = _listar_participantes_desde_inscripciones(t)
    n = len(participantes)
    if n < 2:
        raise ValueError("Se necesitan al menos 2 participantes para playoff.")

    fase = _get_or_create_fase_playoff(t)
    grupo = _get_or_create_grupo_llaves(t, fase)

    if _primer_round_ya_generado(t, grupo):
        return 0

    M = _next_power_of_two(n)
    byes = M - n

    partidos_creados = 0
    ronda_num = "1"  # string para ser consistente

    auto_winners_ids = set()
    for idx in range(byes):
        ganador = participantes[idx]
        m = TorneoPartido(
            torneo_id=t.id,
            grupo_id=grupo.id,
            participante_a_id=ganador.id,
            participante_b_id=ganador.id,  # o None si tu DB lo permite; si no, usa self-bye
            estado='JUGADO',
            ganador_participante_id=ganador.id,
            resultado_json={'walkover': 'BYE'},
            ronda=ronda_num
        )
        db.session.add(m)
        partidos_creados += 1
        auto_winners_ids.add(ganador.id)

    vivos = [p for p in participantes if p.id not in auto_winners_ids]
    i, j = 0, len(vivos) - 1
    while i < j:
        a = vivos[i]
        b = vivos[j]
        m = TorneoPartido(
            torneo_id=t.id,
            grupo_id=grupo.id,
            participante_a_id=a.id,
            participante_b_id=b.id,
            estado='PENDIENTE',
            ronda=ronda_num
        )
        db.session.add(m)
        partidos_creados += 1
        i += 1
        j -= 1

    db.session.commit()
    return partidos_creados


def _obtener_ganador_partido(p: 'TorneoPartido') -> int | None:
    """Devuelve el participante_id ganador si el partido está JUGADO; si no, None."""
    try:
        if getattr(p, 'estado', None) == 'JUGADO' and getattr(p, 'ganador_participante_id', None):
            return int(p.ganador_participante_id)
    except Exception:
        pass
    return None


def _max_ronda_de_playoff(torneo_id: int) -> int | None:
    """Devuelve el número de ronda de playoff más alta creada para el torneo, o None si no hay."""
    # Asumimos que en TorneoPartido guardás la ronda (p.ej. 1: cuartos, 2: semis, 3: final).
    # Si tu modelo guarda ronda en otro lado (TorneoLlaveNodo o similar), ajustá este query.
    max_r = (db.session.query(sa.func.max(TorneoPartido.ronda))
             .filter(TorneoPartido.torneo_id == torneo_id)
             .scalar())
    return int(max_r) if max_r is not None else None


def generar_playoff_siguiente_ronda(torneo_id: int) -> int:
    """
    Crea la siguiente ronda del playoff para el torneo dado.
    Empareja ganadores de la ronda previa en orden de ID de partido (estable).
    Retorna la cantidad de partidos creados en la nueva ronda.
    Reglas:
      - Si no hay ronda previa o no está completa, no crea nada.
      - Si la ronda previa tiene un único partido y ya tiene ganador, no crea nada (ya hay campeón).
    """
    t = db.session.get(Torneo, int(torneo_id))
    if not t:
        raise RuntimeError("Torneo inexistente.")

    # Última ronda existente
    ronda_actual = _max_ronda_de_playoff(t.id)
    if not ronda_actual:
        # No hay playoff previo generado (primera ronda se crea con generar_playoff_directo)
        raise RuntimeError("Aún no hay partidos de playoff generados para este torneo.")

    # Traer partidos de la ronda actual, orden estable
    partidos_actual = (db.session.query(TorneoPartido)
                       .filter(TorneoPartido.torneo_id == t.id,
                               TorneoPartido.ronda == ronda_actual)
                       .order_by(TorneoPartido.id.asc())
                       .all())

    if not partidos_actual:
        return 0  # nada que hacer

    # Si solo quedaba la final: si ya está jugada -> hay campeón; si no, no hay siguiente
    if len(partidos_actual) == 1:
        ganador = _obtener_ganador_partido(partidos_actual[0])
        # Si la final ya tiene ganador, no hay siguiente ronda; si no, se espera resultado.
        return 0

    # Reunir ganadores de la ronda actual
    ganadores_ids: list[int] = []
    for p in partidos_actual:
        g = _obtener_ganador_partido(p)
        if not g:
            # Algún partido sin definir -> no se puede crear ronda siguiente
            return 0
        ganadores_ids.append(g)

    # Emparejar ganadores de a pares (1 vs 2, 3 vs 4, etc.)
    if len(ganadores_ids) % 2 != 0:
        # Playoff bien formado debería dar número par
        raise RuntimeError("Cantidad de ganadores impar; el playoff previo no está bien definido.")

    nueva_ronda = ronda_actual + 1
    creados = 0

    # Si usás TorneoFase / TorneoLlaveNodo para modelar el árbol, podés crear/ubicar la fase de playoff aquí.
    # Este MVP crea los partidos directamente en TorneoPartido, como ya venís haciendo.
    for i in range(0, len(ganadores_ids), 2):
        a = ganadores_ids[i]
        b = ganadores_ids[i + 1]

        # Evitar duplicado paranoico: ¿ya existe un partido con esos participantes en esta ronda?
        dup = (db.session.query(TorneoPartido)
               .filter(TorneoPartido.torneo_id == t.id,
                       TorneoPartido.ronda == nueva_ronda,
                       sa.or_(
                           sa.and_(TorneoPartido.participante1_id == a,
                                   TorneoPartido.participante2_id == b),
                           sa.and_(TorneoPartido.participante1_id == b,
                                   TorneoPartido.participante2_id == a)
                       ))
               .first())
        if dup:
            continue

        m = TorneoPartido(
            torneo_id=t.id,
            ronda=nueva_ronda,
            participante1_id=a,
            participante2_id=b,
            estado='PENDIENTE'
        )
        # Sellar timestamps si tu modelo los tiene
        now = datetime.utcnow()
        if hasattr(m, "created_at") and getattr(m, "created_at") is None:
            m.created_at = now
        if hasattr(m, "updated_at") and getattr(m, "updated_at") is None:
            m.updated_at = now

        db.session.add(m)
        creados += 1

    if creados > 0 and t.estado != 'EN_JUEGO':
        # pequeño ajuste: si seguía en BORRADOR/INSCRIPCION pero ya hay playoff, lo marcamos en juego
        t.estado = 'EN_JUEGO'

    db.session.commit()
    return creados

def _round_robin_pairs(ids, ida_y_vuelta=False):
    """
    ids: lista de IDs de TorneoParticipante (enteros)
    Devuelve lista de dicts: {a_id, b_id, ronda, orden}
    Implementa método del círculo. Soporta BYE si es impar.
    """
    jugadores = list(ids)
    bye = None
    if len(jugadores) % 2 == 1:
        jugadores.append(bye)

    n = len(jugadores)
    if n < 2:
        return []

    mitad = n // 2
    rondas = n - 1
    arr = jugadores[:]
    resultado = []

    orden_global = 1
    for r in range(1, rondas + 1):
        izquierda = arr[:mitad]
        derecha = arr[mitad:][::-1]

        orden_en_ronda = 1
        for i in range(mitad):
            a = izquierda[i]
            b = derecha[i]
            if a is not None and b is not None:
                resultado.append({
                    "a_id": a,
                    "b_id": b,
                    "ronda": r,
                    "orden": orden_en_ronda
                })
                orden_en_ronda += 1
                orden_global += 1

        # rotación: fijamos arr[0]
        arr = [arr[0]] + [arr[-1]] + arr[1:-1]

    if ida_y_vuelta:
        # segunda rueda invirtiendo local/visita
        vuelta = []
        for item in resultado:
            vuelta.append({
                "a_id": item["b_id"],
                "b_id": item["a_id"],
                "ronda": item["ronda"] + rondas,
                "orden": item["orden"]
            })
        resultado.extend(vuelta)

    return resultado


def generar_fixture_americano_singles(torneo_id: int, ida_y_vuelta: bool = False) -> dict:
    torneo = Torneo.query.options(joinedload(Torneo.inscripciones)).get(torneo_id)
    if not torneo:
        return {"ok": False, "msg": "Torneo no encontrado."}

    if torneo.es_dobles():
        return {"ok": False, "msg": "El torneo está en formato DOBLES. Este generador es para SINGLES."}

    # Inscripciones válidas SINGLES: confirmadas + activas + sin jugador2
    inscs = (TorneoInscripcion.query
             .filter(
                 TorneoInscripcion.torneo_id == torneo.id,
                 TorneoInscripcion.confirmado.is_(True),
                 TorneoInscripcion.estado == 'ACTIVA',
                 or_(TorneoInscripcion.jugador2_id.is_(None), TorneoInscripcion.jugador2_id == 0)
             )
             .options(joinedload(TorneoInscripcion.jugador1))
             .all())

    if len(inscs) < 2:
        return {"ok": False, "msg": "Se necesitan al menos 2 inscripciones activas para generar el fixture."}

    # Forzar IDs y detectar inconsistentes
    db.session.flush()
    malas = [i for i in inscs if not getattr(i, 'id', None)]
    if malas:
        return {"ok": False, "msg": "Hay inscripciones sin ID. Revisá persistencia antes de generar."}

    # Asegurar/crear TorneoParticipante usando el helper seguro
    participantes_ids = []
    nuevos_participantes = 0
    for insc in inscs:
        antes = TorneoParticipante.query.filter_by(torneo_id=torneo.id, inscripcion_id=insc.id).one_or_none()
        tp = _inscripcion_to_participante(torneo, insc)  # <-- clave
        if not antes:
            nuevos_participantes += 1
        participantes_ids.append(tp.id)

    # Evitar duplicados (A-B o B-A) si se vuelve a correr
    ya = set()
    for p in TorneoPartido.query.filter_by(torneo_id=torneo.id).all():
        ya.add(frozenset({p.participante_a_id, p.participante_b_id}))

    # Round-robin plano (usa tu helper _round_robin_pairs)
    cruces = _round_robin_pairs(participantes_ids, ida_y_vuelta=ida_y_vuelta)
    creados = 0

    for c in cruces:
        par = frozenset({c["a_id"], c["b_id"]})
        if par in ya:
            continue
        db.session.add(TorneoPartido(
            torneo_id=torneo.id,
            fase_id=None,
            grupo_id=None,
            ronda=f"R{c['ronda']}",
            orden=c["orden"],
            participante_a_id=c["a_id"],
            participante_b_id=c["b_id"],
            estado='PENDIENTE'
        ))
        ya.add(par)
        creados += 1

    db.session.commit()
    return {
        "ok": True,
        "msg": f"Fixture generado: {creados} partidos. (SINGLES{' ida y vuelta' if ida_y_vuelta else ''})",
        "nuevos_participantes": nuevos_participantes,
        "partidos_creados": creados
    }

def _generar_fixture_americano_parejas(t: Torneo, zonas: int | None = None, ida_y_vuelta: bool = False) -> int:
    """
    AMERICANO PAREJAS (pareja fija):
      - Toma inscripciones ACTIVAS, CONFIRMADAS, con jugador2_id (dobles)
      - Crea/asegura TorneoParticipante (1–a–1 con la inscripción)
      - Genera round robin por grupo(s)
    """
    # 1) Inscripciones válidas de DOBLES
    insc_q = (db.session.query(TorneoInscripcion)
              .filter(
                  TorneoInscripcion.torneo_id == t.id,
                  TorneoInscripcion.estado == 'ACTIVA',
                  TorneoInscripcion.confirmado.is_(True),
                  TorneoInscripcion.jugador2_id.isnot(None)  # pareja fija
              ))

    # orden estable: por seed si existe, si no por created_at/id
    if hasattr(TorneoInscripcion, 'seed'):
        insc_q = insc_q.order_by(
            db.nulls_last(TorneoInscripcion.seed.asc())
            if hasattr(db, 'nulls_last') else TorneoInscripcion.seed.asc(),
            TorneoInscripcion.created_at.asc() if hasattr(TorneoInscripcion, 'created_at') else TorneoInscripcion.id.asc()
        )
    else:
        insc_q = insc_q.order_by(
            TorneoInscripcion.created_at.asc() if hasattr(TorneoInscripcion, 'created_at') else TorneoInscripcion.id.asc()
        )

    insc = insc_q.all()
    if len(insc) < 2:
        raise ValueError("Se necesitan al menos 2 parejas inscriptas (ACTIVAS y CONFIRMADAS) para generar el fixture DOBLES.")

    # 2) Asegurar TorneoParticipante por cada inscripción (1–a–1)
    participantes: list[TorneoParticipante] = []
    for i in insc:
        p = _inscripcion_to_participante(t, i)  # tu helper existente
        participantes.append(p)

    # 3) Fase única (LIGA) y grupos/zona(s)
    fase = _get_or_create_fase_unica(t)  # tu helper

    cant_zonas = int(zonas) if (zonas and zonas > 1) else 1

    # ordenar por seed (si la tenés como proxy desde la inscripción) y luego por id
    participantes.sort(
        key=lambda x: (
            getattr(x, 'seed', None) is None,
            getattr(x, 'seed', 10**9),
            x.id
        )
    )

    grupos: list[tuple[TorneoGrupo, list[int]]] = []
    if cant_zonas == 1:
        g = _get_or_create_grupo(t, fase, "GENERAL", 1)
        grupos.append((g, [p.id for p in participantes]))
    else:
        repartidas = _repartir_en_zonas(participantes, cant_zonas)  # tu helper
        for idx, zona_list in enumerate(repartidas, start=1):
            g = _get_or_create_grupo(t, fase, f"ZONA {idx}", idx)
            grupos.append((g, [p.id for p in zona_list]))

    # 4) Crear partidos: round robin por grupo (ida y vuelta opcional)
    partidos_creados = 0
    for g, ids in grupos:
        if len(ids) < 2:
            continue

        # _round_robin_pairs debe devolver lista de rondas; cada ronda = lista de pares (a,b)
        rounds = _round_robin_pairs(ids)

        jornada = 1
        for pares in rounds:
            for (a, b) in pares:
                _crear_partido_rr(t, g, a, b, jornada)  # tu helper pone estado/ronda/orden si lo configuraste
                partidos_creados += 1
            jornada += 1

        if ida_y_vuelta:
            for pares in rounds:
                for (a, b) in pares:
                    _crear_partido_rr(t, g, b, a, jornada)
                    partidos_creados += 1
                jornada += 1

    db.session.commit()
    return partidos_creados

def _rotaciones_americano_individual(insc_ids: list[int]) -> list[list[tuple[tuple[int,int], tuple[int,int]]]]:
    """
    Devuelve una lista de rondas.
    Cada ronda es una lista de partidos, y cada partido es ((A1,A2),(B1,B2)),
    donde A1/A2 y B1/B2 son IDs de TorneoInscripcion (SINGLES).
    """
    n = len(insc_ids)
    if n < 4 or n % 2 != 0:
        raise ValueError("Americano individual requiere N par >= 4 inscripciones SINGLES.")

    ids = list(insc_ids)
    if n == 4:
        A,B,C,D = ids
        return [
            [((A,B), (C,D))],
            [((A,C), (B,D))],
            [((A,D), (B,C))],
        ]

    # Rotación general (círculo), formando parejas internas/externas cada ronda
    left = ids[:n//2]
    right = ids[n//2:][::-1]  # espejo
    rondas = []
    R = n - 1  # número estándar de rondas

    for _ in range(R):
        # Formamos parejas: extremos hacia el centro
        parejas = []
        half = n // 4
        for i in range(half):
            parejas.append( (left[i], left[-(i+1)]) )     # internas del lado izquierdo
            parejas.append( (right[i], right[-(i+1)]) )   # internas del lado derecho

        # Cruzar de a dos parejas para formar partidos
        partidos = []
        for i in range(0, len(parejas), 2):
            partidos.append( (parejas[i], parejas[i+1]) )

        rondas.append(partidos)

        # Rotar manteniendo left[0] fijo
        pivot = left[0]
        ring = left[1:] + right
        ring = [ring[-1]] + ring[:-1]
        left = [pivot] + list(islice(ring, 0, len(left)-1))
        right = list(islice(ring, len(left)-1, None))

    return rondas


def generar_fixture_americano_individual(torneo_id: int, ida_y_vuelta: bool = False) -> dict:
    t = Torneo.query.get(torneo_id)
    if not t:
        return {"ok": False, "msg": "Torneo no encontrado."}
    if not t.es_americano_individual():
        return {"ok": False, "msg": "El torneo no es AMERICANO SINGLES."}

    # SINGLES: inscripciones activas/confirmadas SIN jugador2
    inscs = (TorneoInscripcion.query
             .filter(
                 TorneoInscripcion.torneo_id == t.id,
                 TorneoInscripcion.estado == 'ACTIVA',
                 (TorneoInscripcion.confirmado.is_(True) if hasattr(TorneoInscripcion, 'confirmado') else True),
                 or_(TorneoInscripcion.jugador2_id.is_(None), TorneoInscripcion.jugador2_id == 0)
             )
             .order_by(TorneoInscripcion.created_at.asc() if hasattr(TorneoInscripcion, 'created_at') else TorneoInscripcion.id.asc())
             .all())

    if len(inscs) < 4 or len(inscs) % 2 != 0:
        return {"ok": False, "msg": "Se requieren al menos 4 inscripciones SINGLES (número par)."}

    # Asegurar participantes (1–a–1)
    tp_map = {}  # insc_id -> TorneoParticipante.id
    nuevos_participantes = 0
    for insc in inscs:
        antes = TorneoParticipante.query.filter_by(torneo_id=t.id, inscripcion_id=insc.id).one_or_none()
        tp = _inscripcion_to_participante(t, insc)
        if not antes:
            nuevos_participantes += 1
        tp_map[insc.id] = tp.id

    insc_ids = [i.id for i in inscs]
    rondas = _rotaciones_americano_individual(insc_ids)

    fase = _get_or_create_fase_unica(t)
    grupo = _get_or_create_grupo(t, fase, "GENERAL", 1)

    # --- helper idempotente para lados (evita UNIQUE (partido_id, lado)) ---
    LadoModel = globals().get('TorneoPartidoLado')
    def _set_lado(partido_id: int, lado: str, insc1_id: int | None, insc2_id: int | None):
        if not LadoModel:
            return None
        lado = (lado or 'A').upper()
        existente = (db.session.query(LadoModel)
                     .filter_by(partido_id=partido_id, lado=lado)
                     .one_or_none())
        if existente:
            existente.insc1_id = insc1_id
            existente.insc2_id = insc2_id
            return existente
        nuevo = LadoModel(partido_id=partido_id, lado=lado, insc1_id=insc1_id, insc2_id=insc2_id)
        db.session.add(nuevo)
        return nuevo

    creados = 0
    orden_global = 1
    jornada = 1

    # Utilidad: limpia lados previos por si SQLite reusó IDs de partido
    def _clear_lados(partido_id: int):
        if not LadoModel:
            return
        db.session.query(LadoModel).filter_by(partido_id=partido_id).delete(synchronize_session=False)

    # ------- Ida -------
    for partidos in rondas:
        for (A1, A2), (B1, B2) in partidos:
            # Crear TorneoPartido “titular” apuntando a un participante por lado (p.ej. A1 y B1)
            p_obj = TorneoPartido(
                torneo_id=t.id,
                fase_id=fase.id,
                grupo_id=grupo.id,
                ronda=f"R{jornada}",
                orden=orden_global,
                participante_a_id=tp_map[A1],  # uno del lado A
                participante_b_id=tp_map[B1],  # uno del lado B
                estado='PENDIENTE'
            )
            db.session.add(p_obj)
            db.session.flush()  # obtener p_obj.id

            # Limpiar posibles lados viejos con el mismo partido_id (por reutilización de IDs)
            _clear_lados(p_obj.id)

            # Guardar / actualizar explícitamente las duplas reales de cada lado
            _set_lado(p_obj.id, 'A', A1, A2)
            _set_lado(p_obj.id, 'B', B1, B2)

            creados += 1
            orden_global += 1
        jornada += 1

    # ------- Vuelta (opcional) -------
    if ida_y_vuelta:
        for partidos in rondas:
            for (A1, A2), (B1, B2) in partidos:
                p_obj = TorneoPartido(
                    torneo_id=t.id,
                    fase_id=fase.id,
                    grupo_id=grupo.id,
                    ronda=f"R{jornada}",
                    orden=orden_global,
                    participante_a_id=tp_map[B1],  # invertimos localía
                    participante_b_id=tp_map[A1],
                    estado='PENDIENTE'
                )
                db.session.add(p_obj)
                db.session.flush()

                _clear_lados(p_obj.id)
                _set_lado(p_obj.id, 'A', B1, B2)
                _set_lado(p_obj.id, 'B', A1, A2)

                creados += 1
                orden_global += 1
            jornada += 1

    db.session.commit()
    return {
        "ok": True,
        "msg": f"Fixture generado: {creados} partidos. (AMERICANO SINGLES rotativo 2v2{' ida y vuelta' if ida_y_vuelta else ''})",
        "nuevos_participantes": nuevos_participantes,
        "partidos_creados": creados
    }


# ----------------------------
# MODELOS
# ----------------------------
class Categoria(db.Model):
    __tablename__ = 'categorias'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), unique=True, nullable=False)
    puntos_min = db.Column(db.Integer, nullable=False)
    puntos_max = db.Column(db.Integer, nullable=False)
    creada_en = db.Column(db.DateTime, default=datetime.utcnow)

    jugadores = db.relationship('Jugador', backref='categoria', lazy=True)

    def rango(self):
        return f"{self.puntos_min}–{self.puntos_max}"

class Jugador(db.Model):
    __tablename__ = 'jugadores'
    id = db.Column(db.Integer, primary_key=True)
    nombre_completo = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    telefono = db.Column(db.String(50))
    puntos = db.Column(db.Integer, nullable=False)
    categoria_id = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)
    activo = db.Column(db.Boolean, nullable=False, default=True)
    # en class Jugador(...)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    # ===== Nuevos campos opcionales =====
    pais = db.Column(db.String(100), nullable=True)
    provincia = db.Column(db.String(120), nullable=True)
    ciudad = db.Column(db.String(120), nullable=True)
    fecha_nacimiento = db.Column(db.Date, nullable=True)

    # NUEVO: PIN simple para login MVP (ya lo tenías)
    pin = db.Column(db.String(10), nullable=False, default='0000')


class JugadorEstado(db.Model):
    __tablename__ = 'jugador_estado'
    id = db.Column(db.Integer, primary_key=True)
    jugador_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), unique=True, nullable=False)
    victorias_vs_superior = db.Column(db.Integer, default=0)  # 3 → asciende
    derrotas_vs_inferior = db.Column(db.Integer, default=0)  # 3 → desciende
    actualizado_en = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    jugador = db.relationship('Jugador', backref=db.backref('estado', uselist=False))


class Pareja(db.Model):
    __tablename__ = 'parejas'
    id = db.Column(db.Integer, primary_key=True)
    categoria_id = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=False)
    jugador1_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    jugador2_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    puntos = db.Column(db.Integer, nullable=False)  # puntaje de la pareja en el nivel
    victorias_vs_superior = db.Column(db.Integer, default=0)
    derrotas_vs_inferior = db.Column(db.Integer, default=0)
    creada_en = db.Column(db.DateTime, default=datetime.utcnow)

    jugador1 = db.relationship('Jugador', foreign_keys=[jugador1_id])
    jugador2 = db.relationship('Jugador', foreign_keys=[jugador2_id])
    categoria = db.relationship('Categoria', foreign_keys=[categoria_id])

    __table_args__ = (
        db.UniqueConstraint('categoria_id', 'jugador1_id', 'jugador2_id', name='uq_pareja_cat_j1_j2'),
    )

class Partido(db.Model):
    __tablename__ = 'partidos'
    id = db.Column(db.Integer, primary_key=True)

    # Intra-nivel por ahora: ambas parejas deben ser de la misma categoría
    categoria_id = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=False)
    pareja1_id   = db.Column(db.Integer, db.ForeignKey('parejas.id'), nullable=False)
    pareja2_id   = db.Column(db.Integer, db.ForeignKey('parejas.id'), nullable=False)

    # --- datos de invitación ---
    creador_id   = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=True)
    companero_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=True)
    rival1_id    = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=True)
    rival2_id    = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=True)

    # --- respuestas de rivales ---
    rival1_acepto = db.Column(db.Boolean, nullable=True, default=None)
    rival2_acepto = db.Column(db.Boolean, nullable=True, default=None)

    # --- workflow de propuesta/confirmación de resultado ---
    resultado_propuesto_ganador_pareja_id = db.Column(db.Integer, nullable=True)
    resultado_propuesto_sets_text         = db.Column(db.String(100), nullable=True)
    resultado_propuesto_por_id            = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=True)
    # NUEVO: cuándo se propuso (para autocierre a las 12h)
    resultado_propuesto_en                = db.Column(db.DateTime, nullable=True)

    # Confirmaciones por pareja: NULL = pendiente, 1 = confirmó, 0 = disputó
    confirmo_pareja1 = db.Column(db.Integer, nullable=True, default=None)
    confirmo_pareja2 = db.Column(db.Integer, nullable=True, default=None)

    # --- rechazos de propuesta ---
    rechazo_ultimo_por_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=True)
    rechazo_ultimo_en     = db.Column(db.DateTime, nullable=True)

    # --- trazabilidad (NUEVO): si fue creado desde un Desafío ---
    # FK blanda para no depender del __tablename__ de Desafio ni romper en entornos legacy.
    creado_por_desafio_id = db.Column(db.Integer, nullable=True)
    # Relación de solo lectura usando primaryjoin explícito (no requiere FK real):
    creado_por_desafio = db.relationship(
        'Desafio',
        primaryjoin="foreign(Partido.creado_por_desafio_id)==Desafio.id",
        viewonly=True,
        lazy='joined'
    )

    # Campos básicos
    fecha = db.Column(db.DateTime, nullable=True)  # opcional por ahora
    # Estados posibles:
    # POR_CONFIRMAR (invitación a rivales) -> PENDIENTE (rivals aceptaron)
    # PROPUESTO (hay resultado propuesto, esperando confirmaciones)
    # EN_REVISION (disputa; resuelve admin)
    # JUGADO (cerrado) | CANCELADO
    estado    = db.Column(db.String(20), default='POR_CONFIRMAR')
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    # Relaciones existentes
    categoria = db.relationship('Categoria', foreign_keys=[categoria_id])
    pareja1   = db.relationship('Pareja', foreign_keys=[pareja1_id])
    pareja2   = db.relationship('Pareja', foreign_keys=[pareja2_id])

    # Relaciones nuevas (comodidad en vistas)
    creador   = db.relationship('Jugador', foreign_keys=[creador_id])
    companero = db.relationship('Jugador', foreign_keys=[companero_id])
    rival1    = db.relationship('Jugador', foreign_keys=[rival1_id])
    rival2    = db.relationship('Jugador', foreign_keys=[rival2_id])

    # Quién propuso / quién rechazó
    resultado_propuesto_por = db.relationship('Jugador', foreign_keys=[resultado_propuesto_por_id])
    rechazo_ultimo_por      = db.relationship('Jugador', foreign_keys=[rechazo_ultimo_por_id])

    __table_args__ = (
        db.CheckConstraint('pareja1_id <> pareja2_id', name='chk_parejas_distintas'),
    )

    # ------------------------------------------------------------
    # Helpers de participación / propuesta / confirmación
    # ------------------------------------------------------------
    def _jugador_en_pareja(self, jugador_id: int, pareja) -> bool:
        """True si el jugador_id pertenece a la pareja dada."""
        if pareja is None:
            return False
        return jugador_id in (pareja.jugador1_id, pareja.jugador2_id)

    def jugador_participa(self, jugador_id: int) -> bool:
        """True si el jugador participa en el partido (pareja1 o pareja2)."""
        return self._jugador_en_pareja(jugador_id, self.pareja1) or \
               self._jugador_en_pareja(jugador_id, self.pareja2)

    def pareja_del_jugador(self, jugador_id: int):
        """Devuelve 1 si el jugador está en pareja1, 2 si está en pareja2, o None si no participa."""
        if self._jugador_en_pareja(jugador_id, self.pareja1):
            return 1
        if self._jugador_en_pareja(jugador_id, self.pareja2):
            return 2
        return None

    def propuesta_abierta(self):
        """
        Devuelve el registro de PartidoResultadoPropuesto si existe (único por partido),
        o None si no hay propuesta abierta.
        """
        try:
            # Import tardío para evitar problemas de orden de definición
            from .models import PartidoResultadoPropuesto
        except Exception:
            PartidoResultadoPropuesto = globals().get('PartidoResultadoPropuesto', None)

        if not PartidoResultadoPropuesto:
            return None

        return db.session.query(PartidoResultadoPropuesto).filter_by(partido_id=self.id).one_or_none()

    def necesita_respuesta_de(self, jugador_id: int) -> bool:
        """
        True si:
          - el jugador participa,
          - existe propuesta abierta (o, como fallback, self.estado == 'PROPUESTO' con self.resultado_propuesto_por_id),
          - y la pareja del jugador aún NO confirmó ni disputó (confirmo_parejaX is None).
        """
        if not self.jugador_participa(jugador_id):
            return False

        prp = self.propuesta_abierta()
        if prp:
            pareja_idx = self.pareja_del_jugador(jugador_id)
            if pareja_idx == 1:
                return self.confirmo_pareja1 is None
            elif pareja_idx == 2:
                return self.confirmo_pareja2 is None
            return False

        # Fallback “legacy” con campos del propio Partido
        if self.estado == 'PROPUESTO' and self.resultado_propuesto_por_id:
            pareja_idx = self.pareja_del_jugador(jugador_id)
            if pareja_idx == 1:
                return self.confirmo_pareja1 is None
            elif pareja_idx == 2:
                return self.confirmo_pareja2 is None

        return False

    def puede_proponer_resultado(self, jugador_id: int) -> bool:
        """
        True si:
          - el jugador participa,
          - el partido NO tiene resultado final,
          - NO hay propuesta abierta,
          - y el estado permite proponer (PENDIENTE o POR_CONFIRMAR).
        """
        if not self.jugador_participa(jugador_id):
            return False

        if hasattr(self, "resultado") and self.resultado is not None:
            return False

        if self.propuesta_abierta():
            return False

        return self.estado in ('PENDIENTE', 'POR_CONFIRMAR')



class PartidoResultado(db.Model):
    __tablename__ = 'partido_resultados'
    id = db.Column(db.Integer, primary_key=True)
    partido_id = db.Column(db.Integer, db.ForeignKey('partidos.id'), unique=True, nullable=False)
    ganador_pareja_id = db.Column(db.Integer, db.ForeignKey('parejas.id'), nullable=False)
    sets_text = db.Column(db.String(80))  # Ej: "6-4 3-6 10-7"
    confirmado_en = db.Column(db.DateTime, default=datetime.utcnow)

    partido = db.relationship(
        'Partido',
        foreign_keys=[partido_id],
        backref=db.backref('resultado', uselist=False)  # <- acceso como partido.resultado
    )
    ganador_pareja = db.relationship('Pareja', foreign_keys=[ganador_pareja_id])

class PartidoResultadoPropuesto(db.Model):
    __tablename__ = 'partido_resultado_propuesto'

    id = db.Column(db.Integer, primary_key=True)

    # Un partido puede tener a lo sumo UNA propuesta abierta a la vez
    partido_id = db.Column(db.Integer, db.ForeignKey('partidos.id'), nullable=False, unique=True)

    # Quién propuso: pareja1 o pareja2 del partido
    propuesto_por_pareja_id = db.Column(db.Integer, db.ForeignKey('parejas.id'), nullable=False)

    # Propuesta concreta
    ganador_pareja_id = db.Column(db.Integer, db.ForeignKey('parejas.id'), nullable=False)
    sets_text = db.Column(db.String(100), nullable=True)

    creado_en = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relaciones (comodidad)
    partido = db.relationship('Partido', foreign_keys=[partido_id])
    propuesto_por_pareja = db.relationship('Pareja', foreign_keys=[propuesto_por_pareja_id])
    ganador_pareja = db.relationship('Pareja', foreign_keys=[ganador_pareja_id])

class Desafio(db.Model):
    __tablename__ = 'desafios'
    id = db.Column(db.Integer, primary_key=True)

    # El desafío es INDIVIDUAL: el desafiante elige compañero del mismo nivel (ambos en zona de ascenso)
    desafiante_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    companero_id  = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)

    # Rivales (pareja del NIVEL SUPERIOR)
    rival1_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    rival2_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)

    # Respuestas individuales de los rivales
    rival1_acepto = db.Column(db.Boolean, nullable=False, default=False)
    rival2_acepto = db.Column(db.Boolean, nullable=False, default=False)

    # Categorías para dejar trazado el contexto en el momento de crear el desafío
    categoria_origen_id   = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=False)  # nivel del desafiante al crear
    categoria_superior_id = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=False)  # nivel al que desafía

    # Vinculación con partido cuando se programe
    partido_id = db.Column(db.Integer, db.ForeignKey('partidos.id'), nullable=True)

    # Estado del desafío
    # PENDIENTE | ACEPTADO_PARCIAL | ACEPTADO | RECHAZADO | JUGADO | CANCELADO
    estado = db.Column(db.String(20), default='PENDIENTE')
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    # Relaciones (solo para comodidad en vistas)
    desafiante = db.relationship('Jugador', foreign_keys=[desafiante_id])
    companero  = db.relationship('Jugador', foreign_keys=[companero_id])
    rival1     = db.relationship('Jugador', foreign_keys=[rival1_id])
    rival2     = db.relationship('Jugador', foreign_keys=[rival2_id])
    categoria_origen   = db.relationship('Categoria', foreign_keys=[categoria_origen_id])
    categoria_superior = db.relationship('Categoria', foreign_keys=[categoria_superior_id])
    partido = db.relationship('Partido', foreign_keys=[partido_id])

    __table_args__ = (
        db.CheckConstraint('desafiante_id <> companero_id', name='chk_desafio_jugadores_distintos'),
        db.CheckConstraint('rival1_id <> rival2_id',       name='chk_desafio_rivales_distintos'),
    )

class PartidoAbierto(db.Model):
    __tablename__ = 'partidos_abiertos'
    id = db.Column(db.Integer, primary_key=True)
    categoria_id = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=False)
    creador_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    nota = db.Column(db.String(200))   # opcional: horario sugerido, club, etc.
    estado = db.Column(db.String(20), default='ABIERTO')  # ABIERTO | LLENO | PARTIDO_CREADO | CANCELADO
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    categoria = db.relationship('Categoria')
    creador = db.relationship('Jugador', foreign_keys=[creador_id])

class PartidoAbiertoJugador(db.Model):
    __tablename__ = 'partido_abierto_jugadores'
    id = db.Column(db.Integer, primary_key=True)
    pa_id = db.Column(db.Integer, db.ForeignKey('partidos_abiertos.id'), nullable=False, index=True)
    jugador_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    agregado_en = db.Column(db.DateTime, default=datetime.utcnow)

    # NUEVO: preferencia de compañero (opcional)
    partner_pref_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=True)

    partido_abierto = db.relationship('PartidoAbierto', backref=db.backref('inscriptos', lazy=True, cascade="all, delete-orphan"))
    jugador = db.relationship('Jugador', foreign_keys=[jugador_id])

    # NUEVO: relación a la preferencia
    partner_pref = db.relationship('Jugador', foreign_keys=[partner_pref_id])

    __table_args__ = (
        db.UniqueConstraint('pa_id', 'jugador_id', name='uq_pa_jugador_unico'),
    )

class PartidoAbiertoSuplente(db.Model):
    __tablename__ = 'partido_abierto_suplentes'
    id = db.Column(db.Integer, primary_key=True)
    pa_id = db.Column(db.Integer, db.ForeignKey('partidos_abiertos.id'), nullable=False, index=True)
    jugador_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False, index=True)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    partido_abierto = db.relationship('PartidoAbierto', backref=db.backref('suplentes', lazy=True, cascade="all, delete-orphan"))
    jugador = db.relationship('Jugador', foreign_keys=[jugador_id])

    __table_args__ = (
        db.UniqueConstraint('pa_id', 'jugador_id', name='uq_suplente_unico'),
    )

class SolicitudAlta(db.Model):
    __tablename__ = 'solicitudes_alta'

    id              = db.Column(db.Integer, primary_key=True)
    nombre_completo = db.Column(db.String(120), nullable=False)
    email           = db.Column(db.String(120))
    telefono        = db.Column(db.String(50))
    categoria_id    = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=False)
    mensaje         = db.Column(db.String(300))
    estado          = db.Column(db.String(20), nullable=False, default='PENDIENTE')  # PENDIENTE | APROBADA | RECHAZADA
    creado_en       = db.Column(db.DateTime, default=datetime.utcnow)
    resuelto_en     = db.Column(db.DateTime)

    # ====== NUEVOS CAMPOS (opcionales) ======
    pais             = db.Column(db.String(80), nullable=True)
    provincia        = db.Column(db.String(80), nullable=True)
    ciudad           = db.Column(db.String(120), nullable=True)
    # En SQLite, db.Date se guarda como TEXT 'YYYY-MM-DD' sin problema
    fecha_nacimiento = db.Column(db.Date, nullable=True)

    categoria = db.relationship('Categoria')


from datetime import datetime, timezone

class PinReset(db.Model):
    __tablename__ = "pin_resets"

    id          = db.Column(db.Integer, primary_key=True)

    # Puede generarse un PIN aunque el Jugador aún no exista → nullable=True
    jugador_id  = db.Column(db.Integer, db.ForeignKey("jugadores.id"),
                            nullable=True, index=True)

    # NUEVO: para poder validar por email si aún no hay jugador
    email       = db.Column(db.Text, nullable=True, index=True)

    # Guardar como texto para no perder ceros a la izquierda
    code        = db.Column(db.String(6), nullable=False)

    # Timestamps "aware" en UTC para evitar errores de TZ
    created_en  = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    expires_en  = db.Column(db.DateTime(timezone=True), nullable=False)

    used        = db.Column(db.Boolean, nullable=False, default=False,
                            server_default=db.text("0"))

    # Relación (puede no existir si el PIN fue emitido solo con email)
    jugador     = db.relationship("Jugador", lazy="joined")

    def __repr__(self):
        return f"<PinReset id={self.id} email={self.email} jugador_id={self.jugador_id} used={self.used}>"


# ===== Torneos: modelos base (MVP) =====

EST_BORRADOR = "BORRADOR"
EST_INSCRIPCION = "INSCRIPCION"
EST_INSCRIPCION_CERRADA = "INSCRIPCION_CERRADA"
EST_EN_JUEGO = "EN_JUEGO"
EST_FINALIZADO = "FINALIZADO"
EST_CANCELADO = "CANCELADO"


class Torneo(db.Model):
    __tablename__ = 'torneos'
    id = db.Column(db.Integer, primary_key=True)

    nombre = db.Column(db.String(120), nullable=False)
    categoria_id = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=True)

    # Nuevo (ya lo tenías)
    formato = db.Column(db.String(10), nullable=False, default='SINGLES')  # 'SINGLES' | 'DOBLES'
    # Legacy (compat con DB existente)
    modalidad = db.Column(db.String(10), nullable=False, default='SINGLES')  # mantener hasta migrar

    tipo = db.Column(db.String(20), nullable=False, default='AMERICANO')  # 'AMERICANO' | 'ZONAS+PLAYOFF' | 'PLAYOFF'
    estado = db.Column(db.String(15), nullable=False, default='BORRADOR')

    inscripcion_libre = db.Column(db.Boolean, nullable=False, default=True)
    cupo_max = db.Column(db.Integer, nullable=True)
    permite_playoff_desde = db.Column(db.String(20), nullable=False, default='ZONAS')
    reglas_json = db.Column(db.JSON, nullable=True)

    fecha_inicio = db.Column(db.Date, nullable=True)
    sede = db.Column(db.String(120), nullable=True)
    notas = db.Column(db.Text, nullable=True)

    # NUEVO (visibilidad + control de inscripciones públicas)
    es_publico = db.Column(db.Boolean, nullable=False, default=True, index=True)
    inscripciones_abiertas = db.Column(db.Boolean, nullable=False, default=True, index=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=True)

    categoria = db.relationship('Categoria', backref='torneos', lazy='joined')
    created_by = db.relationship('Jugador', foreign_keys=[created_by_id], lazy='joined')

    __table_args__ = (
        db.Index('ix_torneos_publicos_cat', 'es_publico', 'categoria_id'),
    )

    # ----------------- Helpers existentes -----------------
    def es_dobles(self) -> bool:
        return (self.formato or '').upper() == 'DOBLES'

    # (Azúcar para vistas)
    def inscripcion_habilitada(self) -> bool:
        return bool(self.es_publico and self.inscripciones_abiertas)

    # ----------------- Helpers nuevos (americano) -----------------
    def _formato_norm(self) -> str:
        """Devuelve el formato normalizado priorizando 'formato' y usando 'modalidad' como fallback legacy."""
        v = (self.formato or '').strip().upper()
        if not v:
            v = (self.modalidad or '').strip().upper()
        return v

    def es_americano(self) -> bool:
        return (self.tipo or '').strip().upper() == 'AMERICANO'

    def es_americano_individual(self) -> bool:
        """Americano con formato SINGLES: parejas rotativas, puntaje por jugador."""
        return self.es_americano() and self._formato_norm() == 'SINGLES'

    def es_americano_parejas(self) -> bool:
        """Americano con formato DOBLES: pareja fija, puntaje por pareja."""
        return self.es_americano() and self._formato_norm() == 'DOBLES'



from datetime import datetime
from sqlalchemy import event, or_
from sqlalchemy.exc import IntegrityError

class TorneoInscripcion(db.Model):
    __tablename__ = 'torneos_inscripciones'
    id = db.Column(db.Integer, primary_key=True)

    torneo_id = db.Column(db.Integer, db.ForeignKey('torneos.id'), nullable=False)

    jugador1_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    jugador2_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=True)  # requerido si formato=DOBLES

    # Semillas / estado
    seed = db.Column(db.Integer, nullable=True)
    confirmado = db.Column(db.Boolean, nullable=False, default=True)

    # estado (PENDIENTE/ACTIVA/BAJA) y baja_motivo
    estado = db.Column(db.String(15), nullable=False, default='ACTIVA')
    baja_motivo = db.Column(db.String(120), nullable=True)

    # timestamps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Clave normalizada de dupla para evitar duplicados (j1-j2 == j2-j1)
    # Mantiene coherencia con la ruta: "S:<id>" | "D:<a>-<b>"
    pareja_key = db.Column(db.String(50), nullable=True, index=True)

    # Datos opcionales
    alias = db.Column(db.String(80), nullable=True)
    club = db.Column(db.String(80), nullable=True)
    disponibilidad = db.Column(db.String(120), nullable=True)

    # Relaciones
    torneo = db.relationship('Torneo', backref='inscripciones', lazy='joined')
    jugador1 = db.relationship('Jugador', foreign_keys=[jugador1_id], lazy='joined')
    jugador2 = db.relationship('Jugador', foreign_keys=[jugador2_id], lazy='joined')

    __table_args__ = (
        # Evita inscribir dos veces a la misma persona/pareja en el mismo torneo (soporta singles y dobles)
        db.UniqueConstraint('torneo_id', 'pareja_key', name='uq_torneo_pareja_key'),
        # Índices útiles
        db.Index('ix_insc_torneo', 'torneo_id'),
        db.Index('ix_insc_j1', 'jugador1_id'),
        db.Index('ix_insc_j2', 'jugador2_id'),
    )

    # -------- Helpers de conveniencia --------
    def calcular_pareja_key(self) -> str:
        """
        Normaliza la clave de inscripción:
        - Singles:  S:<j1>
        - Dobles:   D:<min(j1,j2)>-<max(j1,j2)>
        Prioriza el formato del torneo si está disponible.
        """
        is_dobles = None
        if self.torneo is not None:
            try:
                is_dobles = bool(self.torneo.es_dobles())
            except Exception:
                is_dobles = None

        if is_dobles is None:
            # fallback por datos presentes
            is_dobles = bool(self.jugador2_id)

        if is_dobles:
            if not self.jugador2_id:
                # Si falta j2 en dobles, devolvemos algo consistente pero inválido (se validará antes de insert/update)
                return f"D:{int(self.jugador1_id)}-?"
            a, b = sorted([int(self.jugador1_id), int(self.jugador2_id)])
            return f"D:{a}-{b}"

        # Singles
        return f"S:{int(self.jugador1_id)}"

    def es_dobles(self) -> bool:
        # Usa el formato del torneo cuando esté cargado
        if self.torneo:
            try:
                return bool(self.torneo.es_dobles())
            except Exception:
                pass
        # fallback: si hay jugador2 cargado
        return bool(self.jugador2_id)

    def integrantes_ids(self):
        return [x for x in [self.jugador1_id, self.jugador2_id] if x]

    def pertenece_a(self, jugador_id: int) -> bool:
        return jugador_id in self.integrantes_ids()


# ============================
#  Event listeners (validación)
# ============================

def _validar_inscripcion_y_setear_clave(mapper, connection, target: TorneoInscripcion):
    """
    - Setea pareja_key si falta, usando el helper consistente con la ruta.
    - Valida:
      * Formato (singles/dobles) vs. campos cargados.
      * Categoría de jugador1 (y jugador2 si dobles) = categoría del torneo (si la tiene).
    """
    # Cargar torneo si no está pegado
    torneo = target.torneo
    if torneo is None and target.torneo_id:
        # conexión cruda: cargar sólo lo necesario
        row = connection.execute(
            db.text("SELECT id, categoria_id, modalidad FROM torneos WHERE id = :tid"),
            {"tid": target.torneo_id}
        ).mappings().first()
        if row:
            class _T:
                id = row["id"]
                categoria_id = row["categoria_id"]
                modalidad = row.get("modalidad") if hasattr(row, "get") else row["modalidad"]
                def es_dobles(self):
                    m = (self.modalidad or '').upper()
                    return m in ('DOBLES', 'DOUBLES')
            torneo = _T()

    # --- Validación de formato
    is_dobles = None
    if torneo is not None:
        try:
            is_dobles = bool(torneo.es_dobles())
        except Exception:
            is_dobles = None
    if is_dobles is None:
        is_dobles = bool(target.jugador2_id)

    if is_dobles and not target.jugador2_id:
        raise IntegrityError("dobles-sin-j2", params=None, orig=None)
    if (not is_dobles) and target.jugador2_id:
        raise IntegrityError("singles-con-j2", params=None, orig=None)

    # --- Setear pareja_key si está vacío
    if not target.pareja_key:
        target.pareja_key = target.calcular_pareja_key()

    # --- Validación de categoría (si el torneo tiene categoría)
    categoria_torneo_id = getattr(torneo, 'categoria_id', None) if torneo else None
    if categoria_torneo_id:
        # Cargar categorías de j1 y j2, si corresponde
        j1_id = target.jugador1_id
        j2_id = target.jugador2_id

        if j1_id:
            row_j1 = connection.execute(
                db.text("SELECT categoria_id, activo FROM jugadores WHERE id = :jid"),
                {"jid": j1_id}
            ).mappings().first()
            if not row_j1 or not row_j1["activo"]:
                raise IntegrityError("jugador1-inactivo-o-invalido", params=None, orig=None)
            if (row_j1["categoria_id"] or None) != categoria_torneo_id:
                raise IntegrityError("categoria-j1-distinta-al-torneo", params=None, orig=None)

        if is_dobles and j2_id:
            row_j2 = connection.execute(
                db.text("SELECT categoria_id, activo FROM jugadores WHERE id = :jid"),
                {"jid": j2_id}
            ).mappings().first()
            if not row_j2 or not row_j2["activo"]:
                raise IntegrityError("jugador2-inactivo-o-invalido", params=None, orig=None)
            if (row_j2["categoria_id"] or None) != categoria_torneo_id:
                raise IntegrityError("categoria-j2-distinta-al-torneo", params=None, orig=None)


# Hookear en insert/update
event.listen(TorneoInscripcion, 'before_insert', _validar_inscripcion_y_setear_clave)
event.listen(TorneoInscripcion, 'before_update', _validar_inscripcion_y_setear_clave)



class TorneoFase(db.Model):
    __tablename__ = 'torneos_fases'
    id = db.Column(db.Integer, primary_key=True)
    torneo_id = db.Column(db.Integer, db.ForeignKey('torneos.id'), nullable=False)

    # 'ZONAS','LIGA','PLAYOFF'  -> dejamos default 'LIGA' para el round-robin (americano)
    tipo = db.Column(db.String(12), nullable=False, default='LIGA')

    orden = db.Column(db.Integer, nullable=False, default=1)
    nombre = db.Column(db.String(80), nullable=False, default='Fase')
    config_json = db.Column(db.JSON, nullable=True)

    torneo = db.relationship('Torneo', backref='fases', lazy='joined')



class TorneoGrupo(db.Model):
    __tablename__ = 'torneos_grupos'
    id = db.Column(db.Integer, primary_key=True)
    fase_id = db.Column(db.Integer, db.ForeignKey('torneos_fases.id'), nullable=False)

    nombre = db.Column(db.String(40), nullable=False, default='Grupo')
    orden = db.Column(db.Integer, nullable=False, default=1)
    metadata_json = db.Column(db.JSON, nullable=True)

    fase = db.relationship('TorneoFase', backref='grupos', lazy='joined')



class TorneoParticipante(db.Model):
    __tablename__ = 'torneos_participantes'

    id = db.Column(db.Integer, primary_key=True)
    torneo_id = db.Column(db.Integer, db.ForeignKey('torneos.id'), nullable=False)
    inscripcion_id = db.Column(db.Integer, db.ForeignKey('torneos_inscripciones.id'), nullable=False, index=True)

    # Relaciones
    torneo = db.relationship('Torneo', backref='participantes', lazy='joined')
    # 1–a–1 con la inscripción (un participante referencia exactamente una inscripción)
    inscripcion = db.relationship('TorneoInscripcion', backref='participante', lazy='joined', uselist=False)

    # ===== Proxies a datos derivados de la inscripción (NO columnas reales) =====
    pareja_key   = association_proxy('inscripcion', 'pareja_key')
    jugador1_id  = association_proxy('inscripcion', 'jugador1_id')
    jugador2_id  = association_proxy('inscripcion', 'jugador2_id')
    seed         = association_proxy('inscripcion', 'seed')

    # Alias opcional si en algún lado referenciás participante.participante_key
    participante_key = synonym('pareja_key')

    # === Constructor seguro (airbag) ===
    def __init__(self, **kwargs):
        # Permitir pasar el objeto 'inscripcion' y resolver a su id
        insc_obj = kwargs.pop("inscripcion", None)
        if insc_obj is not None and getattr(insc_obj, "id", None):
            kwargs["inscripcion_id"] = insc_obj.id

        # Aceptamos solo estas claves reales de la tabla
        allowed = {"torneo_id", "inscripcion_id"}
        filtered = {k: v for k, v in kwargs.items() if k in allowed}

        # Validaciones fuertes
        if filtered.get("torneo_id") is None:
            raise RuntimeError("No se puede crear TorneoParticipante sin torneo_id.")
        if filtered.get("inscripcion_id") is None:
            raise RuntimeError(
                "No se puede crear TorneoParticipante sin inscripcion_id. "
                "Pasá una TorneoInscripcion válida o usá _inscripcion_to_participante(t, insc)."
            )

        super().__init__(**filtered)


class TorneoPartido(db.Model):
    __tablename__ = 'torneos_partidos'

    id = db.Column(db.Integer, primary_key=True)
    torneo_id = db.Column(db.Integer, db.ForeignKey('torneos.id'), nullable=False)
    fase_id = db.Column(db.Integer, db.ForeignKey('torneos_fases.id'), nullable=True)
    grupo_id = db.Column(db.Integer, db.ForeignKey('torneos_grupos.id'), nullable=True)

    # ej. "J1" (jornada 1), "QF", "SF", "Final"
    ronda = db.Column(db.String(30), nullable=True)
    orden = db.Column(db.Integer, nullable=True)

    participante_a_id = db.Column(db.Integer, db.ForeignKey('torneos_participantes.id'), nullable=False)
    participante_b_id = db.Column(db.Integer, db.ForeignKey('torneos_participantes.id'), nullable=False)

    # 'PENDIENTE','PROGRAMADO','JUGADO','WO','SUSPENDIDO'
    estado = db.Column(db.String(12), nullable=False, default='PENDIENTE')

    # sets/games u otro payload
    resultado_json = db.Column(db.JSON, nullable=True)
    ganador_participante_id = db.Column(db.Integer, db.ForeignKey('torneos_participantes.id'), nullable=True)

    programado_en = db.Column(db.DateTime, nullable=True)
    cancha = db.Column(db.String(80), nullable=True)

    # Relaciones (respetando tus lazy='joined')
    torneo = db.relationship('Torneo', backref='partidos', lazy='joined')
    fase = db.relationship('TorneoFase', backref='partidos', lazy='joined')
    grupo = db.relationship('TorneoGrupo', backref='partidos', lazy='joined')

    participante_a = db.relationship('TorneoParticipante', foreign_keys=[participante_a_id], lazy='joined')
    participante_b = db.relationship('TorneoParticipante', foreign_keys=[participante_b_id], lazy='joined')
    ganador_participante = db.relationship('TorneoParticipante', foreign_keys=[ganador_participante_id], lazy='joined')

    __table_args__ = (
        # Evita duplicar el mismo cruce A vs B dentro del mismo grupo
        db.UniqueConstraint('grupo_id', 'participante_a_id', 'participante_b_id', name='uq_grupo_partido_ab'),
        # Índices útiles para listados / filtros
        db.Index('ix_torneos_partidos_torneo_estado', 'torneo_id', 'estado'),
        db.Index('ix_torneos_partidos_programado', 'programado_en'),
    )

    # -----------------------------
    # Helpers NO intrusivos (robustos)
    # -----------------------------
    def _extraer_ids_de_participante(self, tp: 'TorneoParticipante') -> list[int]:
        """
        Devuelve 1 o 2 ids de Jugador desde TorneoParticipante.
        Intenta múltiples variantes de campos: single, parejas, inscripción y pareja relacional.
        No rompe si algo no existe. Devuelve [] si no puede resolver.
        """
        if not tp:
            return []

        Ins = globals().get('TorneoInscripcion')
        Pareja = globals().get('Pareja')

        # --- 1) Campo "single" (varias variantes)
        single_variants = ['jugador_id', 'player_id', 'id_jugador']
        for attr in single_variants:
            j_id = getattr(tp, attr, None)
            if j_id:
                return [j_id]

        # --- 2) Campos de pareja (varias variantes)
        pair_variants = [
            ('jugador1_id', 'jugador2_id'),
            ('player1_id',  'player2_id'),
            ('jugador_a_id','jugador_b_id'),
            ('j1_id',       'j2_id'),
        ]
        for a1, a2 in pair_variants:
            j1 = getattr(tp, a1, None)
            j2 = getattr(tp, a2, None)
            ids = [j for j in (j1, j2) if j]
            if ids:
                return ids

        # --- 3) Vía inscripción (id o relación) con variantes de nombre
        insc_rel = getattr(tp, 'inscripcion', None) or getattr(tp, 'insc', None)
        if not insc_rel:
            insc_id = getattr(tp, 'inscripcion_id', None) or getattr(tp, 'insc_id', None)
            if insc_id and Ins:
                try:
                    insc_rel = db.session.get(Ins, insc_id)  # SQLAlchemy 2.x safe
                except Exception:
                    insc_rel = db.session.query(Ins).get(insc_id)  # compat

        if insc_rel:
            # Inscripción puede ser single o pareja (probamos varias)
            for a1, a2 in [('jugador1_id','jugador2_id'),
                           ('player1_id','player2_id'),
                           ('jugador_id', None),
                           ('player_id', None)]:
                j1 = getattr(insc_rel, a1, None)
                j2 = getattr(insc_rel, a2, None) if a2 else None
                ids = [j for j in (j1, j2) if j]
                if ids:
                    return ids

        # --- 4) Vía pareja (id o relación)
        pareja_rel = getattr(tp, 'pareja', None)
        if not pareja_rel:
            pareja_id = getattr(tp, 'pareja_id', None)
            if pareja_id and Pareja:
                try:
                    pareja_rel = db.session.get(Pareja, pareja_id)
                except Exception:
                    pareja_rel = db.session.query(Pareja).get(pareja_id)

        if pareja_rel:
            ids = [getattr(pareja_rel, x, None) for x in ('jugador1_id','jugador2_id')]
            ids = [j for j in ids if j]
            if ids:
                return ids

        # --- 5) Último recurso: listas tipo "participante_jugadores"
        rel_list = getattr(tp, 'jugadores', None) or getattr(tp, 'participante_jugadores', None)
        if rel_list:
            out = []
            for j in rel_list:
                jid = getattr(j, 'id', None) or getattr(j, 'jugador_id', None)
                if jid:
                    out.append(jid)
            if out:
                return out[:2]

        return []

    # === LADOS (soporta SINGLES 2v2 y también dobles) ===
    def _jugadores_ids_desde_lados(self) -> list[int]:
        """
        Extrae IDs de jugador desde TorneoPartidoLado (insc1_id/insc2_id -> TorneoInscripcion).
        Soporta singles (jugador1_id) y dobles (jugador1_id/jugador2_id).
        """
        Ins = globals().get('TorneoInscripcion')
        if not Ins:
            return []
        out: list[int] = []
        try:
            for lado in getattr(self, 'lados', []) or []:
                for insc_id in (getattr(lado, 'insc1_id', None), getattr(lado, 'insc2_id', None)):
                    if not insc_id:
                        continue
                    insc = db.session.get(Ins, insc_id)
                    if not insc:
                        continue
                    j1 = getattr(insc, 'jugador1_id', None)
                    j2 = getattr(insc, 'jugador2_id', None)
                    if j1:
                        out.append(int(j1))
                    if j2:
                        out.append(int(j2))
        except Exception:
            # fail-safe: no rompemos el render si algo raro pasa
            pass
        return out

    def _nombres_lado_desde_lados(self, lado_char: str) -> list[str]:
        """
        Si existen registros en TorneoPartidoLado para el lado dado ('A'/'B'),
        devuelve los nombres de ambos integrantes. Si no, lista vacía.
        """
        lado_char = (lado_char or '').upper()
        if lado_char not in ('A', 'B'):
            return []
        Ins = globals().get('TorneoInscripcion')
        Jug = globals().get('Jugador')
        if not (Ins and Jug):
            return []

        try:
            # buscar el registro del lado A o B
            for l in getattr(self, 'lados', []) or []:
                if getattr(l, 'lado', '').upper() != lado_char:
                    continue
                nombres: list[str] = []
                for insc_id in (getattr(l, 'insc1_id', None), getattr(l, 'insc2_id', None)):
                    if not insc_id:
                        continue
                    insc = db.session.get(Ins, insc_id)
                    if not insc:
                        continue
                    for jid in (getattr(insc, 'jugador1_id', None), getattr(insc, 'jugador2_id', None)):
                        if jid:
                            try:
                                j = db.session.get(Jug, int(jid))
                            except Exception:
                                j = db.session.query(Jug).get(int(jid))
                            if j and getattr(j, 'nombre_completo', None):
                                nombres.append(j.nombre_completo)
                # solo primer match (cada lado es único por constraint)
                return nombres
        except Exception:
            pass
        return []

    # === API pública para permisos/vistas ===
    def jugadores_ids(self) -> set[int]:
        """
        Set de IDs de jugadores (1 o 2 por lado) que participan en este partido.
        Incluye A1/A2/B1/B2 a través de participante_* y también de la tabla de LADOS.
        """
        ids: set[int] = set()
        ids.update(self._extraer_ids_de_participante(self.participante_a))
        ids.update(self._extraer_ids_de_participante(self.participante_b))
        ids.update(self._jugadores_ids_desde_lados())
        return ids

    def jugadores_ids_por_lado(self) -> dict[str, set[int]]:
        """
        {'A': {ids...}, 'B': {ids...}}.
        Si existen LADOS, se priorizan; si no, se infieren desde participante_a/b.
        """
        lados_presentes = bool(getattr(self, 'lados', None))
        out = {'A': set(), 'B': set()}
        if lados_presentes:
            Ins = globals().get('TorneoInscripcion')
            if Ins:
                for l in self.lados:
                    bucket = out.get((l.lado or '').upper())
                    if bucket is None:
                        continue
                    for insc_id in (getattr(l, 'insc1_id', None), getattr(l, 'insc2_id', None)):
                        if not insc_id:
                            continue
                        insc = db.session.get(Ins, insc_id)
                        if not insc:
                            continue
                        for jid in (getattr(insc, 'jugador1_id', None), getattr(insc, 'jugador2_id', None)):
                            if jid:
                                bucket.add(int(jid))
            return out

        # Fallback participantes
        out['A'].update(self._extraer_ids_de_participante(self.participante_a))
        out['B'].update(self._extraer_ids_de_participante(self.participante_b))
        return out

    def lado_de_jugador(self, jugador_id: int) -> str | None:
        """
        Devuelve 'A' si el jugador está del lado A, 'B' si está del lado B, o None.
        Prioriza LADOS; si no hay, usa participante_a/b.
        """
        if not jugador_id:
            return None
        lados = self.jugadores_ids_por_lado()
        if jugador_id in lados['A']:
            return 'A'
        if jugador_id in lados['B']:
            return 'B'
        return None

    def jugador_participa(self, jugador_id: int) -> bool:
        """
        True si 'jugador_id' pertenece al lado A o B.
        """
        if not jugador_id:
            return False
        return jugador_id in self.jugadores_ids()

    def _nombres_de_ids(self, jugador_ids: list[int]) -> list[str]:
        """
        Resuelve nombres a partir de IDs de Jugador. Falla-silencioso si Jugador no existe.
        Usa db.session.get(...) para evitar LegacyAPIWarning.
        """
        Jug = globals().get('Jugador')
        nombres: list[str] = []
        if not (Jug and jugador_ids):
            return nombres
        for jid in jugador_ids:
            if not jid:
                continue
            try:
                j = db.session.get(Jug, jid)  # SQLAlchemy 2.x
            except Exception:
                j = db.session.query(Jug).get(jid)  # compat
            if j and getattr(j, 'nombre_completo', None):
                nombres.append(j.nombre_completo)
        return nombres

    def nombres_lado(self, lado: str) -> str:
        """
        'A' o 'B' -> "Nombre1 / Nombre2" (o el que haya).
        Prefiere los datos de LADOS si existen; si no, usa participante_a/b.
        """
        # 1) intentar por LADOS
        by_lados = self._nombres_lado_desde_lados(lado)
        if by_lados:
            return " / ".join(by_lados)

        # 2) fallback al participante_a/b (comportamiento original)
        lado = (lado or '').upper()
        tp = self.participante_a if lado == 'A' else self.participante_b
        ids = self._extraer_ids_de_participante(tp)
        nombres = self._nombres_de_ids(ids)
        return " / ".join(nombres) if nombres else f"Lado {lado or '-'}"

    # Azúcar sintáctico útil en templates
    @property
    def ladoA_nombres(self) -> str:
        return self.nombres_lado('A')

    @property
    def ladoB_nombres(self) -> str:
        return self.nombres_lado('B')

    # -----------------------------
    # Azúcar para Paso 2 (listado unificado)
    # -----------------------------
    @property
    def tipo(self) -> str:
        """Etiqueta de tipo para el view-model unificado en /partidos."""
        return "TORNEO"

    @property
    def display_ladoA(self) -> str:
        """Alias legible para plantillas/VM."""
        return self.ladoA_nombres

    @property
    def display_ladoB(self) -> str:
        """Alias legible para plantillas/VM."""
        return self.ladoB_nombres

    @property
    def sort_key(self):
        """Clave de orden estable: primero por fecha (None al final), luego por id desc."""
        from datetime import datetime
        # None al final → usamos tuplas con bandera
        return (self.programado_en is None, self.programado_en or datetime.max, -self.id)

    def to_list_vm(self) -> dict:
        """
        View-model base para mezclar en /partidos.
        (Las URLs se agregan en la ruta con url_for, para no acoplar el modelo a Flask.)
        """
        return {
            "id": f"TP-{self.id}",
            "tipo": self.tipo,
            "torneo_id": self.torneo_id,
            "torneo_nombre": getattr(self.torneo, "nombre", "Torneo"),
            "ronda": self.ronda,
            "estado": self.estado,
            "programado_en": self.programado_en,
            "cancha": self.cancha,
            "ladoA": self.display_ladoA,
            "ladoB": self.display_ladoB,
            # urls: se agregan en la ruta
        }

    # -----------------------------
    # Debug amigable
    # -----------------------------
    def __repr__(self) -> str:
        tn = getattr(self.torneo, "nombre", None)
        return f"<TorneoPartido id={self.id} torneo={tn or self.torneo_id} ronda={self.ronda} estado={self.estado}>"



class TorneoPartidoLado(db.Model):
    __tablename__ = 'torneos_partidos_lados'
    id = db.Column(db.Integer, primary_key=True)

    partido_id = db.Column(db.Integer, db.ForeignKey('torneos_partidos.id', ondelete='CASCADE'), nullable=False, index=True)
    lado = db.Column(db.String(1), nullable=False)  # 'A' o 'B'

    # Inscripciones individuales que formaron la pareja de ese lado en este partido
    insc1_id = db.Column(db.Integer, db.ForeignKey('torneos_inscripciones.id'), nullable=False)
    insc2_id = db.Column(db.Integer, db.ForeignKey('torneos_inscripciones.id'), nullable=False)

    __table_args__ = (
        db.CheckConstraint("lado in ('A','B')", name='chk_lado_A_B'),
        db.UniqueConstraint('partido_id', 'lado', name='uq_partidolado_unico'),
    )

    partido = db.relationship('TorneoPartido', backref=db.backref('lados', cascade="all, delete-orphan", lazy='joined'))

class TorneoLlaveNodo(db.Model):
    __tablename__ = 'torneos_llave_nodos'
    id = db.Column(db.Integer, primary_key=True)
    torneo_id = db.Column(db.Integer, db.ForeignKey('torneos.id'), nullable=False)
    fase_id = db.Column(db.Integer, db.ForeignKey('torneos_fases.id'), nullable=False)

    ronda = db.Column(db.String(20), nullable=True)     # "QF","SF","Final"
    posicion = db.Column(db.Integer, nullable=False, default=1)

    from_nodo_left_id = db.Column(db.Integer, db.ForeignKey('torneos_llave_nodos.id'), nullable=True)
    from_nodo_right_id = db.Column(db.Integer, db.ForeignKey('torneos_llave_nodos.id'), nullable=True)

    partido_id = db.Column(db.Integer, db.ForeignKey('torneos_partidos.id'), nullable=True)
    seed_slot = db.Column(db.Integer, nullable=True)

    torneo = db.relationship('Torneo', backref='llave_nodos', lazy='joined')
    fase = db.relationship('TorneoFase', backref='llave_nodos', lazy='joined')
    partido = db.relationship('TorneoPartido', lazy='joined')

# models.py (junto a tus otros modelos)


class TorneoPartidoResultadoPropuesto(db.Model):
    __tablename__ = 'torneos_partidos_resultados_propuestos'

    id = db.Column(db.Integer, primary_key=True)

    # Un PRP por partido (en DB ya era unique=True, lo dejamos y además documentamos por __table_args__)
    partido_id = db.Column(
        db.Integer,
        db.ForeignKey('torneos_partidos.id', ondelete='CASCADE'),
        nullable=False,
        unique=True,
        index=True
    )

    # 'A' o 'B'
    ganador_lado = db.Column(db.String(1), nullable=False)
    # ej. "6-3, 4-6, 10-8"
    sets_text    = db.Column(db.String(120), nullable=True)

    # tracking / auditoría
    propuesto_por_jugador_id = db.Column(
        db.Integer,
        db.ForeignKey('jugadores.id', ondelete='SET NULL'),
        nullable=True,
        index=True
    )
    # Timestamps consistentes
    creado_en       = db.Column(db.DateTime, nullable=False, server_default=func.now())
    actualizado_en  = db.Column(db.DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    # confirmaciones por lado (None = pendiente; True = acepta; False = rechaza)
    confirma_ladoA = db.Column(db.Boolean, nullable=True)
    confirma_ladoB = db.Column(db.Boolean, nullable=True)

    # Relaciones
    partido = db.relationship(
        'TorneoPartido',
        backref=db.backref('propuesta', uselist=False, lazy='joined'),
        lazy='joined',
        passive_deletes=True
    )
    propuesto_por = db.relationship('Jugador', foreign_keys=[propuesto_por_jugador_id], lazy='joined')

    __table_args__ = (
        # Asegura A/B en DB (si tu motor soporta CHECK)
        CheckConstraint("ganador_lado IN ('A','B')", name='ck_torneo_prp_ganador_lado'),
        # Redundante con unique=True, pero explícito si alguna vez quitas el flag:
        UniqueConstraint('partido_id', name='uq_torneo_prp_partido'),
        # Índices útiles
        Index('ix_torneo_prp_lado', 'ganador_lado'),
    )

    # ------- Helpers de conveniencia (no rompen nada) -------
    @property
    def ambos_confirmaron(self) -> bool:
        return self.confirma_ladoA is True and self.confirma_ladoB is True

    def __repr__(self) -> str:
        return f"<TorneoPRP partido={self.partido_id} ganador={self.ganador_lado}>"


class TorneoPartidoResultado(db.Model):
    __tablename__ = 'torneos_partidos_resultados'

    id = db.Column(db.Integer, primary_key=True)

    # Un resultado definitivo por partido
    partido_id = db.Column(
        db.Integer,
        db.ForeignKey('torneos_partidos.id', ondelete='CASCADE'),
        nullable=False,
        unique=True,
        index=True
    )

    # 'A' o 'B' + ganador_participante_id (participante del torneo)
    ganador_lado = db.Column(db.String(1), nullable=False)
    ganador_participante_id = db.Column(
        db.Integer,
        db.ForeignKey('torneos_participantes.id', ondelete='SET NULL'),
        nullable=False,
        index=True
    )

    sets_text = db.Column(db.String(120), nullable=True)

    # Auditoría de confirmación
    confirmado_en = db.Column(db.DateTime, nullable=False, server_default=func.now())
    confirmado_por_jugador_id = db.Column(
        db.Integer,
        db.ForeignKey('jugadores.id', ondelete='SET NULL'),
        nullable=True,
        index=True
    )

    # Relaciones
    partido = db.relationship(
        'TorneoPartido',
        backref=db.backref('resultado_def', uselist=False, lazy='joined'),
        lazy='joined',
        passive_deletes=True
    )
    ganador_participante = db.relationship('TorneoParticipante', foreign_keys=[ganador_participante_id], lazy='joined')
    confirmado_por = db.relationship('Jugador', foreign_keys=[confirmado_por_jugador_id], lazy='joined')

    __table_args__ = (
        CheckConstraint("ganador_lado IN ('A','B')", name='ck_torneo_res_ganador_lado'),
        UniqueConstraint('partido_id', name='uq_torneo_resultado_partido'),
        Index('ix_torneo_res_lado', 'ganador_lado'),
    )

    def __repr__(self) -> str:
        return f"<TorneoRes partido={self.partido_id} ganador={self.ganador_lado} participante={self.ganador_participante_id}>"



# --------------------------------------------------------------------
# Bootstrap/seed legado: SOLO bajo guardias, nunca en import
# Alembic es el dueño del esquema; no usamos create_all() aquí.
# --------------------------------------------------------------------
def _legacy_bootstrap_minimo():
    """Seed mínimo: asegurar una categoría base y (opcional) crear admin."""
    admin_nombre = os.getenv("ADMIN_NOMBRE")
    admin_pin    = os.getenv("ADMIN_PIN")

    # Asegurar categoría base
    cat = Categoria.query.filter_by(nombre="7ma").first()
    if not cat:
        cat = Categoria(nombre="7ma", puntos_min=0, puntos_max=199)
        db.session.add(cat)
        db.session.commit()

    # Admin opcional (si está configurado por env)
    if admin_nombre and admin_pin:
        admin = Jugador.query.filter_by(nombre_completo=admin_nombre).first()
        if not admin:
            admin = Jugador(
                nombre_completo=admin_nombre,
                email=None,
                telefono=None,
                puntos=150,
                categoria_id=cat.id,
                activo=True,
                is_admin=True,
                pin=admin_pin
            )
            db.session.add(admin)
            db.session.commit()
            print(f"[SEED] Admin creado: {admin_nombre}")
        else:
            changed = False
            if not admin.is_admin:
                admin.is_admin = True
                changed = True
            if not admin.categoria_id:
                admin.categoria_id = cat.id
                changed = True
            if changed:
                db.session.commit()
            print(f"[SEED] Admin ya existía: {admin_nombre}")
    else:
        print("[SEED] ADMIN_NOMBRE/ADMIN_PIN no configurados; seed omitido")

# NOTA: eliminamos completamente:
# - db.create_all()
# - ensure_torneos_schema()
# - los PRAGMAs/ALTER TABLE manuales
# porque ahora los maneja Alembic en migrations/.


# === Compat / Bootstrap de esquema idempotente (SQLite) ===
def _ensure_schema():
    from sqlalchemy import text
    with app.app_context():
        # --- JUGADORES: pin ---
        cols_j = [row[1] for row in db.session.execute(db.text("PRAGMA table_info(jugadores)")).all()]
        if 'pin' not in cols_j:
            db.session.execute(db.text("ALTER TABLE jugadores ADD COLUMN pin TEXT NOT NULL DEFAULT '0000'"))
            db.session.commit()

        # --- PARTIDOS: columnas para propuesta/confirmación de resultado ---
        cols_p = [r[1] for r in db.session.execute(db.text("PRAGMA table_info(partidos)")).all()]

        def add_col_if_missing(col_name, col_type):
            nonlocal cols_p
            if col_name not in cols_p:
                db.session.execute(db.text(f"ALTER TABLE partidos ADD COLUMN {col_name} {col_type}"))
                db.session.commit()
                # refrescar cache local por si más abajo lo volvemos a usar
                cols_p = [r[1] for r in db.session.execute(db.text("PRAGMA table_info(partidos)")).all()]

        # Campos del workflow de resultados
        add_col_if_missing('resultado_propuesto_ganador_pareja_id', 'INTEGER')
        add_col_if_missing('resultado_propuesto_sets_text',         'TEXT')
        add_col_if_missing('resultado_propuesto_por_id',            'INTEGER')
        add_col_if_missing('resultado_propuesto_en',                'TIMESTAMP')
        add_col_if_missing('confirmo_pareja1',                      'INTEGER')  # BOOLEAN = INTEGER en SQLite
        add_col_if_missing('confirmo_pareja2',                      'INTEGER')

        # Índice para orden temporal de propuestas
        db.session.execute(db.text("""
            CREATE INDEX IF NOT EXISTS ix_partidos_resultado_propuesto_en
            ON partidos(resultado_propuesto_en)
        """))
        db.session.commit()

        # --- PARTIDO_ABIERTO_JUGADORES: partner_pref_id ---
        cols = [row[1] for row in db.session.execute(db.text("PRAGMA table_info(partido_abierto_jugadores)")).all()]
        if 'partner_pref_id' not in cols:
            db.session.execute(db.text("ALTER TABLE partido_abierto_jugadores ADD COLUMN partner_pref_id INTEGER"))
            db.session.commit()

        # --- JUGADORES: is_admin + normalización de email + índice parcial único ---
        cols_j = [r[1] for r in db.session.execute(db.text("PRAGMA table_info(jugadores)")).all()]
        if 'is_admin' not in cols_j:
            db.session.execute(db.text("ALTER TABLE jugadores ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"))
            db.session.commit()

        db.session.execute(db.text("UPDATE jugadores SET email = LOWER(email) WHERE email IS NOT NULL"))
        db.session.commit()

        db.session.execute(db.text("""
            CREATE UNIQUE INDEX IF NOT EXISTS ux_jugadores_email
            ON jugadores(email)
            WHERE email IS NOT NULL
        """))
        db.session.commit()

        # --- PARTIDOS: invitaciones (4 jugadores + flags de aceptación) ---
        add_col_if_missing('creador_id',   'INTEGER')
        add_col_if_missing('companero_id', 'INTEGER')
        add_col_if_missing('rival1_id',    'INTEGER')
        add_col_if_missing('rival2_id',    'INTEGER')
        add_col_if_missing('rival1_acepto','INTEGER')  # NULL=sin responder, 1=aceptó, 0=rechazó
        add_col_if_missing('rival2_acepto','INTEGER')

        db.session.execute(db.text("CREATE INDEX IF NOT EXISTS ix_partidos_rival1   ON partidos(rival1_id)"))
        db.session.execute(db.text("CREATE INDEX IF NOT EXISTS ix_partidos_rival2   ON partidos(rival2_id)"))
        db.session.execute(db.text("CREATE INDEX IF NOT EXISTS ix_partidos_creador  ON partidos(creador_id)"))
        db.session.execute(db.text("CREATE INDEX IF NOT EXISTS ix_partidos_estado   ON partidos(estado)"))
        db.session.commit()

        # --- DESAFIOS: flags de aceptación individual + backfill ---
        cols_d = [row[1] for row in db.session.execute(db.text("PRAGMA table_info(desafios)")).all()]
        if 'rival1_acepto' not in cols_d:
            db.session.execute(db.text("ALTER TABLE desafios ADD COLUMN rival1_acepto INTEGER NOT NULL DEFAULT 0"))
            db.session.commit()
        if 'rival2_acepto' not in cols_d:
            db.session.execute(db.text("ALTER TABLE desafios ADD COLUMN rival2_acepto INTEGER NOT NULL DEFAULT 0"))
            db.session.commit()

        db.session.execute(db.text(
            "UPDATE desafios SET rival1_acepto=1, rival2_acepto=1 WHERE estado IN ('ACEPTADO','JUGADO')"
        ))
        db.session.commit()

        # --- PARTIDO_RESULTADO_PROPUESTO: crear tabla si falta + índice ---
        tables = [r[0] for r in db.session.execute(db.text("SELECT name FROM sqlite_master WHERE type='table'")).all()]
        if 'partido_resultado_propuesto' not in tables:
            db.session.execute(db.text("""
                CREATE TABLE partido_resultado_propuesto (
                    id INTEGER PRIMARY KEY,
                    partido_id INTEGER NOT NULL UNIQUE,
                    propuesto_por_pareja_id INTEGER NOT NULL,
                    ganador_pareja_id INTEGER NOT NULL,
                    sets_text TEXT,
                    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(partido_id) REFERENCES partidos(id),
                    FOREIGN KEY(propuesto_por_pareja_id) REFERENCES parejas(id),
                    FOREIGN KEY(ganador_pareja_id) REFERENCES parejas(id)
                )
            """))
            db.session.commit()

        db.session.execute(db.text("""
            CREATE INDEX IF NOT EXISTS ix_prp_creado_en ON partido_resultado_propuesto(creado_en)
        """))
        db.session.commit()

    print("[ensure-schema] compat/DDL aplicado OK")
    

# === Comando CLI para ejecutarlo post-migraciones ===
@app.cli.command("ensure-schema")
def ensure_schema_cmd():
    """Aplica compat/DDL idempotente tras alembic upgrade."""
    _ensure_schema()



# Config puntos (ajustable)
DELTA_WIN = -10
DELTA_LOSS = +5
DELTA_WIN_BONUS = -3   # extra por compañero repetido (desde la 3ª victoria conjunta)
BONUS_APLICA_DESDE = 3 # a partir de cuántas victorias juntos empieza a aplicar

# === Hora local para templates (con filtros Jinja) ===
APP_TZ = ZoneInfo("America/Argentina/Salta")  # o "America/Argentina/Buenos_Aires"


def _assume_utc(dt):
    """Trata datetimes naive como UTC (guardamos en UTC)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def to_local(dt):
    """Convierte un datetime (naive=UTC) a la zona APP_TZ."""
    dt_utc = _assume_utc(dt)
    return dt_utc.astimezone(APP_TZ) if dt_utc else None

@app.template_filter("localdt")
def jinja_localdt(dt, fmt="%Y-%m-%d %H:%M"):
    """Uso: {{ obj.fecha|localdt('%d/%m %H:%M') }}"""
    dt_loc = to_local(dt)
    return dt_loc.strftime(fmt) if dt_loc else "-"

@app.template_filter("utcms")
def jinja_utcms(dt):
    """Devuelve epoch ms asumiendo UTC para JS (contadores)."""
    dt_utc = _assume_utc(dt)
    return int(dt_utc.timestamp() * 1000) if dt_utc else ""

# ===== Seed seguro: solo si el esquema está listo y no estamos corriendo comandos de DB =====
from sqlalchemy import inspect

def _is_running_db_command():
    """Detecta si el proceso actual está ejecutando un comando de migración (flask db ...)."""
    import sys
    cmds = ("db", "migrate", "upgrade", "downgrade", "stamp", "current", "heads")
    return any(c in sys.argv for c in cmds)

# --- Seed seguro (no correr en comandos de DB / Alembic / esquema incompleto) ---
def _run_seed_if_ready():
    import sys, os, logging
    from sqlalchemy import text

    try:
        argv = " ".join(sys.argv).lower()

        # 1) Kill-switch por env
        if os.getenv("SEED_DISABLED") == "1":
            print("[SEED] deshabilitado por SEED_DISABLED=1; seed omitido")
            return

        # 2) No correr en comandos de DB/Alembic
        blocked_tokens = (" db ", "alembic", "upgrade", "migrate", "stamp", "current", "heads")
        if any(tok in argv for tok in blocked_tokens):
            print("[SEED] deshabilitado (comando DB/aleembic); seed omitido")
            return

        # 3) Sólo correr cuando el esquema YA tiene las columnas nuevas (migración aplicada)
        with app.app_context():
            try:
                cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(jugadores)")).all()]
            except Exception:
                print("[SEED] tabla 'jugadores' no accesible; seed omitido")
                return

            needed = {"pais", "provincia", "ciudad", "fecha_nacimiento"}
            if not needed.issubset(set(cols)):
                print("[SEED] esquema incompleto (faltan columnas nuevas en 'jugadores'); seed omitido")
                return

            # 4) Asegurar categoría base mínima (evita usar Jugador ORM para no hacer SELECT *)
            #    Usamos ORM en Categoria porque su esquema no cambió con esta migración.
            base_cat = Categoria.query.filter_by(nombre="7ma").first()
            if not base_cat:
                base_cat = Categoria(nombre="7ma", puntos_min=0, puntos_max=199)
                db.session.add(base_cat)
                db.session.commit()
                print("[SEED] categoría base '7ma' creada")

            # 5) Crear admin sólo si ADMIN_* está configurado y no existe
            admin_nombre = os.getenv('ADMIN_NOMBRE')
            admin_pin    = os.getenv('ADMIN_PIN')
            if not admin_nombre or not admin_pin:
                print("[SEED] ADMIN_NOMBRE/ADMIN_PIN no configurados; seed omitido")
                return

            # Chequeo de existencia SIN ORM (evita SELECT * de Jugador)
            exists = db.session.execute(
                text("SELECT 1 FROM jugadores WHERE nombre_completo = :n LIMIT 1"),
                {"n": admin_nombre}
            ).first()

            if not exists:
                # Crear admin con ORM (INSERT sólo incluye columnas seteadas; las nuevas son NULL por defecto)
                admin = Jugador(
                    nombre_completo=admin_nombre,
                    email=None,
                    telefono=None,
                    puntos=150,
                    categoria_id=base_cat.id,
                    activo=True,
                    is_admin=True,
                    pin=admin_pin
                )
                db.session.add(admin)
                db.session.commit()
                print(f"[SEED] admin creado: {admin_nombre}")
            else:
                # Asegurar flags básicos sin hacer un SELECT * completo: actualizamos por SQL crudo
                db.session.execute(
                    text("""
                        UPDATE jugadores
                        SET is_admin = 1,
                            categoria_id = COALESCE(categoria_id, :catid),
                            activo = COALESCE(activo, 1)
                        WHERE nombre_completo = :n
                    """),
                    {"catid": base_cat.id, "n": admin_nombre}
                )
                db.session.commit()
                print(f"[SEED] admin ya existía: {admin_nombre}")

    except Exception:
        logging.exception("[SEED] error inesperado; seed omitido")

# IMPORTANTE: mantener esta llamada al final del módulo
_run_seed_if_ready()

# ----------------------------
# RUTAS
# ----------------------------
@app.route('/')
def home():
    j = get_current_jugador()
    en_zona = False
    if j and j.categoria and j.puntos is not None:
        en_zona = (j.puntos <= j.categoria.puntos_min)

    return render_template('index.html', en_zona=en_zona)

@app.route('/alta', methods=['GET', 'POST'])
def alta_publica():
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()

    if request.method == 'POST':
        from datetime import datetime
        from zoneinfo import ZoneInfo
        import logging, os

        nombre = (request.form.get('nombre_completo') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        telefono = (request.form.get('telefono') or '').strip()
        categoria_id = request.form.get('categoria_id', type=int)
        mensaje = (request.form.get('mensaje') or '').strip()
        tel_cc = (request.form.get('tel_cc') or '').strip() or '54'
        tel_local = (request.form.get('tel_local') or '').strip()

        # === Datos personales opcionales ===
        def _safe_title(s: str | None):
            if not s:
                return None
            return " ".join(w.capitalize() for w in s.strip().split())

        def _parse_date_yyyy_mm_dd(s: str | None):
            if not s:
                return None
            try:
                return datetime.strptime(s, "%Y-%m-%d").date()
            except Exception:
                return None

        pais = _safe_title(request.form.get('pais'))
        provincia = _safe_title(request.form.get('provincia'))
        ciudad = _safe_title(request.form.get('ciudad'))
        fecha_nacimiento = _parse_date_yyyy_mm_dd(request.form.get('fecha_nacimiento'))

        # === Validaciones básicas ===
        if not nombre:
            flash('El nombre es obligatorio.', 'error')
            return redirect(url_for('alta_publica'))
        if not categoria_id:
            flash('La categoría es obligatoria.', 'error')
            return redirect(url_for('alta_publica'))
        if not email or '@' not in email or len(email) < 6:
            flash('Ingresá un email válido.', 'error')
            return redirect(url_for('alta_publica'))

        # === Validación de teléfono ===
        def only_digits(s: str) -> str:
            return ''.join(ch for ch in s if ch.isdigit())

        telefono_final = ''
        if tel_local:
            cc_digits = only_digits(tel_cc)
            local_digits = only_digits(tel_local)
            if len(local_digits) < 7:
                flash('Ingresá un teléfono válido (mínimo 7 dígitos en el número local).', 'error')
                return redirect(url_for('alta_publica'))
            if not cc_digits:
                flash('Ingresá un código de país válido.', 'error')
                return redirect(url_for('alta_publica'))
            telefono_final = f'+{cc_digits}{local_digits}'
        else:
            if not telefono:
                flash('El teléfono es obligatorio.', 'error')
                return redirect(url_for('alta_publica'))
            tel_digits = only_digits(telefono)
            if len(tel_digits) < 7:
                flash('Ingresá un teléfono válido (mínimo 7 dígitos).', 'error')
                return redirect(url_for('alta_publica'))
            if telefono.strip().startswith('+'):
                telefono_final = '+' + tel_digits
            else:
                telefono_final = f'+54{tel_digits}'

        cat = db.session.get(Categoria, int(categoria_id)) if categoria_id else None
        if not cat:
            flash('Categoría inválida.', 'error')
            return redirect(url_for('alta_publica'))

        # === Validaciones de duplicado ===
        existe_pend = (db.session.query(SolicitudAlta)
                       .filter(SolicitudAlta.email == email,
                               SolicitudAlta.estado == 'PENDIENTE')
                       .first())
        if existe_pend:
            flash('Ya hay una solicitud pendiente con ese email. Te contactaremos pronto.', 'error')
            return redirect(url_for('alta_publica'))

        existe_jugador = db.session.query(Jugador).filter(Jugador.email == email).first()
        if existe_jugador:
            flash('Ese email ya está registrado como jugador. Probá iniciar sesión o contactá al organizador.', 'error')
            return redirect(url_for('alta_publica'))

        # === Normalizar nombre ===
        nombre_upper = nombre.upper()

        # === Crear nueva solicitud ===
        s = SolicitudAlta(
            nombre_completo=nombre_upper,
            email=email,
            telefono=telefono_final,
            categoria_id=cat.id,
            mensaje=mensaje or None,
            estado='PENDIENTE',
            pais=pais,
            provincia=provincia,
            ciudad=ciudad,
            fecha_nacimiento=fecha_nacimiento,
        )
        db.session.add(s)
        db.session.commit()

        # === Envío de notificación a admins ===
        try:
            admin_emails = [e.strip() for e in (os.getenv('ADMIN_EMAILS') or '').split(',') if e.strip()]
            if admin_emails:
                ahora_ar = datetime.now(ZoneInfo('America/Argentina/Buenos_Aires')).strftime('%Y-%m-%d %H:%M')
                fn_str = fecha_nacimiento.strftime('%Y-%m-%d') if fecha_nacimiento else '-'
                body = (
                    "📥 NUEVA SOLICITUD DE ALTA\n\n"
                    f"👤 Nombre: {nombre_upper}\n"
                    f"✉️ Email: {email}\n"
                    f"📞 Teléfono: {telefono_final}\n"
                    f"🏆 Categoría solicitada: {cat.nombre} (ID {cat.id})\n"
                    f"🌎 Ubicación: {pais or '-'} / {provincia or '-'} / {ciudad or '-'}\n"
                    f"🎂 Fecha de nacimiento: {fn_str}\n"
                    f"💬 Mensaje: {mensaje or '-'}\n"
                    f"🕓 Fecha/Hora (AR): {ahora_ar}\n\n"
                    "Revisar en el panel: /admin/solicitudes"
                )
                ok = send_mail(
                    subject=f'Nueva solicitud de alta: {nombre_upper}',
                    body=body,
                    to=admin_emails
                )
                current_app.logger.info(f"Notificación enviada a admins={admin_emails}, send_mail={ok}")
            else:
                logging.warning('ADMIN_EMAILS vacío; no se envía aviso de alta.')
        except Exception as e:
            logging.exception('Fallo enviando email de notificación de nueva solicitud de alta.')

        flash('✅ Solicitud enviada correctamente. Un administrador la revisará en breve.', 'success')
        return redirect(url_for('home'))

    # GET
    return render_template('alta_form.html', categorias=categorias)



def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        j = get_current_jugador()
        if not j or not getattr(j, 'is_admin', False):
            flash('Acceso de administrador requerido.', 'error')
            return redirect(url_for('home'))
        return fn(*args, **kwargs)
    return wrapper


# --- Categorías ---
@app.route('/categorias')
def categorias_list():
    cats = Categoria.query.order_by(Categoria.puntos_min.desc()).all()
    return render_template('categorias_list.html', categorias=cats)

from flask import render_template, request, redirect, url_for, flash, abort

@app.route('/categorias/nueva', methods=['GET', 'POST'])
@admin_required
def categorias_new():
    if request.method == 'POST':
        nombre = (request.form.get('nombre') or '').strip()
        puntos_min = request.form.get('puntos_min')
        puntos_max = request.form.get('puntos_max')

        # Validaciones básicas
        if not nombre or puntos_min is None or puntos_max is None:
            flash('Completá todos los campos.', 'error')
            return redirect(url_for('categorias_new'))

        try:
            pmin = int(puntos_min)
            pmax = int(puntos_max)
        except ValueError:
            flash('Los puntos deben ser números enteros.', 'error')
            return redirect(url_for('categorias_new'))

        if pmin < 0 or pmax < 0 or pmin >= pmax:
            flash('Verificá el rango: puntos_min < puntos_max y ambos ≥ 0.', 'error')
            return redirect(url_for('categorias_new'))

        # Unicidad por nombre
        if Categoria.query.filter_by(nombre=nombre).first():
            flash('Ya existe una categoría con ese nombre.', 'error')
            return redirect(url_for('categorias_new'))

        # (Opcional) Evitar solapamiento de rangos con categorías existentes
        # Descomentar si querés forzar que los rangos no se pisen:
        # solapada = Categoria.query.filter(
        #     db.or_(
        #         db.and_(Categoria.puntos_min <= pmin, Categoria.puntos_max >= pmin),
        #         db.and_(Categoria.puntos_min <= pmax, Categoria.puntos_max >= pmax),
        #         db.and_(Categoria.puntos_min >= pmin, Categoria.puntos_max <= pmax)
        #     )
        # ).first()
        # if solapada:
        #     flash(f'El rango se solapa con la categoría "{solapada.nombre}".', 'error')
        #     return redirect(url_for('categorias_new'))

        try:
            cat = Categoria(nombre=nombre, puntos_min=pmin, puntos_max=pmax)
            db.session.add(cat)
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash('Ocurrió un error al guardar la categoría.', 'error')
            return redirect(url_for('categorias_new'))

        flash('Categoría creada.', 'ok')
        return redirect(url_for('categorias_list'))

    return render_template('categorias_form.html')

# --- Editar categoría ---
@app.route('/categorias/<int:cat_id>/editar', methods=['GET', 'POST'])
@admin_required
def categorias_edit(cat_id):
    c = get_or_404(Categoria, cat_id)

    if request.method == 'POST':
        nombre = (request.form.get('nombre') or '').strip()
        puntos_min = request.form.get('puntos_min')
        puntos_max = request.form.get('puntos_max')

        if not nombre or puntos_min is None or puntos_max is None:
            flash('Completá todos los campos.', 'error')
            return redirect(url_for('categorias_edit', cat_id=c.id))

        try:
            pmin = int(puntos_min)
            pmax = int(puntos_max)
        except ValueError:
            flash('Los puntos deben ser enteros.', 'error')
            return redirect(url_for('categorias_edit', cat_id=c.id))

        if pmin < 0 or pmax < 0 or pmin >= pmax:
            flash('Verificá el rango: puntos_min < puntos_max y ambos ≥ 0.', 'error')
            return redirect(url_for('categorias_edit', cat_id=c.id))

        # Unicidad por nombre (excluyendo la misma categoría)
        existe = (db.session.query(Categoria)
                  .filter(Categoria.nombre == nombre, Categoria.id != c.id)
                  .first())
        if existe:
            flash('Ya existe otra categoría con ese nombre.', 'error')
            return redirect(url_for('categorias_edit', cat_id=c.id))

        # Seguridad: asegurarnos de no dejar jugadores fuera del rango
        fuera_de_rango = (
            db.session.query(Jugador)
            .filter(Jugador.categoria_id == c.id)
            .filter(db.or_(Jugador.puntos < pmin, Jugador.puntos > pmax))
            .count()
        )
        if fuera_de_rango:
            flash('No se puede ajustar el rango: hay jugadores con puntos fuera del nuevo rango.', 'error')
            return redirect(url_for('categorias_edit', cat_id=c.id))

        # Guardar
        c.nombre = nombre
        c.puntos_min = pmin
        c.puntos_max = pmax
        db.session.commit()
        flash('Categoría actualizada.', 'ok')
        return redirect(url_for('categorias_list'))

    # GET
    return render_template('categorias_form.html', categoria=c)


# --- Eliminar categoría ---
@app.route('/categorias/<int:cat_id>/eliminar', methods=['POST'])
@admin_required
def categorias_delete(cat_id):
    c = get_or_404(Categoria, cat_id)

    # No permitir borrar si tiene datos asociados
    jugadores = db.session.query(Jugador).filter_by(categoria_id=c.id).count()
    parejas   = db.session.query(Pareja).filter_by(categoria_id=c.id).count()
    partidos  = db.session.query(Partido).filter_by(categoria_id=c.id).count()
    abiertos  = db.session.query(PartidoAbierto).filter_by(categoria_id=c.id).count()
    desafios_origen   = db.session.query(Desafio).filter_by(categoria_origen_id=c.id).count()
    desafios_superior = db.session.query(Desafio).filter_by(categoria_superior_id=c.id).count()

    total_refs = jugadores + parejas + partidos + abiertos + desafios_origen + desafios_superior
    if total_refs > 0:
        flash('No se puede eliminar: hay registros que dependen de esta categoría (jugadores/parejas/partidos/abiertos/desafíos).', 'error')
        return redirect(url_for('categorias_list'))

    db.session.delete(c)
    db.session.commit()
    flash('Categoría eliminada.', 'ok')
    return redirect(url_for('categorias_list'))



# --- Jugadores ---
from sqlalchemy import func

@app.route('/jugadores')
def jugadores_list():
    from flask import g
    from sqlalchemy import func  # para DISTINCT en provincias/ciudades

    # ====== Jugador actual + flag admin ======
    current_jugador = getattr(g, 'current_jugador', None)
    if not current_jugador and 'get_current_jugador' in globals():
        try:
            current_jugador = get_current_jugador()
        except Exception:
            current_jugador = None
    is_admin = bool(current_jugador and getattr(current_jugador, 'is_admin', False))

    # ====== Parámetros GET (manteniendo lo que ya tenías) ======
    raw_inactivos = request.args.get('inactivos', default=0, type=int)  # 1 = incluir inactivos
    q_text        = (request.args.get('q') or '').strip()
    categoria_id  = request.args.get('categoria_id', type=int)
    solo_mi_cat   = request.args.get('solo_mi_cat', type=int) == 1

    # NUEVOS filtros de ubicación
    provincia     = (request.args.get('provincia') or '').strip()
    ciudad        = (request.args.get('ciudad') or '').strip()

    # ====== Solo permitir ver inactivos a admins ======
    mostrar_inactivos = 1 if (is_admin and raw_inactivos == 1) else 0

    # ====== Mantener estado de jugadores (tu helper) ======
    asegurar_estado_jugadores()

    # ====== Base query ======
    base = db.session.query(Jugador)

    # Activos / inactivos (igual que antes)
    if mostrar_inactivos != 1:
        base = base.filter(Jugador.activo.is_(True))

    # Filtro por categoría elegida o "solo mi categoría"
    if categoria_id:
        base = base.filter(Jugador.categoria_id == categoria_id)
    elif solo_mi_cat:
        if current_jugador and getattr(current_jugador, 'categoria_id', None):
            base = base.filter(Jugador.categoria_id == current_jugador.categoria_id)

    # Buscador por nombre (en DB, case-insensitive)
    if q_text:
        like = f"%{q_text}%"
        base = base.filter(Jugador.nombre_completo.ilike(like))

    # ====== Filtros de ubicación (solo si vienen con valor) ======
    if provincia:
        base = base.filter(Jugador.provincia == provincia)
    if ciudad:
        base = base.filter(Jugador.ciudad == ciudad)

    # Orden original por nombre (preservado)
    base = base.order_by(Jugador.nombre_completo.asc())
    jugadores = base.all()

    # ====== Combo de categorías (como tenías) ======
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()

    # ====== Listas únicas para filtros de ubicación ======
    # (coherente con visibilidad de inactivos)
    base_distinct = db.session.query(Jugador)
    if mostrar_inactivos != 1:
        base_distinct = base_distinct.filter(Jugador.activo.is_(True))

    # Provincias disponibles (no nulas ni vacías)
    provincias = [
        r[0] for r in base_distinct
            .with_entities(func.distinct(Jugador.provincia))
            .filter(Jugador.provincia.isnot(None), Jugador.provincia != '')
            .order_by(Jugador.provincia.asc())
            .all()
    ]

    # Ciudades disponibles (si hay provincia seleccionada, acotar a esa)
    ciudades_q = base_distinct.with_entities(func.distinct(Jugador.ciudad)) \
                              .filter(Jugador.ciudad.isnot(None), Jugador.ciudad != '')
    if provincia:
        ciudades_q = ciudades_q.filter(Jugador.provincia == provincia)
    ciudades = [r[0] for r in ciudades_q.order_by(Jugador.ciudad.asc()).all()]

    # ====== Zona de ascenso (tu lógica original) ======
    zona_ascenso = {}
    for j in jugadores:
        cat = j.categoria
        zona_ascenso[j.id] = bool(cat and j.puntos is not None and j.puntos <= cat.puntos_min)

    # ====== Render ======
    return render_template(
        'jugadores_list.html',
        jugadores=jugadores,
        categorias=categorias,
        zona_ascenso=zona_ascenso,
        mostrar_inactivos=mostrar_inactivos,
        q=q_text,
        categoria_id=categoria_id,
        solo_mi_cat=1 if solo_mi_cat else 0,
        # filtros de ubicación
        provincia=provincia,
        ciudad=ciudad,
        provincias=provincias,
        ciudades=ciudades,
        # el template usa current_jugador
        current_jugador=current_jugador
    )




@app.route('/jugadores/nuevo', methods=['GET', 'POST'])
def jugadores_new():
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()

    if request.method == 'POST':
        nombre = (request.form.get('nombre_completo') or '').strip()
        email = (request.form.get('email') or '').strip()
        telefono_compat = (request.form.get('telefono') or '').strip()  # compat: campo viejo
        puntos = request.form.get('puntos')
        categoria_id = request.form.get('categoria_id')

        # NUEVO: teléfono partido (opcional)
        tel_cc = (request.form.get('tel_cc') or '').strip()
        tel_local = (request.form.get('tel_local') or '').strip()

        # NUEVO: ubicación + fecha de nacimiento (opcionales)
        pais = (request.form.get('pais') or '').strip() or None
        provincia = (request.form.get('provincia') or '').strip() or None
        ciudad = (request.form.get('ciudad') or '').strip() or None
        fn_raw = (request.form.get('fecha_nacimiento') or '').strip()

        # === Helpercitos locales (no tocan el resto de tu app) ===
        def only_digits(s: str) -> str:
            return ''.join(ch for ch in (s or '') if ch.isdigit())

        def parse_fecha_yyyy_mm_dd(s: str):
            if not s:
                return None
            try:
                from datetime import datetime
                return datetime.strptime(s, '%Y-%m-%d').date()
            except Exception:
                return None

        # === Validaciones originales ===
        if not nombre or not puntos or not categoria_id:
            flash('Nombre, puntos y categoría son obligatorios.', 'error')
            return redirect(url_for('jugadores_new'))

        try:
            pts = int(puntos)
        except ValueError:
            flash('Los puntos deben ser un entero.', 'error')
            return redirect(url_for('jugadores_new'))

        cat = db.session.get(Categoria, int(categoria_id))
        if not cat:
            flash('Categoría inválida.', 'error')
            return redirect(url_for('jugadores_new'))

        # Validar rango de puntos (igual que antes)
        if not (cat.puntos_min <= pts <= cat.puntos_max):
            flash(f'Los puntos {pts} no están dentro del rango de la categoría {cat.nombre} ({cat.rango()}).', 'error')
            return redirect(url_for('jugadores_new'))

        # === Armar teléfono final (opcional) ===
        telefono_final = None
        if tel_local:
            cc_digits = only_digits(tel_cc)
            local_digits = only_digits(tel_local)
            if cc_digits and len(local_digits) >= 7:
                telefono_final = f'+{cc_digits}{local_digits}'
            else:
                # si no es válido, no bloqueamos el alta porque antes era opcional
                # podrías flashear aviso suave si querés:
                # flash('Teléfono ingresado incompleto, se guarda vacío.', 'warning')
                telefono_final = None
        elif telefono_compat:
            # compat: si viene el viejo, normalizamos lo que se pueda
            tel_digits = only_digits(telefono_compat)
            if telefono_compat.startswith('+') and tel_digits:
                telefono_final = '+' + tel_digits
            else:
                # si no empieza con +, lo dejamos como estaba (opcional) o None si no hay dígitos
                telefono_final = '+' + tel_digits if tel_digits else None

        # === Parse fecha de nacimiento (opcional) ===
        fecha_nacimiento = parse_fecha_yyyy_mm_dd(fn_raw)

        # === Crear jugador (misma semántica que tenías) ===
        jug = Jugador(
            nombre_completo=nombre,
            email=email or None,
            telefono=telefono_final,
            puntos=pts,
            categoria_id=cat.id,
            # NUEVOS CAMPOS (opcionales)
            pais=pais,
            provincia=provincia,
            ciudad=ciudad,
            fecha_nacimiento=fecha_nacimiento,
        )
        db.session.add(jug)
        db.session.commit()

        flash('Jugador creado.', 'ok')
        return redirect(url_for('jugadores_list'))

    return render_template('jugadores_form.html', categorias=categorias)

# --- Editar jugador ---
@app.route('/jugadores/<int:jugador_id>/editar', methods=['GET', 'POST'])
def jugadores_edit(jugador_id):
    j = get_or_404(Jugador, jugador_id)
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()

    if request.method == 'POST':
        # --- Campos básicos
        nombre = (request.form.get('nombre_completo') or '').strip()
        email = (request.form.get('email') or '').strip()
        telefono_compat = (request.form.get('telefono') or '').strip()  # compat
        puntos = request.form.get('puntos')
        categoria_id = request.form.get('categoria_id')
        pin = (request.form.get('pin') or '').strip()  # opcional
        is_admin_form = request.form.get('is_admin')   # '1' si viene marcado

        # --- Teléfono partido
        tel_cc = (request.form.get('tel_cc') or '').strip()
        tel_local = (request.form.get('tel_local') or '').strip()

        # --- Nuevos datos personales
        pais = (request.form.get('pais') or '').strip() or None
        provincia = (request.form.get('provincia') or '').strip() or None
        ciudad = (request.form.get('ciudad') or '').strip() or None
        fecha_nacimiento_raw = (request.form.get('fecha_nacimiento') or '').strip()

        # --- Validaciones mínimas
        if not nombre or not puntos or not categoria_id:
            flash('Nombre, puntos y categoría son obligatorios.', 'error')
            return redirect(url_for('jugadores_edit', jugador_id=j.id))

        try:
            pts = int(puntos)
            cat_id = int(categoria_id)
        except ValueError:
            flash('Los puntos y la categoría deben ser válidos.', 'error')
            return redirect(url_for('jugadores_edit', jugador_id=j.id))

        cat = db.session.get(Categoria, cat_id) if cat_id is not None else None
        if not cat:
            flash('Categoría inválida.', 'error')
            return redirect(url_for('jugadores_edit', jugador_id=j.id))

        # Rango de puntos de la categoría
        if not (cat.puntos_min <= pts <= cat.puntos_max):
            flash(f'Los puntos {pts} no están dentro del rango de la categoría {cat.nombre} ({cat.puntos_min}–{cat.puntos_max}).', 'error')
            return redirect(url_for('jugadores_edit', jugador_id=j.id))

        # Si el PIN viene cargado, validarlo (4–6 dígitos)
        if pin:
            if not (pin.isdigit() and 4 <= len(pin) <= 6):
                flash('El PIN debe tener 4–6 dígitos numéricos.', 'error')
                return redirect(url_for('jugadores_edit', jugador_id=j.id))
            j.pin = pin  # actualizar PIN

        # --- Teléfono: priorizamos tel_cc + tel_local; si no, usamos compat
        def only_digits(s: str) -> str:
            return ''.join(ch for ch in s if ch.isdigit())

        telefono_final = None
        if tel_cc or tel_local:
            cc = only_digits(tel_cc) if tel_cc else ''
            local = only_digits(tel_local) if tel_local else ''
            if not local or len(local) < 7:
                flash('Ingresá un teléfono válido: el número local debe tener al menos 7 dígitos.', 'error')
                return redirect(url_for('jugadores_edit', jugador_id=j.id))
            if not cc:
                flash('Ingresá un código de país válido (1–4 dígitos).', 'error')
                return redirect(url_for('jugadores_edit', jugador_id=j.id))
            telefono_final = f'+{cc}{local}'
        else:
            tel_dig = only_digits(telefono_compat)
            if tel_dig:
                # si ya venía con +, preservamos + y dígitos; si no, guardamos como +<digits>
                telefono_final = ('+' + tel_dig) if telefono_compat.strip().startswith('+') else ('+' + tel_dig)
            else:
                telefono_final = None  # teléfono opcional al editar

        # --- Fecha de nacimiento
        fecha_nacimiento = None
        if fecha_nacimiento_raw:
            try:
                fecha_nacimiento = datetime.strptime(fecha_nacimiento_raw, '%Y-%m-%d').date()
            except ValueError:
                flash('Fecha de nacimiento inválida.', 'error')
                return redirect(url_for('jugadores_edit', jugador_id=j.id))

        # --- Guardar cambios
        j.nombre_completo = nombre.upper()
        j.email = email or None
        j.telefono = telefono_final
        j.puntos = pts
        j.categoria_id = cat.id

        j.pais = pais
        j.provincia = provincia
        j.ciudad = ciudad
        j.fecha_nacimiento = fecha_nacimiento

        # Solo un admin puede cambiar el flag de admin
        cur = get_current_jugador()
        if cur and cur.is_admin:
            j.is_admin = bool(is_admin_form)

        db.session.commit()
        flash('Jugador actualizado.', 'ok')
        return redirect(url_for('jugadores_list'))

    # GET
    return render_template('jugadores_form.html', categorias=categorias, jugador=j)

# --- Eliminar (soft-delete) jugador + inactivar parejas ---
@app.route('/jugadores/<int:jugador_id>/eliminar', methods=['POST'])
@admin_required
def jugadores_delete(jugador_id):
    j = get_or_404(Jugador, jugador_id)

    try:
        # 1) Inactivar/romper sus parejas
        _inactivar_parejas_de(j.id)

        # 2) Sacar inscripciones a abiertos (opcional pero recomendado para no dejar “fantasmas”)
        db.session.query(PartidoAbiertoJugador).filter_by(jugador_id=j.id).delete()

        # 3) Borrar estado/contadores si existe (lo mantenías)
        JugadorEstado.query.filter_by(jugador_id=j.id).delete()

        # 4) Soft-delete del jugador (no se elimina la fila)
        if hasattr(Jugador, 'activo'):
            j.activo = False
        else:
            # Si tu modelo no tiene 'activo', último recurso: borrar
            db.session.delete(j)

        db.session.commit()
        flash(f'Se desactivó a "{j.nombre_completo}" y se inactivaron sus parejas.', 'ok')

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Error soft-delete jugador %s: %s", j.id, e)
        flash(f'No se pudo desactivar al jugador: {e}', 'error')

    return redirect(url_for('jugadores_list'))


@app.route('/jugadores/<int:jugador_id>/desactivar', methods=['POST'])
@admin_required
def jugadores_deactivate(jugador_id):
    j = get_or_404(Jugador, jugador_id)

    if hasattr(Jugador, 'activo') and not j.activo:
        flash('El jugador ya estaba inactivo.', 'error')
        return redirect(url_for('jugadores_list'))

    try:
        # Inactivar/romper sus parejas (o borrar si tu modelo no tiene .activa)
        _inactivar_parejas_de(j.id)

        # Quitar inscripciones a “partidos abiertos” para no dejar pendientes
        db.session.query(PartidoAbiertoJugador).filter_by(jugador_id=j.id).delete()

        # Dejar en falso el flag activo (soft-delete)
        if hasattr(Jugador, 'activo'):
            j.activo = False
        else:
            # Si tu modelo no tiene 'activo', no lo borro aquí (la ruta eliminar ya contempla ese caso)
            pass

        db.session.commit()
        flash(f'Se desactivó a {j.nombre_completo}. Ya no aparecerá para nuevos partidos/desafíos.', 'ok')

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Error desactivando jugador %s: %s", j.id, e)
        flash(f'No se pudo desactivar al jugador: {e}', 'error')

    return redirect(url_for('jugadores_list'))


@app.route('/jugadores/<int:jugador_id>/reactivar', methods=['POST'])
@admin_required
def jugadores_activate(jugador_id):
    j = get_or_404(Jugador, jugador_id)

    if hasattr(Jugador, 'activo') and j.activo:
        flash('El jugador ya estaba activo.', 'error')
        return redirect(url_for('jugadores_list'))

    try:
        # Reactivar jugador (soft-undelete)
        if hasattr(Jugador, 'activo'):
            j.activo = True

        # NOTA: No reactivamos parejas antiguas automáticamente.
        #       Si hace falta, se crearán nuevas al volver a jugar.
        db.session.commit()
        flash(f'{j.nombre_completo} reactivado.', 'ok')

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Error reactivando jugador %s: %s", j.id, e)
        flash(f'No se pudo reactivar al jugador: {e}', 'error')

    return redirect(url_for('jugadores_list'))


# --- Parejas (solo vista vacía por ahora) ---
@app.route('/parejas')
def parejas_list():
    parejas = (db.session.query(Pareja)
               .order_by(Pareja.creada_en.desc())
               .all())
    return redirect(url_for('partidos_list'))


@app.context_processor
def inject_now():
    # now: fecha/hora actual en UTC
    # timedelta: para hacer cálculos (p.ej., now + timedelta(hours=12)) en Jinja
    return {
        'now': datetime.utcnow(),
        'timedelta': timedelta,
    }

@app.route('/parejas/nueva', methods=['GET','POST'])
def parejas_new():
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()
    jugadores = Jugador.query.order_by(Jugador.nombre_completo.asc()).all()

    if request.method == 'POST':
        categoria_id = request.form.get('categoria_id')
        j1_id = request.form.get('jugador1_id')
        j2_id = request.form.get('jugador2_id')

        # Validaciones básicas
        if not categoria_id or not j1_id or not j2_id:
            flash('Elegí categoría y 2 jugadores.', 'error')
            return redirect(url_for('parejas_new'))

        if j1_id == j2_id:
            flash('Los dos jugadores deben ser distintos.', 'error')
            return redirect(url_for('parejas_new'))

        cat = db.session.get(Categoria, int(categoria_id))
        j1 = db.session.get(Jugador, int(j1_id))
        j2 = db.session.get(Jugador, int(j2_id))
        if not cat or not j1 or not j2:
            flash('Datos inválidos.', 'error')
            return redirect(url_for('parejas_new'))

        # Ambos jugadores deben pertenecer a la MISMA categoría seleccionada
        if j1.categoria_id != cat.id or j2.categoria_id != cat.id:
            flash('Ambos jugadores deben pertenecer a la categoría elegida.', 'error')
            return redirect(url_for('parejas_new'))

        # Evitar duplicado j1-j2 o j2-j1 en la misma categoría
        existe = (db.session.query(Pareja)
                  .filter(Pareja.categoria_id == cat.id)
                  .filter(
                      or_(
                          and_(Pareja.jugador1_id == j1.id, Pareja.jugador2_id == j2.id),
                          and_(Pareja.jugador1_id == j2.id, Pareja.jugador2_id == j1.id)
                      )
                  ).first())
        if existe:
            flash('Esa pareja ya existe en esta categoría.', 'error')
            return redirect(url_for('parejas_new'))

        puntos_inicial = cat.puntos_max  # tope “peor” del nivel
        p = Pareja(
            categoria_id=cat.id,
            jugador1_id=j1.id,
            jugador2_id=j2.id,
            puntos=puntos_inicial
        )
        try:
            db.session.add(p)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Esa pareja ya existe en esta categoría.', 'error')
            return redirect(url_for('parejas_new'))

        flash('Pareja creada.', 'ok')
        return redirect(url_for('parejas_list'))

    return render_template('parejas_form.html', categorias=categorias, jugadores=jugadores)


# ===== Helpers =====

def _partido_to_vm(p: 'Partido') -> dict:
    """Mapper defensivo para tus Partidos 'sueltos'."""
    def _nom(j):
        return getattr(j, "nombre_completo", None) or getattr(j, "nombre", None) or "-"

    # Intento 1: parejas (jugador1/jugador2)
    ladoA, ladoB = None, None
    try:
        pj1 = getattr(getattr(p, "pareja1", None), "jugador1", None)
        pj2 = getattr(getattr(p, "pareja1", None), "jugador2", None)
        if pj1 or pj2:
            ladoA = " + ".join([_nom(x) for x in [pj1, pj2] if x])
    except Exception:
        pass
    try:
        pj1 = getattr(getattr(p, "pareja2", None), "jugador1", None)
        pj2 = getattr(getattr(p, "pareja2", None), "jugador2", None)
        if pj1 or pj2:
            ladoB = " + ".join([_nom(x) for x in [pj1, pj2] if x])
    except Exception:
        pass

    # Intento 2: individuales (si tu modelo los tiene)
    if not ladoA:
        ladoA = _nom(getattr(p, "jugador_a", None))
    if not ladoB:
        ladoB = _nom(getattr(p, "jugador_b", None))

    # Respaldo final
    if not ladoA or ladoA == "-":
        ladoA = getattr(p, "rival1", None) or "Lado A"
    if not ladoB or ladoB == "-":
        ladoB = getattr(p, "rival2", None) or "Lado B"

    # Fecha/cancha/estado con tolerancia a ausencia de campos
    prog = getattr(p, "programado_en", None) or getattr(p, "fecha", None)
    cancha = getattr(p, "cancha", None)
    estado = getattr(p, "estado", None) or "-"

    try:
        url_detalle  = url_for("partido_detalle", partido_id=p.id)
    except Exception:
        url_detalle = url_for("partidos_list")

    return {
        "id": f"P-{p.id}",
        "tipo": "PARTIDO",
        "torneo_nombre": None,
        "ronda": None,
        "estado": estado,
        "programado_en": prog,
        "cancha": cancha,
        "ladoA": ladoA,
        "ladoB": ladoB,
        "url_detalle": url_detalle,
        "url_proponer": None,
        "url_responder": None,
    }


from sqlalchemy import or_, and_, exists
from sqlalchemy.orm import joinedload

def _query_torneo_partidos_del_jugador(jugador_id: int):
    """
    Devuelve TODOS los TorneoPartido en los que participa 'jugador_id'.
    - Hace un match SQL *siempre* (cuando es posible) y además
      filtra *siempre* en Python con tp.jugador_participa(jugador_id).
    - Une ambos resultados y deduplica por id.
    - Loguea contadores para diagnóstico.
    """
    TP   = TorneoPartido
    TPar = globals().get('TorneoParticipante')
    TIns = globals().get('TorneoInscripcion')

    # ---------- 1) SQL (mejor esfuerzo; puede ser parcial según el esquema) ----------
    tps_sql = []
    try:
        if TPar is not None:
            match_par = []

            # Campos directos si existen en TPar
            for attr in ('jugador_id', 'jugador1_id', 'jugador2_id'):
                if hasattr(TPar, attr):
                    match_par.append(getattr(TPar, attr) == jugador_id)

            # Vía inscripción si existe, solo con attrs reales de TIns
            if hasattr(TPar, 'inscripcion_id') and TIns is not None:
                ins_or_terms = []
                for ins_attr in ('jugador1_id', 'jugador2_id', 'jugador_id'):
                    if hasattr(TIns, ins_attr):
                        ins_or_terms.append(getattr(TIns, ins_attr) == jugador_id)
                if ins_or_terms:
                    match_par.append(
                        and_(
                            TPar.inscripcion_id.isnot(None),
                            exists().where(
                                and_(
                                    TIns.id == TPar.inscripcion_id,
                                    or_(*ins_or_terms)
                                )
                            )
                        )
                    )

            if match_par:
                participa_en_A = exists().where(and_(TPar.id == TP.participante_a_id, or_(*match_par)))
                participa_en_B = exists().where(and_(TPar.id == TP.participante_b_id, or_(*match_par)))
                tps_sql = (
                    TP.query
                      .filter(or_(participa_en_A, participa_en_B))
                      .options(
                          joinedload(TP.torneo),
                          joinedload(TP.participante_a),
                          joinedload(TP.participante_b),
                      )
                      .all()
                )
    except Exception as e:
        try:
            current_app.logger.exception(f"[/partidos] SQL match falló: {e}")
        except Exception:
            pass
        tps_sql = []

    # ---------- 2) Fallback Python (SIEMPRE) ----------
    try:
        candidatos = (
            TP.query
              .options(
                  joinedload(TP.torneo),
                  joinedload(TP.participante_a),
                  joinedload(TP.participante_b),
              )
              .all()
        )
        tps_py = [tp for tp in candidatos
                  if getattr(tp, 'jugador_participa', None) and tp.jugador_participa(jugador_id)]
    except Exception as e:
        try:
            current_app.logger.exception(f"[/partidos] fallback falló: {e}")
        except Exception:
            pass
        tps_py = []

    # ---------- 3) Unión + deduplicación ----------
    by_id = {}
    for tp in tps_sql:
        by_id[tp.id] = tp
    for tp in tps_py:
        by_id[tp.id] = tp
    result = list(by_id.values())

    # ---------- 4) Logs de diagnóstico útiles ----------
    try:
        current_app.logger.info(
            f"[/partidos] torneo union: jugador_id={jugador_id} sql={len(tps_sql)} py={len(tps_py)} union={len(result)}"
        )
        # Si querés, logueá también los ids para ver cuáles “faltaban” en SQL:
        if len(result) != len(tps_sql):
            ids_sql = {tp.id for tp in tps_sql}
            ids_py  = {tp.id for tp in tps_py}
            ids_missing_in_sql = sorted(ids_py - ids_sql)
            current_app.logger.info(f"[/partidos] ids faltantes en SQL: {ids_missing_in_sql}")
    except Exception:
        pass

    return result



def _tp_to_vm(tp: 'TorneoPartido', jugador_id: int | None = None) -> dict:
    try:
        ladoA = tp.ladoA_nombres
        ladoB = tp.ladoB_nombres
    except Exception:
        ladoA = "Lado A"
        ladoB = "Lado B"

    # ¿el usuario actual participa?
    soy_participante = False
    try:
        if jugador_id:
            soy_participante = bool(getattr(tp, "jugador_participa", None) and tp.jugador_participa(jugador_id))
    except Exception:
        soy_participante = False

    vm = {
        "id": f"TP-{tp.id}",
        "tipo": "TORNEO",
        "torneo_nombre": getattr(tp.torneo, "nombre", "Torneo"),
        "ronda": tp.ronda,
        "estado": tp.estado,
        "programado_en": tp.programado_en,
        "cancha": tp.cancha,
        "ladoA": ladoA,
        "ladoB": ladoB,
        "url_detalle":  url_for("torneo_partido_detalle", partido_id=tp.id),
        "url_proponer": url_for("torneo_partido_proponer", partido_id=tp.id),
        "url_responder":url_for("torneo_partido_responder", partido_id=tp.id),
        # permisos
        "puede_ver": True,                # cualquiera puede ver
        "puede_proponer": soy_participante,
        "puede_responder": soy_participante,
    }
    return vm


def _order_items(items: list[dict]) -> None:
    """Ordena IN PLACE: fecha (None al final) y luego id numérico desc."""
    def key(it):
        prog = it.get("programado_en")
        try:
            nid = int(str(it.get("id", "")).split("-")[-1])
        except Exception:
            nid = 0
        return (prog is None, prog or datetime.max, -nid)
    items.sort(key=key)

def _resolve_jugador_id():
    """
    Devuelve el jugador_id del usuario actual buscando en varios lugares:
    1) current_user.jugador.id
    2) g.current_jugador.id
    3) session['jugador_id']
    4) Jugador.user_id == current_user.id   (si existe ese campo)
    5) Jugador.email == current_user.email  (último recurso, si existe campo email)
    """
    # 1) current_user.jugador.id
    try:
        from flask_login import current_user as _cu
        if _cu and getattr(_cu, "is_authenticated", False):
            j = getattr(_cu, "jugador", None)
            jid = getattr(j, "id", None)
            if jid:
                return jid
    except Exception:
        pass

    # 2) g.current_jugador.id
    try:
        from flask import g
        jid = getattr(getattr(g, "current_jugador", None), "id", None)
        if jid:
            return jid
    except Exception:
        pass

    # 3) session['jugador_id']
    try:
        from flask import session
        jid = session.get("jugador_id")
        if jid:
            return jid
    except Exception:
        pass

    # 4) buscar por user_id si el modelo Jugador tiene ese campo
    try:
        from app import Jugador  # ajustá import si tu modelo está en otro módulo
        if _cu and getattr(_cu, "is_authenticated", False):
            if hasattr(Jugador, "user_id"):
                q = db.session.query(Jugador.id).filter(Jugador.user_id == _cu.id).first()
                if q and q[0]:
                    return q[0]
    except Exception:
        pass

    # 5) buscar por email si el modelo Jugador tiene 'email'
    try:
        from app import Jugador
        if _cu and getattr(_cu, "is_authenticated", False):
            email = getattr(_cu, "email", None)
            if email and hasattr(Jugador, "email"):
                q = db.session.query(Jugador.id).filter(Jugador.email == email).first()
                if q and q[0]:
                    return q[0]
    except Exception:
        pass

    return None


# ===== Ruta =====

@app.route('/partidos')
def partidos_list():
    # ---- helpers locales de respaldo (no pisan los que ya existan) -----------------
    def _safe_resolve_jugador_id():
        # Usa tu helper si existe
        try:
            if '._resolve_jugador_id' in str(_resolve_jugador_id):  # pragma: no cover
                pass
        except Exception:
            pass
        try:
            return _resolve_jugador_id()  # ya lo tenés en tu app
        except Exception:
            # fallback con current_user.jugador.id si existiera
            try:
                cu = globals().get('current_user')
                j = getattr(cu, 'jugador', None)
                return getattr(j, 'id', None)
            except Exception:
                return None

    def _safe_partido_to_vm(p):
        try:
            return _partido_to_vm(p)  # tu formateador si existe
        except Exception:
            # fallback mínimo
            return {
                'tipo': 'libre',
                'obj': p,
                'cuando': getattr(p, 'fecha', None) or getattr(p, 'creado_en', None),
            }

    def _safe_tp_to_vm(tp, jugador_id):
        try:
            return _tp_to_vm(tp, jugador_id)  # tu formateador si existe
        except Exception:
            return {
                'tipo': 'torneo',
                'obj': tp,
                'cuando': getattr(tp, 'programado_en', None) or getattr(tp, 'creado_en', None),
            }

    def _safe_order_items(items):
        try:
            _order_items(items)  # tu ordenador si existe
            return
        except Exception:
            # fallback: por fecha/cuando desc y luego id desc
            def _k(it):
                o = it.get('obj')
                tstamp = it.get('cuando')
                oid = getattr(o, 'id', 0)
                return (0 if isinstance(tstamp, datetime) else 1, tstamp or datetime.min, oid)
            items.sort(key=_k, reverse=True)

    def _safe_query_torneo_partidos_del_jugador(jugador_id: int):
        # Usa tu helper si existe
        try:
            return _query_torneo_partidos_del_jugador(jugador_id)
        except Exception:
            pass

        # Fallback genérico: trae TP y filtra por pertenencia usando lado_de_jugador_en_partido
        TP = globals().get('TorneoPartido')
        if TP is None:
            return []

        q = (db.session.query(TP)
             .options(
                 joinedload(TP.participante_a) if hasattr(TP, 'participante_a') else joinedload(TP.torneo),
                 joinedload(TP.participante_b) if hasattr(TP, 'participante_b') else joinedload(TP.torneo),
             )
             )
        # ordenar “razonable”
        ordenes = []
        if hasattr(TP, 'ronda'): ordenes.append(TP.ronda.asc())
        if hasattr(TP, 'orden'): ordenes.append(TP.orden.asc())
        ordenes.append(TP.id.asc())
        q = q.order_by(*ordenes)

        tps = []
        for tp in q.all():
            try:
                lado = lado_de_jugador_en_partido(tp, jugador_id)
            except Exception:
                lado = None
            if lado in ('A', 'B'):
                tps.append(tp)
        return tps

    # ---- 1) Partidos “libres” (mantengo tu lógica) --------------------------------
    try:
        q_libres = (db.session.query(Partido)
                    .options(
                        joinedload(Partido.pareja1).joinedload(Pareja.jugador1),
                        joinedload(Partido.pareja1).joinedload(Pareja.jugador2),
                        joinedload(Partido.pareja2).joinedload(Pareja.jugador1),
                        joinedload(Partido.pareja2).joinedload(Pareja.jugador2),
                        joinedload(Partido.categoria),
                    )
                    .order_by(Partido.creado_en.desc()))
        partidos = q_libres.all()
    except Exception:
        current_app.logger.exception("Error listando partidos libres; uso fallback simple")
        partidos = (db.session.query(Partido)
                    .order_by(Partido.id.desc())
                    .all())

    items = [_safe_partido_to_vm(p) for p in partidos]

    # ---- 2) Jugador actual ---------------------------------------------------------
    jugador_id = _safe_resolve_jugador_id()
    try:
        current_app.logger.info("[/partidos] jugador_id(resuelto)=%r", jugador_id)
    except Exception:
        pass

    # ---- 3) Partidos de TORNEO del jugador ----------------------------------------
    if jugador_id:
        try:
            tps = _safe_query_torneo_partidos_del_jugador(jugador_id)
            current_app.logger.info("[/partidos] torneo encontrados=%d", len(tps))
        except Exception:
            current_app.logger.exception("Error consultando TorneoPartido del jugador")
            tps = []

        items.extend([_safe_tp_to_vm(tp, jugador_id) for tp in tps])

    # ---- 4) Orden unificado --------------------------------------------------------
    _safe_order_items(items)

    # ---- 5) Render ----------------------------------------------------------------
    return render_template('partidos_list.html', items=items, partidos=partidos)

def subq_participantes_de_jugador(jugador_id: int):
    # Casos: individual (jugador1_id usado y jugador2_id = NULL) y parejas (ambos llenos)
    return (
        db.session.query(TorneoParticipante.id)
        .join(TorneoInscripcion, TorneoInscripcion.id == TorneoParticipante.inscripcion_id)
        .filter(
            (TorneoInscripcion.jugador1_id == jugador_id) |
            (TorneoInscripcion.jugador2_id == jugador_id)
        )
        .subquery()
    )

def _q_partidos_torneo_de(jugador_id: int):
    subp = subq_participantes_de_jugador(jugador_id)

    q = (
        db.session.query(TorneoPartido)
        .filter(
            (TorneoPartido.participante_a_id.in_(subp)) |
            (TorneoPartido.participante_b_id.in_(subp))
        )
        # si querés excluir finalizados, ajustá este filtro:
        # .filter(TorneoPartido.estado.in_(("PROPUESTO","ACEPTADO","PENDIENTE","PROGRAMADO","EN_CURSO","FINALIZADO")))
        .order_by(TorneoPartido.fase_id.nullslast(), TorneoPartido.grupo_id.nullslast(), TorneoPartido.orden.nullslast(), TorneoPartido.id.desc())
    )

    # Log de diagnóstico bien claro:
    total = q.count()
    app.logger.info(f"[/partidos] torneo: jugador_id={jugador_id} partidos_encontrados={total}")

    # Extra opcional: desglose por torneo/grupo para detectar “huecos”
    rows = (
        db.session.query(
            TorneoPartido.torneo_id,
            TorneoPartido.grupo_id,
            db.func.count(TorneoPartido.id)
        )
        .filter(
            (TorneoPartido.participante_a_id.in_(subp)) |
            (TorneoPartido.participante_b_id.in_(subp))
        )
        .group_by(TorneoPartido.torneo_id, TorneoPartido.grupo_id)
        .all()
    )
    for tid, gid, cnt in rows:
        app.logger.info(f"[/partidos] torneo: jugador_id={jugador_id} torneo={tid} grupo={gid} cnt={cnt}")

    return q



@app.route('/partidos/nuevo', methods=['GET', 'POST'])
def partidos_new():
    # Debe haber sesión
    creador = get_current_jugador()
    if not creador:
        flash('Iniciá sesión para crear un partido.', 'error')
        return redirect(url_for('login'))

    # Debe tener categoría
    cat = creador.categoria
    if not cat:
        flash('Tu perfil no tiene categoría asignada.', 'error')
        return redirect(url_for('partidos_list'))

    if request.method == 'POST':
        companero_id = request.form.get('companero_id', type=int)
        rival1_id    = request.form.get('rival1_id', type=int)
        rival2_id    = request.form.get('rival2_id', type=int)
        fecha_str    = (request.form.get('fecha') or '').strip()

        # Presencia
        if not (companero_id and rival1_id and rival2_id):
            flash('Completá compañero y los dos rivales.', 'error')
            return redirect(url_for('partidos_new'))

        # Distintos
        if len({creador.id, companero_id, rival1_id, rival2_id}) != 4:
            flash('Los cuatro jugadores deben ser distintos.', 'error')
            return redirect(url_for('partidos_new'))

        # Cargar jugadores
        companero = db.session.get(Jugador, int(companero_id)) if companero_id else None
        r1        = db.session.get(Jugador, int(rival1_id)) if rival1_id else None
        r2        = db.session.get(Jugador, int(rival2_id)) if rival2_id else None
        if not all([companero, r1, r2]):
            flash('Alguno de los jugadores seleccionados no existe.', 'error')
            return redirect(url_for('partidos_new'))

        # Activos
        if not (creador.activo and companero.activo and r1.activo and r2.activo):
            flash('Todos los jugadores deben estar activos.', 'error')
            return redirect(url_for('partidos_new'))

        # Misma categoría
        if not (companero.categoria_id == cat.id and r1.categoria_id == cat.id and r2.categoria_id == cat.id):
            flash('Todos deben pertenecer a tu misma categoría.', 'error')
            return redirect(url_for('partidos_new'))

        # Parseo de fecha (opcional)
        fecha = None
        if fecha_str:
            try:
                fecha = datetime.fromisoformat(fecha_str)
            except ValueError:
                flash('Formato de fecha inválido.', 'error')
                return redirect(url_for('partidos_new'))

        # Crear/obtener parejas y partido
        pareja_mia   = get_or_create_pareja(creador.id, companero.id, cat.id)
        pareja_rival = get_or_create_pareja(r1.id, r2.id, cat.id)

        partido = Partido(
            categoria_id=cat.id,
            pareja1_id=pareja_mia.id,
            pareja2_id=pareja_rival.id,
            fecha=fecha,
            estado='PENDIENTE',
            creador_id=creador.id,
            companero_id=companero.id,
            rival1_id=r1.id,
            rival2_id=r2.id,
            rival1_acepto=None,
            rival2_acepto=None
        )
        db.session.add(partido)
        db.session.commit()

        # =================== ✉️ EMAIL UPLAY ===================
        from flask import current_app
        from datetime import datetime

        enlace = url_for('partidos_list', _external=True)
        asunto = f"🎾 Nuevo partido creado en UPLAY #{partido.id}"

        mensaje_html = f"""
        <div style="font-family:'Poppins',Arial,sans-serif;background:#f3f4f8;padding:32px 0;">
          <div style="max-width:620px;margin:auto;background:white;border-radius:16px;overflow:hidden;
                      box-shadow:0 4px 16px rgba(0,0,0,0.12);">
            <div style="text-align:center;padding:30px 0;background:linear-gradient(135deg,#7B68EE,#9b8df3);color:white;">
              <img src="https://uplay-gev5.onrender.com/static/logo/uplay-logo.svg" alt="UPLAY"
                   style="height:70px;margin-bottom:10px;">
              <h2 style="margin:0;font-size:1.5rem;">Nuevo partido creado en UPLAY</h2>
            </div>
            <div style="padding:28px;color:#222;line-height:1.6;">
              <p style="font-size:1.05rem;">
                <strong>{creador.nombre_completo}</strong> creó un nuevo partido y te agregó como jugador.
              </p>
              <p style="margin:10px 0 18px 0;">
                <b>Compañero:</b> {companero.nombre_completo}<br>
                <b>Rivales:</b> {r1.nombre_completo} y {r2.nombre_completo}
              </p>
              <p style="margin-bottom:22px;">
                Ingresá a UPLAY para confirmar tu participación o revisar los detalles del partido.
              </p>
              <div style="text-align:center;">
                <a href="{enlace}" style="background:#7B68EE;color:white;padding:14px 26px;font-weight:600;
                   border-radius:10px;text-decoration:none;display:inline-block;box-shadow:0 2px 6px rgba(0,0,0,0.2);">
                   ⚡ Ver partido en UPLAY
                </a>
              </div>
            </div>
            <div style="background:#fafafa;border-top:1px solid #eee;text-align:center;padding:16px;">
              <p style="font-size:0.85rem;color:#666;margin:4px 0;">© {datetime.now().year} UPLAY</p>
              <p style="font-size:0.8rem;color:#aaa;margin:0;">Este mensaje fue enviado automáticamente por el sistema UPLAY.</p>
            </div>
          </div>
        </div>
        """

        # Enviar a todos los involucrados
        for jugador in [companero, r1, r2]:
            try:
                if jugador.email:
                    send_mail(
                        subject=asunto,
                        body="Nuevo partido en UPLAY",
                        to=jugador.email,
                        html_body=mensaje_html
                    )
            except Exception as e:
                current_app.logger.warning(f"[UPLAY] Error al enviar mail a {jugador.email}: {e}")

        flash(f'Partido #{partido.id} creado y notificaciones enviadas.', 'ok')
        return redirect(url_for('partidos_list'))

    # GET -> armar combos
    jugadores_mi_cat = (
        db.session.query(Jugador)
        .filter(
            Jugador.activo.is_(True),
            Jugador.categoria_id == cat.id,
            Jugador.id != creador.id
        )
        .order_by(Jugador.nombre_completo.asc())
        .all()
    )

    candidatos_companero = jugadores_mi_cat
    candidatos_rivales   = jugadores_mi_cat

    return render_template(
        'partidos_form.html',
        categoria=cat,
        candidatos_companero=candidatos_companero,
        candidatos_rivales=candidatos_rivales
    )



# =========================
# RUTA: PROPONER RESULTADO (vista de carga / edición de propuesta)
# =========================
@app.route('/partidos/<int:partido_id>/resultado', methods=['GET', 'POST'])
def partidos_resultado(partido_id):
    from datetime import datetime

    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión.', 'error')
        return redirect(url_for('login'))

    p = get_or_404(Partido, partido_id)

    # 0) Bloqueos duros
    if getattr(p, 'resultado', None) is not None:
        flash('El partido ya tiene un resultado confirmado.', 'warning')
        return redirect(url_for('partidos_list'))

    # 1) Si fue armado por invitación, exigir aceptación de ambos rivales
    requiere_aceptaciones = (p.rival1_id is not None and p.rival2_id is not None)
    if requiere_aceptaciones and not (p.rival1_acepto == 1 and p.rival2_acepto == 1):
        flash('Aún falta que ambos rivales acepten la invitación.', 'error')
        return redirect(url_for('partidos_list'))

    # 2) Solo participantes (o admin) pueden proponer/editar
    try:
        participantes_ids = {
            p.pareja1.jugador1_id, p.pareja1.jugador2_id,
            p.pareja2.jugador1_id, p.pareja2.jugador2_id
        }
    except Exception:
        participantes_ids = set()

    soy_participante = j.id in participantes_ids
    if not (soy_participante or getattr(j, 'is_admin', False)):
        flash('Solo los jugadores del partido (o un admin) pueden cargar el resultado.', 'error')
        return redirect(url_for('partidos_list'))

    # 3) Si ya hay propuesta del rival, redirigir a confirmar
    # (usamos únicamente los campos del propio Partido para evitar sangrado a torneos)
    ya_hay_propuesta = p.resultado_propuesto_ganador_pareja_id is not None
    if ya_hay_propuesta:
        # Si la propuso el rival, que vayan a confirmar
        soy_p1 = bool(p.pareja1 and j.id in (p.pareja1.jugador1_id, p.pareja1.jugador2_id))
        mi_confirmacion = p.confirmo_pareja1 if soy_p1 else p.confirmo_pareja2
        if not mi_confirmacion:
            flash("Ya hay una propuesta del rival: por favor, respondela.", "warning")
            return redirect(url_for('partidos_confirmar_resultado', partido_id=p.id))

    # 4) POST: crear/editar propuesta (no cierra partido)
    if request.method == 'POST':
        ganador_id = request.form.get('ganador_pareja_id')
        sets_text  = (request.form.get('sets_text') or '').strip() or None

        if not ganador_id:
            flash('Elegí la pareja ganadora.', 'error')
            return redirect(url_for('partidos_resultado', partido_id=p.id))
        try:
            ganador_id = int(ganador_id)
        except ValueError:
            flash('Ganador inválido.', 'error')
            return redirect(url_for('partidos_resultado', partido_id=p.id))

        if ganador_id not in (p.pareja1_id, p.pareja2_id):
            flash('La pareja ganadora no corresponde a este partido.', 'error')
            return redirect(url_for('partidos_resultado', partido_id=p.id))

        soy_p1 = bool(p.pareja1 and j.id in (p.pareja1.jugador1_id, p.pareja1.jugador2_id))

        # Grabar SOLO en el propio partido (legacy fields)
        p.resultado_propuesto_ganador_pareja_id = ganador_id
        p.resultado_propuesto_sets_text = sets_text
        p.resultado_propuesto_por_id = j.id
        p.resultado_propuesto_en = datetime.utcnow()

        # Estado y confirmaciones: dejo mi lado confirmado y reseteo el rival
        p.estado = 'PROPUESTO'
        if soy_p1:
            p.confirmo_pareja1 = 1
            p.confirmo_pareja2 = None
        else:
            p.confirmo_pareja2 = 1
            p.confirmo_pareja1 = None

        db.session.commit()
        flash('Resultado propuesto. Ahora debe confirmarlo la otra pareja.', 'ok')
        return redirect(url_for('partidos_confirmar_resultado', partido_id=p.id))

    # 5) GET → mostrar formulario
    return render_template('partidos_resultado.html', partido=p, prp=None)

# =========================
# RUTA: RESPONDER INVITACIÓN (aceptar/rechazar rivales/compañero)
# =========================
@app.route('/partidos/<int:partido_id>/responder', methods=['GET', 'POST'])
def partidos_responder(partido_id):
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión para responder.', 'error')
        return redirect(url_for('login'))

    p = get_or_404(Partido, partido_id)

    # Flujo de invitación
    requiere_inv = (p.rival1_id is not None and p.rival2_id is not None)
    if p.estado not in ('PENDIENTE', 'POR_CONFIRMAR') or not requiere_inv:
        flash('Este partido ya no está pendiente de invitación.', 'error')
        return redirect(url_for('partidos_list'))

    if j.id not in (p.rival1_id, p.rival2_id):
        flash('Solo los rivales invitados pueden responder.', 'error')
        return redirect(url_for('partidos_list'))

    contrario_1 = p.creador
    contrario_2 = p.companero

    if j.id == p.rival1_id:
        mi_compa_id = p.rival2_id
        soy_rival1 = True
    else:
        mi_compa_id = p.rival1_id
        soy_rival1 = False

    mi_compa = db.session.get(Jugador, int(mi_compa_id)) if mi_compa_id else None

    ocupados_base = {pid for pid in [p.creador_id, p.companero_id, p.rival1_id, p.rival2_id] if pid}
    candidatos = (
        db.session.query(Jugador)
        .filter(
            Jugador.activo.is_(True),
            Jugador.categoria_id == p.categoria_id,
            Jugador.id != j.id
        )
        .order_by(Jugador.nombre_completo.asc())
        .all()
    )
    ocupados_para_filtrar = set(ocupados_base)
    if mi_compa:
        ocupados_para_filtrar.discard(mi_compa.id)
    opciones_companero = [c for c in candidatos if c.id not in ocupados_para_filtrar]
    yo_acepto = (p.rival1_acepto if soy_rival1 else p.rival2_acepto)

    if request.method == 'POST':
        accion = (request.form.get('accion') or '').strip()  # 'aceptar' | 'rechazar'
        if accion not in ('aceptar', 'rechazar'):
            flash('Acción inválida.', 'error')
            return redirect(url_for('partidos_responder', partido_id=p.id))

        if accion == 'rechazar':
            if soy_rival1:
                p.rival1_acepto = 0
            else:
                p.rival2_acepto = 0
            if p.rival1_acepto is None:
                p.rival1_acepto = 0
            if p.rival2_acepto is None:
                p.rival2_acepto = 0
            p.estado = 'CANCELADO'
            db.session.commit()
            flash('Rechazaste la invitación. El partido fue cancelado.', 'ok')
            return redirect(url_for('partidos_list'))

        # === ACEPTAR ===
        elegido_id = request.form.get('partner_id', type=int)

        if not mi_compa and not elegido_id:
            flash('Elegí un compañero antes de aceptar.', 'error')
            return redirect(url_for('partidos_responder', partido_id=p.id))

        if elegido_id:
            if not (mi_compa and elegido_id == mi_compa.id):
                elegido = db.session.get(Jugador, int(elegido_id))
                if (not elegido) or (not elegido.activo) or (elegido.categoria_id != p.categoria_id):
                    flash('El compañero elegido no es válido para este partido.', 'error')
                    return redirect(url_for('partidos_responder', partido_id=p.id))
                if elegido.id in ocupados_para_filtrar:
                    flash('Ese jugador ya está en este partido.', 'error')
                    return redirect(url_for('partidos_responder', partido_id=p.id))

                if soy_rival1:
                    p.rival2_id = elegido.id
                    p.rival2_acepto = None
                else:
                    p.rival1_id = elegido.id
                    p.rival1_acepto = None

                if p.estado not in ('PENDIENTE', 'POR_CONFIRMAR'):
                    p.estado = 'POR_CONFIRMAR'

        if soy_rival1:
            p.rival1_acepto = 1
        else:
            p.rival2_acepto = 1

        ambos_ok = (
            p.rival1_id is not None and p.rival2_id is not None and
            p.rival1_acepto in (True, 1, '1') and p.rival2_acepto in (True, 1, '1')
        )

        if ambos_ok:
            p.estado = 'ACEPTADO'
            msg = 'Ambos rivales aceptaron. El partido está listo para jugar.'

            # ✉️ Enviar notificación al creador
            try:
                from flask import current_app
                from datetime import datetime

                creador = p.creador
                companero = p.companero
                r1 = db.session.get(Jugador, int(p.rival1_id))
                r2 = db.session.get(Jugador, int(p.rival2_id))
                enlace = url_for('partidos_list', _external=True)
                asunto = f"✅ Tu partido #{p.id} fue confirmado por todos en UPLAY"

                mensaje_html = f"""
                <div style="font-family:'Poppins',Arial,sans-serif;background:#f6f6f9;padding:30px 0;">
                  <div style="max-width:600px;margin:auto;background:white;border-radius:12px;overflow:hidden;
                              box-shadow:0 4px 10px rgba(0,0,0,0.08);">
                    <div style="text-align:center;padding:25px 0;background:linear-gradient(135deg,#7B68EE,#9b8df3);color:white;">
                      <img src="https://uplay-gev5.onrender.com/static/logo/uplay-logo.svg" alt="UPLAY" style="height:68px;margin-bottom:6px;">
                      <h2 style="margin:0;">🎾 ¡Tu partido fue confirmado!</h2>
                    </div>
                    <div style="padding:22px;color:#222;line-height:1.6;">
                      <p>Todos los jugadores confirmaron su participación en el partido <b>#{p.id}</b>.</p>
                      <p>
                        <b>Compañero:</b> {companero.nombre_completo}<br>
                        <b>Rivales:</b> {r1.nombre_completo} y {r2.nombre_completo}
                      </p>
                      <div style="text-align:center;margin-top:20px;">
                        <a href="{enlace}" style="background:#7B68EE;color:white;padding:12px 22px;border-radius:8px;
                           text-decoration:none;display:inline-block;">Ver mis partidos en UPLAY</a>
                      </div>
                    </div>
                    <div style="background:#fafafa;border-top:1px solid #eee;text-align:center;padding:12px;">
                      <p style="font-size:0.85rem;color:#666;margin:4px 0;">© {datetime.now().year} UPLAY</p>
                      <p style="font-size:0.8rem;color:#aaa;margin:0;">Este es un mensaje automático del sistema.</p>
                    </div>
                  </div>
                </div>
                """

                if creador.email:
                    send_mail(
                        subject=asunto,
                        body="Tu partido fue confirmado",
                        to=creador.email,
                        html_body=mensaje_html
                    )
                    current_app.logger.info(f"[UPLAY] Email enviado al creador {creador.email} confirmando el partido #{p.id}")
            except Exception as e:
                current_app.logger.warning(f"[UPLAY] Error al enviar mail de confirmación al creador: {e}")

        else:
            if p.estado not in ('PENDIENTE', 'POR_CONFIRMAR'):
                p.estado = 'POR_CONFIRMAR'
            msg = 'Respuesta registrada. Falta que el otro rival/compañero confirme.'

        db.session.commit()
        flash(msg, 'ok')
        return redirect(url_for('partidos_list'))

    return render_template(
        'partidos_responder.html',
        partido=p,
        yo=j,
        contrario_1=contrario_1,
        contrario_2=contrario_2,
        mi_compa=mi_compa,
        opciones_companero=opciones_companero,
        yo_acepto=yo_acepto
    )



# =========================
# RUTA: CONFIRMAR / RECHAZAR PROPUESTA DE RESULTADO
# =========================
from datetime import datetime
from sqlalchemy import and_

@app.route('/partidos/<int:partido_id>/confirmar-resultado', methods=['GET', 'POST'])
def partidos_confirmar_resultado(partido_id):
    from datetime import datetime

    # Carga estricta del partido solicitado
    p = get_or_404(Partido, partido_id)
    yo = get_current_jugador()
    if not yo:
        flash('Iniciá sesión.', 'error')
        return redirect(url_for('login'))

    # Estados válidos para confirmar/rechazar una propuesta
    if p.estado not in ('PENDIENTE', 'PROPUESTO', 'CONFIRMADO', 'EN_JUEGO'):
        flash('Este partido ya no está pendiente de confirmación.', 'error')
        return redirect(url_for('partidos_list'))

    # Usamos solo la propuesta guardada en el propio Partido
    if p.resultado_propuesto_ganador_pareja_id is None:
        flash('Aún no hay un resultado propuesto.', 'error')
        return redirect(url_for('partidos_list'))

    # Debe ser participante (o admin)
    try:
        participantes_ids = {
            p.pareja1.jugador1_id, p.pareja1.jugador2_id,
            p.pareja2.jugador1_id, p.pareja2.jugador2_id
        }
    except Exception:
        participantes_ids = set()

    if yo.id not in participantes_ids and not getattr(yo, 'is_admin', False):
        flash('Solo jugadores de este partido pueden confirmar el resultado.', 'error')
        return redirect(url_for('partidos_list'))

    soy_p1 = yo.id in (p.pareja1.jugador1_id, p.pareja1.jugador2_id)

    if request.method == 'POST':
        accion = (request.form.get('accion') or '').strip()  # 'aceptar' | 'rechazar'
        if accion not in ('aceptar', 'rechazar'):
            flash('Acción inválida.', 'error')
            return redirect(url_for('partidos_confirmar_resultado', partido_id=p.id))

        try:
            # --- RECHAZAR: limpiar propuesta y volver a PENDIENTE
            if accion == 'rechazar':
                p.resultado_propuesto_ganador_pareja_id = None
                p.resultado_propuesto_sets_text = None
                p.resultado_propuesto_por_id = None
                p.resultado_propuesto_en = None
                p.confirmo_pareja1 = None
                p.confirmo_pareja2 = None
                # trazabilidad del rechazo
                p.rechazo_ultimo_por_id = yo.id
                p.rechazo_ultimo_en = datetime.utcnow()
                p.estado = 'PENDIENTE'
                db.session.commit()
                flash('Rechazaste la propuesta. El partido sigue pendiente sin resultado.', 'ok')
                return redirect(url_for('partidos_list'))

            # --- ACEPTAR: marcar confirmación de MI pareja
            if soy_p1:
                p.confirmo_pareja1 = 1
            else:
                p.confirmo_pareja2 = 1

            # ¿Ambas parejas confirmadas? → cerrar y aplicar puntos
            if (p.confirmo_pareja1 == 1) and (p.confirmo_pareja2 == 1):
                ganador_id = p.resultado_propuesto_ganador_pareja_id
                sets_text  = p.resultado_propuesto_sets_text

                # === CIERRE con tu lógica de puntos + bonus + desafío ===
                DELTA_WIN = globals().get('DELTA_WIN', -10)
                DELTA_LOSS = globals().get('DELTA_LOSS', +5)
                DELTA_WIN_BONUS = globals().get('DELTA_WIN_BONUS', -3)
                BONUS_APLICA_DESDE = globals().get('BONUS_APLICA_DESDE', 3)

                def clamp_por_jugador(jg):
                    cat = getattr(jg, 'categoria', None)
                    if not cat:
                        return jg.puntos
                    try:
                        p_val = int(jg.puntos or 0)
                        pmin = int(cat.puntos_min)
                        pmax = int(cat.puntos_max)
                    except Exception:
                        return jg.puntos
                    jg.puntos = max(pmin, min(pmax, p_val))
                    return jg.puntos

                p1 = p.pareja1
                p2 = p.pareja2
                pareja_g = p1 if ganador_id == p1.id else p2
                pareja_p = p2 if ganador_id == p1.id else p1

                ganadores  = [pareja_g.jugador1, pareja_g.jugador2]
                perdedores = [pareja_p.jugador1, pareja_p.jugador2]

                # bonus por repetición de victorias
                victorias_previas = (
                    db.session.query(PartidoResultado)
                    .join(Partido, PartidoResultado.partido_id == Partido.id)
                    .filter(PartidoResultado.ganador_pareja_id == pareja_g.id)
                    .filter(Partido.id != p.id)  # nunca contar el actual
                    .count()
                )
                aplica_bonus = (victorias_previas + 1) >= BONUS_APLICA_DESDE

                for jg in ganadores:
                    base = (jg.puntos or (jg.categoria.puntos_max if jg.categoria else 0))
                    jg.puntos = base + DELTA_WIN + (DELTA_WIN_BONUS if aplica_bonus else 0)
                    clamp_por_jugador(jg)

                for jp in perdedores:
                    base = (jp.puntos or (jp.categoria.puntos_max if jp.categoria else 0))
                    jp.puntos = base + DELTA_LOSS
                    clamp_por_jugador(jp)

                # Registrar resultado definitivo
                pr = PartidoResultado(
                    partido_id=p.id,
                    ganador_pareja_id=ganador_id,
                    sets_text=sets_text or None
                )
                db.session.add(pr)
                p.estado = 'JUGADO'

                # Desafío (si aplica) — tu lógica actual
                desafio = Desafio.query.filter_by(partido_id=p.id).first()
                msg_extra = ''
                if desafio:
                    def ensure_estado(jg):
                        e = JugadorEstado.query.filter_by(jugador_id=jg.id).first()
                        if not e:
                            e = JugadorEstado(jugador_id=jg.id)
                            db.session.add(e)
                            db.session.flush()
                        return e

                    pareja_inferior = p.pareja1
                    pareja_superior = p.pareja2
                    inferiores = [pareja_inferior.jugador1, pareja_inferior.jugador2]
                    superiores = [pareja_superior.jugador1, pareja_superior.jugador2]

                    if ganador_id == pareja_inferior.id:
                        subio_alguien = []
                        for jj in inferiores:
                            e = ensure_estado(jj)
                            e.victorias_vs_superior = (e.victorias_vs_superior or 0) + 1
                            if e.victorias_vs_superior >= 3:
                                cat_sup = desafio.categoria_superior
                                if cat_sup:
                                    jj.categoria_id = cat_sup.id
                                    jj.puntos = cat_sup.puntos_max
                                e.victorias_vs_superior = 0
                                e.derrotas_vs_inferior = 0
                                subio_alguien.append(jj.nombre_completo)
                        if subio_alguien:
                            msg_extra += f" Ascenso: {', '.join(subio_alguien)}."
                    else:
                        bajo_alguien = []
                        for jj in superiores:
                            e = ensure_estado(jj)
                            e.derrotas_vs_inferior = (e.derrotas_vs_inferior or 0) + 1
                            if e.derrotas_vs_inferior >= 3:
                                cat_inf = desafio.categoria_origen
                                if cat_inf:
                                    jj.categoria_id = cat_inf.id
                                    jj.puntos = cat_inf.puntos_max
                                e.derrotas_vs_inferior = 0
                                e.victorias_vs_superior = 0
                                bajo_alguien.append(jj.nombre_completo)
                        if bajo_alguien:
                            msg_extra += f" Descenso: {', '.join(bajo_alguien)}."

                    desafio.estado = 'JUGADO'

                # Limpiar la propuesta (solo de este partido)
                p.resultado_propuesto_ganador_pareja_id = None
                p.resultado_propuesto_sets_text = None
                p.resultado_propuesto_en = None
                p.resultado_propuesto_por_id = None
                p.confirmo_pareja1 = None
                p.confirmo_pareja2 = None

                db.session.commit()
                base_msg = ('Resultado confirmado y cerrado. Se aplicó bonus por compañero'
                            if aplica_bonus else
                            'Resultado confirmado y cerrado.')
                flash(base_msg + (f' {msg_extra}' if msg_extra else ''), 'ok')
                return redirect(url_for('partidos_list'))

            # Aceptación parcial: mantener/forzar PROPUESTO
            if p.estado != 'PROPUESTO':
                p.estado = 'PROPUESTO'
            db.session.commit()
            flash('Tu confirmación fue registrada. Falta la otra pareja.', 'ok')
            return redirect(url_for('partidos_list'))

        except Exception:
            db.session.rollback()
            current_app.logger.exception("Error al confirmar/rechazar propuesta del partido %s", p.id)
            flash('No se pudo procesar la acción. Intentá nuevamente.', 'error')
            return redirect(url_for('partidos_confirmar_resultado', partido_id=p.id))

    # GET → mostrar propuesta + botones aceptar/rechazar
    return render_template(
        'partidos_confirmar_resultado.html',
        partido=p, yo=yo, soy_p1=soy_p1, propuesta=None
    )




# === FUNCIÓN CORE: cierra propuestas >12h (idéntica a confirmar por ambas partes) ===
def _cerrar_propuestas_vencidas_core():
    """Cierra automáticamente propuestas con >12h de antigüedad."""
    limite = datetime.utcnow() - timedelta(hours=12)

    candidatos = (
        db.session.query(Partido)
        .filter(
            Partido.estado == 'PROPUESTO',
            Partido.resultado_propuesto_en.isnot(None),
            Partido.resultado_propuesto_en <= limite
        )
        .all()
    )

    cerrados = 0

    # Intentamos usar PRP si existe, sino los campos legacy en Partido
    try:
        from .models import PartidoResultadoPropuesto
    except Exception:
        PartidoResultadoPropuesto = globals().get('PartidoResultadoPropuesto', None)

    # Helpers / constantes
    DELTA_WIN = globals().get('DELTA_WIN', -10)
    DELTA_LOSS = globals().get('DELTA_LOSS', +5)
    DELTA_WIN_BONUS = globals().get('DELTA_WIN_BONUS', -3)
    BONUS_APLICA_DESDE = globals().get('BONUS_APLICA_DESDE', 3)

# --- imports necesarios en el módulo ---
from datetime import datetime, timedelta
from sqlalchemy import and_

# === HELPERS ================================================================

def clamp_por_jugador(j):
    """
    Lleva j.puntos al rango [pmin, pmax] de su categoría (sin mover categoria_id).
    No decide deltas; sólo encierra.
    """
    if not j or getattr(j, "puntos", None) is None:
        return None

    cat = getattr(j, "categoria", None)
    if not cat:
        return j.puntos

    try:
        p    = int(j.puntos)
        pmin = int(cat.puntos_min)
        pmax = int(cat.puntos_max)
    except Exception:
        return j.puntos

    j.puntos = max(pmin, min(pmax, p))
    return j.puntos


def aplicar_delta_rankeable(j, delta):
    """
    Aplica un delta respetando bordes de categoría:
    - Si j.puntos > pmax y delta<0 => queda en pmax (no baja).
    - Si j.puntos < pmin y delta>0 => queda en pmin (no sube).
    - En otros casos: puntos += delta y luego clamp al rango.
    """
    if not j or getattr(j, "puntos", None) is None:
        return

    cat = getattr(j, "categoria", None)
    if not cat:
        # sin categoría, aplicamos delta “crudo”
        try:
            j.puntos = int(j.puntos) + int(delta)
        except Exception:
            pass
        return

    try:
        p    = int(j.puntos)
        pmin = int(cat.puntos_min)
        pmax = int(cat.puntos_max)
        delta = int(delta)
    except Exception:
        return

    # reglas de borde
    if p > pmax and delta < 0:
        j.puntos = pmax
        return
    if p < pmin and delta > 0:
        j.puntos = pmin
        return

    # caso normal (+ clamp final)
    j.puntos = max(pmin, min(pmax, p + delta))


# === FUNCIÓN CORE: cierra propuestas >12h (idéntica a confirmar por ambas partes) ===
def _cerrar_propuestas_vencidas_core():
    """Cierra automáticamente propuestas con >12h de antigüedad y resultado propuesto."""
    limite = datetime.utcnow() - timedelta(hours=12)

    candidatos = (
        db.session.query(Partido)
        .filter(
            Partido.estado == 'PROPUESTO',
            Partido.resultado_propuesto_en.isnot(None),
            Partido.resultado_propuesto_en <= limite
        )
        .all()
    )

    cerrados = 0

    # Intentamos usar PRP si existe, sino los campos legacy en Partido
    try:
        from .models import PartidoResultadoPropuesto
    except Exception:
        PartidoResultadoPropuesto = globals().get('PartidoResultadoPropuesto', None)

    # Helpers / constantes
    DELTA_WIN = globals().get('DELTA_WIN', -10)
    DELTA_LOSS = globals().get('DELTA_LOSS', +5)
    DELTA_WIN_BONUS = globals().get('DELTA_WIN_BONUS', -3)
    BONUS_APLICA_DESDE = globals().get('BONUS_APLICA_DESDE', 3)

    for p in candidatos:
        # por si el partido quedó confirmado por ambos antes de correr este cierre
        if (getattr(p, "confirmo_pareja1", None) == 1) and (getattr(p, "confirmo_pareja2", None) == 1):
            continue

        # Validaciones mínimas de estructura
        p1 = getattr(p, "pareja1", None)
        p2 = getattr(p, "pareja2", None)
        if not p1 or not p2:
            # partido mal conformado, lo salteamos
            continue

        prp = None
        if PartidoResultadoPropuesto:
            prp = (
                db.session.query(PartidoResultadoPropuesto)
                .filter_by(partido_id=p.id)
                .one_or_none()
            )

        ganador_id = prp.ganador_pareja_id if prp else getattr(p, "resultado_propuesto_ganador_pareja_id", None)
        sets_text  = prp.sets_text            if prp else getattr(p, "resultado_propuesto_sets_text", None)

        # Si falta info mínima, no cerramos
        if not ganador_id:
            continue

        pareja_g = p1 if ganador_id == p1.id else p2
        pareja_p = p2 if ganador_id == p1.id else p1

        # Seguridad: que existan jugadores
        ganadores  = [getattr(pareja_g, "jugador1", None), getattr(pareja_g, "jugador2", None)]
        perdedores = [getattr(pareja_p, "jugador1", None), getattr(pareja_p, "jugador2", None)]
        ganadores  = [j for j in ganadores  if j]
        perdedores = [j for j in perdedores if j]

        # Bonus por victoria n° N (contando ésta)
        victorias_previas = (
            db.session.query(PartidoResultado)
            .join(Partido, PartidoResultado.partido_id == Partido.id)
            .filter(PartidoResultado.ganador_pareja_id == pareja_g.id)
            .filter(Partido.id != p.id)
            .count()
        )
        aplica_bonus = (victorias_previas + 1) >= BONUS_APLICA_DESDE

        # ===== Aplicar puntos (con bordes de categoría) =====
        for jg in ganadores:
            delta = DELTA_WIN + (DELTA_WIN_BONUS if aplica_bonus else 0)
            aplicar_delta_rankeable(jg, delta)

        for jp in perdedores:
            aplicar_delta_rankeable(jp, DELTA_LOSS)
        # ===== fin aplicar puntos =====

        # Guardar resultado final
        pr = PartidoResultado(
            partido_id=p.id,
            ganador_pareja_id=ganador_id,
            sets_text=(sets_text or None)
        )
        db.session.add(pr)
        p.estado = 'JUGADO'

        # Si hay desafío atado, actualizá estados (idéntico a tu flujo de confirmación)
        desafio = Desafio.query.filter_by(partido_id=p.id).first()
        if desafio:
            def ensure_estado(j):
                e = JugadorEstado.query.filter_by(jugador_id=j.id).first()
                if not e:
                    e = JugadorEstado(jugador_id=j.id)
                    db.session.add(e)
                    db.session.flush()
                return e

            pareja_inferior = p.pareja1
            pareja_superior = p.pareja2
            inferiores = [getattr(pareja_inferior, "jugador1", None), getattr(pareja_inferior, "jugador2", None)]
            superiores = [getattr(pareja_superior, "jugador1", None), getattr(pareja_superior, "jugador2", None)]
            inferiores = [j for j in inferiores if j]
            superiores = [j for j in superiores if j]

            if ganador_id == pareja_inferior.id:
                for jj in inferiores:
                    e = ensure_estado(jj)
                    e.victorias_vs_superior = (e.victorias_vs_superior or 0) + 1
                    if e.victorias_vs_superior >= 3:
                        cat_sup = desafio.categoria_superior
                        if cat_sup:
                            jj.categoria_id = cat_sup.id
                            jj.puntos = cat_sup.puntos_max
                        e.victorias_vs_superior = 0
                        e.derrotas_vs_inferior = 0
            else:
                for jj in superiores:
                    e = ensure_estado(jj)
                    e.derrotas_vs_inferior = (e.derrotas_vs_inferior or 0) + 1
                    if e.derrotas_vs_inferior >= 3:
                        cat_inf = desafio.categoria_origen
                        if cat_inf:
                            jj.categoria_id = cat_inf.id
                            jj.puntos = cat_inf.puntos_max
                        e.derrotas_vs_inferior = 0
                        e.victorias_vs_superior = 0

            desafio.estado = 'JUGADO'

        # Limpiar propuesta (tabla + legacy)
        if prp:
            db.session.delete(prp)

        p.resultado_propuesto_ganador_pareja_id = None
        p.resultado_propuesto_sets_text = None
        p.resultado_propuesto_por_id = None
        p.resultado_propuesto_en = None
        p.confirmo_pareja1 = None
        p.confirmo_pareja2 = None

        cerrados += 1

    db.session.commit()
    return cerrados

def pertenece_a_alguna_pareja(p, usuario):
    """Devuelve 'p1'/'p2' si el usuario integra esa pareja, sino ''."""
    if not usuario or not p:
        return ''
    uid = getattr(usuario, 'id', None)
    if not uid:
        return ''
    if p.pareja1 and (getattr(p.pareja1.jugador1, 'id', None) == uid or getattr(p.pareja1.jugador2, 'id', None) == uid):
        return 'p1'
    if p.pareja2 and (getattr(p.pareja2.jugador1, 'id', None) == uid or getattr(p.pareja2.jugador2, 'id', None) == uid):
        return 'p2'
    return ''


def puede_proponer_resultado(p, usuario=None):
    """
    Reglas:
      - Bloquear sólo estados terminales/no editables ('JUGADO', 'CANCELADO', 'EN_REVISION').
      - No debe existir PartidoResultado definitivo.
      - Si existe PRP:
          * si la propuso mi misma pareja -> permitir 'editar propuesta' (opcional)
          * si la propuso la pareja rival -> NO proponer; redirigir a 'responder propuesta'.
      - Debe pertenecer a alguna pareja del partido (o ser admin; el admin pasa el guard
        pero no se le asigna 'side' automáticamente).
    """
    if not p:
        return (False, "Partido inválido.", False, None)

    # Estados no editables (blacklist)
    estados_bloqueados = {'JUGADO', 'CANCELADO', 'EN_REVISION'}
    if getattr(p, 'estado', None) in estados_bloqueados:
        return (False, "Estado no habilitado.", False, None)

    # ¿ya hay resultado final?
    ya = db.session.query(PartidoResultado).filter_by(partido_id=p.id).first()
    if ya:
        return (False, "El partido ya tiene resultado definitivo.", False, None)

    # ¿existe propuesta?
    try:
        from .models import PartidoResultadoPropuesto as PRP
    except Exception:
        PRP = globals().get('PartidoResultadoPropuesto', None)

    if PRP:
        prp = db.session.query(PRP).filter_by(partido_id=p.id).one_or_none()
    else:
        prp = None

    # ¿pertenezco a alguna pareja? (o soy admin)
    side = pertenece_a_alguna_pareja(p, usuario)
    es_admin = bool(getattr(usuario, 'is_admin', False))
    if not side and not es_admin:
        return (False, "No integrás este partido.", False, None)

    # Si no hay PRP, puedo proponer
    if not prp:
        return (True, "", False, None)  # OK proponer

    # Hay PRP existente → ¿de quién es?
    pareja_prop_id = getattr(prp, 'propuesto_por_pareja_id', None)
    mi_pareja_id = None
    if side == 'p1':
        mi_pareja_id = getattr(p.pareja1, 'id', None)
    elif side == 'p2':
        mi_pareja_id = getattr(p.pareja2, 'id', None)

    # Si soy admin pero no integrante, no forzamos ownership: tratamos como "rival" para obligar a responder
    if mi_pareja_id is not None and pareja_prop_id == mi_pareja_id:
        # Mi misma pareja propuso → permitir “editar”
        return (True, "", False, prp)
    else:
        # La tiene que responder la pareja rival (o el admin viene a revisar)
        return (False, "Hay una propuesta pendiente del rival. Debés responderla.", True, prp)





# === ENDPOINT HTTP: para cron (protegido por token) ===
import hmac

# === CRON SEGURO: POST + Authorization: Bearer ===
@app.post('/tareas/propuestas/autocerrar')
def tareas_autocerrar_propuestas_vencidas():
    # Esperamos: Authorization: Bearer <AUTOCRON_TOKEN>
    auth = request.headers.get('Authorization', '')
    expected = f"Bearer {AUTOCRON_TOKEN}"

    if not (auth and hmac.compare_digest(auth, expected)):
        # No revelamos detalles: 403 genérico
        return jsonify({"error": "forbidden"}), 403

    try:
        cerrados = _cerrar_propuestas_vencidas_core()
        return jsonify({"cerrados": cerrados}), 200
    except Exception as e:
        current_app.logger.exception("Error en autocerrar propuestas vencidas")
        return jsonify({"error": "internal_error"}), 500


# === HOOK LAZY: lo corre como máximo 1 vez por minuto cuando hay tráfico ===
_last_autocierre_run = {'ts': None}

@app.before_request
def _autocierre_lazy_hook():
    # Deshabilitado por defecto; sólo corre si AUTOCRON_ENABLED está activo (1/true/yes/on)
    if not (globals().get('AUTOCRON_ENABLED') or False):
        return

    # Evitar estáticos y POST (lo corremos en GETs “normales”)
    if request.method != 'GET' or request.path.startswith('/static'):
        return

    now = datetime.utcnow()
    ts = _last_autocierre_run['ts']
    # Run cada 60s como máximo
    if ts is None or (now - ts) >= timedelta(seconds=60):
        try:
            _cerrar_propuestas_vencidas_core()
        except Exception:
            # No interrumpas la navegación si algo falla
            pass
        # ⚠️ importante: actualizar el último run
        _last_autocierre_run['ts'] = now



@app.route('/desafios')
def desafios_list():
    desafios = (db.session.query(Desafio)
                .order_by(Desafio.creado_en.desc())
                .all())
    return render_template('desafios_list.html', desafios=desafios)


@app.route('/desafios/<int:desafio_id>/programar', methods=['POST'])
def desafios_programar(desafio_id):
    d = get_or_404(Desafio, desafio_id)

    # Debe estar plenamente aceptado
    if not (d.estado == 'ACEPTADO' and d.rival1_acepto == 1 and d.rival2_acepto == 1):
        flash('Aún falta que ambos rivales acepten. No se puede programar el partido.', 'error')
        return redirect(url_for('desafios_list'))

    pareja_inferior = get_or_create_pareja(d.desafiante_id, d.companero_id, d.categoria_origen_id)
    pareja_superior = get_or_create_pareja(d.rival1_id, d.rival2_id, d.categoria_superior_id)

    # ⬅️ Trazabilidad: guardar el desafío que originó el partido
    partido = Partido(
        categoria_id=d.categoria_superior_id,
        pareja1_id=pareja_inferior.id,  # inferior
        pareja2_id=pareja_superior.id,  # superior
        estado='PENDIENTE',
        creado_por_desafio_id=d.id      # <<<<<<<<<<<<<<<<< clave de trazabilidad
    )
    db.session.add(partido)
    db.session.flush()  # asegura partido.id sin cerrar la transacción

    d.partido_id = partido.id
    # El estado del desafío se mantiene en ACEPTADO hasta que se juegue
    db.session.commit()

    flash(f'Partido #{partido.id} programado para el desafío.', 'ok')
    return redirect(url_for('desafios_list'))


@app.route('/desafios/nuevo', methods=['GET', 'POST'])
def desafios_new():
    # --- Debe haber sesión ---
    desafiante = get_current_jugador()
    if not desafiante:
        flash('Iniciá sesión para crear un desafío.', 'error')
        return redirect(url_for('login'))

    # --- Debe tener categoría ---
    if not desafiante.categoria:
        flash('Tu perfil no tiene categoría asignada.', 'error')
        return redirect(url_for('desafios_list'))

    cat_origen = desafiante.categoria

    # --- Buscar categoría superior ---
    cat_superior = (
        db.session.query(Categoria)
        .filter(Categoria.puntos_max == cat_origen.puntos_min - 1)
        .first()
    )

    # --- Candidatos a compañero: misma categoría, distinto de mí, en zona de ascenso ---
    candidatos_companero = (
        db.session.query(Jugador)
        .filter(
            Jugador.activo.is_(True),
            Jugador.categoria_id == cat_origen.id,
            Jugador.id != desafiante.id,
            Jugador.puntos <= cat_origen.puntos_min
        )
        .order_by(Jugador.nombre_completo.asc())
        .all()
    )

    # --- Candidatos a rivales (si hay categoría superior) ---
    candidatos_rivales = []
    if cat_superior:
        candidatos_rivales = (
            db.session.query(Jugador)
            .filter(
                Jugador.activo.is_(True),
                Jugador.categoria_id == cat_superior.id
            )
            .order_by(Jugador.puntos.asc())
            .all()
        )

    # --- POST: creación del desafío ---
    if request.method == 'POST':
        companero_id = request.form.get('companero_id', type=int)
        rival1_id    = request.form.get('rival1_id', type=int)
        rival2_id    = request.form.get('rival2_id', type=int)

        # 1) Validaciones de presencia
        if not (companero_id and rival1_id and rival2_id):
            flash('Completá compañero y los dos rivales.', 'error')
            return redirect(url_for('desafios_new'))

        # 2) No se pueden repetir jugadores
        if len({desafiante.id, companero_id, rival1_id, rival2_id}) != 4:
            flash('Los cuatro jugadores deben ser distintos.', 'error')
            return redirect(url_for('desafios_new'))

        # 3) Cargar jugadores
        companero = db.session.get(Jugador, companero_id)
        rival1    = db.session.get(Jugador, rival1_id)
        rival2    = db.session.get(Jugador, rival2_id)
        if not all([companero, rival1, rival2]):
            flash('Alguno de los jugadores seleccionados no existe.', 'error')
            return redirect(url_for('desafios_new'))

        # 4) Todos activos
        if not (desafiante.activo and companero.activo and rival1.activo and rival2.activo):
            flash('Todos los jugadores deben estar activos.', 'error')
            return redirect(url_for('desafios_new'))

        # 5) Compañero: misma categoría y en zona de ascenso
        if companero.categoria_id != cat_origen.id:
            flash('El compañero debe ser de tu misma categoría.', 'error')
            return redirect(url_for('desafios_new'))
        if companero.puntos is None or companero.puntos > cat_origen.puntos_min:
            flash(f'El compañero debe estar en zona de ascenso (≤ {cat_origen.puntos_min}).', 'error')
            return redirect(url_for('desafios_new'))

        # 6) Yo también debo estar en zona de ascenso
        if desafiante.puntos is None or desafiante.puntos > cat_origen.puntos_min:
            flash(f'Necesitás estar en zona de ascenso (≤ {cat_origen.puntos_min}) para desafiar.', 'error')
            return redirect(url_for('desafios_new'))

        # 7) Rivales: ambos en categoría superior
        if not cat_superior:
            flash('No se encontró la categoría superior correspondiente.', 'error')
            return redirect(url_for('desafios_new'))
        if not (rival1.categoria_id == cat_superior.id and rival2.categoria_id == cat_superior.id):
            flash(f'Los rivales deben pertenecer a {cat_superior.nombre}.', 'error')
            return redirect(url_for('desafios_new'))

        # 8) Crear desafío
        d = Desafio(
            desafiante_id=desafiante.id,
            companero_id=companero.id,
            rival1_id=rival1.id,
            rival2_id=rival2.id,
            categoria_origen_id=cat_origen.id,
            categoria_superior_id=cat_superior.id,
            partido_id=None,
            estado='PENDIENTE'
        )
        db.session.add(d)
        db.session.commit()

        flash('Desafío creado. Falta programar el partido.', 'ok')
        return redirect(url_for('desafios_list'))

    # --- GET: mostrar formulario con listas filtradas ---
    return render_template(
        'desafios_form.html',
        desafiante=desafiante,
        candidatos_companero=candidatos_companero,
        candidatos_rivales=candidatos_rivales,
        cat_superior_nombre=cat_superior.nombre if cat_superior else None
    )


@app.route('/desafios/<int:desafio_id>/responder', methods=['GET', 'POST'])
def desafios_responder(desafio_id):
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión para responder desafíos.', 'error')
        return redirect(url_for('login'))

    d = get_or_404(Desafio, desafio_id)

    # Solo los rivales pueden responder y solo si sigue pendiente o parcialmente aceptado
    if d.estado not in ('PENDIENTE', 'ACEPTADO_PARCIAL'):
        flash('Este desafío ya no permite respuestas.', 'error')
        return redirect(url_for('desafios_list'))

    if j.id not in (d.rival1_id, d.rival2_id):
        flash('Solo los rivales desafiados pueden responder.', 'error')
        return redirect(url_for('desafios_list'))

    cat_sup = d.categoria_superior
    if not cat_sup:
        flash('No se pudo determinar la categoría superior.', 'error')
        return redirect(url_for('desafios_list'))

    # Para elegir compañero alternativo (misma categoría superior, activo, que no sea yo)
    candidatos_compa = (
        db.session.query(Jugador)
        .filter(
            Jugador.activo.is_(True),
            Jugador.categoria_id == cat_sup.id,
            Jugador.id != j.id
        )
        .order_by(Jugador.nombre_completo.asc())
        .all()
    )

    if request.method == 'POST':
        accion = (request.form.get('accion') or '').strip()  # 'aceptar' o 'rechazar'
        compa_nuevo_id = request.form.get('compa_nuevo_id', type=int)  # opcional

        if accion not in ('aceptar', 'rechazar'):
            flash('Acción inválida.', 'error')
            return redirect(url_for('desafios_responder', desafio_id=d.id))

        # Helper para setear flags según quién responde
        def set_flag_acepto(del_rival_id: int, valor: bool):
            if del_rival_id == d.rival1_id:
                d.rival1_acepto = 1 if valor else 0
            elif del_rival_id == d.rival2_id:
                d.rival2_acepto = 1 if valor else 0

        if accion == 'rechazar':
            d.estado = 'RECHAZADO'
            # Reseteamos flags por claridad
            d.rival1_acepto = 0
            d.rival2_acepto = 0
            db.session.commit()
            flash('Rechazaste el desafío.', 'ok')
            return redirect(url_for('desafios_list'))

        # ========= ACEPTAR =========
        # Si el otro rival ya aceptó, NO permitir cambiar compañero
        otro_flag_acepto = d.rival2_acepto if j.id == d.rival1_id else d.rival1_acepto
        if compa_nuevo_id is not None and compa_nuevo_id and (otro_flag_acepto == 1):
            flash('No podés cambiar el compañero: el otro rival ya aceptó la dupla.', 'error')
            return redirect(url_for('desafios_responder', desafio_id=d.id))

        # ¿elige nuevo compañero?
        if compa_nuevo_id:
            if compa_nuevo_id == j.id:
                flash('No podés elegirte a vos mismo como compañero.', 'error')
                return redirect(url_for('desafios_responder', desafio_id=d.id))

            compa_nuevo = db.session.get(Jugador, int(compa_nuevo_id)) if compa_nuevo_id else None
            if not compa_nuevo or not compa_nuevo.activo or compa_nuevo.categoria_id != cat_sup.id:
                flash('El compañero elegido no es válido para este desafío.', 'error')
                return redirect(url_for('desafios_responder', desafio_id=d.id))

            # El que responde queda sí o sí en la dupla; reemplaza al "otro" rival
            if j.id == d.rival1_id:
                d.rival2_id = compa_nuevo.id
            else:
                d.rival1_id = compa_nuevo.id

            # Acepta el que responde; el nuevo compañero aún no aceptó
            d.rival1_acepto = 1 if j.id == d.rival1_id else 0
            d.rival2_acepto = 1 if j.id == d.rival2_id else 0

        else:
            # Acepta con la dupla original → marcamos solo su flag
            set_flag_acepto(j.id, True)

        # Estado según flags
        ambos = (d.rival1_acepto == 1 and d.rival2_acepto == 1)
        d.estado = 'ACEPTADO' if ambos else 'ACEPTADO_PARCIAL'
        db.session.commit()

        flash('Respuesta registrada.' + ('' if ambos else ' Falta aceptación del otro rival.'), 'ok')
        return redirect(url_for('desafios_list'))

    # GET
    return render_template(
        'desafios_responder.html',
        desafio=d,
        yo=j,
        candidatos_compa=candidatos_compa,
        cat_superior_nombre=cat_sup.nombre
    )

@app.route('/abiertos')
def abiertos_list():
    # Categoría preseleccionada para el formulario "Crear"
    selected_cat = request.args.get('new_cat', type=int)

    # ¿Admin quiere ver todo? (solo aplica si el logueado es admin)
    j = get_current_jugador()
    admin_wants_all = (request.args.get('all', type=int) == 1) and (j and j.is_admin)

    # Listado de abiertos (filtrado por estado salvo que admin pida all=1)
    q = db.session.query(PartidoAbierto)
    if not admin_wants_all:
        q = q.filter(PartidoAbierto.estado.in_(["ABIERTO", "LLENO"]))
    abiertos = q.order_by(PartidoAbierto.creado_en.desc()).all()

    # Para los formularios
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()
    jugadores_all = (
        db.session.query(Jugador)
        .filter(Jugador.activo.is_(True))
        .order_by(Jugador.nombre_completo.asc())
        .all()
    )

    # Jugadores a mostrar en el combo "Creador": solo si ya se eligió una categoría
    if selected_cat:
        jugadores_creador = [jug for jug in jugadores_all if jug.categoria_id == selected_cat]
    else:
        jugadores_creador = []

    # === Info de suplencias para la UI (solo de los abiertos que estamos mostrando) ===
    pa_ids = [a.id for a in abiertos] if abiertos else []
    suplentes_counts = {pid: 0 for pid in pa_ids}
    mis_suplencias_pa_ids = set()

    if pa_ids:
        todas_supls = (
            db.session.query(PartidoAbiertoSuplente)
            .filter(PartidoAbiertoSuplente.pa_id.in_(pa_ids))
            .all()
        )
        for s in todas_supls:
            suplentes_counts[s.pa_id] = suplentes_counts.get(s.pa_id, 0) + 1
            if j and s.jugador_id == j.id:
                mis_suplencias_pa_ids.add(s.pa_id)

    return render_template(
        'abiertos_list.html',
        abiertos=abiertos,
        categorias=categorias,
        jugadores=jugadores_all,          # se sigue usando para "Unirse"
        jugadores_creador=jugadores_creador,
        selected_cat=selected_cat,

        # NUEVO: para ocultar/mostrar acciones y contar suplentes
        suplentes_counts=suplentes_counts,
        mis_suplencias_pa_ids=mis_suplencias_pa_ids,

        # Opcional: por si querés mostrar un toggle o badge en el template
        admin_wants_all=1 if admin_wants_all else 0
    )


@app.route('/abiertos/nuevo', methods=['POST'])
def abiertos_new():
    categoria_id = request.form.get('categoria_id', type=int)
    creador_id = request.form.get('creador_id', type=int)
    nota = (request.form.get('nota') or '').strip()

    if not categoria_id or not creador_id:
        flash('Elegí categoría y creador.', 'error')
        return redirect(url_for('abiertos_list'))

    cat = db.session.get(Categoria, int(categoria_id)) if categoria_id is not None else None
    creador = db.session.get(Jugador, int(creador_id)) if creador_id else None
    if not cat or not creador:
        flash('Datos inválidos.', 'error')
        return redirect(url_for('abiertos_list'))

    if not creador.activo:
        flash('El creador está inactivo. Reactivalo o elegí otro jugador.', 'error')
        return redirect(url_for('abiertos_list'))

    if creador.categoria_id != cat.id:
        flash('El creador debe pertenecer a la categoría elegida.', 'error')
        return redirect(url_for('abiertos_list'))

    # Crear partido abierto
    pa = PartidoAbierto(
        categoria_id=cat.id,
        creador_id=creador.id,
        nota=nota or None,
        estado='ABIERTO'
    )
    db.session.add(pa)
    db.session.flush()  # obtener id antes del commit

    db.session.add(PartidoAbiertoJugador(pa_id=pa.id, jugador_id=creador.id))
    db.session.commit()

    # =================== ✉️ EMAIL MASIVO UPLAY ===================
    from flask import current_app
    from datetime import datetime

    try:
        # Obtener todos los jugadores activos de la categoría (menos el creador)
        jugadores_misma_cat = (
            db.session.query(Jugador)
            .filter(
                Jugador.activo.is_(True),
                Jugador.categoria_id == cat.id,
                Jugador.id != creador.id
            )
            .all()
        )

        if jugadores_misma_cat:
            asunto = f"🎾 ¡Nuevo partido abierto en tu categoría ({cat.nombre})!"
            enlace = url_for('abiertos_list', _external=True)

            mensaje_html = f"""
            <div style="font-family:'Poppins',Arial,sans-serif;background:#f6f6f9;padding:30px 0;">
              <div style="max-width:600px;margin:auto;background:white;border-radius:12px;
                          box-shadow:0 3px 10px rgba(0,0,0,0.08);overflow:hidden;">
                <div style="text-align:center;padding:24px 0;border-bottom:1px solid #eee;">
                  <img src="https://uplay-gev5.onrender.com/static/logo/uplay-logo.svg"
                       alt="UPLAY" style="height:64px;margin-bottom:8px;">
                  <h2 style="color:#7B68EE;margin:0;font-size:1.3rem;">¡Nuevo partido abierto en tu categoría!</h2>
                </div>
                <div style="padding:24px;color:#222;line-height:1.5;">
                  <p><strong>{creador.nombre_completo}</strong> abrió un partido y busca compañero y rivales.</p>
                  {"<p><em>Nota del creador:</em> " + nota + "</p>" if nota else ""}
                  <p>Si querés sumarte, podés hacerlo desde UPLAY:</p>
                  <div style="text-align:center;margin-top:18px;">
                    <a href="{enlace}" style="background:#7B68EE;color:white;padding:12px 22px;
                       border-radius:8px;text-decoration:none;display:inline-block;">
                       Ver partidos abiertos en UPLAY
                    </a>
                  </div>
                </div>
                <div style="background:#fafafa;border-top:1px solid #eee;text-align:center;padding:12px;">
                  <p style="font-size:0.85rem;color:#666;margin:4px 0;">© {datetime.now().year} UPLAY</p>
                  <p style="font-size:0.8rem;color:#aaa;margin:0;">Este es un mensaje automático del sistema.</p>
                </div>
              </div>
            </div>
            """

            # Enviar a todos los jugadores de la categoría
            for jugador in jugadores_misma_cat:
                if jugador.email:
                    try:
                        send_mail(
                            subject=asunto,
                            body="Nuevo partido abierto en UPLAY",
                            to=jugador.email,
                            html_body=mensaje_html
                        )
                    except Exception as e:
                        current_app.logger.warning(
                            f"[UPLAY] Error enviando mail a {jugador.email}: {e}"
                        )

            current_app.logger.info(
                f"[UPLAY] Mails enviados a {len(jugadores_misma_cat)} jugadores de la categoría {cat.nombre}"
            )

    except Exception as e:
        current_app.logger.exception(f"[UPLAY] Error general al enviar notificación masiva: {e}")
    # ===============================================================

    flash('Partido abierto creado y notificaciones enviadas a tu categoría.', 'ok')
    return redirect(url_for('abiertos_list'))


@app.route('/abiertos/<int:pa_id>/unirse', methods=['POST'])
def abiertos_join(pa_id):
    pa = get_or_404(PartidoAbierto, pa_id)

    # Debe haber sesión iniciada
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión para unirte.', 'error')
        return redirect(url_for('login'))

    # Validar estado del abierto
    if pa.estado not in ('ABIERTO', 'LLENO'):
        flash('Este partido no acepta inscripciones.', 'error')
        return redirect(url_for('abiertos_list'))

    # Validar categoría y estado del jugador
    if not j.activo:
        flash('No se puede unir un jugador inactivo.', 'error')
        return redirect(url_for('abiertos_list'))

    if j.categoria_id != pa.categoria_id:
        flash('Solo pueden unirse jugadores de la misma categoría.', 'error')
        return redirect(url_for('abiertos_list'))

    # Capacidad (consulta directa a DB para evitar desfasajes)
    cupo = (db.session.query(PartidoAbiertoJugador)
            .filter_by(pa_id=pa.id)
            .count())
    if cupo >= 4:
        flash('Este partido ya tiene 4 inscriptos.', 'error')
        return redirect(url_for('abiertos_list'))

    # Ya inscripto
    existe = PartidoAbiertoJugador.query.filter_by(pa_id=pa.id, jugador_id=j.id).first()
    if existe:
        flash('Ya estás inscripto en este partido abierto.', 'ok')
        return redirect(url_for('abiertos_list'))

    # Preferencia de compañero (opcional)
    pref_id = request.form.get('partner_pref_id', type=int)
    partner_pref_id = None
    if pref_id:
        # aseguramos que la preferencia apunte a alguien ya inscripto
        ids_inscriptos = {
            it.jugador_id
            for it in db.session.query(PartidoAbiertoJugador)
                                 .filter_by(pa_id=pa.id).all()
        }
        if pref_id == j.id:
            flash('No podés elegirte a vos mismo como compañero.', 'error')
            return redirect(url_for('abiertos_list'))
        if pref_id not in ids_inscriptos:
            flash('La preferencia debe ser alguien ya inscripto en este partido.', 'error')
            return redirect(url_for('abiertos_list'))
        partner_pref_id = pref_id

    # Inscribir (y limpiar suplencia si la tuviera en este abierto)
    db.session.add(PartidoAbiertoJugador(
        pa_id=pa.id,
        jugador_id=j.id,
        partner_pref_id=partner_pref_id
    ))

    # Si estaba como suplente en este mismo abierto, lo quitamos
    sup = (db.session.query(PartidoAbiertoSuplente)
           .filter_by(pa_id=pa.id, jugador_id=j.id)
           .first())
    if sup:
        db.session.delete(sup)

    # Actualizar estado si corresponde
    cupo += 1
    if cupo >= 4:
        pa.estado = 'LLENO'

    db.session.commit()

    msg = 'Te uniste al partido abierto.'
    if partner_pref_id:
        msg += ' Preferencia de compañero guardada.'
    if sup:
        msg += ' (Se eliminó tu suplencia en este abierto).'

    flash(msg, 'ok')
    return redirect(url_for('abiertos_list'))




@app.route('/abiertos/<int:pa_id>/salir', methods=['POST'])
def abiertos_leave(pa_id):
    pa = get_or_404(PartidoAbierto, pa_id)

    # Debe haber sesión
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión para continuar.', 'error')
        return redirect(url_for('login'))

    # Si no viene jugador_id en el form, asumimos que el que se baja es el logueado
    jugador_id = request.form.get('jugador_id', type=int) or j.id

    # Autorización: solo el propio jugador o un admin puede dar la baja
    if not (j.is_admin or jugador_id == j.id):
        flash('No tenés permisos para dar de baja a ese jugador.', 'error')
        return redirect(url_for('abiertos_list'))

    r = PartidoAbiertoJugador.query.filter_by(pa_id=pa.id, jugador_id=jugador_id).first()
    if not r:
        flash('Ese jugador no estaba inscripto.', 'error')
        return redirect(url_for('abiertos_list'))

    # Guardamos el jugador que se baja (para notificaciones)
    try:
        jugador_baja = r.jugador  # si hay relación
    except Exception:
        jugador_baja = db.session.get(Jugador, int(jugador_id)) if jugador_id else None

    # Eliminar inscripción de titular
    db.session.delete(r)

    # Si, además, estaba como suplente por alguna razón, quitarlo también
    s_mismo = PartidoAbiertoSuplente.query.filter_by(pa_id=pa.id, jugador_id=jugador_id).first()
    if s_mismo:
        db.session.delete(s_mismo)

    db.session.flush()  # aseguramos que la baja impacte en los conteos

    # Cupo actual luego de la baja
    cupo_actual = (db.session.query(PartidoAbiertoJugador)
                   .filter_by(pa_id=pa.id)
                   .count())

    suplente_promovido = None

    # Si quedó un lugar libre, intentamos promover al primer suplente (FIFO)
    if cupo_actual < 4:
        s = (db.session.query(PartidoAbiertoSuplente)
             .filter_by(pa_id=pa.id)
             .order_by(PartidoAbiertoSuplente.id.asc())
             .first())

        if s:
            # Seguridad: evitar duplicar si por alguna razón ya está inscripto
            ya_titular = (db.session.query(PartidoAbiertoJugador)
                          .filter_by(pa_id=pa.id, jugador_id=s.jugador_id)
                          .first())
            if not ya_titular:
                db.session.add(PartidoAbiertoJugador(pa_id=pa.id, jugador_id=s.jugador_id))
                suplente_promovido = s.jugador
                cupo_actual += 1

            # Quitamos al suplente de la lista
            db.session.delete(s)
            db.session.flush()

    # Estado del abierto según cupo final
    if cupo_actual >= 4:
        pa.estado = 'LLENO'
    else:
        # Si estaba “LLENO” y ahora hay menos de 4, vuelve a ABIERTO
        if pa.estado == 'LLENO':
            pa.estado = 'ABIERTO'

    db.session.commit()

    # ================== Notificaciones por email (no bloqueantes) ==================
    # Link útil (lista de abiertos)
    try:
        abiertos_url = url_for('abiertos_list', _external=True)
    except Exception:
        abiertos_url = request.url_root.rstrip('/') + '/abiertos'

    categoria_nombre = getattr(pa.categoria, 'nombre', 'Categoría')
    creador = getattr(pa, 'creador', None)
    creador_nombre = getattr(creador, 'nombre_completo', 'alguien')

    # 1) Aviso al suplente promovido
    if suplente_promovido and getattr(suplente_promovido, 'email', None):
        try:
            subject = f"UPLAY: Fuiste promovido a titular en un abierto (#{pa.id})"
            body = (
                f"¡Buenas {suplente_promovido.nombre_completo}!\n\n"
                f"Se liberó un lugar y fuiste promovido a titular en el abierto #{pa.id} "
                f"de {categoria_nombre} (creado por {creador_nombre}).\n\n"
                f"Ver abiertos: {abiertos_url}\n\n"
                f"— UPLAY"
            )
            html_body = (
                f"<p>¡Hola <strong>{suplente_promovido.nombre_completo}</strong>!</p>"
                f"<p>Se liberó un lugar y fuiste promovido a <strong>titular</strong> en el "
                f"abierto <strong>#{pa.id}</strong> de <strong>{categoria_nombre}</strong> "
                f"(creado por {creador_nombre}).</p>"
                f"<p><a href='{abiertos_url}'>Ver abiertos</a></p>"
                f"<p>— UPLAY</p>"
            )
            send_mail(subject=subject, body=body, html_body=html_body, to=[suplente_promovido.email])
        except Exception as e:
            current_app.logger.exception("No se pudo enviar correo al suplente promovido: %s", e)

    # 2) Aviso al creador del abierto (CC admins)
    try:
        # Emails de admins (solo los que tienen email)
        admin_emails = [a.email for a in db.session.query(Jugador).filter(
            Jugador.is_admin.is_(True),
            Jugador.email.isnot(None)
        ).all() if a.email]

        creador_email = getattr(creador, 'email', None)
        if creador_email or admin_emails:
            quien_baja = getattr(jugador_baja, 'nombre_completo', f'Jugador #{jugador_id}')
            promo_txt = (f" Fue promovido {suplente_promovido.nombre_completo} desde la lista de suplentes."
                         if suplente_promovido else
                         " No había suplentes disponibles.")
            subject_c = f"UPLAY: Baja en abierto #{pa.id} ({categoria_nombre})"
            body_c = (
                f"Hola {creador_nombre},\n\n"
                f"{quien_baja} se dio de baja del abierto #{pa.id} de {categoria_nombre}.\n"
                f"{promo_txt}\n\n"
                f"Ver abiertos: {abiertos_url}\n\n"
                f"— UPLAY"
            )
            html_body_c = (
                f"<p>Hola <strong>{creador_nombre}</strong>,</p>"
                f"<p><strong>{quien_baja}</strong> se dio de baja del abierto <strong>#{pa.id}</strong> "
                f"de <strong>{categoria_nombre}</strong>.</p>"
                f"<p>{promo_txt}</p>"
                f"<p><a href='{abiertos_url}'>Ver abiertos</a></p>"
                f"<p>— UPLAY</p>"
            )

            to_list = [creador_email] if creador_email else []
            cc_list = admin_emails or []

            # Tu helper puede aceptar cc/bcc; si no, duplicá el envío a admins.
            try:
                send_mail(subject=subject_c, body=body_c, html_body=html_body_c, to=to_list, cc=cc_list)
            except TypeError:
                # Fallback si send_mail no soporta cc: enviar a creador y luego a admins
                if to_list:
                    send_mail(subject=subject_c, body=body_c, html_body=html_body_c, to=to_list)
                for adm in cc_list:
                    send_mail(subject=subject_c, body=body_c, html_body=html_body_c, to=[adm])
    except Exception as e:
        current_app.logger.exception("No se pudo enviar correo de notificación al creador/admins: %s", e)

    # ================== Mensajes de UI ==================
    if suplente_promovido:
        flash(f'Baja confirmada. Se sumó {suplente_promovido.nombre_completo} desde la lista de suplentes.', 'ok')
    else:
        flash('Baja confirmada.', 'ok')

    return redirect(url_for('abiertos_list'))



@app.route('/abiertos/<int:pa_id>/armar', methods=['POST'])
def abiertos_armar(pa_id):
    pa = get_or_404(PartidoAbierto, pa_id)

    # Estado válido y cupo exacto
    if pa.estado not in ('ABIERTO', 'LLENO'):
        flash('Este abierto no se puede armar en este estado.', 'error')
        return redirect(url_for('abiertos_list'))

    ins = list(pa.inscriptos or [])
    if len(ins) != 4:
        flash('Necesitás exactamente 4 inscriptos para armar el partido.', 'error')
        return redirect(url_for('abiertos_list'))

    # Construimos estructuras de trabajo
    jugadores = {it.jugador_id: it.jugador for it in ins}
    prefs = {it.jugador_id: (it.partner_pref_id or None) for it in ins}
    libres = set(jugadores.keys())
    parejas = []

    # 1) Parejas por preferencia RECÍPROCA (A prefiere B y B prefiere A)
    usados = set()
    for a in list(libres):
        if a in usados:
            continue
        b = prefs.get(a)
        if b and (b in libres) and (prefs.get(b) == a) and (b not in usados):
            parejas.append((a, b))
            usados.update([a, b])
    libres -= usados

    # 2) Parejas por preferencia UNILATERAL (si el preferido sigue libre)
    usados = set()
    for a in list(libres):
        if a in usados:
            continue
        b = prefs.get(a)
        if b and (b in libres) and (b not in usados):
            parejas.append((a, b))
            usados.update([a, b])
    libres -= usados

    # 3) Completar con los que queden (emparejar arbitrariamente)
    libres = list(libres)
    libres.sort()  # orden estable
    while len(libres) >= 2 and len(parejas) < 2:
        a = libres.pop(0)
        b = libres.pop(0)
        parejas.append((a, b))

    # Validación final
    if len(parejas) != 2:
        flash('No se pudo determinar las dos parejas. Revisá las preferencias.', 'error')
        return redirect(url_for('abiertos_list'))

    # Crear/obtener parejas en DB (misma categoría del abierto)
    try:
        p1_ids = parejas[0]
        p2_ids = parejas[1]
        parejaA = get_or_create_pareja(p1_ids[0], p1_ids[1], pa.categoria_id)
        parejaB = get_or_create_pareja(p2_ids[0], p2_ids[1], pa.categoria_id)
    except Exception as e:
        flash(f'Error creando parejas: {e}', 'error')
        return redirect(url_for('abiertos_list'))

    # Crear el Partido (intra-nivel) PENDIENTE
    partido = Partido(
        categoria_id=pa.categoria_id,
        pareja1_id=parejaA.id,
        pareja2_id=parejaB.id,
        estado='PENDIENTE'
    )
    db.session.add(partido)
    db.session.flush()  # obtener partido.id

    # Marcar el abierto como partido creado
    pa.estado = 'PARTIDO_CREADO'
    db.session.commit()

    flash(f'Partido #{partido.id} creado a partir del abierto. Ya podés cargar el resultado cuando jueguen.', 'ok')
    return redirect(url_for('partidos_list'))

@app.post('/abiertos/<int:pa_id>/eliminar')
def abiertos_eliminar(pa_id):
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión.', 'error')
        return redirect(url_for('login'))
    if not j.is_admin:
        flash('Solo administradores pueden eliminar partidos abiertos.', 'error')
        return redirect(url_for('abiertos_list'))

    pa = get_or_404(PartidoAbierto, pa_id)

    # Seguridad: si ya derivó en un partido, no permitir borrado duro
    if pa.estado == 'PARTIDO_CREADO':
        flash('Este abierto ya creó un partido. No se puede eliminar.', 'warning')
        return redirect(url_for('abiertos_list'))

    # Borrado duro: gracias al backref con cascade, también borra inscriptos
    db.session.delete(pa)
    db.session.commit()
    flash(f'Abierto #{pa_id} eliminado.', 'ok')
    return redirect(url_for('abiertos_list'))

@app.post('/abiertos/<int:pa_id>/cancelar')
def abiertos_cancelar(pa_id):
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión.', 'error')
        return redirect(url_for('login'))

    pa = get_or_404(PartidoAbierto, pa_id)

    # Permisos: admin o creador del abierto
    if not (j.is_admin or j.id == pa.creador_id):
        flash('No tenés permisos para cancelar este abierto.', 'error')
        return redirect(url_for('abiertos_list'))

    # Estados que no se deben cancelar
    if pa.estado == 'PARTIDO_CREADO':
        flash('Este abierto ya derivó en un partido. No se puede cancelar.', 'warning')
        return redirect(url_for('abiertos_list'))

    if pa.estado == 'CANCELADO':
        flash('Este abierto ya está cancelado.', 'warning')
        return redirect(url_for('abiertos_list'))

    # Cancelar
    pa.estado = 'CANCELADO'
    db.session.commit()
    flash(f'Abierto #{pa_id} cancelado.', 'ok')
    return redirect(url_for('abiertos_list'))

@app.post('/abiertos/<int:pa_id>/suplente')
def abiertos_suplente(pa_id):
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión.', 'error')
        return redirect(url_for('login'))

    pa = get_or_404(PartidoAbierto, pa_id)

    # (Opcional) misma categoría
    if j.categoria_id != pa.categoria_id:
        flash('Solo jugadores de la misma categoría pueden proponerse como suplentes.', 'error')
        return redirect(url_for('abiertos_list'))

    # Si ya está inscripto como titular, no permitir suplencia
    ya_titular = PartidoAbiertoJugador.query.filter_by(pa_id=pa.id, jugador_id=j.id).first()
    if ya_titular:
        flash('Ya estás inscripto en este abierto.', 'warning')
        return redirect(url_for('abiertos_list'))

    # Si ya es suplente, no duplicar
    ya_suplente = PartidoAbiertoSuplente.query.filter_by(pa_id=pa.id, jugador_id=j.id).first()
    if ya_suplente:
        flash('Ya estás propuesto como suplente en este abierto.', 'ok')
        return redirect(url_for('abiertos_list'))

    db.session.add(PartidoAbiertoSuplente(pa_id=pa.id, jugador_id=j.id))
    db.session.commit()
    flash('Quedaste propuesto como suplente. Si se libera un lugar, te avisamos.', 'ok')
    return redirect(url_for('abiertos_list'))


@app.post('/abiertos/<int:pa_id>/suplente/quitar')
def abiertos_suplente_quitar(pa_id):
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión.', 'error')
        return redirect(url_for('login'))

    pa = get_or_404(PartidoAbierto, pa_id)

    reg = PartidoAbiertoSuplente.query.filter_by(pa_id=pa.id, jugador_id=j.id).first()
    if not reg:
        flash('No estabas anotado como suplente en este abierto.', 'warning')
        return redirect(url_for('abiertos_list'))

    db.session.delete(reg)
    db.session.commit()
    flash('Te quitaste de la lista de suplentes.', 'ok')
    return redirect(url_for('abiertos_list'))


@app.route('/ranking')
def ranking():
    # Filtro opcional de rama (?rama=CABALLEROS|DAMAS|MIXTA)
    rama_filtro = (request.args.get('rama') or '').upper().strip()
    rama_filtro = rama_filtro if rama_filtro in ('CABALLEROS', 'DAMAS', 'MIXTA') else ''

    # NUEVO: filtro opcional de categoría (?categoria_id=123)
    categoria_id = request.args.get('categoria_id', type=int)

    # 1) Traer categorías y ordenarlas de superior→inferior (superior = puntos_min más BAJO)
    categorias = Categoria.query.all()

    # Aplicar filtro de rama por nombre (sin tocar DB)
    if rama_filtro:
        categorias = [c for c in categorias if infer_rama(c.nombre) == rama_filtro]

    # Orden: superior primero (puntos_min asc)
    categorias.sort(key=lambda c: c.puntos_min)

    # Para el combo del template (categorías visibles según rama)
    categorias_visible = list(categorias)

    # Si vino categoría específica, quedarnos solo con esa
    if categoria_id:
        categorias = [c for c in categorias if c.id == categoria_id]

    # 2) Traer todos los jugadores y agrupar por categoría
    jugadores = (
        db.session.query(Jugador)
        .order_by(Jugador.puntos.asc(), Jugador.nombre_completo.asc())
        .all()
    )

    # Mapear jugadores por categoria_id respetando filtros (rama y categoría)
    jugadores_por_cat: dict[int, list[Jugador]] = {}
    cats_ids_permitidos = {c.id for c in categorias}  # tras filtros

    for j in jugadores:
        # filtro por rama
        if rama_filtro and infer_rama(j.categoria.nombre if j.categoria else '') != rama_filtro:
            continue
        # filtro por categoría (si aplica)
        if categoria_id and (j.categoria_id != categoria_id):
            continue
        # si no hay categoría asociada, salteamos
        if not j.categoria_id:
            continue
        # además, limitar a las categorías finales seleccionadas
        if cats_ids_permitidos and j.categoria_id not in cats_ids_permitidos:
            continue

        jugadores_por_cat.setdefault(j.categoria_id, []).append(j)

    # Ordenar dentro de cada categoría por puntos (mejor = número más bajo), luego nombre
    for cid, lst in jugadores_por_cat.items():
        lst.sort(key=lambda x: (x.puntos if x.puntos is not None else 10**9, x.nombre_completo))

    # Helper: encontrar categoría superior dentro de la MISMA rama (puntos_max == puntos_min_anterior - 1)
    cats_por_clave = {}  # (rama, puntos_max) -> Categoria
    for c in categorias_visible:
        rama = infer_rama(c.nombre) or ''
        cats_por_clave[(rama, c.puntos_max)] = c

    def categoria_superior(cat: Categoria) -> Categoria | None:
        rama = infer_rama(cat.nombre) or ''
        return cats_por_clave.get((rama, cat.puntos_min - 1))

    # 3) Calcular banderas por jugador
    zona_ascenso = {}
    rivales_count = {}
    for c in categorias:
        filas = jugadores_por_cat.get(c.id, [])
        for j in filas:
            if c:
                zona_ascenso[j.id] = (j.puntos is not None and j.puntos <= c.puntos_min)
                sup = categoria_superior(c)
                if sup:
                    rivales_count[j.id] = len(jugadores_por_cat.get(sup.id, []))
                else:
                    rivales_count[j.id] = 0
            else:
                zona_ascenso[j.id] = False
                rivales_count[j.id] = 0

    # 4) Construir estructura agrupada para el template
    grupos = []
    for c in categorias:
        filas = jugadores_por_cat.get(c.id, [])
        grupos.append((c, filas))

    return render_template(
        'ranking.html',
        grupos=grupos,                # [(Categoria, [Jugadores ordenados])]
        zona_ascenso=zona_ascenso,
        rivales_count=rivales_count,
        rama_filtro=rama_filtro,
        categorias_visible=categorias_visible,  # NUEVO: para <select> de categoría
        categoria_id=categoria_id               # NUEVO: categoría seleccionada
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Solo jugadores activos para el dropdown
    jugadores = (db.session.query(Jugador)
                 .filter(Jugador.activo.is_(True))
                 .order_by(Jugador.nombre_completo.asc())
                 .all())
    if request.method == 'POST':
        jugador_id = request.form.get('jugador_id', type=int)
        pin = (request.form.get('pin') or '').strip()
        j = db.session.get(Jugador, int(jugador_id)) if jugador_id else None

        if not j or not j.activo:
            flash('Jugador inválido o inactivo.', 'error')
            return redirect(url_for('login'))

        if not pin or pin != (j.pin or ''):
            flash('PIN incorrecto.', 'error')
            return redirect(url_for('login'))

        session['jugador_id'] = j.id
        flash(f'Bienvenido, {j.nombre_completo}.', 'ok')
        return redirect(url_for('mi_panel'))

    return render_template('login.html', jugadores=jugadores)

def _gen_code(n=6) -> str:
    # 6 dígitos (0–9), sin letras para que sea fácil de tipear
    return ''.join(secrets.choice(string.digits) for _ in range(n))

def _mask_email(e):
    try:
        name, domain = e.split('@', 1)
        name_m = (name[:2] + '*'*max(0, len(name)-2)) if len(name) > 2 else name
        dom_main, *dom_tail = domain.split('.')
        dom_m = (dom_main[:1] + '*'*max(0, len(dom_main)-1))
        return f"{name_m}@{dom_m}" + ('.' + '.'.join(dom_tail) if dom_tail else '')
    except Exception:
        return e[:2] + '***'

def _mask_pin(pin):
    return ('*'*(len(pin)-2) + pin[-2:]) if pin else '****'

@app.route('/olvide-pin', methods=['GET', 'POST'])
def olvide_pin():
    if request.method == 'POST':
        # Logs para diagnóstico rápido
        current_app.logger.info(
            "POST /olvide-pin -> form_keys=%s args_keys=%s is_json=%s",
            list(request.form.keys()), list(request.args.keys()), request.is_json
        )

        # Usa tu helper existente
        email = (_extraer_email_desde_request(request) or "").lower()

        # Mensaje genérico (no revelar existencia)
        generic_msg = 'Si el correo existe en el sistema, te enviamos instrucciones.'

        # Validación básica
        if not email or not EMAIL_RE.match(email):
            current_app.logger.warning("Email ausente o inválido recibido en /olvide-pin: %r", email)
            flash(generic_msg, 'ok')
            return redirect(url_for('olvide_pin'))

        # Throttle por email
        now = time.time()
        last = _OLVIDE_PIN_COOLDOWN.get(email, 0)
        if now - last < _COOLDOWN_SECONDS:
            current_app.logger.info("Throttle /olvide-pin para %s (cooldown %ss)", _mask_email(email), _COOLDOWN_SECONDS)
            flash(generic_msg, 'ok')
            return redirect(url_for('olvide_pin'))
        _OLVIDE_PIN_COOLDOWN[email] = now

        # Buscar jugador
        j = db.session.query(Jugador).filter(Jugador.email == email).first()
        if not j:
            current_app.logger.info("Solicitud /olvide-pin para email no registrado: %s", _mask_email(email))
            flash(generic_msg, 'ok')
            return redirect(url_for('olvide_pin'))

        # === PIN permanente desde la DB ===
        perma_pin = (j.pin or '').strip()
        if not perma_pin:
            # Contingencia: jugador sin PIN por migración
            current_app.logger.warning("Jugador %s (id=%s) no tiene PIN permanente seteado.", j.email, j.id)
            flash(generic_msg, 'ok')
            return redirect(url_for('olvide_pin'))

        # === URL de inicio de sesión (botón del correo) ===
        try:
            login_url = url_for('login', _external=True)
        except Exception:
            login_url = request.url_root.rstrip('/') + '/login'

        # === Email (sin códigos temporales) ===
        subject = "UPLAY · Tu PIN de acceso"
        body = (
            f"Hola {j.nombre_completo},\n\n"
            f"Este es tu PIN permanente de acceso a UPLAY:\n\n"
            f"{perma_pin}\n\n"
            f"Iniciar sesión:\n{login_url}\n\n"
            "Ingresá a la app, seleccioná tu nombre e introducí este PIN.\n"
            "Si no solicitaste este correo, podés ignorarlo.\n"
        )
        html_body = f"""\
<!doctype html><html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tu PIN UPLAY</title>
<style>
@media (prefers-color-scheme: dark) {{
  body {{ background:#111; color:#ECECEC; }}
  .card {{ background:#1B1B1B; color:#ECECEC; }}
  .muted {{ color:#B5B9C0; }}
  .btn {{ background:#2563EB; color:#fff; }}
}}
</style></head>
<body style="margin:0;padding:0;background:#F3F5F7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">Tu PIN de acceso a UPLAY es {perma_pin}. Iniciá sesión en {login_url}.</div>
<table role="presentation" width="100%" style="width:100%;background:#F3F5F7;padding:24px 12px;"><tr><td align="center">
  <table role="presentation" width="100%" style="max-width:560px;">
    <tr><td align="center" style="padding:8px 0 16px;">
      <img src="cid:uplaylogo" alt="UPLAY" width="120" height="120" style="display:block;margin:0 auto;max-width:100%;height:auto;border:0;outline:0;">
    </td></tr>
    <tr><td class="card" style="background:#ffffff;border-radius:14px;padding:24px 22px;box-shadow:0 1px 3px rgba(16,24,40,0.08);">
      <h1 style="margin:0 0 8px;font-size:20px;line-height:1.3;color:#0F172A;">Tu PIN de acceso</h1>
      <p style="margin:0 0 14px;font-size:14px;line-height:1.6;color:#334155;">
        Hola <strong>{j.nombre_completo}</strong>, este es tu <strong>PIN permanente</strong> para ingresar a UPLAY:
      </p>
      <div role="text" aria-label="PIN" style="margin:12px 0 18px;font-size:24px;letter-spacing:4px;font-weight:700;text-align:center;background:#EEF2FF;color:#0F172A;border-radius:10px;padding:12px 16px;border:1px solid #E3E8EF;">
        {perma_pin}
      </div>
      <table role="presentation" align="center" style="margin:0 auto 16px;">
        <tr><td>
          <a class="btn" href="{login_url}"
             style="display:inline-block;background:#2563EB;color:#ffffff;font-weight:600;font-size:14px;padding:12px 18px;border-radius:10px;text-decoration:none;">
             Iniciar sesión
          </a>
        </td></tr>
      </table>
      <p class="muted" style="margin:0;font-size:12px;line-height:1.6;color:#64748B;">
        Si el botón no funciona, copiá y pegá este enlace:<br>{login_url}
      </p>
    </td></tr>
    <tr><td align="center" style="padding:16px 6px;">
      <p class="muted" style="margin:0;font-size:12px;color:#94A3B8;">© {datetime.utcnow().year} UPLAY · Email generado automáticamente.</p>
    </td></tr>
  </table>
</td></tr></table>
</body></html>"""

        try:
            ok = send_mail(
                subject=subject,
                body=body,                 # texto plano
                html_body=html_body,       # HTML con el PIN + botón a /login
                to=[email],
                inline_images={"uplaylogo": "static/logo/uplay.png"}  # CID del logo
            )
            current_app.logger.info(
                "OlvidePIN: send_mail=%s a %s (jugador_id=%s, pin_log=%s)",
                ok, _mask_email(email), j.id, _mask_pin(perma_pin)
            )
        except Exception:
            ok = False
            current_app.logger.exception("OlvidePIN: error enviando a %s", _mask_email(email))

        # Siempre mensaje genérico hacia el usuario
        flash(generic_msg, 'ok')
        return redirect(url_for('olvide_pin'))

    # GET
    return render_template('olvide_pin_request.html')

    

@app.route('/olvide-pin-confirmar', methods=['GET','POST'])
def olvide_pin_confirmar():
    flash('El flujo cambió: revisá tu email con tu PIN permanente e iniciá sesión.', 'ok')
    return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('jugador_id', None)
    flash('Sesión cerrada.', 'ok')
    return redirect(url_for('home'))

@app.route('/mi')
def mi_panel():
    # Aliases seguros para evitar UnboundLocalError
    from sqlalchemy import and_ as sa_and, or_ as sa_or, select, distinct, union
    from sqlalchemy.sql import exists
    from sqlalchemy import Table, MetaData

    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión para ver tu panel.', 'error')
        return redirect(url_for('login'))

    # Parejas donde participa
    parejas_ids = [
        p.id for p in db.session.query(Pareja)
        .filter(sa_or(Pareja.jugador1_id == j.id, Pareja.jugador2_id == j.id))
        .all()
    ]

    # Partidos donde participa (todo lo no JUGADO = "pendiente")
    partidos_pend = []
    partidos_jug = []
    if parejas_ids:
        partidos_q = (
            db.session.query(Partido)
            .filter(sa_or(Partido.pareja1_id.in_(parejas_ids),
                          Partido.pareja2_id.in_(parejas_ids)))
            .order_by(Partido.creado_en.desc())
        )
        for m in partidos_q.all():
            if m.estado == 'JUGADO':
                partidos_jug.append(m)
            else:
                partidos_pend.append(m)

    # Propuestas de resultado existentes (partidos "normales")
    propuestas_map = {}
    try:
        from .models import PartidoResultadoPropuesto
    except Exception:
        PartidoResultadoPropuesto = globals().get('PartidoResultadoPropuesto', None)

    if partidos_pend and PartidoResultadoPropuesto:
        p_ids = [m.id for m in partidos_pend]
        props = (
            db.session.query(PartidoResultadoPropuesto)
            .filter(PartidoResultadoPropuesto.partido_id.in_(p_ids))
            .all()
        )
        propuestas_map = {pr.partido_id: pr for pr in props}

    # Desafíos relacionados (en cualquier rol)
    desafios_rel = (
        db.session.query(Desafio)
        .filter(sa_or(
            Desafio.desafiante_id == j.id,
            Desafio.companero_id == j.id,
            Desafio.rival1_id == j.id,
            Desafio.rival2_id == j.id
        ))
        .order_by(Desafio.creado_en.desc())
        .all()
    )

    # Desafíos que este jugador debe responder
    desafios_para_responder = (
        db.session.query(Desafio)
        .filter(
            sa_or(Desafio.estado == 'PENDIENTE', Desafio.estado == 'ACEPTADO_PARCIAL'),
            sa_or(
                sa_and(Desafio.rival1_id == j.id,
                       sa_or(Desafio.rival1_acepto.is_(False), Desafio.rival1_acepto.is_(None))),
                sa_and(Desafio.rival2_id == j.id,
                       sa_or(Desafio.rival2_acepto.is_(False), Desafio.rival2_acepto.is_(None)))
            )
        )
        .order_by(Desafio.creado_en.desc())
        .all()
    )

    # PARTIDOS PARA RESPONDER (invitación)
    partidos_para_responder = (
        db.session.query(Partido)
        .filter(
            Partido.estado.in_(['POR_CONFIRMAR', 'PENDIENTE']),
            sa_or(
                sa_and(Partido.rival1_id == j.id, Partido.rival1_acepto.is_(None)),
                sa_and(Partido.rival2_id == j.id, Partido.rival2_acepto.is_(None))
            )
        )
        .order_by(Partido.creado_en.desc())
        .all()
    )

    # PARTIDOS CREADOS POR MÍ esperando aceptación
    partidos_creados_pend = (
        db.session.query(Partido)
        .filter(
            Partido.estado.in_(['POR_CONFIRMAR', 'PENDIENTE']),
            Partido.creador_id == j.id,
            sa_or(Partido.rival1_acepto.is_(None), Partido.rival2_acepto.is_(None))
        )
        .order_by(Partido.creado_en.desc())
        .all()
    )

    # Desafíos creados por mí
    desafios_creados_pend = (
        db.session.query(Desafio)
        .filter(
            Desafio.desafiante_id == j.id,
            sa_or(Desafio.estado == 'PENDIENTE', Desafio.estado == 'ACEPTADO_PARCIAL')
        )
        .order_by(Desafio.creado_en.desc())
        .all()
    )
    desafios_creados_listos = (
        db.session.query(Desafio)
        .filter(
            Desafio.desafiante_id == j.id,
            Desafio.estado == 'ACEPTADO',
            Desafio.partido_id.is_(None)
        )
        .order_by(Desafio.creado_en.desc())
        .all()
    )

    # Abiertos de su categoría
    abiertos_cat = (
        db.session.query(PartidoAbierto)
        .filter(
            PartidoAbierto.categoria_id == j.categoria_id,
            PartidoAbierto.estado.in_(["ABIERTO", "LLENO"])
        )
        .order_by(PartidoAbierto.creado_en.desc())
        .all()
    )

    # Suplencias
    estados_activos = ['ABIERTO', 'LLENO', 'PARTIDO_CREADO']
    try:
        suplencias = (
            db.session.query(PartidoAbiertoSuplente)
            .join(PartidoAbierto, PartidoAbiertoSuplente.pa_id == PartidoAbierto.id)
            .filter(
                PartidoAbiertoSuplente.jugador_id == j.id,
                PartidoAbierto.estado.in_(estados_activos)
            )
            .order_by(PartidoAbierto.creado_en.desc())
            .all()
        )
    except Exception:
        suplencias = []
    cant_suplencias = len(suplencias)

    # Para "Unirme a un partido": ya soy suplente + conteos
    pa_ids = [pa.id for pa in abiertos_cat] if abiertos_cat else []
    mis_suplencias_pa_ids = set()
    suplentes_counts = {pid: 0 for pid in pa_ids}
    if pa_ids:
        todas_supls = (
            db.session.query(PartidoAbiertoSuplente)
            .filter(PartidoAbiertoSuplente.pa_id.in_(pa_ids))
            .all()
        )
        for s in todas_supls:
            suplentes_counts[s.pa_id] = suplentes_counts.get(s.pa_id, 0) + 1
            if s.jugador_id == j.id:
                mis_suplencias_pa_ids.add(s.pa_id)

    # Zona de ascenso
    en_zona = (j.puntos is not None and j.categoria and j.puntos <= j.categoria.puntos_min)

    # Categoria superior y rivales
    cat_superior = None
    rivales_superior = []
    if j.categoria:
        cat_superior = (
            db.session.query(Categoria)
            .filter(Categoria.puntos_max == j.categoria.puntos_min - 1)
            .first()
        )
        if cat_superior:
            rivales_superior = (
                db.session.query(Jugador)
                .filter(
                    Jugador.activo.is_(True),
                    Jugador.categoria_id == cat_superior.id
                )
                .order_by(Jugador.puntos.asc())
                .limit(10)
                .all()
            )

    # Jugadores activos de mi categoría
    jugadores_mi_cat = (
        db.session.query(Jugador)
        .filter(
            Jugador.activo.is_(True),
            Jugador.categoria_id == j.categoria_id
        )
        .order_by(Jugador.nombre_completo.asc())
        .all()
    )

    # === Métricas / listas para UI ===
    ESTADOS_PROPONIBLES = {'PENDIENTE', 'POR_CONFIRMAR', 'CONFIRMADO', 'ACEPTADO', 'PROGRAMADO'}

    def _as_bool(v):
        return True if v in (True, 1, '1') else False

    # 1) "Listos para cargar"
    listos_para_cargar = []
    for m in partidos_pend:
        hubo_invitacion = (m.rival1_id is not None and m.rival2_id is not None)
        r1_ok = _as_bool(getattr(m, 'rival1_acepto', None))
        r2_ok = _as_bool(getattr(m, 'rival2_acepto', None))
        aceptado = (not hubo_invitacion) or (r1_ok and r2_ok) or (m.estado in ('CONFIRMADO', 'ACEPTADO'))
        tiene_propuesta = (m.id in propuestas_map)
        if aceptado and not tiene_propuesta and (m.estado in ESTADOS_PROPONIBLES):
            listos_para_cargar.append(m)

    # 2) Resultado propuesto y YO debo responder (partidos "normales")
    partidos_resultado_para_responder = [m for m in partidos_pend if m.necesita_respuesta_de(j.id)]

    # 2.b) Propuestas ENVIADAS por mí (partidos "normales")
    partidos_propuestas_enviadas_pend = []
    for m in partidos_pend:
        pr = propuestas_map.get(m.id)
        if not pr:
            continue
        proponente_id = (
            getattr(pr, 'jugador_id', None)
            or getattr(pr, 'propuesto_por_id', None)
            or getattr(pr, 'autor_id', None)
            or getattr(pr, 'creador_id', None)
        )
        if proponente_id == j.id:
            estado_pr = (getattr(pr, 'estado', None) or '').upper()
            aceptada = _as_bool(getattr(pr, 'aceptado', None)) or _as_bool(getattr(pr, 'confirmado', None)) or (estado_pr in ('ACEPTADA', 'CONFIRMADA'))
            rechazada = _as_bool(getattr(pr, 'rechazado', None)) or (estado_pr in ('RECHAZADA', 'RECHAZADO'))
            if not aceptada and not rechazada:
                partidos_propuestas_enviadas_pend.append(m)

    partidos_sin_resultado = listos_para_cargar

    # Contadores base (sin torneo aún)
    cant_pend_sin_resultado = len(partidos_sin_resultado)
    cant_abiertos_mi_cat = len(abiertos_cat)
    puede_desafiar = bool(en_zona and cat_superior)

    cant_partidos_para_responder = len(partidos_para_responder)
    cant_partidos_creados_pend = len(partidos_creados_pend)
    cant_partidos_resultado_para_responder = len(partidos_resultado_para_responder)
    cant_propuestas_enviadas_pend = len(partidos_propuestas_enviadas_pend)

    # =========================
    # === BLOQUE: TORNEOS ===
    # =========================
    try:
        from datetime import datetime, timedelta
        hace_60d = datetime.utcnow().date() - timedelta(days=60)
        torneos_q = db.session.query(Torneo).filter(
            sa_or(Torneo.categoria_id == j.categoria_id, Torneo.categoria_id.is_(None))
        ).filter(
            sa_or(Torneo.fecha_inicio.is_(None), Torneo.fecha_inicio >= hace_60d)
        ).order_by(Torneo.id.desc()).limit(6)
        torneos_mi_cat = torneos_q.all()
    except Exception:
        torneos_mi_cat = []

    # === Partidos de TORNEO pendientes del jugador (incluye puente 'torneos_partidos_lados') ===
    ESTADOS_TORNEO_PEND = ('PENDIENTE', 'PROGRAMADO', 'POR_CONFIRMAR', 'ACEPTADO', 'CONFIRMADO')

    # 1) Inscripciones del jugador (SELECT 1-col)
    insc_ids_sq = (
        select(TorneoInscripcion.id)
        .where(sa_or(TorneoInscripcion.jugador1_id == j.id,
                     TorneoInscripcion.jugador2_id == j.id))
    )

    # 2) Participantes (wrapper de inscripción) (SELECT 1-col)
    part_ids_sq = (
        select(TorneoParticipante.id)
        .where(TorneoParticipante.inscripcion_id.in_(insc_ids_sq))
    )

    # 3) Sin resultado (prefiere ganador nulo; cae a resultado_json vacío)
    if hasattr(TorneoPartido, 'ganador_participante_id'):
        sin_resultado = sa_or(
            TorneoPartido.ganador_participante_id.is_(None),
            TorneoPartido.resultado_json.is_(None),
            TorneoPartido.resultado_json == '',
            TorneoPartido.resultado_json == 'null'
        )
    else:
        sin_resultado = sa_or(
            TorneoPartido.resultado_json.is_(None),
            TorneoPartido.resultado_json == '',
            TorneoPartido.resultado_json == 'null'
        )

    # 4) IDs vía columnas A/B (SELECT 1-col)
    ids_via_ab = (
        select(TorneoPartido.id)
        .where(sa_or(
            TorneoPartido.participante_a_id.in_(part_ids_sq),
            TorneoPartido.participante_b_id.in_(part_ids_sq)
        ))
    )

    # 5) IDs vía tabla puente torneos_partidos_lados (reflexión + detección de columnas)
    metadata = MetaData()
    try:
        lados_tbl = Table('torneos_partidos_lados', metadata, autoload_with=db.engine)
        cols = set(lados_tbl.c.keys())
    except Exception:
        lados_tbl = None
        cols = set()

    ids_via_lados = None
    if lados_tbl is not None:
        # Detectar nombre de columna del partido
        partido_col_name = next((n for n in ('partido_id', 'torneo_partido_id', 'tpartido_id') if n in cols), None)
        # Variantes para "quién participa"
        participante_col_name = next((n for n in ('participante_id', 'torneo_participante_id', 'tp_id') if n in cols), None)
        jugador_col_name = next((n for n in ('jugador_id', 'player_id') if n in cols), None)
        insc1_col = 'insc1_id' if 'insc1_id' in cols else None
        insc2_col = 'insc2_id' if 'insc2_id' in cols else None

        if partido_col_name:
            if participante_col_name:
                ids_via_lados = (
                    select(distinct(lados_tbl.c[partido_col_name]))
                    .where(lados_tbl.c[participante_col_name].in_(part_ids_sq))
                )
            elif jugador_col_name:
                ids_via_lados = (
                    select(distinct(lados_tbl.c[partido_col_name]))
                    .where(lados_tbl.c[jugador_col_name] == j.id)
                )
            elif insc1_col and insc2_col:
                # Diseño actual: lados(partido_id, lado, insc1_id, insc2_id)
                ids_via_lados = (
                    select(distinct(lados_tbl.c[partido_col_name]))
                    .where(sa_or(
                        lados_tbl.c[insc1_col].in_(insc_ids_sq),
                        lados_tbl.c[insc2_col].in_(insc_ids_sq),
                    ))
                )
            # Si no hay columnas compatibles, queda como None

    # 6) Unión de criterios (A/B + puente) → todos SELECT 1-col
    if ids_via_lados is not None:
        ids_union = union(ids_via_ab, ids_via_lados).alias('ids_union')
        ids_union_select = select(ids_union.c[0])  # única columna
    else:
        ids_union_select = ids_via_ab  # ya es SELECT 1-col

    try:
        partidos_torneo_pend = (
            db.session.query(TorneoPartido)
            .filter(
                TorneoPartido.id.in_(ids_union_select),
                sin_resultado,
                TorneoPartido.estado.in_(ESTADOS_TORNEO_PEND)
            )
            .order_by(TorneoPartido.programado_en.is_(None), TorneoPartido.programado_en.asc())
            .all()
        )
        cant_torneo_partidos_pend = len(partidos_torneo_pend)
    except Exception:
        partidos_torneo_pend = []
        cant_torneo_partidos_pend = 0

    # ====== NUEVO: Propuestas de TORNEO que YO debo responder (optimizado, sin megajoin) ======
    helper_torneo   = globals().get('_jugadores_del_lado_torneo')
    helper_generico = globals().get('_jugadores_del_lado')

    TP  = globals().get('TorneoPartido')
    TPR = globals().get('TorneoPartidoResultado')
    try:
        TPRP = globals().get('TorneoPartidoResultadoPropuesto') or __import__('app').TorneoPartidoResultadoPropuesto
    except Exception:
        TPRP = globals().get('TorneoPartidoResultadoPropuesto', None)

    torneo_partidos_resultado_para_responder = []
    jug_ids_necesarios = set()

    # === IDs para nombres en 'partidos_torneo_pend' ===
    for tp in (partidos_torneo_pend or []):
        try:
            idsA = (helper_torneo(tp, 'A') if helper_torneo else (helper_generico(tp, 'A') if helper_generico else [])) or []
            idsB = (helper_torneo(tp, 'B') if helper_torneo else (helper_generico(tp, 'B') if helper_generico else [])) or []
        except TypeError:
            idsA, idsB = [], []
        idsA = [int(x) for x in idsA if x]
        idsB = [int(x) for x in idsB if x]
        setattr(tp, 'idsA', idsA)
        setattr(tp, 'idsB', idsB)
        jug_ids_necesarios.update(idsA)
        jug_ids_necesarios.update(idsB)

    if TP and TPRP:
        # Query mínima: solo TPRP + TP, y "sin resultado definitivo" con NOT EXISTS
        pr_rows = db.session.execute(
            select(
                TPRP.id.label('pr_id'),
                TPRP.partido_id.label('tp_id'),
                TPRP.ganador_lado,
                TPRP.sets_text,
                TPRP.propuesto_por_jugador_id,
                TPRP.creado_en,
                TP.ronda,
                TP.orden,
                TP.programado_en,
                TP.cancha,
                TP.torneo_id,
            )
            .select_from(TPRP)
            .join(TP, TPRP.partido_id == TP.id)
            .where(
                ~exists(select(TPR.id).where(TPR.partido_id == TP.id))  # aún sin resultado final
            )
        ).all()


        for row in pr_rows:
            tp = db.session.get(TP, row.tp_id)  # carga puntual

            # Determinar jugadores de ambos lados
            try:
                idsA = (helper_torneo(tp, 'A') if helper_torneo else helper_generico(tp, 'A')) or []
                idsB = (helper_torneo(tp, 'B') if helper_torneo else helper_generico(tp, 'B')) or []
            except TypeError:
                idsA, idsB = [], []

            idsA = [int(x) for x in idsA if x]
            idsB = [int(x) for x in idsB if x]
            ids_all = set(idsA) | set(idsB)

            # Si participo y NO fui el proponente → me toca responder
            prop_id = int(row.propuesto_por_jugador_id) if row.propuesto_por_jugador_id else None
            if j and (j.id in ids_all) and (prop_id != j.id):
                torneo_partidos_resultado_para_responder.append({
                    'id': row.tp_id,
                    'ronda': row.ronda,
                    'orden': row.orden,
                    'programado_en': row.programado_en,
                    'cancha': row.cancha,
                    'torneo': getattr(tp, 'torneo', None),
                    'idsA': idsA,
                    'idsB': idsB,
                    'propuesta_id': row.pr_id,
                    'propuesto_por_jugador_id': prop_id,
                    'sets_text': row.sets_text,
                    'ganador_lado': row.ganador_lado,
                    'creado_en': row.creado_en,
                })
                jug_ids_necesarios.update(ids_all)
                if prop_id:
                    jug_ids_necesarios.add(prop_id)

    # Map de jugadores (para nombres humanos)
    jugadores_by_id = {}
    if jug_ids_necesarios:
        from app import Jugador as _JUG_
        rows = db.session.query(_JUG_).filter(_JUG_.id.in_(list(jug_ids_necesarios))).all()
        jugadores_by_id = {row.id: row for row in rows}

    # Helpers para nombres
    def _nomb(jg):
        if not jg:
            return '—'
        return getattr(jg, 'nombre_completo', None) or getattr(jg, 'display_name', None) or getattr(jg, 'nombre', None) or f'#{getattr(jg, "id", "?")}'

    def _join_nombres(ids):
        return ' + '.join(_nomb(jugadores_by_id.get(i)) for i in ids) if ids else '—'

    for it in torneo_partidos_resultado_para_responder:
        it['a_nombres'] = _join_nombres(it['idsA'])
        it['b_nombres'] = _join_nombres(it['idsB'])

    # >>> NOMBRES PARA 'partidos_torneo_pend' (usa idsA/idsB cargados en el punto 1)
    for tp in (partidos_torneo_pend or []):
        try:
            an = getattr(tp, 'a_nombres', None)
            bn = getattr(tp, 'b_nombres', None)
            if not an:
                setattr(tp, 'a_nombres', _join_nombres(getattr(tp, 'idsA', []) or []))
            if not bn:
                setattr(tp, 'b_nombres', _join_nombres(getattr(tp, 'idsB', []) or []))
        except Exception:
            setattr(tp, 'a_nombres', an if an else '—')
            setattr(tp, 'b_nombres', bn if bn else '—')

    # Aumentamos el contador de “para responder resultado” con los de torneo
    cant_partidos_resultado_para_responder += len(torneo_partidos_resultado_para_responder)

    # ===== Contador de tareas de resultados (normales + torneo) =====
    cant_tareas_resultados = (
        cant_pend_sin_resultado
        + cant_partidos_resultado_para_responder
        + cant_propuestas_enviadas_pend
    )


    # =========================
    # === /BLOQUE: TORNEOS ===
    # =========================

    return render_template(
        'mi.html',
        jugador=j,
        en_zona=en_zona,
        partidos_pend=partidos_pend,
        partidos_jug=partidos_jug[:5],
        desafios_rel=desafios_rel[:10],
        desafios_para_responder=desafios_para_responder,
        desafios_creados_pend=desafios_creados_pend,
        desafios_creados_listos=desafios_creados_listos,

        partidos_para_responder=partidos_para_responder,
        partidos_creados_pend=partidos_creados_pend,
        cant_partidos_para_responder=cant_partidos_para_responder,
        cant_partidos_creados_pend=cant_partidos_creados_pend,

        propuestas_map=propuestas_map,

        abiertos_cat=abiertos_cat[:10],
        cat_superior=cat_superior,
        rivales_superior=rivales_superior,
        jugadores_mi_cat=jugadores_mi_cat,

        cant_pend_sin_result=cant_pend_sin_resultado,
        cant_abiertos_mi_cat=cant_abiertos_mi_cat,
        puede_desafiar=puede_desafiar,

        partidos_resultado_para_responder=partidos_resultado_para_responder,
        cant_partidos_resultado_para_responder=cant_partidos_resultado_para_responder,

        partidos_sin_resultado=partidos_sin_resultado,

        partidos_propuestas_enviadas_pend=partidos_propuestas_enviadas_pend,
        cant_propuestas_enviadas_pend=cant_propuestas_enviadas_pend,

        suplencias=suplencias,
        cant_suplencias=cant_suplencias,

        suplentes_counts=suplentes_counts,
        mis_suplencias_pa_ids=mis_suplencias_pa_ids,

        cant_tareas_resultados=cant_tareas_resultados,

        torneos_mi_cat=torneos_mi_cat,
        partidos_torneo_pend=partidos_torneo_pend,
        cant_torneo_partidos_pend=cant_torneo_partidos_pend,

        # NUEVO para poder mostrar nombres humanos en propuestas de torneo
        torneo_partidos_resultado_para_responder=torneo_partidos_resultado_para_responder,
        jugadores_by_id=jugadores_by_id,
    )




def en_zona_ascenso(j: 'Jugador') -> bool:
    return bool(j and j.categoria and j.puntos is not None and j.puntos <= j.categoria.puntos_min)

def asegurar_estado_jugadores():
    """Crea registros de JugadorEstado faltantes sin tocar los existentes."""
    ids_existentes = {e.jugador_id for e in JugadorEstado.query.all()}
    nuevos = []
    for j in Jugador.query.with_entities(Jugador.id).all():
        if j.id not in ids_existentes:
            nuevos.append(JugadorEstado(jugador_id=j.id))
    if nuevos:
        db.session.add_all(nuevos)
        db.session.commit()

# Asegurate de tener este import cerca de tus otros imports:
from sqlalchemy import or_, and_

def get_or_create_pareja(j1_id: int, j2_id: int, categoria_id: int):
    """Devuelve una Pareja (en esa categoría) con esos 2 jugadores, en cualquier orden.
       Si no existe, la crea con puntos informativos = promedio individual."""
    # normalizamos orden para buscar
    a, b = sorted([j1_id, j2_id])
    p = (db.session.query(Pareja)
         .filter(Pareja.categoria_id == categoria_id)
         .filter(
             or_(
                 and_(Pareja.jugador1_id == a, Pareja.jugador2_id == b),
                 and_(Pareja.jugador1_id == b, Pareja.jugador2_id == a)
             )
         ).first())
    if p:
        return p

    # crear si no existe
    j1 = db.session.get(Jugador, int(j1_id)) if j1_id else None
    j2 = db.session.get(Jugador, int(j2_id)) if j2_id else None
    prom = int(((j1.puntos or 0) + (j2.puntos or 0)) / 2)
    p = Pareja(
        categoria_id=categoria_id,
        jugador1_id=j1_id,
        jugador2_id=j2_id,
        puntos=prom  # solo informativo; ranking es individual
    )
    db.session.add(p)
    db.session.commit()
    return p


def infer_rama(nombre: str) -> str | None:
    """Intenta inferir la rama desde el nombre de la categoría."""
    if not nombre:
        return None
    n = nombre.lower()
    if 'caballeros' in n:
        return 'CABALLEROS'
    if 'damas' in n:
        return 'DAMAS'
    if 'mixta' in n or 'mixto' in n:
        return 'MIXTA'
    return None  # desconocida / no especificada

def get_current_jugador():
    jid = session.get('jugador_id')
    return db.session.get(Jugador, int(jid)) if jid else None

# --- Helpers de categoría/visibilidad torneo ---

def _jugador_puede_ver_torneo(torneo, jugador) -> bool:
    """
    Visibilidad en listas: si el torneo NO tiene categoría fija -> lo ven todos.
    Si tiene categoría -> solo lo ven jugadores de ESA misma categoría.
    """
    if torneo is None:
        return False
    if getattr(torneo, 'categoria_id', None) is None:
        return True
    if jugador is None:
        # usuario no logueado: solo mostramos torneos sin categoría fija
        return False
    return jugador.categoria_id == torneo.categoria_id

def _jugador_puede_inscribirse_en_torneo(torneo, jugador) -> bool:
    """
    Inscripción: misma lógica que visibilidad (idéntica categoría si el torneo la tiene fija).
    Si el torneo no tiene categoría fija, permitimos (puede que lo segmentes por puntos luego).
    """
    return _jugador_puede_ver_torneo(torneo, jugador)


@app.route('/mi/pin', methods=['GET', 'POST'])
def mi_cambiar_pin():
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión para cambiar tu PIN.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        pin_actual = (request.form.get('pin_actual') or '').strip()
        pin_nuevo  = (request.form.get('pin_nuevo')  or '').strip()
        pin_nuevo2 = (request.form.get('pin_nuevo2') or '').strip()

        # Validaciones
        if not pin_actual or pin_actual != (j.pin or ''):
            flash('El PIN actual no es correcto.', 'error')
            return redirect(url_for('mi_cambiar_pin'))

        if not (pin_nuevo.isdigit() and 4 <= len(pin_nuevo) <= 6):
            flash('El nuevo PIN debe tener 4–6 dígitos.', 'error')
            return redirect(url_for('mi_cambiar_pin'))

        if pin_nuevo != pin_nuevo2:
            flash('La confirmación no coincide.', 'error')
            return redirect(url_for('mi_cambiar_pin'))

        if pin_nuevo == pin_actual:
            flash('El PIN nuevo no puede ser igual al actual.', 'warning')
            return redirect(url_for('mi_cambiar_pin'))

        # Guardar
        j.pin = pin_nuevo
        db.session.commit()

        # Aviso por email (si el jugador tiene email)
        try:
            if j.email:
                subject = "UPLAY: tu PIN fue actualizado"
                body = (
                    f"Hola {j.nombre_completo},\n\n"
                    f"Tu PIN fue actualizado correctamente.\n"
                    f"Si no fuiste vos, comunicate con el organizador.\n\n"
                    f"— UPLAY"
                )
                send_mail(subject, body, to_addrs=[j.email])
            flash('PIN actualizado correctamente.', 'ok')
        except Exception as e:
            # No bloquear el cambio si el correo falla
            flash(f'PIN actualizado. (Aviso por email no enviado: {e})', 'warning')

        return redirect(url_for('mi_panel'))

    # GET
    return render_template('mi_cambiar_pin.html', jugador=j)


@app.context_processor
def inject_current_jugador():
    # permite usar current_jugador en templates y navbar
    return dict(current_jugador=get_current_jugador())


# Endpoints públicos (pueden entrar sin sesión)
PUBLIC_ENDPOINTS = {
    'home','login','alta_publica','healthz','static','ranking','categorias_list',
    'olvide_pin','olvide_pin_confirmar',
    # + torneos públicos
    'torneos_public_list','torneo_public_detail','torneo_public_detail_legacy',
    'torneo_public_fixture','torneo_public_tabla',
}

@app.before_request
def require_login_for_app():
    # permitir archivos estáticos y los endpoints públicos
    if request.endpoint in PUBLIC_ENDPOINTS or (request.endpoint or '').startswith('static'):
        return
    # si no hay sesión, redirigir a login
    if not get_current_jugador():
        flash('Iniciá sesión para acceder.', 'error')
        return redirect(url_for('login'))


@app.route('/admin')
@admin_required
def admin_home():
    counts = {
        'jugadores_activos': db.session.query(Jugador).filter(Jugador.activo.is_(True)).count(),
        'jugadores_inactivos': db.session.query(Jugador).filter(Jugador.activo.is_(False)).count(),
        'categorias': db.session.query(Categoria).count(),
        'abiertos': db.session.query(PartidoAbierto).filter(PartidoAbierto.estado.in_(['ABIERTO','LLENO'])).count(),
        'partidos_pend': db.session.query(Partido).filter_by(estado='PENDIENTE').count(),
        'partidos_jug': db.session.query(Partido).filter_by(estado='JUGADO').count(),
        'desafios_pend': db.session.query(Desafio).filter(Desafio.estado.in_(['PENDIENTE','ACEPTADO'])).count(),
        'solicitudes_pend': db.session.query(SolicitudAlta).filter_by(estado='PENDIENTE').count(),
        # NUEVO: total de torneos
        'torneos': db.session.query(Torneo).count(),
    }

    recientes_partidos = (
        db.session.query(Partido)
        .order_by(Partido.creado_en.desc())
        .limit(5).all()
    )
    recientes_abiertos = (
        db.session.query(PartidoAbierto)
        .order_by(PartidoAbierto.creado_en.desc())
        .limit(5).all()
    )

    return render_template(
        'admin.html',
        counts=counts,
        recientes_partidos=recientes_partidos,
        recientes_abiertos=recientes_abiertos
    )


@app.route('/admin/solicitudes')
@admin_required
def admin_solicitudes_list():
    from sqlalchemy import func

    pend = (
        db.session.query(SolicitudAlta)
        .filter(func.trim(func.upper(SolicitudAlta.estado)) == 'PENDIENTE')
        .order_by(SolicitudAlta.creado_en.desc())
        .all()
    )

    hist = (
        db.session.query(SolicitudAlta)
        .filter(func.trim(func.upper(SolicitudAlta.estado)) != 'PENDIENTE')
        .order_by(SolicitudAlta.creado_en.desc())
        .limit(50)
        .all()
    )

    return render_template('admin_solicitudes.html', pendientes=pend, historial=hist)

@app.route('/admin/solicitudes/<int:sid>/aprobar', methods=['GET', 'POST'])
@admin_required
def admin_solicitudes_aprobar(sid):
    """Aprobación de solicitud de alta — crea jugador, asigna PIN y notifica por email."""
    from datetime import datetime, timezone
    import secrets, string, logging

    s = get_or_404(SolicitudAlta, sid)
    if s.estado != 'PENDIENTE':
        flash('Esta solicitud ya fue procesada.', 'error')
        return redirect(url_for('admin_solicitudes_list'))

    if request.method == 'POST':
        puntos = request.form.get('puntos', type=int)
        _pin_ignorado = (request.form.get('pin') or '').strip()

        cat = s.categoria
        if not cat:
            flash('La categoría de la solicitud no es válida.', 'error')
            return redirect(url_for('admin_solicitudes_list'))

        if puntos is None or not (cat.puntos_min <= puntos <= cat.puntos_max):
            flash(f'Los puntos deben estar entre {cat.puntos_min} y {cat.puntos_max}.', 'error')
            return redirect(url_for('admin_solicitudes_aprobar', sid=s.id))

        email_norm = (s.email or '').strip().lower()
        if not email_norm or '@' not in email_norm:
            flash('La solicitud no tiene email válido.', 'error')
            return redirect(url_for('admin_solicitudes_list'))

        # Verificar duplicados
        if db.session.query(Jugador).filter(Jugador.email == email_norm).first():
            flash(f'Ya existe un jugador con el email {email_norm}.', 'error')
            return redirect(url_for('admin_solicitudes_list'))

        # --- Crear jugador ---
        j = Jugador(
            nombre_completo=s.nombre_completo,
            email=email_norm,
            telefono=s.telefono,
            puntos=puntos,
            categoria_id=s.categoria_id,
            activo=True,
            pais=getattr(s, 'pais', None),
            provincia=getattr(s, 'provincia', None),
            ciudad=getattr(s, 'ciudad', None),
            fecha_nacimiento=getattr(s, 'fecha_nacimiento', None),
        )
        db.session.add(j)
        db.session.flush()  # obtiene j.id

        # --- Marcar solicitud ---
        s.estado = 'APROBADA'
        try:
            s.resuelto_en = datetime.now(timezone.utc)
        except Exception:
            s.resuelto_en = datetime.utcnow()

        # --- PIN permanente ---
        def _pin_perm(long_min=4, long_max=6):
            L = secrets.choice(range(long_min, long_max + 1))
            return ''.join(secrets.choice(string.digits) for _ in range(L))
        pin_permanente = _pin_perm()
        j.pin = pin_permanente

        db.session.commit()

        # --- Generar PIN one-time (login rápido) ---
        try:
            codigo = emitir_codigo(j.email)  # se guarda en tabla de códigos
            current_app.logger.info(f"PIN one-time emitido para {j.email}: {codigo}")
        except Exception as e:
            logging.exception("No se pudo emitir código temporal")
            codigo = None

        # --- Construir email ---
        try:
            login_url = url_for('login', _external=True)
        except Exception:
            login_url = (request.url_root.rstrip('/') + '/login')

        body = (
            f"Hola {j.nombre_completo},\n\n"
            "¡Tu alta fue aprobada!\n\n"
            f"PIN permanente: {pin_permanente}\n"
            + (f"PIN temporal (válido por minutos): {codigo}\n\n" if codigo else "") +
            f"Ingresá desde: {login_url}\n\n"
            f"Categoría: {j.categoria.nombre if j.categoria else '-'}\n"
            f"Puntos iniciales: {j.puntos}\n\n"
            "— Equipo UPLAY"
        )

        try:
            send_mail(
                subject="¡Bienvenido a UPLAY!",
                body=body,
                to=[j.email],
                html_body=None,
            )
            flash(f'Jugador creado y notificado: {j.nombre_completo}', 'ok')
        except Exception:
            logging.exception("Fallo al enviar email de bienvenida")
            flash(f'Jugador creado, pero no se envió el email.', 'warning')

        return redirect(url_for('admin_solicitudes_list'))

    # GET
    puntos_sugeridos = s.categoria.puntos_max if s.categoria else 0
    return render_template('admin_solicitudes_aprobar.html', sol=s, puntos_sugeridos=puntos_sugeridos)



@app.route('/admin/solicitudes/<int:sid>/rechazar', methods=['POST'])
@admin_required
def admin_solicitudes_rechazar(sid):
    s = get_or_404(SolicitudAlta, sid)
    if s.estado != 'PENDIENTE':
        flash('Esta solicitud ya fue procesada.', 'error')
        return redirect(url_for('admin_solicitudes_list'))
    s.estado = 'RECHAZADA'
    s.resuelto_en = datetime.utcnow()
    db.session.commit()
    flash('Solicitud rechazada.', 'ok')
    return redirect(url_for('admin_solicitudes_list'))

# ====== ADMIN: PARTIDOS ABIERTOS ======
@app.route('/admin/abiertos/<int:pa_id>/cerrar', methods=['POST'])
@admin_required
def admin_abiertos_cerrar(pa_id):
    pa = get_or_404(PartidoAbierto, pa_id)
    pa.estado = 'CERRADO'
    db.session.commit()
    flash('Abierto cerrado.', 'ok')
    return redirect(url_for('abiertos_list'))

@app.route('/admin/abiertos/<int:pa_id>/cancelar', methods=['POST'])
@admin_required
def admin_abiertos_cancelar(pa_id):
    pa = get_or_404(PartidoAbierto, pa_id)
    pa.estado = 'CANCELADO'
    db.session.commit()
    flash('Abierto cancelado.', 'ok')
    return redirect(url_for('abiertos_list'))

@app.route('/admin/abiertos/<int:pa_id>/eliminar', methods=['POST'])
@admin_required
def admin_abiertos_eliminar(pa_id):
    pa = get_or_404(PartidoAbierto, pa_id)

    # Misma regla que en la ruta pública: si ya creó un partido, no permitir borrado duro
    if pa.estado == 'PARTIDO_CREADO':
        flash('Este abierto ya creó un partido. No se puede eliminar.', 'warning')
        return redirect(url_for('abiertos_list'))

    try:
        # Borrado duro; gracias a los backrefs con cascade se eliminan inscriptos/suplentes
        db.session.delete(pa)
        db.session.commit()
        flash(f'Abierto #{pa_id} eliminado.', 'ok')
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Error eliminando abierto (admin): %s", e)
        flash('No se pudo eliminar el abierto.', 'error')

    return redirect(url_for('abiertos_list'))



# ====== ADMIN: PARTIDOS ======
@app.route('/admin/partidos/<int:partido_id>/eliminar', methods=['POST'])
@admin_required
def admin_partidos_eliminar(partido_id):
    p = get_or_404(Partido, partido_id)

    # Si hay desafío vinculado, lo “desprogramamos”
    d = Desafio.query.filter_by(partido_id=p.id).first()
    if d:
        d.partido_id = None
        # Si querés volverlo a PENDIENTE (para reprogramar):
        if d.estado in ('ACEPTADO', 'PENDIENTE'):
            d.estado = 'PENDIENTE'

    # Borrar resultado si existiera
    if p.resultado:
        db.session.delete(p.resultado)

    db.session.delete(p)
    db.session.commit()
    flash('Partido eliminado.', 'ok')
    return redirect(url_for('partidos_list'))


# ====== ADMIN: DESAFÍOS ======
@app.route('/admin/desafios/<int:desafio_id>/eliminar', methods=['POST'])
@admin_required
def admin_desafios_eliminar(desafio_id):
    d = get_or_404(Desafio, desafio_id)

    # Si el desafío tenía partido, eliminarlo también (con su resultado)
    if d.partido:
        if d.partido.resultado:
            db.session.delete(d.partido.resultado)
        db.session.delete(d.partido)

    db.session.delete(d)
    db.session.commit()
    flash('Desafío eliminado.', 'ok')
    return redirect(url_for('desafios_list'))


@app.route('/admin/partidos/<int:partido_id>/resultado/editar', methods=['GET', 'POST'])
@admin_required
def admin_partido_resultado_editar(partido_id):
    partido = get_or_404(Partido, partido_id)

    # Para elegir ganador en el form
    p1 = partido.pareja1
    p2 = partido.pareja2
    if not p1 or not p2:
        flash('El partido no tiene parejas válidas.', 'error')
        return redirect(url_for('partidos_list'))

    # Helper local: intenta llamar a tu recálculo si existe (no rompe si no está)
    def _try_recalc(_partido):
        try:
            fn = (globals().get('recalcular_puntos_partido')
                  or globals().get('recalcular_elo_para_partido'))
            if callable(fn):
                fn(_partido.id)
                return True
        except Exception as e:
            try:
                current_app.logger.exception("Error recalculando puntos para partido_id=%s: %s", _partido.id, e)
            except Exception:
                pass
        return False

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()
        # checkbox/flag opcional del form: <input type="checkbox" name="recalcular" value="1">
        want_recalc = (request.form.get('recalcular') or '').lower() in ('1', 'true', 'on', 'sí', 'si')

        if action == 'reopen':
            # Reabrir partido: borrar resultado y volver a PENDIENTE
            if partido.resultado:
                db.session.delete(partido.resultado)
            partido.estado = 'PENDIENTE'
            db.session.commit()

            # recálculo opcional (por si querés revertir/corregir puntos al reabrir)
            if want_recalc and _try_recalc(partido):
                flash('Partido reabierto y puntos recalculados.', 'ok')
            else:
                flash('Partido reabierto. (Ojo: puntos NO se recalcularon automáticamente)', 'ok')

            return redirect(url_for('partidos_list'))

        elif action == 'update':
            ganador_id = request.form.get('ganador_pareja_id')
            sets_text = (request.form.get('sets_text') or '').strip()

            try:
                ganador_id = int(ganador_id)
            except (TypeError, ValueError):
                flash('Ganador inválido.', 'error')
                return redirect(url_for('admin_partido_resultado_editar', partido_id=partido.id))

            if ganador_id not in (partido.pareja1_id, partido.pareja2_id):
                flash('La pareja ganadora no corresponde a este partido.', 'error')
                return redirect(url_for('admin_partido_resultado_editar', partido_id=partido.id))

            # Crear o actualizar el resultado
            if partido.resultado:
                pr = partido.resultado
                pr.ganador_pareja_id = ganador_id
                pr.sets_text = sets_text or None
                pr.confirmado_en = datetime.utcnow()
            else:
                pr = PartidoResultado(
                    partido_id=partido.id,
                    ganador_pareja_id=ganador_id,
                    sets_text=sets_text or None
                )
                db.session.add(pr)

            partido.estado = 'JUGADO'
            db.session.commit()

            if want_recalc and _try_recalc(partido):
                flash('Resultado actualizado y puntos recalculados.', 'ok')
            else:
                flash('Resultado actualizado. (Ojo: puntos NO se recalcularon automáticamente)', 'ok')

            return redirect(url_for('partidos_list'))

        else:
            flash('Acción inválida.', 'error')
            return redirect(url_for('admin_partido_resultado_editar', partido_id=partido.id))

    # GET -> mostrar formulario con datos actuales
    return render_template('admin_partido_resultado_edit.html', partido=partido, p1=p1, p2=p2)


# ===== Torneos: rutas MVP =====

@app.route('/admin/torneos', methods=['GET'])
@admin_required
def admin_torneos_list():
    torneos = (db.session.query(Torneo)
               .order_by(Torneo.created_at.desc())
               .all())
    return render_template('admin_torneos_list.html', torneos=torneos)



@app.route('/admin/torneos/new', methods=['GET', 'POST'])
@admin_required
def admin_torneos_new():
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()

    if request.method == 'POST':
        # --- Datos del form (con defaults seguros) ---
        nombre = (request.form.get('nombre') or '').strip()
        modalidad = (request.form.get('modalidad') or 'SINGLES').strip().upper()   # UI: SINGLES | DOBLES
        formato = modalidad  # en el modelo usamos 'formato'
        tipo = (request.form.get('formato') or 'AMERICANO').strip().upper()       # AMERICANO | ZONAS+PLAYOFF | PLAYOFF

        categoria_id = request.form.get('categoria_id', type=int)
        fecha_inicio_raw = (request.form.get('fecha_inicio') or '').strip()
        sede = (request.form.get('sede') or '').strip() or None
        notas = (request.form.get('notas') or '').strip() or None

        # límites opcionales
        lim_jug = request.form.get('limite_jugadores', type=int)
        lim_par = request.form.get('limite_parejas', type=int)

        current_app.logger.info(
            "[admin_torneos_new] POST: nombre=%r modalidad=%r tipo=%r cat_id=%r fecha=%r lim_jug=%r lim_par=%r",
            nombre, modalidad, tipo, categoria_id, fecha_inicio_raw, lim_jug, lim_par
        )

        if not nombre:
            flash('El nombre es obligatorio.', 'error')
            return redirect(url_for('admin_torneos_new'))

        # cupo_max según modalidad
        cupo_max = None
        if formato == 'SINGLES':
            cupo_max = lim_jug if (lim_jug and lim_jug >= 2) else None
        else:  # DOBLES
            cupo_max = lim_par if (lim_par and lim_par >= 2) else None

        # Parse de fecha tolerante
        fecha_dt = None
        if fecha_inicio_raw:
            for fmt in ('%Y-%m-%d', '%Y/%m/%d'):
                try:
                    fecha_dt = datetime.strptime(fecha_inicio_raw, fmt).date()
                    break
                except ValueError:
                    continue
            if fecha_dt is None:
                flash('Fecha de inicio inválida. Usá formato YYYY-MM-DD.', 'error')
                return redirect(url_for('admin_torneos_new'))

        # creador opcional
        creador_id = None
        try:
            cj = get_current_jugador()
            if cj:
                creador_id = cj.id
        except Exception:
            pass

        # Crear torneo (manteniendo compat con columna legacy modalidad NOT NULL)
        t = Torneo(
            nombre=nombre,
            categoria_id=categoria_id or None,
            formato=formato,        # 'SINGLES' | 'DOBLES'
            modalidad=formato,      # compat: legacy
            tipo=tipo,              # 'AMERICANO' | 'ZONAS+PLAYOFF' | 'PLAYOFF'
            estado='BORRADOR',
            inscripcion_libre=True, # MVP
            cupo_max=cupo_max,
            fecha_inicio=fecha_dt,
            sede=sede,
            notas=notas,
            created_by_id=creador_id,
        )
        db.session.add(t)
        try:
            db.session.commit()
            current_app.logger.info("[admin_torneos_new] creado OK id=%s", t.id)
        except IntegrityError:
            db.session.rollback()
            current_app.logger.exception("IntegrityError creando torneo")
            flash('No se pudo crear el torneo (datos inválidos o duplicados).', 'error')
            return redirect(url_for('admin_torneos_new'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Error inesperado creando torneo")
            flash(f'Error al crear el torneo: {e}', 'error')
            return redirect(url_for('admin_torneos_new'))

        flash('Torneo creado.', 'ok')
        # Redirigir al detalle admin; si el endpoint no existe en el deploy, ir al listado
        try:
            return redirect(url_for('admin_torneos_view', tid=t.id))
        except BuildError:
            current_app.logger.exception("BuildError al redirigir a admin_torneos_view")
            flash('Torneo creado. No encontré la vista de detalle en este entorno; te llevo al listado.', 'info')
            return redirect(url_for('admin_torneos_list'))

    # GET -> usar tu template existente
    return render_template('admin_torneos_form.html', categorias=categorias)



@app.route('/admin/torneos/<int:tid>', methods=['GET'])
@admin_required
def admin_torneos_view(tid):
    t = get_or_404(Torneo, tid)

    # Inscripciones (como ya lo tenías)
    insc = (
        db.session.query(TorneoInscripcion)
        .filter(TorneoInscripcion.torneo_id == t.id)
        .order_by(
            TorneoInscripcion.seed.asc().nulls_last(),
            TorneoInscripcion.id.asc()
        )
        .all()
    )

    # Partidos del torneo (como ya lo tenías)
    partidos = (
        db.session.query(TorneoPartido)
        .filter(TorneoPartido.torneo_id == t.id)
        .order_by(
            TorneoPartido.ronda.asc().nulls_last(),
            TorneoPartido.orden.asc().nulls_last(),
            TorneoPartido.id.asc()
        )
        .all()
    )

    # Resultados existentes (dict por partido_id) — como lo tenías
    res_list = (
        db.session.query(TorneoPartidoResultado)
        .join(TorneoPartido, TorneoPartidoResultado.partido_id == TorneoPartido.id)
        .filter(TorneoPartido.torneo_id == t.id)
        .all()
    )
    resultados = {r.partido_id: r for r in res_list}

    # ==== PRO-PUESTOS (si el modelo existe) ====
    propuestas = {}
    try:
        from app import TorneoPartidoResultadoPropuesto as TPRP
    except Exception:
        TPRP = globals().get('TorneoPartidoResultadoPropuesto', None)

    if TPRP:
        pids = [p.id for p in partidos]
        if pids:
            prps = (
                db.session.query(TPRP)
                .filter(TPRP.partido_id.in_(pids))
                .all()
            )
            propuestas = {x.partido_id: x for x in prps}

    # ==== JUGADORES POR PARTIDO (A/B) usando helpers del proyecto ====
    helper_torneo = globals().get('_jugadores_del_lado_torneo')
    helper_generico = globals().get('_jugadores_del_lado')

    jugadores_por_partido_ids: dict[int, dict[str, list[int]]] = {}
    all_ids: set[int] = set()

    for p in partidos:
        jugadores_por_partido_ids[p.id] = {'A': [], 'B': []}
        for lado in ('A', 'B'):
            ids = []
            try:
                if helper_torneo:
                    ids = helper_torneo(p, lado) or []
                elif helper_generico:
                    ids = helper_generico(p, lado) or []
            except TypeError:
                # Por si algún helper tiene firma distinta
                ids = []
            # normalizar y filtrar nulos/ceros
            ids = [int(x) for x in ids if x]
            jugadores_por_partido_ids[p.id][lado] = ids
            all_ids.update(ids)

    # ➕ AÑADIDO: incluir confirmador (resultado definitivo) y proponente (resultado propuesto)
    for r in res_list:
        cid = getattr(r, 'confirmado_por_jugador_id', None)
        if cid:
            try:
                all_ids.add(int(cid))
            except (TypeError, ValueError):
                pass

    for rp in propuestas.values():
        pid = getattr(rp, 'propuesto_por_jugador_id', None)
        if pid:
            try:
                all_ids.add(int(pid))
            except (TypeError, ValueError):
                pass

    # Mapear id -> Jugador y reemplazar por objetos
    jug_map = {}
    if all_ids:
        from app import Jugador
        rows = (
            db.session.query(Jugador)
            .filter(Jugador.id.in_(list(all_ids)))
            .all()
        )
        jug_map = {j.id: j for j in rows}

    jugadores_por_partido_obj: dict[int, dict[str, list]] = {}
    for pid, lados in jugadores_por_partido_ids.items():
        jugadores_por_partido_obj[pid] = {
            'A': [jug_map.get(jid) for jid in lados.get('A', []) if jug_map.get(jid)],
            'B': [jug_map.get(jid) for jid in lados.get('B', []) if jug_map.get(jid)],
        }

    return render_template(
        'admin_torneos_view.html',
        t=t,
        inscripciones=insc,
        partidos=partidos,
        resultados=resultados,
        propuestas=propuestas,
        jugadores_por_partido=jugadores_por_partido_obj,
        jugadores_by_id=jug_map,   # << para mostrar nombres de proponente/confirmador
    )









@app.route('/admin/torneos/<int:tid>/estado', methods=['POST'])
@admin_required
def admin_torneos_cambiar_estado(tid):
    t = get_or_404(Torneo, tid)

    # Usar tus constantes si están definidas; si no, fallback a literales
    EST_BORRADOR            = globals().get('EST_BORRADOR', 'BORRADOR')
    EST_INSCRIPCION         = globals().get('EST_INSCRIPCION', 'INSCRIPCION')
    EST_INSCRIPCION_CERRADA = globals().get('EST_INSCRIPCION_CERRADA', 'INSCRIPCION_CERRADA')
    EST_EN_JUEGO            = globals().get('EST_EN_JUEGO', 'EN_JUEGO')
    EST_FINALIZADO          = globals().get('EST_FINALIZADO', 'FINALIZADO')
    EST_CANCELADO           = globals().get('EST_CANCELADO', 'CANCELADO')

    nuevo_estado = (request.form.get('estado') or '').upper()
    validos = {
        EST_BORRADOR, EST_INSCRIPCION, EST_INSCRIPCION_CERRADA,
        EST_EN_JUEGO, EST_FINALIZADO, EST_CANCELADO
    }
    if nuevo_estado not in validos:
        flash('Estado inválido.', 'error')
        return redirect(url_for('admin_torneos_view', tid=t.id))

    # Reglas MVP actualizadas (ahora incluye INSCRIPCION_CERRADA)
    if t.estado == EST_BORRADOR and nuevo_estado == EST_INSCRIPCION:
        t.estado = EST_INSCRIPCION

    elif t.estado == EST_INSCRIPCION and nuevo_estado == EST_INSCRIPCION_CERRADA:
        t.estado = EST_INSCRIPCION_CERRADA

    elif t.estado in {EST_BORRADOR, EST_INSCRIPCION, EST_INSCRIPCION_CERRADA} and nuevo_estado == EST_EN_JUEGO:
        t.estado = EST_EN_JUEGO

    elif nuevo_estado in {EST_FINALIZADO, EST_CANCELADO}:
        t.estado = nuevo_estado

    else:
        flash('Transición no permitida en MVP.', 'error')
        return redirect(url_for('admin_torneos_view', tid=t.id))

    db.session.commit()
    flash(f'Estado actualizado a {t.estado}.', 'ok')
    return redirect(url_for('admin_torneos_view', tid=t.id))


@app.route('/torneos/<int:tid>/inscribirme', methods=['GET', 'POST'])
def torneo_inscribirme(tid):
    # Requiere jugador logueado y activo
    j = get_current_jugador()
    if not j or not j.activo:
        flash('Necesitás iniciar sesión con un jugador activo.', 'error')
        return redirect(url_for('login'))

    t = get_or_404(Torneo, tid)

    # === 🔒 Validación de categoría ===
    if getattr(t, 'categoria_id', None) and j.categoria_id != t.categoria_id:
        flash('No podés inscribirte: el torneo es de otra categoría.', 'error')
        return redirect(url_for('torneo_public_detail', torneo_id=t.id))

    # Helper local idempotente (si ya lo definiste global, se usa ese)
    try:
        build_pareja_key  # noqa: F821
    except NameError:
        def build_pareja_key(torneo: Torneo, j1_id: int, j2_id: int | None) -> str:
            if torneo.es_dobles():
                if not j2_id:
                    raise ValueError("Este torneo es de dobles: falta jugador2_id.")
                a, b = sorted([int(j1_id), int(j2_id)])
                return f"D:{a}-{b}"
            return f"S:{int(j1_id)}"

    # Solo si el torneo está visible y en inscripción
    if not getattr(t, 'es_publico', False) and not session.get('is_admin'):
        flash('El torneo no es público.', 'error')
        return redirect(url_for('torneo_public_detail', torneo_id=t.id))

    if t.estado != 'INSCRIPCION' or not getattr(t, 'inscripciones_abiertas', False):
        flash('La inscripción no está abierta para este torneo.', 'error')
        return redirect(url_for('torneo_public_detail', torneo_id=t.id))

    # ¿permite auto-inscripción?
    if not getattr(t, 'inscripcion_libre', False):
        flash('Este torneo no permite auto-inscripción.', 'error')
        return redirect(url_for('torneo_public_detail', torneo_id=t.id))

    # Control de cupo
    total = db.session.query(TorneoInscripcion).filter_by(torneo_id=t.id).count()
    if t.cupo_max is not None and total >= int(t.cupo_max):
        flash('Cupo completo.', 'error')
        return redirect(url_for('torneo_public_detail', torneo_id=t.id))

    # Evitar duplicado del propio jugador ya inscripto
    ya = (db.session.query(TorneoInscripcion)
          .filter(TorneoInscripcion.torneo_id == t.id,
                  or_(TorneoInscripcion.jugador1_id == j.id,
                      TorneoInscripcion.jugador2_id == j.id))
          .first())
    if ya:
        flash('Ya estás inscripto en este torneo.', 'error')
        return redirect(url_for('torneo_public_detail', torneo_id=t.id))

    if request.method == 'POST':
        alias = request.form.get('alias') or None
        club = request.form.get('club') or None
        disponibilidad = request.form.get('disponibilidad') or None

        if t.es_dobles():
            # Necesita compañero
            companero_id = request.form.get('companero_id', type=int)
            if not companero_id:
                flash('Elegí un compañero para dobles.', 'error')
                return redirect(url_for('torneo_inscribirme', tid=t.id))
            if companero_id == j.id:
                flash('El compañero debe ser otra persona.', 'error')
                return redirect(url_for('torneo_inscribirme', tid=t.id))

            comp = db.session.get(Jugador, companero_id)
            if not comp or not comp.activo:
                flash('Compañero inválido o inactivo.', 'error')
                return redirect(url_for('torneo_inscribirme', tid=t.id))

            # 🔒 Validación de categoría del compañero
            if getattr(t, 'categoria_id', None) and comp.categoria_id != t.categoria_id:
                flash('El compañero no pertenece a la categoría del torneo.', 'error')
                return redirect(url_for('torneo_inscribirme', tid=t.id))

            # El compañero ya está inscripto?
            ya_comp = (db.session.query(TorneoInscripcion)
                       .filter(TorneoInscripcion.torneo_id == t.id,
                               or_(TorneoInscripcion.jugador1_id == comp.id,
                                   TorneoInscripcion.jugador2_id == comp.id))
                       .first())
            if ya_comp:
                flash('Ese compañero ya está inscripto en este torneo.', 'error')
                return redirect(url_for('torneo_inscribirme', tid=t.id))

            pareja_key = build_pareja_key(t, j.id, comp.id)
            dup = TorneoInscripcion.query.filter_by(torneo_id=t.id, pareja_key=pareja_key).first()
            if dup:
                flash('Esa pareja ya está inscripta en este torneo.', 'error')
                return redirect(url_for('torneo_public_detail', torneo_id=t.id))

            ins = TorneoInscripcion(
                torneo_id=t.id,
                jugador1_id=j.id,
                jugador2_id=comp.id,
                alias=alias,
                club=club,
                disponibilidad=disponibilidad,
                estado='ACTIVA',
                pareja_key=pareja_key,
                confirmado=True
            )
        else:
            # Singles
            pareja_key = build_pareja_key(t, j.id, None)
            dup = TorneoInscripcion.query.filter_by(torneo_id=t.id, pareja_key=pareja_key).first()
            if dup:
                flash('Ya estás inscripto en este torneo.', 'error')
                return redirect(url_for('torneo_public_detail', torneo_id=t.id))

            ins = TorneoInscripcion(
                torneo_id=t.id,
                jugador1_id=j.id,
                alias=alias,
                club=club,
                disponibilidad=disponibilidad,
                estado='ACTIVA',
                pareja_key=pareja_key,
                confirmado=True
            )

        # Timestamps defensivos
        now = datetime.utcnow()
        if hasattr(ins, "created_at") and getattr(ins, "created_at") is None:
            ins.created_at = now
        if hasattr(ins, "updated_at") and getattr(ins, "updated_at") is None:
            ins.updated_at = now

        db.session.add(ins)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Inscripción duplicada (pareja o jugador ya inscripto).', 'error')
            return redirect(url_for('torneo_public_detail', torneo_id=t.id))

        flash('Inscripción registrada.', 'ok')
        return redirect(url_for('torneo_public_detail', torneo_id=t.id))

    # GET: mostrar form (solo si dobles necesita selector)
    jugadores_activos = (db.session.query(Jugador)
                         .filter(Jugador.activo == True, Jugador.id != j.id)
                         .order_by(Jugador.nombre_completo.asc())
                         .all())
    return render_template(
        'torneo_inscribirme.html',
        t=t,
        es_dobles=t.es_dobles(),
        jugadores_activos=jugadores_activos
    )




@app.route('/admin/torneos/<int:tid>/generar_fixture', methods=['POST'])
@admin_required
def admin_torneos_generar_fixture(tid):
    from sqlalchemy import and_, or_, func

    t = get_or_404(Torneo, tid)

    EST_INSCRIPCION_CERRADA = globals().get('EST_INSCRIPCION_CERRADA', 'INSCRIPCION_CERRADA')
    EST_EN_JUEGO            = globals().get('EST_EN_JUEGO', 'EN_JUEGO')

    modo = (request.form.get('modo') or '').upper().strip()  # 'AMERICANO' | 'PLAYOFF' | 'PLAYOFF_NEXT'
    zonas = request.form.get('zonas', type=int) or 1
    if zonas < 1:
        zonas = 1
    ida_y_vuelta = (request.form.get('ida_y_vuelta') or '').lower() in ('1','true','on','sí','si')

    # ✅ usar el tid del path para no tocar la sesión si está en error
    def back():
        return redirect(url_for('admin_torneos_view', tid=tid))

    if modo not in ('AMERICANO', 'PLAYOFF', 'PLAYOFF_NEXT'):
        flash('Modo de fixture inválido.', 'error')
        return back()

    if modo in ('AMERICANO', 'PLAYOFF') and t.estado != EST_INSCRIPCION_CERRADA:
        flash('Primero cerrá la inscripción para generar el fixture.', 'error')
        return back()

    try:
        if modo == 'AMERICANO':
            # ===============================
            # GENERADOR AMERICANO *IDEMPOTENTE*
            # ===============================
            # 1) Participantes del torneo (orden estable)
            participantes = (
                db.session.query(TorneoParticipante)
                .filter(TorneoParticipante.torneo_id == tid)
                .order_by(TorneoParticipante.id.asc())
                .all()
            )
            ids = [p.id for p in participantes]

            if not ids:
                flash('No hay participantes para generar fixture.', 'warning')
                return back()

            # 2) Método del círculo (round-robin). Manejo BYE si es impar.
            part_list = ids[:]
            bye_added = False
            if len(part_list) % 2 == 1:
                part_list.append(None)  # BYE
                bye_added = True

            n = len(part_list)
            num_rondas_base = n - 1  # N-1
            rondas = []  # lista de rondas; cada ronda = lista de pares (a,b)

            # Algoritmo estándar: fijás el primero y rotás el resto a la derecha
            cur = part_list[:]
            for _r in range(num_rondas_base):
                pairs = []
                for i in range(n // 2):
                    a = cur[i]
                    b = cur[n - 1 - i]
                    if a is None or b is None:
                        # BYE → se salta
                        continue
                    pairs.append((a, b))
                rondas.append(pairs)
                # rotación: deja fijo cur[0], rota el resto a la derecha
                cur = [cur[0]] + [cur[-1]] + cur[1:-1]

            # 3) Si ida_y_vuelta: duplicamos rondas invirtiendo local/visitante
            if ida_y_vuelta:
                rondas_vuelta = []
                for pairs in rondas:
                    vuelta = [(b, a) for (a, b) in pairs]
                    rondas_vuelta.append(vuelta)
                rondas = rondas + rondas_vuelta  # primero toda la ida, luego toda la vuelta

            # 4) Idempotencia: solo crear partidos faltantes entre cada par, sin importar el orden A/B
            #    Si ya existe A-B o B-A, se considera existente.
            creados = 0

            # Para numerar rondas sin chocar con lo previo, tomamos la ronda máxima actual y sumamos offset.
            max_ronda_actual = (
                db.session.query(func.max(TorneoPartido.ronda))
                .filter(TorneoPartido.torneo_id == tid)
                .scalar()
            )
            offset_ronda = (max_ronda_actual or 0)

            # Contamos cuántos partidos existen ya por par (A,B) sin importar el orden
            def existe_partido(a, b):
                return db.session.query(TorneoPartido.id).filter(
                    TorneoPartido.torneo_id == tid,
                    or_(
                        and_(TorneoPartido.participante_a_id == a,
                             TorneoPartido.participante_b_id == b),
                        and_(TorneoPartido.participante_a_id == b,
                             TorneoPartido.participante_b_id == a),
                    )
                ).first() is not None

            # Si ida_y_vuelta, permitimos hasta 2 partidos por par (A-B y B-A).
            def cantidad_existente(a, b):
                return db.session.query(func.count(TorneoPartido.id)).filter(
                    TorneoPartido.torneo_id == tid,
                    or_(
                        and_(TorneoPartido.participante_a_id == a,
                             TorneoPartido.participante_b_id == b),
                        and_(TorneoPartido.participante_a_id == b,
                             TorneoPartido.participante_b_id == a),
                    )
                ).scalar() or 0

            for idx_ronda, pairs in enumerate(rondas, start=1):
                for idx_orden, (a, b) in enumerate(pairs, start=1):
                    if ida_y_vuelta:
                        ya = cantidad_existente(a, b)
                        # queremos hasta 2 (ida y vuelta). Si hay 0 → creamos, si hay 1 → creamos (el inverso),
                        # si hay 2 → nada
                        if ya >= 2:
                            continue
                        # decidimos el orden A/B según la ronda que estamos generando (ya viene invertido en la vuelta)
                        crear_a, crear_b = a, b
                    else:
                        # con ida sola, si ya existe (en cualquier orden), no creamos
                        if existe_partido(a, b):
                            continue
                        crear_a, crear_b = a, b

                    db.session.add(TorneoPartido(
                        torneo_id=tid,
                        participante_a_id=crear_a,
                        participante_b_id=crear_b,
                        ronda=offset_ronda + idx_ronda,
                        orden=idx_orden,
                        estado='PENDIENTE'
                    ))
                    creados += 1

            db.session.commit()

            extra = f" (zonas={zonas}{', ida y vuelta' if ida_y_vuelta else ''})"
            msg = f'Fixture AMERICANO generado/actualizado. Partidos nuevos: {creados}.'
            if bye_added:
                msg += ' (Se usó BYE por cantidad impar.)'
            flash(msg + extra, 'ok')

            if t.estado != EST_EN_JUEGO:
                t.estado = EST_EN_JUEGO
                db.session.commit()
            return back()

        if modo == 'PLAYOFF':
            creados = generar_playoff_directo(t.id)
            if creados is not None:
                flash(f'Playoff generado ({creados} partido(s) en 1ª ronda).', 'ok')
            else:
                flash('Playoff generado.', 'ok')

            if t.estado != EST_EN_JUEGO:
                t.estado = EST_EN_JUEGO
                db.session.commit()
            return back()

        # PLAYOFF_NEXT
        creados = generar_playoff_siguiente_ronda(t.id)
        if creados == 0:
            flash('No se creó nueva ronda (ya hay campeón o falta definir ganadores de la ronda previa).', 'info')
        else:
            flash(f'Siguiente ronda de playoff generada: {creados} partido(s).', 'ok')

        if t.estado != EST_EN_JUEGO:
            t.estado = EST_EN_JUEGO
            db.session.commit()
        return back()

    except RuntimeError as e:
        # ✅ limpiar la sesión tras errores controlados
        db.session.rollback()
        flash(str(e), 'error')
        return back()
    except Exception as e:
        # ✅ limpiar también en errores no controlados
        db.session.rollback()
        current_app.logger.exception('Error generando fixture')
        flash(f'Error generando fixture: {e}', 'error')
        return back()




@app.route('/admin/torneos/partidos/<int:pid>/resultado', methods=['POST'])
@admin_required
def admin_torneo_partido_resultado(pid):
    m = get_or_404(TorneoPartido, pid)
    # MVP: almacenar resultado como texto libre o sets JSON
    resultado_txt = (request.form.get('resultado') or '').strip()
    ganador_id = request.form.get('ganador_participante_id', type=int)

    if not resultado_txt or not ganador_id:
        flash('Falta resultado o ganador.', 'error')
        return redirect(url_for('admin_torneos_view', tid=m.torneo_id))

    m.resultado_json = {'resumen': resultado_txt}
    m.ganador_participante_id = ganador_id
    m.estado = 'JUGADO'
    db.session.commit()
    flash('Resultado cargado.', 'ok')
    return redirect(url_for('admin_torneos_view', tid=m.torneo_id))

# === ADMIN TORNEOS: editar / eliminar resultado de un partido ===

@app.post('/admin/torneos/partidos/<int:pid>/resultado/eliminar')
@admin_required
def admin_torneos_partido_resultado_eliminar(pid):
    """Elimina el resultado definitivo de un partido de torneo revirtiendo ranking y limpia estado/campos."""
    m = get_or_404(TorneoPartido, pid)
    try:
        # Buscar resultado definitivo si existe
        res = (
            db.session.query(TorneoPartidoResultado)
            .filter_by(partido_id=m.id)
            .one_or_none()
        )

        # ——— 1) Revertir ranking ANTES de borrar el resultado ———
        if res:
            # Determinar ganador_lado ("A"/"B")
            ganador_lado = getattr(res, "ganador_lado", None)

            if not ganador_lado:
                # Fallback: inferir por ganador_participante_id del partido
                try:
                    if getattr(m, "ganador_participante_id", None):
                        if m.ganador_participante_id == getattr(m, "participante_a_id", None):
                            ganador_lado = "A"
                        elif m.ganador_participante_id == getattr(m, "participante_b_id", None):
                            ganador_lado = "B"
                except Exception:
                    ganador_lado = None

            # Llamar helper espejo si está definido y tenemos ganador_lado
            try:
                if ganador_lado and "_revertir_ranking_por_torneo" in globals():
                    _revertir_ranking_por_torneo(m, ganador_lado, res)
            except Exception:
                # No abortar por error de reversión: log y continuar con borrado
                current_app.logger.exception(
                    "[admin] Error revirtiendo ranking en eliminar resultado (pid=%s)", pid
                )

            # ——— 2) Borrar resultado definitivo ———
            db.session.delete(res)

        # ——— 3) Borrar propuesta (si tu modelo la usa) ———
        try:
            from app import TorneoPartidoResultadoPropuesto as TPRP
        except Exception:
            TPRP = globals().get('TorneoPartidoResultadoPropuesto', None)

        if TPRP:
            prp = db.session.query(TPRP).filter_by(partido_id=m.id).one_or_none()
            if prp:
                db.session.delete(prp)

        # ——— 4) Limpiar campos del partido ———
        # Ganador explícito en el partido
        if hasattr(m, 'ganador_participante_id'):
            m.ganador_participante_id = None

        # Texto/JSON de sets si existiera
        if hasattr(m, 'sets_text'):
            m.sets_text = None
        if hasattr(m, 'resultado_json'):
            m.resultado_json = None
        if hasattr(m, 'resultado_id'):
            m.resultado_id = None

        # Dejar el estado en 'PENDIENTE' si corresponde
        if hasattr(m, 'estado'):
            m.estado = 'PENDIENTE'

        db.session.commit()
        flash('Resultado eliminado, ranking revertido y partido dejado en PENDIENTE.', 'success')

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception('[admin] eliminar resultado torneo pid=%s', pid)
        flash('No se pudo eliminar el resultado (ver logs).', 'error')

    return redirect(url_for('admin_torneos_view', tid=m.torneo_id))


@app.route('/admin/torneos/partidos/<int:pid>/resultado/editar', methods=['POST'])
@admin_required
def admin_torneos_partido_resultado_editar(pid):
    """
    Edita (o crea) el resultado definitivo de un partido de torneo.
    Espera en el form:
      - ganador_participante_id (int)  O bien ganador_lado in ['A','B'] si preferís por lado
      - sets_text (str, opcional)
    """
    m = get_or_404(TorneoPartido, pid)

    # Tomar ganador por participante directamente…
    ganador_participante_id = request.form.get('ganador_participante_id', type=int)
    # …o permitir indicar por lado (A/B) y derivar el participante
    if not ganador_participante_id:
        lado = (request.form.get('ganador_lado') or '').strip().upper()
        if lado == 'A':
            ganador_participante_id = getattr(m, 'participante_a_id', None)
        elif lado == 'B':
            ganador_participante_id = getattr(m, 'participante_b_id', None)

    sets_text = (request.form.get('sets_text') or '').strip() or None

    if not ganador_participante_id:
        flash('Falta indicar ganador.', 'error')
        return redirect(url_for('admin_torneos_view', tid=m.torneo_id))

    try:
        # upsert del resultado definitivo
        res = db.session.query(TorneoPartidoResultado).filter_by(partido_id=m.id).one_or_none()
        if not res:
            res = TorneoPartidoResultado(partido_id=m.id)
            db.session.add(res)

        res.ganador_participante_id = ganador_participante_id
        res.sets_text = sets_text

        # reflejar en el partido
        m.ganador_participante_id = ganador_participante_id
        if hasattr(m, 'estado'):
            m.estado = 'JUGADO'
        if hasattr(m, 'resultado_json') and sets_text is not None:
            # opcional: si guardás un json de sets, podés serializar desde sets_text
            # acá simplemente lo limpiamos o dejamos como texto; adaptá si hace falta
            m.resultado_json = None

        # si había una propuesta, al confirmar resultado definitivo la borramos
        try:
            from app import TorneoPartidoResultadoPropuesto as TPRP
        except Exception:
            TPRP = globals().get('TorneoPartidoResultadoPropuesto', None)
        if TPRP:
            prp = db.session.query(TPRP).filter_by(partido_id=m.id).one_or_none()
            if prp:
                db.session.delete(prp)

        db.session.commit()
        flash('Resultado guardado correctamente.', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception('[admin] editar resultado torneo pid=%s', pid)
        flash('No se pudo guardar el resultado (ver logs).', 'error')

    return redirect(url_for('admin_torneos_view', tid=m.torneo_id))



@app.route('/admin/torneos/<int:tid>/abrir_inscripcion', methods=['POST'])
@admin_required
def admin_torneo_abrir_inscripcion(tid):
    t = get_or_404(Torneo, tid)

    # Usar constantes si están definidas; fallback a literales
    EST_BORRADOR    = globals().get('EST_BORRADOR', 'BORRADOR')
    EST_INSCRIPCION = globals().get('EST_INSCRIPCION', 'INSCRIPCION')
    EST_CANCELADO   = globals().get('EST_CANCELADO', 'CANCELADO')

    if t.estado not in (EST_BORRADOR, EST_CANCELADO):
        flash('Solo se puede abrir inscripción desde BORRADOR o CANCELADO.', 'error')
        return redirect(url_for('admin_torneos_view', tid=t.id))

    # Estado y flags coherentes con la vista pública
    t.estado = EST_INSCRIPCION
    # si manejás visibilidad/inscripción pública, asegurá la apertura
    try:
        # estos campos existen en tu modelo
        t.inscripciones_abiertas = True
        # no toco es_publico (respetamos lo que tenga)
    except AttributeError:
        # por si en otro entorno no existen estos campos
        pass

    db.session.commit()
    flash('Inscripción abierta.', 'ok')
    return redirect(url_for('admin_torneos_view', tid=t.id))



@app.route('/admin/torneos/<int:tid>/cerrar_inscripcion', methods=['POST'])
@admin_required
def admin_torneo_cerrar_inscripcion(tid):
    t = get_or_404(Torneo, tid)

    # Usar constantes si existen; fallback a literales
    EST_INSCRIPCION         = globals().get('EST_INSCRIPCION', 'INSCRIPCION')
    EST_INSCRIPCION_CERRADA = globals().get('EST_INSCRIPCION_CERRADA', 'INSCRIPCION_CERRADA')

    if t.estado != EST_INSCRIPCION:
        flash('El torneo no está en inscripción.', 'error')
        return redirect(url_for('admin_torneos_view', tid=t.id))

    # Cerrar inscripción "de verdad": queda listo para generar fixture
    t.estado = EST_INSCRIPCION_CERRADA
    try:
        # reflejar en la vista pública
        t.inscripciones_abiertas = False
    except AttributeError:
        pass

    db.session.commit()
    flash('Inscripción cerrada. Ya podés generar el fixture.', 'ok')
    return redirect(url_for('admin_torneos_view', tid=t.id))

@app.route('/admin/torneos/<int:tid>/eliminar', methods=['POST'], endpoint='admin_torneo_eliminar')
@admin_required
def admin_torneo_eliminar(tid):
    t = get_or_404(Torneo, tid)
    try:
        # 1) Partidos
        db.session.query(TorneoPartido).filter_by(torneo_id=t.id).delete(synchronize_session=False)
        # 2) Nodos de llave
        db.session.query(TorneoLlaveNodo).filter_by(torneo_id=t.id).delete(synchronize_session=False)
        # 3) Participantes
        db.session.query(TorneoParticipante).filter_by(torneo_id=t.id).delete(synchronize_session=False)
        # 4) Grupos (por fases del torneo)
        sub_fases = db.session.query(TorneoFase.id).filter(TorneoFase.torneo_id == t.id).subquery()
        db.session.query(TorneoGrupo).filter(TorneoGrupo.fase_id.in_(sub_fases)).delete(synchronize_session=False)
        # 5) Fases
        db.session.query(TorneoFase).filter_by(torneo_id=t.id).delete(synchronize_session=False)
        # 6) Inscripciones
        db.session.query(TorneoInscripcion).filter_by(torneo_id=t.id).delete(synchronize_session=False)
        # 7) Torneo
        db.session.delete(t)

        db.session.commit()
        flash('Torneo eliminado correctamente.', 'ok')
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Error eliminando torneo")
        flash(f'No se pudo eliminar el torneo: {e}', 'error')

    return redirect(url_for('admin_torneos_list'))


@app.route('/torneos', methods=['GET'])
def torneos_public_list():
    # Filtros de querystring
    estado = (request.args.get('estado') or '').upper().strip()
    categoria_id = request.args.get('categoria', type=int)

    # Jugador actual (si está logueado)
    j = get_current_jugador()

    # Solo torneos públicos (visibles para todos)
    q = db.session.query(Torneo).filter(Torneo.es_publico.is_(True))

    # ---- Filtro de VISIBILIDAD por categoría del jugador ----
    # - Logueado: ve torneos sin categoría fija o de su misma categoría
    # - No logueado: ve solo torneos sin categoría fija
    if j is not None:
        q = q.filter(or_(Torneo.categoria_id.is_(None),
                         Torneo.categoria_id == j.categoria_id))
    else:
        q = q.filter(Torneo.categoria_id.is_(None))

    # Filtro por estado (se mantiene tu lógica)
    if estado in {'BORRADOR','INSCRIPCION','EN_JUEGO','FINALIZADO','CANCELADO'}:
        q = q.filter(Torneo.estado == estado)

    # Filtro por categoría (opcional) — se aplica además de la visibilidad
    if categoria_id:
        q = q.filter(Torneo.categoria_id == categoria_id)

    # Orden: primero por fecha (si existe), luego por creación (como tenías)
    torneos = q.order_by(
        Torneo.fecha_inicio.is_(None),
        Torneo.fecha_inicio.asc(),
        Torneo.created_at.desc()
    ).all()

    return render_template(
        'torneos_list.html',
        torneos=torneos,
        estado=estado,
        categoria=categoria_id
    )


@app.route('/torneos/<int:torneo_id>', methods=['GET'])
def torneo_public_detail(torneo_id: int):
    # Obtener torneo o 404
    t = Torneo.query.get_or_404(torneo_id)

    # Si NO es público, solo dejar ver al admin; para el resto, 404
    if not getattr(t, 'es_publico', False) and not session.get('is_admin'):
        abort(404)

    # Traer inscripciones (si existe la tabla/modelo)
    inscriptos = (TorneoInscripcion.query
                  .filter_by(torneo_id=t.id)
                  .order_by(
                      TorneoInscripcion.created_at.asc()
                      if hasattr(TorneoInscripcion, 'created_at')
                      else TorneoInscripcion.id.asc()
                  )
                  .all())

    # Conteos y flags de UI
    total_inscriptos = len(inscriptos)
    cupo_disponible = None if t.cupo_max is None else max(0, int(t.cupo_max) - total_inscriptos)

    puede_inscribirse = (
        getattr(t, 'es_publico', False) and
        getattr(t, 'inscripciones_abiertas', False) and
        getattr(t, 'inscripcion_libre', False) and
        t.estado == 'INSCRIPCION' and
        (t.cupo_max is None or total_inscriptos < int(t.cupo_max))
    )

    # Usuario actual (si tu helper existe)
    j = get_current_jugador() if 'get_current_jugador' in globals() else None

    # Para formulario de dobles: lista de jugadores activos (excluye al actual)
    jugadores_activos = []
    if puede_inscribirse and t.es_dobles() and j and getattr(j, 'activo', False):
        jugadores_activos = (db.session.query(Jugador)
                             .filter(Jugador.activo == True, Jugador.id != j.id)
                             .order_by(Jugador.nombre_completo.asc())
                             .all())

    # JSON si lo piden explícitamente
    if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
        return jsonify({
            "id": t.id,
            "nombre": t.nombre,
            "categoria_id": t.categoria_id,
            "categoria": getattr(t.categoria, "nombre", None),
            "formato": t.formato,
            "tipo": t.tipo,
            "estado": t.estado,
            "fecha_inicio": t.fecha_inicio.isoformat() if t.fecha_inicio else None,
            "sede": t.sede,
            "es_publico": getattr(t, 'es_publico', False),
            "inscripciones_abiertas": getattr(t, 'inscripciones_abiertas', False),
            "inscripcion_libre": t.inscripcion_libre,
            "cupo_max": t.cupo_max,
            "inscriptos": total_inscriptos,
            "cupo_disponible": cupo_disponible,
            "notas": t.notas,
            "puede_inscribirse": puede_inscribirse,
        })

    # Render por defecto (HTML)
    return render_template(
        'torneo_detalle.html',   # si tu template se llama distinto, ajustá acá
        torneo=t,
        inscriptos=inscriptos,
        total_inscriptos=total_inscriptos,
        cupo_disponible=cupo_disponible,
        puede_inscribirse=puede_inscribirse,
        jugadores_activos=jugadores_activos,  # nuevo para el form de dobles
        current_jugador=j                      # útil para el template público
    )


# --- Público: fixture del torneo ---
@app.route('/torneos/<int:torneo_id>/fixture', methods=['GET'])
def torneo_public_fixture(torneo_id: int):
    t = Torneo.query.get_or_404(torneo_id)
    if not getattr(t, 'es_publico', False) and not session.get('is_admin'):
        abort(404)

    # --- Fases ordenadas ---
    fases = (db.session.query(TorneoFase)
             .filter_by(torneo_id=t.id)
             .order_by(TorneoFase.id.asc())
             .all())

    grupos_por_fase = {}
    partidos_por_fase = {}
    partidos_por_grupo = {}

    # --- Todos los partidos del torneo (para el template) ---
    q_partidos = (db.session.query(TorneoPartido)
                  .filter(TorneoPartido.torneo_id == t.id)
                  .order_by(
                      TorneoPartido.ronda.asc(),
                      TorneoPartido.orden.asc(),
                      TorneoPartido.id.asc()
                  ))
    partidos = q_partidos.all()

    # --- Estructuras por fase/grupo (lo que ya tenías) ---
    for f in fases:
        grupos = (db.session.query(TorneoGrupo)
                  .filter_by(fase_id=f.id)
                  .order_by(TorneoGrupo.id.asc())
                  .all())
        grupos_por_fase[f.id] = grupos

        partidos_fase = (db.session.query(TorneoPartido)
                         .filter(TorneoPartido.torneo_id == t.id)
                         .filter(TorneoPartido.fase_id == f.id)
                         .order_by(TorneoPartido.ronda.asc(), TorneoPartido.id.asc())
                         .all())
        partidos_por_fase[f.id] = partidos_fase

        for g in grupos:
            partidos_grupo = [m for m in partidos_fase if getattr(m, 'grupo_id', None) == g.id]
            partidos_por_grupo[g.id] = partidos_grupo

    # ---------- Resolver nombres DESDE INSCRIPTOS del torneo ----------
    ids = set()
    for m in partidos:
        if m.participante_a_id: ids.add(m.participante_a_id)
        if m.participante_b_id: ids.add(m.participante_b_id)

    nombres_por_id = {}
    if ids:
        Jugador = globals().get('Jugador')
        # 1) Intentar con el/los modelos de INSCRIPCIÓN del torneo
        candidatos_insc = []
        for nombre_modelo in ('TorneoInscripcion', 'TorneoParticipante', 'Inscripcion'):
            M = globals().get(nombre_modelo)
            if M is not None and hasattr(M, '__table__') and 'torneo_id' in M.__table__.c.keys():
                candidatos_insc.append(M)

        def cargar_desde_inscripciones(Model):
            cols = set(Model.__table__.c.keys())
            # Solo las inscripciones de ESTE torneo y cuyos IDs aparecen en el fixture
            inscs = (db.session.query(Model)
                     .filter(getattr(Model, 'torneo_id') == t.id)
                     .filter(getattr(Model, 'id').in_(ids))
                     .all())
            if not inscs:
                return False

            # SINGLE: jugador_id
            if 'jugador_id' in cols and Jugador is not None:
                jids = [getattr(r, 'jugador_id') for r in inscs if getattr(r, 'jugador_id', None)]
                jug_map = {}
                if jids:
                    for j in db.session.query(Jugador).filter(Jugador.id.in_(jids)).all():
                        jug_map[j.id] = j.nombre_completo
                for r in inscs:
                    jid = getattr(r, 'jugador_id', None)
                    if jid in jug_map:
                        nombres_por_id[r.id] = jug_map[jid]

            # DOBLES: jugador1_id + jugador2_id
            if {'jugador1_id', 'jugador2_id'} <= cols and Jugador is not None:
                all_j = set()
                for r in inscs:
                    if getattr(r, 'jugador1_id', None): all_j.add(r.jugador1_id)
                    if getattr(r, 'jugador2_id', None): all_j.add(r.jugador2_id)
                jug_map = {}
                if all_j:
                    for j in db.session.query(Jugador).filter(Jugador.id.in_(list(all_j))).all():
                        jug_map[j.id] = j.nombre_completo
                for r in inscs:
                    j1 = jug_map.get(getattr(r, 'jugador1_id', None))
                    j2 = jug_map.get(getattr(r, 'jugador2_id', None))
                    if j1 and j2:
                        nombres_por_id[r.id] = f"{j1} / {j2}"
                    elif j1:
                        nombres_por_id[r.id] = j1
                    elif j2:
                        nombres_por_id[r.id] = j2

            # Si el propio modelo tiene 'nombre' o 'nombre_completo'
            for r in inscs:
                if r.id not in nombres_por_id:
                    nom = getattr(r, 'nombre_completo', None) or getattr(r, 'nombre', None)
                    if nom:
                        nombres_por_id[r.id] = nom

            return True

        resolvio = False
        for Model in candidatos_insc:
            if cargar_desde_inscripciones(Model):
                resolvio = True

        # 2) Fallback (legacy): si no logramos resolver por inscripciones,
        #    tal vez los IDs del fixture son Jugador.id
        if not resolvio and Jugador is not None:
            filas = db.session.query(Jugador).filter(Jugador.id.in_(ids)).all()
            for j in filas:
                nombres_por_id[j.id] = j.nombre_completo

    # ---------- Nombres por PARTIDO y LADO (A/B) para AMERICANO INDIVIDUAL ----------
    nombres_lado = {}  # (partido_id, 'A'|'B') -> "Nombre1 / Nombre2"

    TorneoPartidoLado = globals().get('TorneoPartidoLado')
    TorneoInscripcion = globals().get('TorneoInscripcion')
    Jugador = globals().get('Jugador')

    if TorneoPartidoLado and TorneoInscripcion and Jugador and partidos:
        # 1) Lados de todos los partidos de este torneo
        lados = (db.session.query(TorneoPartidoLado)
                 .join(TorneoPartido, TorneoPartidoLado.partido_id == TorneoPartido.id)
                 .filter(TorneoPartido.torneo_id == t.id)
                 .all())

        if lados:
            # 2) Pre-cargar inscripciones y jugadores involucrados
            insc_ids_lado = set()
            for L in lados:
                if getattr(L, 'insc1_id', None): insc_ids_lado.add(L.insc1_id)
                if getattr(L, 'insc2_id', None): insc_ids_lado.add(L.insc2_id)

            insc_rows = db.session.query(TorneoInscripcion).filter(TorneoInscripcion.id.in_(insc_ids_lado)).all()
            insc_by_id = {r.id: r for r in insc_rows}

            j_ids = set()
            for r in insc_rows:
                if getattr(r, 'jugador1_id', None): j_ids.add(r.jugador1_id)
                if getattr(r, 'jugador2_id', None): j_ids.add(r.jugador2_id)

            jug_map = {}
            if j_ids:
                for j in db.session.query(Jugador).filter(Jugador.id.in_(list(j_ids))).all():
                    jug_map[j.id] = j.nombre_completo

            # 3) Construir "J1 / J2" por lado
            for L in lados:
                insc1 = insc_by_id.get(getattr(L, 'insc1_id', None))
                insc2 = insc_by_id.get(getattr(L, 'insc2_id', None))

                n1 = jug_map.get(getattr(insc1, 'jugador1_id', None))
                n2 = jug_map.get(getattr(insc2, 'jugador1_id', None))
                # Por si alguna inscripción trae jugador2_id usado (no típico en singles)
                if not n1 and insc1 and getattr(insc1, 'jugador2_id', None):
                    n1 = jug_map.get(insc1.jugador2_id)
                if not n2 and insc2 and getattr(insc2, 'jugador2_id', None):
                    n2 = jug_map.get(insc2.jugador2_id)

                if n1 and n2:
                    lado_key = (L.partido_id, (L.lado or 'A').upper())
                    nombres_lado[lado_key] = f"{n1} / {n2}"

    return render_template(
        'torneo_fixture.html',
        torneo=t,
        partidos=partidos,
        fases=fases,
        grupos_por_fase=grupos_por_fase,
        partidos_por_fase=partidos_por_fase,
        partidos_por_grupo=partidos_por_grupo,
        nombres_por_id=nombres_por_id,   # lo que ya usabas
        nombres_lado=nombres_lado,       # NUEVO: para americano individual
    )


def _require_participante(tp: TorneoPartido) -> tuple[int, str]:
    """Valida que el usuario participa y devuelve (jugador_id, lado 'A'/'B')."""
    jugador_id = _jugador_id_actual()
    if not jugador_id:
        abort(403)
    lado = lado_de_jugador_en_partido(tp, jugador_id)
    if lado not in ('A','B'):
        abort(403)
    return jugador_id, lado

def _finalizar_partido(p: 'TorneoPartido',
                       ganador_lado: str,
                       sets_text: str | None,
                       confirmado_por_jugador_id: int | None = None):
    """
    Crea TorneoPartidoResultado, marca el partido como JUGADO y aplica puntos de ranking.
    Idempotente a nivel 'unique' (partido_id único en resultados de torneo).
    """
    ganador_lado = (ganador_lado or '').upper()
    if ganador_lado not in ('A', 'B'):
        raise ValueError("ganador_lado debe ser 'A' o 'B'")

    # Resolver ganador_participante_id según el lado
    ganador_participante_id = p.participante_a_id if ganador_lado == 'A' else p.participante_b_id

    # Upsert-like: si ya existe resultado, lo actualizamos
    res = TorneoPartidoResultado.query.filter_by(partido_id=p.id).one_or_none()
    if res is None:
        res = TorneoPartidoResultado(
            partido_id=p.id,
            ganador_lado=ganador_lado,
            ganador_participante_id=ganador_participante_id,
            sets_text=sets_text or None,
            confirmado_por_jugador_id=confirmado_por_jugador_id
        )
        db.session.add(res)
    else:
        res.ganador_lado = ganador_lado
        res.ganador_participante_id = ganador_participante_id
        res.sets_text = sets_text or None
        res.confirmado_por_jugador_id = confirmado_por_jugador_id

    # Estado del partido
    p.estado = 'JUGADO'
    db.session.flush()  # aseguramos IDs por si hiciera falta

    # 🔢 Ranking: aplicar puntos (mismo esquema que partidos)
    try:
        _aplicar_ranking_por_torneo(p, ganador_lado)
    except Exception:
        # no bloqueamos el cierre si la actualización de puntos falla
        current_app.logger.exception("Fallo aplicando ranking para TorneoPartido %s", p.id)

    db.session.commit()

# --- helpers chiquitos de permiso ---
def _es_admin_actual() -> bool:
    try:
        # si tu modelo de usuario ya tiene is_admin directo, también lo contemplamos
        return bool(
            getattr(getattr(current_user, "jugador", None), "is_admin", False) or
            getattr(current_user, "is_admin", False)
        )
    except Exception:
        return False


def _jugador_id_actual() -> int | None:
    """
    Devuelve el ID del jugador autenticado.
    Orden de resolución (sin dependencias externas):
    1) _resolve_jugador_id() si existe en tu proyecto.
    2) get_current_jugador() si existe (usa tu sesión).
    3) session['jugador_id'] directamente.
    """
    # 1) Resolver por helper propio si existe
    try:
        return _resolve_jugador_id()  # si no existe, caerá en except
    except Exception:
        pass

    # 2) Tu helper existente
    try:
        if 'get_current_jugador' in globals():
            j = get_current_jugador()
            return int(j.id) if j else None
    except Exception:
        pass

    # 3) Fallback a la sesión
    try:
        jid = session.get('jugador_id')
        return int(jid) if jid is not None else None
    except Exception:
        return None


# ================ DETALLE =================
@app.route('/torneos/partidos/<int:partido_id>', methods=['GET'])
def torneo_partido_detalle(partido_id: int):
    # Partido o 404 (usa tu helper 2.x-friendly)
    p = get_or_404(TorneoPartido, partido_id)

    # Usuario actual (obligatorio estar logueado)
    j = get_current_jugador()
    if not j:
        abort(403)

    # ¿en qué lado estoy? (A/B) — robusto: contempla A2/B2 desde la tabla LADOS
    flags = _lado_flag_dict(p, j.id)   # {'A': True/False, 'B': True/False}
    lado_user = 'A' if flags.get('A') else ('B' if flags.get('B') else None)

    es_admin = bool(getattr(j, 'is_admin', False))
    es_participante = lado_user in ('A', 'B')

    # Guard: sólo admin o participantes pueden ver el detalle
    if not (es_admin or es_participante):
        abort(403)

    # Propuesta y resultado actuales (si existen)
    prop = TorneoPartidoResultadoPropuesto.query.filter_by(partido_id=partido_id).one_or_none()
    res  = TorneoPartidoResultado.query.filter_by(partido_id=partido_id).one_or_none()
    hay_propuesta = prop is not None
    hay_resultado = bool(res or getattr(p, 'resultado_json', None))

    # Permisos de acción
    # - Proponer: participa (o admin), partido no cerrado y sin propuesta abierta
    puede_proponer = (
        (es_participante or es_admin)
        and (p.estado in ('PENDIENTE', 'PROGRAMADO', 'POR_CONFIRMAR'))
        and not hay_propuesta
        and not hay_resultado
    )

    # - Responder: participa (o admin) y existe propuesta abierta
    puede_responder = (es_participante or es_admin) and hay_propuesta

    return render_template(
        'torneo_partido_detalle.html',
        p=p,
        prop=prop,
        res=res,
        lado_user=lado_user,
        puede_proponer=puede_proponer,
        puede_responder=puede_responder,
    )



# ================ PROPONER =================
@app.route('/torneos/partidos/<int:partido_id>/proponer', methods=['GET', 'POST'])
def torneo_partido_proponer(partido_id: int):
    """Crear/editar la propuesta de resultado de UN partido de torneo (aislado por partido_id)."""
    p = get_or_404(TorneoPartido, partido_id)
    j = get_current_jugador()
    if not j:
        abort(403)

    # --- Detección robusta de lado ---
    lado_user = None
    try:
        idsA = (_jugadores_del_lado_torneo(p, 'A') or [])
        idsB = (_jugadores_del_lado_torneo(p, 'B') or [])
        if j.id in idsA:
            lado_user = 'A'
        elif j.id in idsB:
            lado_user = 'B'
    except Exception:
        pass
    if lado_user is None:
        try:
            flags = _lado_flag_dict(p, j.id)  # {'A': bool, 'B': bool}
            lado_user = 'A' if flags.get('A') else ('B' if flags.get('B') else None)
        except Exception:
            lado_user = None

    es_admin = bool(getattr(j, 'is_admin', False))
    es_participante = lado_user in ('A', 'B')
    if not (es_admin or es_participante):
        abort(403)

    if (p.estado or '').upper() == 'JUGADO' or getattr(p, 'resultado_def', None):
        flash('El partido ya está cerrado.', 'warning')
        return redirect(url_for('torneo_partido_detalle', partido_id=partido_id))

    prop = TorneoPartidoResultadoPropuesto.query.filter_by(partido_id=p.id).one_or_none()

    if request.method == 'GET':
        return render_template('torneo_partido_proponer.html', p=p, lado_user=lado_user, prop=prop)

    # ---- POST ----
    ganador_lado = (request.form.get('ganador_lado') or '').strip().upper()
    sets_text = (request.form.get('sets_text') or '').strip() or None

    if ganador_lado not in ('A', 'B'):
        flash('Seleccioná el lado ganador (A o B).', 'error')
        return redirect(url_for('torneo_partido_proponer', partido_id=partido_id))

    try:
        if prop is None:
            prop = TorneoPartidoResultadoPropuesto(
                partido_id=p.id,
                ganador_lado=ganador_lado,
                sets_text=sets_text,
                propuesto_por_jugador_id=j.id,
                # auto-confirma sólo el lado del proponente si participa
                confirma_ladoA=True if lado_user == 'A' else None,
                confirma_ladoB=True if lado_user == 'B' else None,
            )
            db.session.add(prop)
        else:
            prop.ganador_lado = ganador_lado
            prop.sets_text = sets_text
            prop.propuesto_por_jugador_id = j.id
            # ⚠️ NO tocar el lado rival: evitamos rulo
            if lado_user == 'A':
                prop.confirma_ladoA = True
            elif lado_user == 'B':
                prop.confirma_ladoB = True
            # admin no participante: no auto-confirma nada

        p.estado = 'PROPUESTO'
        db.session.commit()
        flash('Resultado propuesto enviado.', 'success')
        return redirect(url_for('torneo_partido_detalle', partido_id=partido_id))

    except Exception:
        db.session.rollback()
        current_app.logger.exception("Error al proponer resultado en torneo (partido_id=%s)", p.id)
        flash('No se pudo enviar la propuesta. Intentá nuevamente.', 'error')
        return redirect(url_for('torneo_partido_proponer', partido_id=partido_id))


# ================ RESPONDER =================
@app.route('/torneos/partidos/<int:partido_id>/responder', methods=['GET', 'POST'])
def torneo_partido_responder(partido_id: int):
    """Responder una propuesta de resultado de UN partido de torneo (aislado por partido_id)."""
    p = get_or_404(TorneoPartido, partido_id)
    j = get_current_jugador()
    if not j:
        abort(403)

    # --- Detección robusta de lado ---
    lado_user = None
    try:
        idsA = (_jugadores_del_lado_torneo(p, 'A') or [])
        idsB = (_jugadores_del_lado_torneo(p, 'B') or [])
        if j.id in idsA:
            lado_user = 'A'
        elif j.id in idsB:
            lado_user = 'B'
    except Exception:
        pass
    if lado_user is None:
        try:
            flags = _lado_flag_dict(p, j.id)
            lado_user = 'A' if flags.get('A') else ('B' if flags.get('B') else None)
        except Exception:
            lado_user = None

    es_admin = bool(getattr(j, 'is_admin', False))
    es_participante = lado_user in ('A', 'B')
    if not (es_admin or es_participante):
        abort(403)

    if (p.estado or '').upper() == 'JUGADO' or getattr(p, 'resultado_def', None):
        flash('El partido ya está cerrado.', 'warning')
        return redirect(url_for('torneo_partido_detalle', partido_id=partido_id))

    prop = TorneoPartidoResultadoPropuesto.query.filter_by(partido_id=p.id).one_or_none()
    if not prop:
        flash('No hay propuesta para responder.', 'warning')
        return redirect(url_for('torneo_partido_detalle', partido_id=partido_id))

    if request.method == 'GET':
        return render_template('torneo_partido_responder.html', p=p, prop=prop, lado_user=lado_user, es_admin=es_admin)

    # ---- POST ----
    accion = (request.form.get('accion') or '').strip().lower()  # 'aceptar' | 'rechazar'

    # Determinar lado que responde
    working_lado = lado_user
    if working_lado not in ('A', 'B') and es_admin:
        lado_form = (request.form.get('lado') or '').strip().upper()
        if lado_form in ('A', 'B'):
            working_lado = lado_form

    if working_lado not in ('A', 'B'):
        flash('No se pudo determinar el lado que responde (A/B).', 'error')
        return redirect(url_for('torneo_partido_detalle', partido_id=partido_id))

    try:
        if accion == 'aceptar':
            # marcar SOLAMENTE mi lado como True
            if working_lado == 'A':
                prop.confirma_ladoA = True
            else:
                prop.confirma_ladoB = True

            # si ambos confirmaron → cerrar
            if prop.confirma_ladoA is True and prop.confirma_ladoB is True:
                _finalizar_partido(
                    p,
                    prop.ganador_lado,
                    prop.sets_text,
                    confirmado_por_jugador_id=j.id
                )
                db.session.delete(prop)  # borrar SOLO esta propuesta
                db.session.commit()
                flash('Partido cerrado como JUGADO.', 'success')
                return redirect(url_for('torneo_partido_detalle', partido_id=partido_id))

            # aún falta el otro lado
            p.estado = 'PROPUESTO'
            db.session.commit()
            flash('Aceptaste la propuesta. Falta confirmación del rival.', 'info')
            return redirect(url_for('torneo_partido_detalle', partido_id=partido_id))

        elif accion == 'rechazar':
            # marcar SOLAMENTE mi lado como False (queda en revisión)
            if working_lado == 'A':
                prop.confirma_ladoA = False
            else:
                prop.confirma_ladoB = False
            p.estado = 'EN_REVISION'
            db.session.commit()
            flash('Marcaste la propuesta como RECHAZADA. Se pasó a revisión.', 'warning')
            return redirect(url_for('torneo_partido_detalle', partido_id=partido_id))

        else:
            flash('Acción inválida.', 'error')
            return redirect(url_for('torneo_partido_detalle', partido_id=partido_id))

    except Exception:
        db.session.rollback()
        current_app.logger.exception("Error al responder propuesta en torneo (partido_id=%s)", p.id)
        flash('No se pudo procesar la respuesta. Intentá nuevamente.', 'error')
        return redirect(url_for('torneo_partido_detalle', partido_id=partido_id))



# --- Público: tabla (americano / zonas) ---
@app.route('/torneos/<int:torneo_id>/tabla')
def torneo_public_tabla(torneo_id):
    from sqlalchemy import or_ as sa_or

    t = get_or_404(Torneo, torneo_id)

    # Traer partidos del torneo
    partidos = (
        db.session.query(TorneoPartido)
        .filter(TorneoPartido.torneo_id == t.id)
        .order_by(
            TorneoPartido.ronda.asc().nulls_last(),
            TorneoPartido.orden.asc().nulls_last(),
            TorneoPartido.id.asc()
        )
        .all()
    )

    # Resultados confirmados (si no existe el modelo, tabla queda en 0)
    try:
        res_list = (
            db.session.query(TorneoPartidoResultado)
            .join(TorneoPartido, TorneoPartidoResultado.partido_id == TorneoPartido.id)
            .filter(TorneoPartido.torneo_id == t.id)
            .all()
        )
    except Exception:
        res_list = []
    res_map = {r.partido_id: r for r in res_list}

    # Helper para obtener jugadores por lado (A/B)
    helper_torneo = globals().get('_jugadores_del_lado_torneo')

    # --------- Parser de sets (ej: "6-4 3-6 10-8") ----------
    def parse_sets(texto):
        sw = sl = gw = gl = 0
        if not texto:
            return sw, sl, gw, gl
        # tokens por espacio
        for tok in str(texto).strip().split():
            if '-' not in tok:
                continue
            try:
                a, b = tok.split('-', 1)
                ga = int(a); gb = int(b)
            except Exception:
                continue
            # quién ganó el set
            if ga > gb:
                sw += 1
                gw += ga; gl += gb
            elif gb > ga:
                sl += 1
                gw += ga; gl += gb
                # (el que llama decidirá a qué lado sumar como "won/lost")
            else:
                # empates no deberían existir, igual contamos juegos
                gw += ga; gl += gb
        return sw, sl, gw, gl

    # --------- Acumuladores por jugador ---------
    # standings[jid] = dict con métricas
    standings = {}
    def ensure(jid):
        if jid not in standings:
            standings[jid] = dict(
                PJ=0, G=0, P=0,
                SW=0, SL=0, SD=0,   # Sets Won/Lost/Diff
                GW=0, GL=0, GD=0,   # Games Won/Lost/Diff
                PTS=0
            )

    # Reglas de puntaje (fallback: 2 por victoria, 0 por derrota)
    # Si querés customizar, podés guardar en t.reglas_json = {"pts_victoria":3,"pts_derrota":0}
    pts_v = 2
    pts_d = 0
    try:
        import json
        if t.reglas_json:
            rj = json.loads(t.reglas_json) if isinstance(t.reglas_json, str) else (t.reglas_json or {})
            pts_v = int(rj.get('pts_victoria', pts_v))
            pts_d = int(rj.get('pts_derrota', pts_d))
    except Exception:
        pass

    # Pre-cargar jugadores usados para nombres
    all_ids = set()

    # Recorremos partidos con resultado
    for p in partidos:
        r = res_map.get(p.id)
        if not r:
            continue

        # Jugadores por LADO usando helper fuerte de torneo
        a_ids = []
        b_ids = []
        try:
            if helper_torneo:
                a_ids = [int(x) for x in (helper_torneo(p, 'A') or []) if x]
                b_ids = [int(x) for x in (helper_torneo(p, 'B') or []) if x]
        except TypeError:
            a_ids = []
            b_ids = []

        # Si no hay info de lados, saltamos (no podemos adjudicar victorias)
        if not a_ids and not b_ids:
            continue

        all_ids.update(a_ids); all_ids.update(b_ids)

        # Determinar ganador por lado
        ganador_lado = getattr(r, 'ganador_lado', None)
        ganador_pid = getattr(r, 'ganador_participante_id', None)
        # Si no viene lado pero sí el participante_id, traducimos
        if not ganador_lado and ganador_pid:
            if getattr(p, 'participante_a_id', None) == ganador_pid:
                ganador_lado = 'A'
            elif getattr(p, 'participante_b_id', None) == ganador_pid:
                ganador_lado = 'B'

        # Parseo de sets para ambos lados
        SW_A = SL_A = GW_A = GL_A = 0
        SW_B = SL_B = GW_B = GL_B = 0

        if r and r.sets_text:
            # parse genérico desde perspectiva "texto", luego asignamos
            # Nota: parse_sets suma SW cuando el lado "texto" gana el set y SL cuando lo pierde.
            # Para que ambos lados queden consistentes, interpretamos sets desde A vs B:
            # p.ej "6-4" => A ganó 1 set y B perdió 1; A ganó 6 juegos, B 4.
            for tok in str(r.sets_text).strip().split():
                if '-' not in tok:
                    continue
                try:
                    a, b = tok.split('-', 1)
                    ga = int(a); gb = int(b)
                except Exception:
                    continue
                GW_A += ga; GL_A += gb
                GW_B += gb; GL_B += ga
                if ga > gb:
                    SW_A += 1; SL_B += 1
                elif gb > ga:
                    SW_B += 1; SL_A += 1
                # empates no cuentan sets (evitamos)

        # Sin sets_text: igual computamos PJ + G/P
        # Aseguramos existir en standings
        for jid in a_ids + b_ids:
            ensure(jid)

        # Sumar PJ
        for jid in a_ids:
            standings[jid]['PJ'] += 1
        for jid in b_ids:
            standings[jid]['PJ'] += 1

        # Sumar sets/juegos
        for jid in a_ids:
            standings[jid]['SW'] += SW_A
            standings[jid]['SL'] += SL_A
            standings[jid]['GW'] += GW_A
            standings[jid]['GL'] += GL_A
        for jid in b_ids:
            standings[jid]['SW'] += SW_B
            standings[jid]['SL'] += SL_B
            standings[jid]['GW'] += GW_B
            standings[jid]['GL'] += GL_B

        # Ganador / Perdedor + puntos
        if ganador_lado == 'A':
            for jid in a_ids:
                standings[jid]['G']  += 1
                standings[jid]['PTS'] += pts_v
            for jid in b_ids:
                standings[jid]['P']  += 1
                standings[jid]['PTS'] += pts_d
        elif ganador_lado == 'B':
            for jid in b_ids:
                standings[jid]['G']  += 1
                standings[jid]['PTS'] += pts_v
            for jid in a_ids:
                standings[jid]['P']  += 1
                standings[jid]['PTS'] += pts_d
        else:
            # sin ganador claro: no sumamos G/P ni puntos
            pass

    # Armar difs y mapa de jugadores
    jug_map = {}
    if all_ids:
        rows = (
            db.session.query(Jugador)
            .filter(Jugador.id.in_(list(all_ids)))
            .all()
        )
        jug_map = {j.id: j for j in rows}

    for jid, s in standings.items():
        s['SD'] = s['SW'] - s['SL']
        s['GD'] = s['GW'] - s['GL']

    # Ordenar: PTS desc, SD desc, GD desc, G desc, PJ asc, nombre
    def _name(j):
        if not j:
            return ''
        return (j.nombre_completo or j.display_name or j.nombre or f'Jugador #{j.id}').upper()

    sorted_rows = sorted(
        standings.items(),
        key=lambda kv: (
            -kv[1]['PTS'],
            -kv[1]['SD'],
            -kv[1]['GD'],
            -kv[1]['G'],
            kv[1]['PJ'],
            _name(jug_map.get(kv[0]))
        )
    )

    # Preparar filas para template
    tabla = []
    pos = 1
    for jid, s in sorted_rows:
        jrow = jug_map.get(jid)
        tabla.append(dict(
            pos=pos,
            jugador=jrow,
            **s
        ))
        pos += 1

    return render_template(
        'torneo_tabla.html',
        t=t,
        tabla=tabla
    )


def calcular_tabla_americano(torneo_id: int):
    """
    Calcula standings por grupo para formato AMERICANO.
    - Puntos: 2 por victoria, 0 por derrota.
    - Si hay resultado_json.sets=[[a,b], ...] (a=lado participante1, b=lado participante2),
      acumula 'sets_fav' / 'sets_contra' para desempates.
    - Soporta que no haya grupos: todo va a un grupo 'GENERAL' (clave 0).
    Retorna: {
      group_id: {
         'grupo': TorneoGrupo | None,
         'rows': [ {'participante': TorneoParticipante, 'pj':..,'pg':..,'pp':..,'pts':..,'sets_fav':..,'sets_contra':..,'diff_sets':..}, ...]
      }, ...
    }
    """
    # Traer todos los partidos del torneo (jugados o con ganador seteado)
    partidos = (db.session.query(TorneoPartido)
                .filter(TorneoPartido.torneo_id == torneo_id)
                .all())

    # Recolectar todos los participante_ids que aparezcan
    participante_ids = set()
    for m in partidos:
        p1 = getattr(m, 'participante1_id', None)
        p2 = getattr(m, 'participante2_id', None)
        if p1: participante_ids.add(p1)
        if p2: participante_ids.add(p2)

    # Mapa de participantes
    participantes_map = {}
    if participante_ids:
        participantes = (db.session.query(TorneoParticipante)
                         .filter(TorneoParticipante.id.in_(participante_ids))
                         .all())
        participantes_map = {p.id: p for p in participantes}

    # Mapa de grupos
    # Si el modelo no tiene grupos, usaremos group_id = 0
    grupos = (db.session.query(TorneoGrupo)
              .filter(TorneoGrupo.fase_id.in_(
                  db.session.query(TorneoFase.id).filter_by(torneo_id=torneo_id)
              ))
              .all())
    grupos_map = {g.id: g for g in grupos}

    # Estructura de acumulación
    tablas = {}  # group_id -> pid -> stats
    def ensure_row(gid, pid):
        if gid not in tablas:
            tablas[gid] = {}
        if pid not in tablas[gid]:
            tablas[gid][pid] = {
                'pj': 0, 'pg': 0, 'pp': 0, 'pts': 0,
                'sets_fav': 0, 'sets_contra': 0
            }

    # Recorremos partidos
    for m in partidos:
        p1 = getattr(m, 'participante1_id', None)
        p2 = getattr(m, 'participante2_id', None)
        if not (p1 and p2):
            continue

        # Determinar grupo (si el partido tiene grupo_id, usarlo; si no, 0)
        gid = getattr(m, 'grupo_id', None) or 0

        ganador = getattr(m, 'ganador_participante_id', None)
        estado = getattr(m, 'estado', None)

        # Consideramos “jugado” si estado == 'JUGADO' o si hay ganador seteado
        if estado != 'JUGADO' and not ganador:
            continue

        ensure_row(gid, p1)
        ensure_row(gid, p2)

        # PJ
        tablas[gid][p1]['pj'] += 1
        tablas[gid][p2]['pj'] += 1

        # PG/PP + puntos
        if ganador == p1:
            tablas[gid][p1]['pg'] += 1
            tablas[gid][p2]['pp'] += 1
            tablas[gid][p1]['pts'] += 2
        elif ganador == p2:
            tablas[gid][p2]['pg'] += 1
            tablas[gid][p1]['pp'] += 1
            tablas[gid][p2]['pts'] += 2
        else:
            # Si no hay ganador definido pero está JUGADO, podés asignar 1-1 o 0-0.
            # Para no inventar, dejamos 0 puntos extra (solo PJ).
            pass

        # Sets a favor/en contra (si vienen en resultado_json.sets)
        rj = getattr(m, 'resultado_json', None) or {}
        sets = rj.get('sets') if isinstance(rj, dict) else None
        # sets esperado como [[x,y], [x,y], ...] donde x=side participante1, y=side participante2
        if isinstance(sets, list):
            for parc in sets:
                if (isinstance(parc, (list, tuple)) and len(parc) == 2
                        and isinstance(parc[0], int) and isinstance(parc[1], int)):
                    s1, s2 = parc
                    tablas[gid][p1]['sets_fav'] += s1
                    tablas[gid][p1]['sets_contra'] += s2
                    tablas[gid][p2]['sets_fav'] += s2
                    tablas[gid][p2]['sets_contra'] += s1

    # Armar respuesta final por grupo
    resultado = {}
    for gid, filas in tablas.items():
        rows = []
        for pid, st in filas.items():
            st['diff_sets'] = st['sets_fav'] - st['sets_contra']
            rows.append({
                'participante': participantes_map.get(pid),
                **st
            })

        # Orden: Pts desc, diff_sets desc, PG desc, (opcional) sets_fav desc
        rows.sort(key=lambda r: (r['pts'], r['diff_sets'], r['pg'], r['sets_fav']), reverse=True)

        resultado[gid] = {
            'grupo': grupos_map.get(gid) if gid != 0 else None,
            'rows': rows
        }

    # Si no hubo grupos ni partidos, devolvemos estructura vacía 'GENERAL'
    if not resultado:
        resultado[0] = {'grupo': None, 'rows': []}

    return resultado

# ========= GENERADOR AMERICANO =========

from itertools import combinations
from math import ceil

def _get_or_create_fase_unica(torneo: 'Torneo') -> 'TorneoFase':
    """
    Devuelve la fase única del torneo (creándola si no existe).
    Normaliza 'tipo' si la columna existe.
    """
    fase = (db.session.query(TorneoFase)
            .filter_by(torneo_id=torneo.id, nombre='FASE ÚNICA')
            .first())
    if fase:
        # Normaliza tipo si la columna existe y está vacía
        if 'tipo' in TorneoFase.__table__.c and (getattr(fase, 'tipo', None) in (None, '')):
            fase.tipo = 'AMERICANO'   # todos contra todos / liga
            db.session.flush()
        # Normaliza orden si querés mantenerlo fijo
        if getattr(fase, 'orden', None) in (None, 0):
            try:
                fase.orden = 1
                db.session.flush()
            except Exception:
                pass
        return fase

    # Crear con campos canónicos
    kwargs = dict(torneo_id=torneo.id, nombre='FASE ÚNICA', orden=1)
    if 'tipo' in TorneoFase.__table__.c:
        kwargs['tipo'] = 'AMERICANO'
    fase = TorneoFase(**kwargs)
    db.session.add(fase)
    db.session.flush()
    return fase


def _get_or_create_fase_playoff(torneo: 'Torneo') -> 'TorneoFase':
    """
    Devuelve la fase de playoff del torneo (creándola si no existe).
    Normaliza 'tipo' si la columna existe.
    """
    fase = (db.session.query(TorneoFase)
            .filter_by(torneo_id=torneo.id, nombre='PLAYOFF')
            .first())
    if fase:
        if 'tipo' in TorneoFase.__table__.c and (getattr(fase, 'tipo', None) in (None, '')):
            fase.tipo = 'PLAYOFF'
            db.session.flush()
        if getattr(fase, 'orden', None) in (None, 0):
            try:
                fase.orden = 99
                db.session.flush()
            except Exception:
                pass
        return fase

    kwargs = dict(torneo_id=torneo.id, nombre='PLAYOFF', orden=99)
    if 'tipo' in TorneoFase.__table__.c:
        kwargs['tipo'] = 'PLAYOFF'
    fase = TorneoFase(**kwargs)
    db.session.add(fase)
    db.session.flush()
    return fase


def _get_or_create_grupo(torneo: 'Torneo', fase: 'TorneoFase', nombre: str, orden: int) -> 'TorneoGrupo':
    g = (
        db.session.query(TorneoGrupo)
        .filter_by(fase_id=fase.id, nombre=nombre)
        .first()
    )
    if not g:
        g = TorneoGrupo(fase_id=fase.id, nombre=nombre, orden=orden)
        db.session.add(g)
        db.session.flush()
    return g



def _tp_cols():
    """
    Descubre nombres de columnas en TorneoPartido y devuelve un mapping canónico:
    - p1/p2 → participantes (acepta participante_a_id / participante_b_id o variantes 1/2)
    - ganador, estado, ronda, grupo, torneo
    """
    cols = set(TorneoPartido.__table__.c.keys())

    def pick(*cands):
        for c in cands:
            if c in cols:
                return c
        return None

    return {
        'torneo': pick('torneo_id'),
        'fase':   pick('fase_id'),
        'grupo':  pick('grupo_id'),
        'p1':     pick('participante_a_id', 'participante1_id', 'p1_id', 'inscripcion1_id', 'jugador1_id'),
        'p2':     pick('participante_b_id', 'participante2_id', 'p2_id', 'inscripcion2_id', 'jugador2_id'),
        'ganador':pick('ganador_participante_id', 'ganador_id'),
        'estado': pick('estado', 'status'),
        'ronda':  pick('ronda', 'jornada'),
        'orden':  pick('orden'),
    }


def _inscripcion_to_participante(torneo: 'Torneo', insc) -> 'TorneoParticipante':
    # Permitir id o objeto
    if isinstance(insc, int):
        insc_obj = TorneoInscripcion.query.get(insc)
        if not insc_obj:
            raise RuntimeError(f"Inscripción id={insc} inexistente.")
        insc = insc_obj

    if not isinstance(insc, TorneoInscripcion):
        raise RuntimeError(f"Objeto insc inválido: {type(insc)}. Se espera TorneoInscripcion.")

    # Asegurar que la inscripción tenga ID materializado
    if not getattr(insc, "id", None):
        db.session.flush()
    if not getattr(insc, "id", None):
        raise RuntimeError(
            f"Inscripción sin ID (torneo_id={getattr(insc,'torneo_id',None)}, "
            f"jug1={getattr(insc,'jugador1_id',None)}, jug2={getattr(insc,'jugador2_id',None)})."
        )

    if insc.torneo_id != torneo.id:
        raise RuntimeError(
            f"La inscripción {insc.id} pertenece a torneo {insc.torneo_id}, no al torneo {torneo.id}."
        )

    # Reusar si ya existe (mismo torneo + misma inscripción)
    existente = (db.session.query(TorneoParticipante)
                 .filter_by(torneo_id=torneo.id, inscripcion_id=insc.id)
                 .one_or_none())
    if existente:
        return existente

    # Crear participante SIEMPRE seteando inscripcion_id
    p = TorneoParticipante(
        torneo_id=torneo.id,
        inscripcion_id=insc.id,
    )
    db.session.add(p)
    db.session.flush()  # garantiza p.id
    return p




def _repartir_en_zonas(lista, cant_zonas):
    """Devuelve una lista de listas: zonas balanceadas (1..cant_zonas)."""
    if cant_zonas <= 1:
        return [list(lista)]
    zonas = [[] for _ in range(cant_zonas)]
    # snake draft simple
    idx = 0
    forward = True
    for x in lista:
        zonas[idx].append(x)
        if forward:
            idx += 1
            if idx == cant_zonas:
                forward = False
                idx = cant_zonas - 1
        else:
            idx -= 1
            if idx < 0:
                forward = True
                idx = 0
    return zonas

def _round_robin_pairs(ids):
    """
    Método del círculo.
    Retorna rounds = [[(a,b), (c,d), ...], ...]
    Maneja impar agregando 'BYE' (no genera partido cuando hay BYE).
    """
    ids = list(ids)
    bye = None
    if len(ids) % 2 == 1:
        bye = '_BYE_'
        ids.append(bye)
    n = len(ids)
    half = n // 2
    rounds = []
    arr = ids[:]
    for r in range(n - 1):
        pares = []
        for i in range(half):
            a = arr[i]
            b = arr[-(i+1)]
            if a != bye and b != bye:
                pares.append((a, b))
        # rotación
        arr = [arr[0]] + [arr[-1]] + arr[1:-1]
        rounds.append(pares)
    return rounds


def _crear_partido_rr(t: 'Torneo', grupo: 'TorneoGrupo', a: int, b: int, jornada: int, orden: int | None = None):
    """
    Crea un partido (round-robin) para el esquema fijo:
      torneo_id, grupo_id, participante_a_id, participante_b_id, ronda, estado, orden, fase_id
    Evita duplicados aunque los participantes vengan invertidos (A-B o B-A).
    """

    T = TorneoPartido

    # 1) Evitar duplicados A-B o B-A dentro del mismo torneo y (si aplica) grupo
    filtros_base = [T.torneo_id == t.id]
    if hasattr(T, 'grupo_id'):
        filtros_base.append(T.grupo_id == (grupo.id if grupo else None))

    ya = (db.session.query(T)
          .filter(
              and_(*filtros_base),
              or_(
                  and_(T.participante_a_id == a, T.participante_b_id == b),
                  and_(T.participante_a_id == b, T.participante_b_id == a),
              )
          )
          .first())
    if ya:
        return ya

    # 2) Crear el partido con el esquema conocido
    m = T(
        torneo_id=t.id,
        grupo_id=(grupo.id if grupo else None),
        participante_a_id=a,
        participante_b_id=b,
        estado='PENDIENTE',
        ronda=jornada,
    )

    # 3) Campos opcionales si existen/querés setear
    if hasattr(T, 'orden') and (orden is not None):
        m.orden = orden
    if hasattr(T, 'fase_id') and getattr(grupo, 'fase_id', None):
        m.fase_id = grupo.fase_id

    db.session.add(m)
    return m

def _has_col(model, name: str) -> bool:
    return name in model.__table__.c

def _kwargs_ronda_o_jornada(model, valor):
    """Devuelve kwargs con 'jornada' o 'ronda' según exista en el modelo."""
    if _has_col(model, 'jornada'):
        return {'jornada': valor}
    if _has_col(model, 'ronda'):
        return {'ronda': valor}
    raise RuntimeError("TorneoPartido no tiene ni 'jornada' ni 'ronda'.")


# ========= GENERADOR PLAYOFF (ELIMINACIÓN DIRECTA) =========

from math import log2, ceil


def _safe_upper(s):
    if not s: return None
    return s.strip().upper()

def _safe_title(s):
    if not s: return None
    return " ".join(w.capitalize() for w in s.strip().split())

def _parse_date_yyyy_mm_dd(s):
    if not s: return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None

def _merge_phone(cc, local):
    cc = "".join([c for c in (cc or "") if c.isdigit()])
    local = "".join([c for c in (local or "") if c.isdigit()])
    if not cc and not local:
        return None
    return f"+{cc}{local}"



def _get_or_create_grupo_llaves(torneo: 'Torneo', fase: 'TorneoFase') -> 'TorneoGrupo':
    g = (db.session.query(TorneoGrupo)
         .filter_by(fase_id=fase.id, nombre='LLAVES')
         .first())
    if not g:
        g = TorneoGrupo(torneo_id=torneo.id, fase_id=fase.id, nombre='LLAVES', orden=1)
        db.session.add(g)
        db.session.flush()
    return g

def _listar_participantes_desde_inscripciones(t: 'Torneo') -> list['TorneoParticipante']:
    insc = (db.session.query(TorneoInscripcion)
            .filter_by(torneo_id=t.id, estado='ACTIVA')
            .order_by(
                TorneoInscripcion.seed.asc().nulls_last(),
                (TorneoInscripcion.created_at.asc()
                 if hasattr(TorneoInscripcion, 'created_at')
                 else TorneoInscripcion.id.asc())
            )
            .all())
    if not insc:
        raise ValueError("No hay inscripciones activas para generar playoff.")

    participantes: list[TorneoParticipante] = []
    for i in insc:
        p = (db.session.query(TorneoParticipante)
             .filter_by(torneo_id=t.id, inscripcion_id=i.id)
             .one_or_none())
        if not p:
            p = TorneoParticipante(
                torneo_id=t.id,
                inscripcion_id=i.id,          # << CLAVE: nunca NULL
            )
            db.session.add(p)
            db.session.flush()
        participantes.append(p)

    participantes.sort(
        key=lambda x: (getattr(x, 'seed', None) is None,
                       getattr(x, 'seed', 10**9),
                       x.id)
    )
    return participantes




def _next_power_of_two(n: int) -> int:
    if n <= 1:
        return 1
    return 1 << ceil(log2(n))

def _primer_round_ya_generado(t: 'Torneo', grupo: 'TorneoGrupo') -> bool:
    q = (db.session.query(TorneoPartido)
         .filter_by(torneo_id=t.id, grupo_id=grupo.id))
    # si hay partidos con ronda==1 (si ese campo existe) o cualquiera en LLAVES, asumimos R1 ya creado
    if q.count() > 0:
        # Si el modelo tiene 'ronda', validar explícitamente
        if hasattr(TorneoPartido, 'ronda'):
            return q.filter(TorneoPartido.ronda == 1).count() > 0
        return True
    return False

def generar_playoff_directo(torneo_id: int) -> int:
    """
    Genera la 1ª ronda de eliminación directa, crea BYEs como partidos ganados automáticamente.
    Retorna la cantidad de partidos creados (incluye BYEs autoganados).
    """
    t = get_or_404(Torneo, torneo_id)

    # Participantes
    participantes = _listar_participantes_desde_inscripciones(t)
    n = len(participantes)
    if n < 2:
        raise ValueError("Se necesitan al menos 2 participantes para playoff.")

    # Fase/Grupo
    fase = _get_or_create_fase_playoff(t)
    grupo = _get_or_create_grupo_llaves(t, fase)

    # Evitar duplicados
    if _primer_round_ya_generado(t, grupo):
        return 0  # ya estaba armado

    # Calcular tamaño de llave y BYEs
    M = _next_power_of_two(n)      # 2,4,8,16,...
    byes = M - n                   # cuántos avanzan directo

    # Emparejar por seed: 1 vs n, 2 vs (n-1), ...
    # Y asignar BYEs a los mejores seeds (avanzan sin jugar).
    partidos_creados = 0
    left = 0
    right = n - 1
    ronda_num = 1

    # Primero, marcar BYEs (top seeds avanzan solos)
    # Por convención simple, damos BYE a las primeras 'byes' seeds.
    auto_winners_ids = set()
    for idx in range(byes):
        ganador = participantes[idx]
        # Crear partido de BYE para dejar registro (y para visualización)
        m = TorneoPartido(
            torneo_id=t.id,
            grupo_id=grupo.id,
            participante1_id=ganador.id,
            participante2_id=None,
            estado='JUGADO',
            ganador_participante_id=ganador.id,
            resultado_json={'walkover': 'BYE'}
        )
        if hasattr(m, 'ronda'):
            m.ronda = ronda_num
        db.session.add(m)
        partidos_creados += 1
        auto_winners_ids.add(ganador.id)

    # Ahora, emparejar el resto (sin BYE)
    # Participantes disponibles para jugar R1 (excluyendo quienes ya avanzaron por BYE)
    vivos = [p for p in participantes if p.id not in auto_winners_ids]
    i, j = 0, len(vivos) - 1
    while i < j:
        a = vivos[i]
        b = vivos[j]
        m = TorneoPartido(
            torneo_id=t.id,
            grupo_id=grupo.id,
            participante1_id=a.id,   # seed más alto como "local"
            participante2_id=b.id,
            estado='PENDIENTE'
        )
        if hasattr(m, 'ronda'):
            m.ronda = ronda_num
        db.session.add(m)
        partidos_creados += 1
        i += 1
        j -= 1

    db.session.commit()
    return partidos_creados

def _get_or_create_fase_unica(torneo: 'Torneo') -> 'TorneoFase':
    # Buscamos por nombre dentro del torneo (reutiliza si ya existe)
    fase = (db.session.query(TorneoFase)
            .filter_by(torneo_id=torneo.id, nombre='FASE ÚNICA')
            .first())
    if fase:
        # Si el modelo tiene 'tipo' y está NULL, lo normalizamos
        if hasattr(fase, 'tipo') and (getattr(fase, 'tipo', None) in (None, '')):
            fase.tipo = 'AMERICANO'  # fase de todos contra todos
            db.session.flush()
        return fase

    # Crear con tipo obligatorio
    kwargs = dict(torneo_id=torneo.id, nombre='FASE ÚNICA', orden=1)
    if 'tipo' in TorneoFase.__table__.c:  # por si en otro entorno no existe la columna
        kwargs['tipo'] = 'AMERICANO'
    fase = TorneoFase(**kwargs)
    db.session.add(fase)
    db.session.flush()
    return fase


def _get_or_create_fase_playoff(torneo: 'Torneo') -> 'TorneoFase':
    fase = (db.session.query(TorneoFase)
            .filter_by(torneo_id=torneo.id, nombre='PLAYOFF')
            .first())
    if fase:
        if hasattr(fase, 'tipo') and (getattr(fase, 'tipo', None) in (None, '')):
            fase.tipo = 'PLAYOFF'
            db.session.flush()
        return fase

    kwargs = dict(torneo_id=torneo.id, nombre='PLAYOFF', orden=99)
    if 'tipo' in TorneoFase.__table__.c:
        kwargs['tipo'] = 'PLAYOFF'
    fase = TorneoFase(**kwargs)
    db.session.add(fase)
    db.session.flush()
    return fase


# ========= SIGUIENTE RONDA PLAYOFF =========

def _obtener_ultima_ronda(t: 'Torneo', grupo: 'TorneoGrupo') -> int:
    q = (db.session.query(TorneoPartido)
         .filter_by(torneo_id=t.id, grupo_id=grupo.id))
    # Si el modelo tiene columna 'ronda', usarla
    if hasattr(TorneoPartido, 'ronda'):
        val = q.with_entities(sa.func.max(TorneoPartido.ronda)).scalar()
        return int(val or 0)
    # Sin 'ronda': si no hay partidos -> 0; si hay, asumimos la “última capa”
    # la calculamos agrupando por bloques de emparejamiento de tamaño creciente
    # Para MVP: consideramos que cada “llamada” crea una ronda nueva; así, si hay partidos, la última es >=1
    return 1 if q.count() > 0 else 0

def _partidos_de_ronda(t: 'Torneo', grupo: 'TorneoGrupo', ronda: str) -> list['TorneoPartido']:
    base = (db.session.query(TorneoPartido)
            .filter_by(torneo_id=t.id, grupo_id=grupo.id))
    if hasattr(TorneoPartido, 'ronda'):
        base = base.filter(TorneoPartido.ronda == str(ronda))
    base = base.order_by(TorneoPartido.id.asc())
    return base.all()


def generar_playoff_siguiente_ronda(torneo_id: int) -> int:
    t = get_or_404(Torneo, torneo_id)
    fase = _get_or_create_fase_playoff(t)
    grupo = _get_or_create_grupo_llaves(t, fase)

    # última ronda como string numérica
    ult = _obtener_ultima_ronda(t, grupo)
    if ult == 0:
        raise ValueError("No existe una ronda previa. Primero generá la 1ª ronda del playoff.")

    partidos_prev = _partidos_de_ronda(t, grupo, str(ult))
    if not partidos_prev:
        raise ValueError("No se encontraron partidos en la ronda previa.")
    if any(m.ganador_participante_id is None for m in partidos_prev):
        raise ValueError("Aún hay partidos sin ganador en la ronda anterior.")

    ganadores_ids = [m.ganador_participante_id for m in partidos_prev]
    ganadores = (db.session.query(TorneoParticipante)
                 .filter(TorneoParticipante.id.in_(ganadores_ids))
                 .all())
    mapa = {p.id: p for p in ganadores}
    ganadores = [mapa[g] for g in ganadores_ids if g in mapa]

    if len(ganadores) <= 1:
        return 0

    nueva = str(int(ult) + 1)
    creados = 0

    impar = (len(ganadores) % 2 == 1)
    limite = len(ganadores) - 1 if impar else len(ganadores)

    i = 0
    while i < limite:
        a = ganadores[i]
        b = ganadores[i + 1]
        m = TorneoPartido(
            torneo_id=t.id,
            grupo_id=grupo.id,
            participante_a_id=a.id,
            participante_b_id=b.id,
            estado='PENDIENTE',
            ronda=nueva
        )
        db.session.add(m)
        creados += 1
        i += 2

    if impar:
        bye_winner = ganadores[-1]
        m = TorneoPartido(
            torneo_id=t.id,
            grupo_id=grupo.id,
            participante_a_id=bye_winner.id,
            participante_b_id=bye_winner.id,  # ver nota arriba
            estado='JUGADO',
            ganador_participante_id=bye_winner.id,
            resultado_json={'walkover': 'BYE'},
            ronda=nueva
        )
        db.session.add(m)
        creados += 1

    db.session.commit()
    return creados


def normalizar_sets_text(raw: str | None) -> str | None:
    """
    Deja el texto de sets en formato limpio: "6-3, 4-6, 10-8".
    Acepta cosas como "6-3,4-6 , 10 -8".
    """
    if not raw:
        return None
    # reemplaza separadores varios por coma
    s = re.sub(r'[;|]+', ',', raw)
    # compacta espacios
    s = re.sub(r'\s+', '', s)
    # asegura formato N-N con comas y luego inserta espacio post coma
    s = s.replace('-', '-')
    s = ', '.join([p for p in s.split(',') if p])
    return s

def _recalcular_puntos_partido(partido: 'Partido') -> None:
    """
    Intenta recalcular puntos/elo tras cerrar o reabrir un partido.
    - Si existe una función app-level (recalcular_puntos_partido(partido_id) o
      recalcular_elo_para_partido(partido_id)), la llama.
    - Si no existe, loguea y no rompe.
    """
    try:
        fn = (globals().get('recalcular_puntos_partido')
              or globals().get('recalcular_elo_para_partido'))
        if callable(fn):
            fn(partido.id)
        else:
            current_app.logger.info("No hay función de recálculo definida; omito.")
    except Exception as e:
        current_app.logger.exception("Fallo recálculo de puntos para partido_id=%s: %s",
                                     getattr(partido, 'id', None), e)


def lado_de_jugador_en_partido(tp: 'TorneoPartido', jugador_id: int) -> str | None:
    """
    Devuelve 'A', 'B' o None según pertenencia del jugador al lado A/B del TorneoPartido.

    Robusta a distintos esquemas de modelo:
    - Si existe tp._extraer_ids_de_participante, lo usa (compatibilidad).
    - Si hay inscripcion_id en el participante, consulta TorneoInscripcion y toma
      jugador1_id/jugador2_id/jugador_id.
    - Si no, intenta campos directos en el participante.
    - Soporta nombres participante_a/participante_b y participante1/participante2,
      y también *_id si las relaciones no están cargadas.
    """
    try:
        jugador_id = int(jugador_id) if jugador_id is not None else None
    except Exception:
        return None
    if not jugador_id:
        return None

    TorneoInscripcion   = globals().get('TorneoInscripcion')
    TorneoParticipante  = globals().get('TorneoParticipante')

    # --- 1) Compat: usar helper si existe y funciona ---
    extraer = getattr(tp, '_extraer_ids_de_participante', None)
    if callable(extraer):
        try:
            idsA = set(extraer(getattr(tp, 'participante_a', None)))
            idsB = set(extraer(getattr(tp, 'participante_b', None)))
            if jugador_id in idsA:
                return 'A'
            if jugador_id in idsB:
                return 'B'
        except Exception:
            # si falla, seguimos con el camino robusto
            pass

    # --- helpers internos robustos ---
    def _to_int_or_none(x):
        try:
            return int(x) if x is not None else None
        except Exception:
            return None

    def _cargar_participante_por_id(pid):
        if pid and TorneoParticipante is not None:
            try:
                return db.session.get(TorneoParticipante, int(pid))
            except Exception:
                return None
        return None

    def _ids_desde_inscripcion(inscripcion_id) -> set[int]:
        ids = set()
        if not inscripcion_id or TorneoInscripcion is None:
            return ids
        try:
            insc = db.session.get(TorneoInscripcion, int(inscripcion_id))
        except Exception:
            insc = None
        if not insc:
            return ids
        for attr in ('jugador1_id', 'jugador2_id', 'jugador_id'):
            v = _to_int_or_none(getattr(insc, attr, None))
            if v:
                ids.add(v)
        return ids

    def _ids_directos_en_participante(p) -> set[int]:
        ids = set()
        if not p:
            return ids
        # Campos directos comunes
        for attr in ('jugador1_id', 'jugador2_id', 'jugador_id'):
            v = _to_int_or_none(getattr(p, attr, None))
            if v:
                ids.add(v)
        # Por si el participante tiene relación 'jugadores' iterable
        try:
            js = getattr(p, 'jugadores', None)
            if js:
                for j in js:
                    v = _to_int_or_none(getattr(j, 'id', None))
                    if v:
                        ids.add(v)
        except Exception:
            pass
        return ids

    def _colectar_ids_de_lado(side_obj, side_id_attr_candidates: tuple[str, ...]) -> set[int]:
        """
        Devuelve el set de jugador_ids que conforman ese lado del partido.
        Intenta en este orden:
        1) participante (objeto) -> inscripcion_id -> TorneoInscripcion
        2) participante (objeto) -> campos directos
        3) participante_id numérico -> cargar participante -> pasos 1/2
        """
        ids = set()

        # 1) Objeto participante si está disponible
        p = side_obj
        if not p:
            # 2) Intentar por *_id en el propio partido si no hay relación cargada
            pid = None
            for attr in side_id_attr_candidates:
                pid = _to_int_or_none(getattr(tp, attr, None))
                if pid:
                    break
            if pid:
                p = _cargar_participante_por_id(pid)

        if not p:
            return ids

        # Preferir inscripcion_id si existe
        insc_id = _to_int_or_none(getattr(p, 'inscripcion_id', None))
        if insc_id:
            ids |= _ids_desde_inscripcion(insc_id)

        # Luego, campos directos en el participante
        ids |= _ids_directos_en_participante(p)
        return ids

    # Intentar nombres habituales
    participante_a = getattr(tp, 'participante_a', None) or getattr(tp, 'participante1', None)
    participante_b = getattr(tp, 'participante_b', None) or getattr(tp, 'participante2', None)

    idsA = _colectar_ids_de_lado(
        participante_a,
        side_id_attr_candidates=('participante_a_id', 'participante1_id', 'p1_id')
    )
    idsB = _colectar_ids_de_lado(
        participante_b,
        side_id_attr_candidates=('participante_b_id', 'participante2_id', 'p2_id')
    )

    if jugador_id in idsA:
        return 'A'
    if jugador_id in idsB:
        return 'B'
    return None

def _jugadores_del_lado_torneo(p: 'TorneoPartido', lado: str) -> list[int]:
    """
    Devuelve los IDs de jugador del lado 'A' o 'B' para un TorneoPartido.
    Prioriza la tabla torneos_partidos_lados (insc1/insc2 -> inscripciones -> jugador1/jugador2).
    Si no hay filas en LADOS, cae al participante_a / participante_b.
    """
    lado = (lado or '').upper()
    if lado not in ('A', 'B'):
        return []

    # 1) Intento por tabla de lados
    try:
        Ins = globals().get('TorneoInscripcion')
        if Ins:
            for l in getattr(p, 'lados', []) or []:
                if getattr(l, 'lado', '').upper() != lado:
                    continue
                out = []
                for insc_id in (getattr(l, 'insc1_id', None), getattr(l, 'insc2_id', None)):
                    if not insc_id:
                        continue
                    insc = db.session.get(Ins, insc_id)
                    if not insc:
                        continue
                    for jid in (getattr(insc, 'jugador1_id', None), getattr(insc, 'jugador2_id', None)):
                        if jid:
                            out.append(int(jid))
                if out:
                    return out
    except Exception:
        pass

    # 2) Fallback a participante_a / participante_b
    tp = p.participante_a if lado == 'A' else p.participante_b
    try:
        return p._extraer_ids_de_participante(tp)  # usamos el helper robusto del modelo
    except Exception:
        return []

def _aplicar_ranking_por_torneo(p: 'TorneoPartido', ganador_lado: str):
    """
    Aplica el mismo esquema de puntos que en los partidos 'normales':
    - Ganadores:  DELTA_WIN
    - Perdedores: DELTA_LOSS
    - (Opcional) Bonus de victoria con compañero repetido desde la 3ra (DELTA_WIN_BONUS)
      Solo se intenta si podemos detectar exactamente la dupla en ambos lados.
    """
    ganador_lado = (ganador_lado or '').upper()
    if ganador_lado not in ('A', 'B'):
        return

    perdedor_lado = 'B' if ganador_lado == 'A' else 'A'

    win_ids = _jugadores_del_lado_torneo(p, ganador_lado)
    lose_ids = _jugadores_del_lado_torneo(p, perdedor_lado)

    if not win_ids and not lose_ids:
        return  # nada que hacer

    Jug = globals().get('Jugador')
    if not Jug:
        return

    # Helper esperado ya existente en tu app:
    # aplicar_delta_rankeable(jugador, delta) -> ajusta puntos y "clampa" dentro del rango,
    # permitiendo salir del rango inferior SOLO por la lógica de desafíos.

    # 1) aplicar win/loss usando la misma lógica que en "partidos normales"
    for jid in win_ids:
        j = db.session.get(Jug, int(jid))
        if j:
            aplicar_delta_rankeable(j, DELTA_WIN)

    for jid in lose_ids:
        j = db.session.get(Jug, int(jid))
        if j:
            aplicar_delta_rankeable(j, DELTA_LOSS)

    # 2) (opcional) bonus por compañero repetido desde la 3ra victoria conjunta
    #    Solo si el lado ganador es dupla (2 jugadores).
    try:
        if DELTA_WIN_BONUS and BONUS_APLICA_DESDE and len(win_ids) == 2:
            a, b = sorted(win_ids)
            # Contar cuántas veces esta dupla ganó junta en torneos (según LADOS)
            # Nota: Contamos SOLO en torneos para evitar consultas complejas multi-tabla.
            sql = """
            SELECT COUNT(1)
            FROM torneos_partidos_resultados r
            JOIN torneos_partidos tp ON tp.id = r.partido_id
            JOIN torneos_partidos_lados la ON la.partido_id = tp.id AND la.lado = r.ganador_lado
            JOIN torneos_inscripciones i1 ON i1.id = la.insc1_id
            JOIN torneos_inscripciones i2 ON i2.id = la.insc2_id
            WHERE (
                (i1.jugador1_id IN (?, ?) OR i1.jugador2_id IN (?, ?))
                AND
                (i2.jugador1_id IN (?, ?) OR i2.jugador2_id IN (?, ?))
            )
            """
            # el criterio "IN (?,?)" es un mejor-esfuerzo; asume que la dupla a-b está distribuida en i1/i2
            count_prev = db.session.execute(
                db.text(sql),
                {
                    'param_1': a, 'param_2': b, 'param_3': a, 'param_4': b,
                    'param_5': a, 'param_6': b, 'param_7': a, 'param_8': b
                }
            ).scalar_one_or_none()
            count_prev = int(count_prev or 0)

            # si esta es la N-ésima victoria (>= BONUS_APLICA_DESDE) entonces aplicar bonus
            if count_prev + 1 >= int(BONUS_APLICA_DESDE):
                for jid in win_ids:
                    j = db.session.get(Jug, int(jid))
                    if j:
                        aplicar_delta_rankeable(j, DELTA_WIN_BONUS)
    except Exception:
        # Si algo falla en el bonus, no frenamos el flujo principal
        pass

# ——— util: lado opuesto ———
def _lado_opuesto(lado):
    return "B" if str(lado).upper() == "A" else "A"

# ——— util: lista de jugadores por lado de un partido ———
def _jugadores_del_lado(p, lado):
    # Adaptarse a tu modelo: TorneoParticipante puede ser single o pareja.
    # Intentamos cubrir ambos casos de forma defensiva.
    participante = p.participante_a if str(lado).upper() == "A" else p.participante_b
    js = []
    if not participante:
        return js
    # Casos frecuentes de modelos:
    for attr in ("jugador1", "jugador2", "jugador"):  # soporta single o pareja
        j = getattr(participante, attr, None)
        if j:
            js.append(j)
    # Si tu modelo expone un iterable:
    if hasattr(participante, "jugadores") and callable(getattr(participante, "jugadores")):
        try:
            for j in participante.jugadores():
                if j and j not in js:
                    js.append(j)
        except Exception:
            pass
    return [j for j in js if j is not None]

# ——— util: ¿hubo bono en ESTE partido? (según victorias previas del lado ganador) ———
def _bonus_aplicado_en_partido(p, ganador_lado, resultado):
    """
    Recalcula si este partido gatilló bono, computando las VICTORIAS PREVIAS
    del mismo PARTICIPANTE ganador dentro del mismo torneo, ANTES de este resultado.
    Asume la misma regla que usás al aplicar:
      bono si (victorias_previas + 1) >= BONUS_APLICA_DESDE
    """
    from sqlalchemy import and_, or_
    # Identificar participante ganador (A o B) en este partido
    if str(ganador_lado).upper() == "A":
        ganador_part_id = p.participante_a_id
        filtro_lado = (TorneoPartidoResultado.ganador_lado == "A",
                       TorneoPartido.participante_a_id == ganador_part_id)
    else:
        ganador_part_id = p.participante_b_id
        filtro_lado = (TorneoPartidoResultado.ganador_lado == "B",
                       TorneoPartido.participante_b_id == ganador_part_id)

    # Contar victorias previas de este participante en el torneo, antes de este "resultado"
    # Usamos el id del resultado como proxy temporal (asumiendo autoincremental).
    vict_previas = (
        db.session.query(TorneoPartidoResultado)
        .join(TorneoPartido, TorneoPartidoResultado.partido_id == TorneoPartido.id)
        .filter(
            TorneoPartido.torneo_id == p.torneo_id,
            filtro_lado[0],  # ganador_lado coincide
            filtro_lado[1],  # es el mismo participante en ese lado
            TorneoPartidoResultado.id < resultado.id
        )
        .count()
    )

    try:
        aplica = (vict_previas + 1) >= BONUS_APLICA_DESDE
    except NameError:
        # Si no está importada la constante acá, traela de donde la definas
        from app import BONUS_APLICA_DESDE  # o el módulo correcto
        aplica = (vict_previas + 1) >= BONUS_APLICA_DESDE

    return aplica

def _revertir_ranking_por_torneo(p, ganador_lado, resultado):
    """
    Revierte EXACTAMENTE los deltas aplicados cuando se cerró este partido:
      - ganadores: -(DELTA_WIN) y, si correspondió, -(DELTA_WIN_BONUS)
      - perdedores: -(DELTA_LOSS)
    Debe llamarse ANTES de borrar el TorneoPartidoResultado.
    """
    # Traer constantes (si no están en este scope)
    try:
        _ = DELTA_WIN
    except NameError:
        from app import DELTA_WIN, DELTA_LOSS, DELTA_WIN_BONUS

    # Determinar ganadores y perdedores
    lado_gan = str(ganador_lado).upper()
    lado_perd = _lado_opuesto(lado_gan)
    ganadores  = _jugadores_del_lado(p, lado_gan)
    perdedores = _jugadores_del_lado(p, lado_perd)

    # ¿Este partido gatilló bono?
    hubo_bono = _bonus_aplicado_en_partido(p, lado_gan, resultado)

    # Motivos y metadatos (para auditoría/bitácora)
    motivo_base = f"Reversión resultado torneo (Partido #{p.id})"
    meta = {
        "torneo_id": p.torneo_id,
        "partido_id": p.id,
        "accion": "revertir",
        "resultado_id": resultado.id if resultado else None,
    }

    # Revertir ganadores
    for j in ganadores:
        aplicar_delta_rankeable(j, -DELTA_WIN, f"{motivo_base}: ganadores (-WIN)", meta)
        if hubo_bono:
            aplicar_delta_rankeable(j, -DELTA_WIN_BONUS, f"{motivo_base}: bono (-WIN_BONUS)", meta)

    # Revertir perdedores
    for j in perdedores:
        aplicar_delta_rankeable(j, -DELTA_LOSS, f"{motivo_base}: perdedores (-LOSS)", meta)




@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    # Mensaje amable y sin filtrar razones internas
    flash('Sesión expirada o formulario inválido. Volvé a intentar.', 'error')
    # Volver a la página anterior o al home
    return redirect(request.referrer or url_for('home')), 400

@app.context_processor
def inject_csrf_token():
    # csrf_token() usable en cualquier template
    return dict(csrf_token=lambda: generate_csrf())


@app.route('/healthz')
def healthz():
    return "ok", 200




if __name__ == '__main__':
    app.run(debug=True)
