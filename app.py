import os
import logging
import smtplib, ssl
import secrets
import string
import re  # ← agregado para EMAIL_RE

from email.message import EmailMessage
from datetime import datetime, timedelta, timezone

from functools import wraps
from zoneinfo import ZoneInfo

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort, jsonify, current_app  # ← agregado current_app para logs
)

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError



BASE_DIR = os.path.abspath(os.path.dirname(__file__))

AUTOCRON_TOKEN = os.environ.get("AUTOCRON_TOKEN", "cambia-esto")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


app = Flask(__name__)

# SECRET_KEY desde entorno; fallback para desarrollo local
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-cambiala-mas-tarde')

# DB: usa DATABASE_URL si existe (Postgres en el futuro), si no SQLite local
DB_URL = os.getenv('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'torneo.db'))
if DB_URL.startswith('postgres://'):
    DB_URL = DB_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def send_mail(
    subject: str,
    body: str | None,
    to: list[str],
    html_body: str | None = None,
    from_email: str | None = None,
    inline_logo_path: str | None = None,   # ← NUEVO (opcional)
    inline_logo_cid: str = "uplaylogo",    # ← NUEVO (opcional)
) -> bool:
    # logger seguro dentro/fuera de app context
    try:
        logger = current_app.logger
    except Exception:
        logger = logging.getLogger(__name__)

    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    pwd  = os.getenv("SMTP_PASS", "")
    use_tls = os.getenv("SMTP_TLS", "1") == "1"   # STARTTLS (587)
    use_ssl = os.getenv("SMTP_SSL", "0") == "1"   # SSL puro (465)

    sender = from_email or os.getenv("SMTP_FROM") or (user or "")
    to_clean = [t.strip() for t in (to or []) if t and t.strip()]

    # Validaciones mínimas
    if not host or not port or not sender or not to_clean:
        logger.warning(
            "SMTP: faltan variables o destinatarios. host=%s port=%s sender=%s to=%s",
            host, port, sender, to_clean
        )
        return False

    # Construcción del mensaje
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(to_clean)

    # Contenido: siempre algo en texto; si hay HTML, se adjunta como alternativa
    texto_plano = body or " "
    msg.set_content(texto_plano)

    html_part = None
    if html_body:
        msg.add_alternative(html_body, subtype="html")
        # Localizar la parte HTML para adjuntar el logo inline (si corresponde)
        for part in msg.iter_parts():
            if part.get_content_type() == "text/html":
                html_part = part
                break

        # Adjuntar logo inline usando CID (client-friendly)
        if inline_logo_path and html_part:
            try:
                import os as _os
                import mimetypes as _mimetypes

                mime_type, _ = _mimetypes.guess_type(inline_logo_path)
                maintype, subtype = ("image", "png")
                if mime_type and "/" in mime_type:
                    m_maintype, m_subtype = mime_type.split("/", 1)
                    if m_maintype == "image" and m_subtype:
                        maintype, subtype = m_maintype, m_subtype

                with open(inline_logo_path, "rb") as f:
                    img_bytes = f.read()

                # Importante: Content-ID con <...>
                cid_value = f"<{inline_logo_cid}>"
                html_part.add_related(img_bytes, maintype=maintype, subtype=subtype, cid=cid_value)

                logger.info("SMTP: logo inline embebido cid=%s desde %s (%s/%s)",
                            inline_logo_cid, inline_logo_path, maintype, subtype)
            except Exception as e:
                logger.warning("SMTP: no pude adjuntar logo inline (%s): %s", inline_logo_path, e)

    try:
        logger.info(
            "SMTP intento: host=%s port=%s tls=%s ssl=%s from=%s to=%s",
            host, port, use_tls, use_ssl, sender, to_clean
        )

        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as server:
                if user:
                    server.login(user, pwd)
                resp = server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.ehlo()
                if use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()
                if user:
                    server.login(user, pwd)
                resp = server.send_message(msg)

        # resp: dict de destinatarios que FALLARON; vacío = OK
        if resp:
            logger.error("SMTP: fallos por destinatario: %s", resp)
            return False

        logger.info("SMTP: envío OK a %s", to_clean)
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
    """Devuelve el email desde form/args/json aceptando 'email' o 'mail'."""
    cands = []
    # JSON
    if req.is_json:
        data = req.get_json(silent=True) or {}
        cands.extend([data.get('email'), data.get('mail')])
    # FORM
    cands.extend([req.form.get('email'), req.form.get('mail')])
    # QUERYSTRING
    cands.extend([req.args.get('email'), req.args.get('mail')])

    for v in cands:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


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
    activo = db.Column(db.Boolean, nullable=False, default=True)  # ya lo tenés
    # en class Jugador(...)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    # NUEVO: PIN simple para login MVP
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
            # Si el import relativo no aplica en tu proyecto, ajustalo al path correcto.
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

        # Si ya hay resultado final (relación backref desde PartidoResultado)
        if hasattr(self, "resultado") and self.resultado is not None:
            return False

        # Si ya existe una propuesta abierta, no se puede proponer de nuevo
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
    id = db.Column(db.Integer, primary_key=True)
    nombre_completo = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    telefono = db.Column(db.String(50))
    categoria_id = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=False)
    mensaje = db.Column(db.String(300))
    estado = db.Column(db.String(20), nullable=False, default='PENDIENTE')  # PENDIENTE | APROBADA | RECHAZADA
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)
    resuelto_en = db.Column(db.DateTime)

    categoria = db.relationship('Categoria')

class PinReset(db.Model):
    __tablename__ = 'pin_resets'
    id = db.Column(db.Integer, primary_key=True)
    jugador_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_en = db.Column(db.DateTime, default=datetime.utcnow)
    expires_en = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    jugador = db.relationship('Jugador')


# Crear DB si no existe
with app.app_context():
    db.create_all()

with app.app_context():
    # --- Seed mínimo de datos para que la app funcione ---
    # 1) Asegurar una categoría básica (la usa el index y el admin)
    cat = Categoria.query.filter_by(nombre="7ma").first()
    if not cat:
        cat = Categoria(nombre="7ma", puntos_min=0, puntos_max=199)
        db.session.add(cat)
        db.session.commit()

    # 2) Crear/asegurar un admin inicial desde variables de entorno
    admin_nombre = os.getenv("ADMIN_NOMBRE")
    admin_pin = os.getenv("ADMIN_PIN")
    if admin_nombre and admin_pin:
        admin = Jugador.query.filter_by(nombre_completo=admin_nombre).first()
        if not admin:
            admin = Jugador(
                nombre_completo=admin_nombre,
                email=None,
                telefono=None,
                puntos=150,          # puntos de arranque razonables
                categoria_id=cat.id, # asignado a la categoría básica
                activo=True,
                is_admin=True,
                pin=admin_pin        # tu modelo guarda PIN en texto (MVP)
            )
            db.session.add(admin)
            db.session.commit()
            print(f"[SEED] Admin creado: {admin_nombre}")
        else:
            # Aseguramos que siga siendo admin y tenga categoría si hiciera falta
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


# --- Migraciones/ALTERs idempotentes para SQLite ---
with app.app_context():
    # Jugadores.activo
    cols = [row[1] for row in db.session.execute(db.text("PRAGMA table_info(jugadores)")).all()]
    if 'activo' not in cols:
        # agrega columna y setea valor por defecto 1 (activo) para existentes
        db.session.execute(db.text("ALTER TABLE jugadores ADD COLUMN activo INTEGER NOT NULL DEFAULT 1"))
        # por si alguna fila quedó con NULL (según versión de sqlite)
        db.session.execute(db.text("UPDATE jugadores SET activo = 1 WHERE activo IS NULL"))
        db.session.commit()

    # PartidoAbiertoJugador.partner_pref_id (por si aún no lo agregaste)
    cols_paj = [row[1] for row in db.session.execute(db.text("PRAGMA table_info(partido_abierto_jugadores)")).all()]
    if 'partner_pref_id' not in cols_paj:
        db.session.execute(db.text("ALTER TABLE partido_abierto_jugadores ADD COLUMN partner_pref_id INTEGER"))
        db.session.commit()

with app.app_context():
    cols_j = [row[1] for row in db.session.execute(db.text("PRAGMA table_info(jugadores)")).all()]
    if 'pin' not in cols_j:
        db.session.execute(db.text("ALTER TABLE jugadores ADD COLUMN pin TEXT NOT NULL DEFAULT '0000'"))
        db.session.commit()

# --- Migraciones/ALTERs idempotentes (SQLite) para propuesta/confirmación de resultado ---
with app.app_context():
    cols_p = [r[1] for r in db.session.execute(db.text("PRAGMA table_info(partidos)")).all()]

    def add_col_if_missing(col_name, col_type):
        if col_name not in cols_p:
            db.session.execute(db.text(f"ALTER TABLE partidos ADD COLUMN {col_name} {col_type}"))
            db.session.commit()

    # Campos del workflow de resultados
    # Nota: BOOLEAN en SQLite = INTEGER (0/1/NULL)
    add_col_if_missing('resultado_propuesto_ganador_pareja_id', 'INTEGER')
    add_col_if_missing('resultado_propuesto_sets_text',         'TEXT')
    add_col_if_missing('resultado_propuesto_por_id',            'INTEGER')
    add_col_if_missing('resultado_propuesto_en',                'TIMESTAMP')
    add_col_if_missing('confirmo_pareja1',                      'INTEGER')
    add_col_if_missing('confirmo_pareja2',                      'INTEGER')

    # (Opcional) Si querés normalizar estados antiguos:
    # - Mantener los existentes tal cual está OK; el flujo nuevo funciona igual.
    # - Si querés forzar POR_CONFIRMAR solo en los que estén esperando rivales:
    # db.session.execute(db.text("""
    #     UPDATE partidos
    #     SET estado = 'POR_CONFIRMAR'
    #     WHERE estado = 'PENDIENTE'
    #       AND (rival1_acepto IS NULL OR rival2_acepto IS NULL)
    # """))
    # db.session.commit()

with app.app_context():
    db.session.execute(db.text("""
        CREATE INDEX IF NOT EXISTS ix_partidos_resultado_propuesto_en
        ON partidos(resultado_propuesto_en)
    """))
    db.session.commit()


# --- ALTER column para 'partner_pref_id' si no existe (SQLite) ---
with app.app_context():
    cols = [row[1] for row in db.session.execute(db.text("PRAGMA table_info(partido_abierto_jugadores)")).all()]
    if 'partner_pref_id' not in cols:
        db.session.execute(db.text("ALTER TABLE partido_abierto_jugadores ADD COLUMN partner_pref_id INTEGER"))
        db.session.commit()

with app.app_context():
    cols_j = [r[1] for r in db.session.execute(db.text("PRAGMA table_info(jugadores)")).all()]
    if 'is_admin' not in cols_j:
        db.session.execute(db.text("ALTER TABLE jugadores ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"))
        db.session.commit()

with app.app_context():
    # Emails a minúscula para evitar duplicados por mayúsculas/minúsculas (opcional pero recomendable)
    db.session.execute(db.text("UPDATE jugadores SET email = LOWER(email) WHERE email IS NOT NULL"))
    db.session.commit()

    # Índice único sólo cuando email NO es NULL
    db.session.execute(db.text("""
        CREATE UNIQUE INDEX IF NOT EXISTS ux_jugadores_email
        ON jugadores(email)
        WHERE email IS NOT NULL
    """))
    db.session.commit()

with app.app_context():
    cols_p = [r[1] for r in db.session.execute(db.text("PRAGMA table_info(partidos)")).all()]

    def add_col_if_missing(col_name, col_type):
        if col_name not in cols_p:
            db.session.execute(db.text(f"ALTER TABLE partidos ADD COLUMN {col_name} {col_type}"))
            db.session.commit()

    # Nuevas columnas (idempotentes)
    add_col_if_missing('creador_id',   'INTEGER')
    add_col_if_missing('companero_id', 'INTEGER')
    add_col_if_missing('rival1_id',    'INTEGER')
    add_col_if_missing('rival2_id',    'INTEGER')
    # BOOLEAN en SQLite = INTEGER (0/1/NULL)
    add_col_if_missing('rival1_acepto','INTEGER')
    add_col_if_missing('rival2_acepto','INTEGER')

    # Índices idempotentes para acelerar consultas por rivales/creador/estado
    db.session.execute(db.text("CREATE INDEX IF NOT EXISTS ix_partidos_rival1   ON partidos(rival1_id)"))
    db.session.execute(db.text("CREATE INDEX IF NOT EXISTS ix_partidos_rival2   ON partidos(rival2_id)"))
    db.session.execute(db.text("CREATE INDEX IF NOT EXISTS ix_partidos_creador  ON partidos(creador_id)"))
    db.session.execute(db.text("CREATE INDEX IF NOT EXISTS ix_partidos_estado   ON partidos(estado)"))
    db.session.commit()

# --- NUEVO: flags de aceptación individual en Desafios ---
with app.app_context():
    cols_d = [row[1] for row in db.session.execute(db.text("PRAGMA table_info(desafios)")).all()]
    if 'rival1_acepto' not in cols_d:
        db.session.execute(db.text(
            "ALTER TABLE desafios ADD COLUMN rival1_acepto INTEGER NOT NULL DEFAULT 0"
        ))
        db.session.commit()
    if 'rival2_acepto' not in cols_d:
        db.session.execute(db.text(
            "ALTER TABLE desafios ADD COLUMN rival2_acepto INTEGER NOT NULL DEFAULT 0"
        ))
        db.session.commit()

    # Backfill: si ya había desafíos aceptados o jugados, asumimos que ambos rivales habían aceptado
    db.session.execute(db.text(
        "UPDATE desafios SET rival1_acepto=1, rival2_acepto=1 WHERE estado IN ('ACEPTADO','JUGADO')"
    ))
    db.session.commit()

# --- Migraciones/ALTERs para INVITACIONES de Partido ---
with app.app_context():
    cols_p = [row[1] for row in db.session.execute(db.text("PRAGMA table_info(partidos)")).all()]
    # Datos de los 4 jugadores involucrados en el armado directo
    if 'creador_id' not in cols_p:
        db.session.execute(db.text("ALTER TABLE partidos ADD COLUMN creador_id INTEGER"))
    if 'companero_id' not in cols_p:
        db.session.execute(db.text("ALTER TABLE partidos ADD COLUMN companero_id INTEGER"))
    if 'rival1_id' not in cols_p:
        db.session.execute(db.text("ALTER TABLE partidos ADD COLUMN rival1_id INTEGER"))
    if 'rival2_id' not in cols_p:
        db.session.execute(db.text("ALTER TABLE partidos ADD COLUMN rival2_id INTEGER"))
    # Aceptaciones de los rivales (NULL = sin responder, 1 = aceptó, 0 = rechazó)
    if 'rival1_acepto' not in cols_p:
        db.session.execute(db.text("ALTER TABLE partidos ADD COLUMN rival1_acepto INTEGER"))
    if 'rival2_acepto' not in cols_p:
        db.session.execute(db.text("ALTER TABLE partidos ADD COLUMN rival2_acepto INTEGER"))
    db.session.commit()

with app.app_context():
    # ¿existe la tabla?
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

with app.app_context():
    db.session.execute(db.text("""
        CREATE INDEX IF NOT EXISTS ix_prp_creado_en ON partido_resultado_propuesto(creado_en)
    """))
    db.session.commit()


# Config puntos (ajustable)
DELTA_WIN = -10
DELTA_LOSS = +5
DELTA_WIN_BONUS = -3   # extra por compañero repetido (desde la 3ª victoria conjunta)
BONUS_APLICA_DESDE = 3 # a partir de cuántas victorias juntos empieza a aplicar

# === Hora local para templates (con filtros Jinja) ===
APP_TZ = ZoneInfo("America/Argentina/Buenos_Aires")

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
        nombre = (request.form.get('nombre_completo') or '').strip()
        email = (request.form.get('email') or '').strip()
        telefono = (request.form.get('telefono') or '').strip()
        categoria_id = request.form.get('categoria_id', type=int)
        mensaje = (request.form.get('mensaje') or '').strip()

        # --- Validaciones obligatorias ---
        if not nombre:
            flash('El nombre es obligatorio.', 'error')
            return redirect(url_for('alta_publica'))
        if not categoria_id:
            flash('La categoría es obligatoria.', 'error')
            return redirect(url_for('alta_publica'))
        if not email:
            flash('El email es obligatorio.', 'error')
            return redirect(url_for('alta_publica'))
        if '@' not in email or len(email) < 6:
            flash('Ingresá un email válido.', 'error')
            return redirect(url_for('alta_publica'))
        if not telefono:
            flash('El teléfono es obligatorio.', 'error')
            return redirect(url_for('alta_publica'))
        # validación simple de teléfono (permite +, espacios, paréntesis y dígitos)
        tel_digits = ''.join(ch for ch in telefono if ch.isdigit())
        if len(tel_digits) < 7:
            flash('Ingresá un teléfono válido (al menos 7 dígitos).', 'error')
            return redirect(url_for('alta_publica'))

        cat = db.session.get(Categoria, int(categoria_id)) if categoria_id is not None else None
        if not cat:
            flash('Categoría inválida.', 'error')
            return redirect(url_for('alta_publica'))

        # Duplicado por solicitud pendiente (mismo email)
        existe_pend = (db.session.query(SolicitudAlta)
                       .filter(SolicitudAlta.email == email,
                               SolicitudAlta.estado == 'PENDIENTE')
                       .first())
        if existe_pend:
            flash('Ya hay una solicitud pendiente con ese email. Te contactaremos pronto.', 'ok')
            return redirect(url_for('alta_publica'))

        # Ya existe un jugador con ese email (activo o inactivo)
        existe_jugador = db.session.query(Jugador).filter(Jugador.email == email).first()
        if existe_jugador:
            flash('Ese email ya está registrado como jugador. Probá iniciar sesión o contactá al organizador.', 'error')
            return redirect(url_for('alta_publica'))

        # Crear solicitud
        s = SolicitudAlta(
            nombre_completo=nombre,
            email=email,
            telefono=telefono,
            categoria_id=cat.id,
            mensaje=mensaje or None,
            estado='PENDIENTE'
        )
        db.session.add(s)
        db.session.commit()

        # ==== Aviso por email a administradores (usando send_mail) ====
        try:
            admin_emails = [e.strip() for e in (os.getenv('ADMIN_EMAILS') or '').split(',') if e.strip()]
            if admin_emails:
                ahora_ar = datetime.now(ZoneInfo('America/Argentina/Buenos_Aires')).strftime('%Y-%m-%d %H:%M')
                body = (
                    "Se recibió una nueva solicitud de ALTA.\n\n"
                    f"Nombre:   {nombre}\n"
                    f"Email:    {email}\n"
                    f"Teléfono: {telefono}\n"
                    f"Categoría solicitada: {cat.nombre} (id {cat.id})\n"
                    f"Mensaje:  {mensaje or '-'}\n"
                    f"Fecha/Hora (AR): {ahora_ar}\n\n"
                    "Revisar en: /admin/solicitudes"
                )

                ok = send_mail(
                    subject=f'Nueva solicitud de alta: {nombre}',
                    body=body,          # texto plano
                    to=admin_emails
                )
                current_app.logger.info("Aviso de alta a admins send_mail=%s to=%s", ok, admin_emails)
            else:
                logging.warning('ADMIN_EMAILS vacío; no se envía aviso de alta.')
        except Exception:
            logging.exception('Fallo enviando email de notificación de nueva solicitud de alta.')

        flash('Solicitud enviada. Un administrador la revisará.', 'ok')
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
@app.route('/jugadores')
def jugadores_list():
    # Filtros existentes
    mostrar_inactivos = request.args.get('inactivos', default=0, type=int)  # 1 = incluir inactivos

    # NUEVOS filtros
    q_text = (request.args.get('q') or '').strip()
    categoria_id = request.args.get('categoria_id', type=int)
    solo_mi_cat = request.args.get('solo_mi_cat', type=int) == 1

    asegurar_estado_jugadores()

    base = db.session.query(Jugador)

    # Activos / inactivos
    if mostrar_inactivos != 1:
        base = base.filter(Jugador.activo.is_(True))

    # Filtro por categoría elegida o "solo mi categoría"
    if categoria_id:
        base = base.filter(Jugador.categoria_id == categoria_id)
    elif solo_mi_cat:
        # Intentamos leer el jugador actual desde g (o adaptalo a tu helper/context processor)
        from flask import g
        current_jugador = getattr(g, 'current_jugador', None)
        if current_jugador and current_jugador.categoria_id:
            base = base.filter(Jugador.categoria_id == current_jugador.categoria_id)

    # Orden original por nombre
    base = base.order_by(Jugador.nombre_completo.asc())

    jugadores = base.all()

    # Buscador por nombre (case-insensitive, seguro)
    if q_text:
        ql = q_text.lower()
        jugadores = [j for j in jugadores if ql in (j.nombre_completo or '').lower()]

    # Para el combo de categorías
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()

    # Zona de ascenso (tu lógica original)
    zona_ascenso = {}
    for j in jugadores:
        cat = j.categoria
        zona_ascenso[j.id] = bool(cat and j.puntos is not None and j.puntos <= cat.puntos_min)

    return render_template(
        'jugadores_list.html',
        jugadores=jugadores,
        categorias=categorias,
        zona_ascenso=zona_ascenso,
        mostrar_inactivos=mostrar_inactivos,
        q=q_text,
        categoria_id=categoria_id,
        solo_mi_cat=1 if solo_mi_cat else 0
    )


@app.route('/jugadores/nuevo', methods=['GET', 'POST'])
def jugadores_new():
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()

    if request.method == 'POST':
        nombre = (request.form.get('nombre_completo') or '').strip()
        email = (request.form.get('email') or '').strip()
        telefono = (request.form.get('telefono') or '').strip()
        puntos = request.form.get('puntos')
        categoria_id = request.form.get('categoria_id')

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

        # Validar que los puntos estén dentro del rango de la categoría
        if not (cat.puntos_min <= pts <= cat.puntos_max):
            flash(f'Los puntos {pts} no están dentro del rango de la categoría {cat.nombre} ({cat.rango()}).', 'error')
            return redirect(url_for('jugadores_new'))

        jug = Jugador(
            nombre_completo=nombre,
            email=email or None,
            telefono=telefono or None,
            puntos=pts,
            categoria_id=cat.id
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
        nombre = (request.form.get('nombre_completo') or '').strip()
        email = (request.form.get('email') or '').strip()
        telefono = (request.form.get('telefono') or '').strip()
        puntos = request.form.get('puntos')
        categoria_id = request.form.get('categoria_id')
        pin = (request.form.get('pin') or '').strip()  # opcional
        is_admin_form = request.form.get('is_admin')   # '1' si viene marcado

        if not nombre or not puntos or not categoria_id:
            flash('Nombre, puntos y categoría son obligatorios.', 'error')
            return redirect(url_for('jugadores_edit', jugador_id=j.id))

        try:
            pts = int(puntos)
            cat_id = int(categoria_id)
        except ValueError:
            flash('Los puntos y la categoría deben ser válidos.', 'error')
            return redirect(url_for('jugadores_edit', jugador_id=j.id))

        cat = db.session.get(Categoria, int(cat_id)) if cat_id is not None else None
        if not cat:
            flash('Categoría inválida.', 'error')
            return redirect(url_for('jugadores_edit', jugador_id=j.id))

        # Validar que los puntos estén dentro del rango de la categoría elegida
        if not (cat.puntos_min <= pts <= cat.puntos_max):
            flash(f'Los puntos {pts} no están dentro del rango de la categoría {cat.nombre} ({cat.puntos_min}–{cat.puntos_max}).', 'error')
            return redirect(url_for('jugadores_edit', jugador_id=j.id))

        # Si el PIN viene cargado, validarlo (4–6 dígitos)
        if pin:
            if not (pin.isdigit() and 4 <= len(pin) <= 6):
                flash('El PIN debe tener 4–6 dígitos numéricos.', 'error')
                return redirect(url_for('jugadores_edit', jugador_id=j.id))
            j.pin = pin  # actualizar PIN

        # Guardar cambios básicos
        j.nombre_completo = nombre
        j.email = email or None
        j.telefono = telefono or None
        j.puntos = pts
        j.categoria_id = cat.id

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

@app.route('/partidos')
def partidos_list():
    partidos = (db.session.query(Partido)
                .order_by(Partido.creado_en.desc())
                .all())
    return render_template('partidos_list.html', partidos=partidos)

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

        # Misma categoría del creador
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
            estado='PENDIENTE',     # queda pendiente hasta que acepten
            # --- campos de invitación ---
            creador_id=creador.id,
            companero_id=companero.id,
            rival1_id=r1.id,
            rival2_id=r2.id,
            rival1_acepto=None,     # sin responder
            rival2_acepto=None      # sin responder
        )
        db.session.add(partido)
        db.session.commit()

        flash(f'Partido #{partido.id} creado.', 'ok')
        return redirect(url_for('partidos_list'))

    # GET -> armar combos
    # Todos los jugadores activos de mi categoría, excepto yo
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

    candidatos_companero = jugadores_mi_cat  # cualquier otro de mi categoría
    candidatos_rivales   = jugadores_mi_cat  # idem (se filtrará en el front para no repetir)

    return render_template(
        'partidos_form.html',
        categoria=cat,
        candidatos_companero=candidatos_companero,
        candidatos_rivales=candidatos_rivales
    )

@app.route('/partidos/<int:partido_id>/resultado', methods=['GET', 'POST'])
def partidos_resultado(partido_id):
    # --- Sesión requerida
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión.', 'error')
        return redirect(url_for('login'))

    partido = get_or_404(Partido, partido_id)

    # No permitir si ya hay resultado final
    if hasattr(partido, 'resultado') and partido.resultado is not None:
        flash('El partido ya tiene un resultado confirmado.', 'warning')
        return redirect(url_for('partidos_list'))

    # --- Estados permitidos para proponer
    # Permitimos PENDIENTE y POR_CONFIRMAR. Si ya está PROPUESTO, vamos a confirmar.
    if partido.estado not in ('PENDIENTE', 'POR_CONFIRMAR'):
        if partido.estado == 'PROPUESTO':
            flash('Ya hay un resultado propuesto. Podés confirmarlo o rechazarlo.', 'ok')
            return redirect(url_for('partidos_confirmar_resultado', partido_id=partido.id))
        else:
            flash('Este partido no permite cargar resultado en su estado actual.', 'error')
            return redirect(url_for('partidos_list'))

    # --- Sólo participantes o admin pueden proponer resultado
    try:
        participantes_ids = {
            partido.pareja1.jugador1_id, partido.pareja1.jugador2_id,
            partido.pareja2.jugador1_id, partido.pareja2.jugador2_id
        }
    except Exception:
        participantes_ids = set()

    if not (j.is_admin or j.id in participantes_ids):
        flash('Solo los jugadores del partido (o un admin) pueden cargar el resultado.', 'error')
        return redirect(url_for('partidos_list'))

    # --- Si el partido fue armado invitando rivales, exigir aceptación de ambos
    requiere_aceptaciones = (partido.rival1_id is not None and partido.rival2_id is not None)
    if requiere_aceptaciones and not (partido.rival1_acepto == 1 and partido.rival2_acepto == 1):
        flash('Aún falta que ambos rivales acepten la invitación.', 'error')
        return redirect(url_for('partidos_list'))

    # --- Si ya existe una propuesta previa (legacy o tabla) → ir directo a confirmar
    if partido.resultado_propuesto_ganador_pareja_id is not None:
        flash('Ya hay un resultado propuesto. Podés confirmarlo o rechazarlo.', 'ok')
        return redirect(url_for('partidos_confirmar_resultado', partido_id=partido.id))

    # Chequear también en la tabla PartidoResultadoPropuesto
    try:
        from .models import PartidoResultadoPropuesto
    except Exception:
        PartidoResultadoPropuesto = globals().get('PartidoResultadoPropuesto', None)

    if PartidoResultadoPropuesto:
        existente = (db.session.query(PartidoResultadoPropuesto)
                     .filter_by(partido_id=partido.id)
                     .one_or_none())
        if existente:
            flash('Ya existe una propuesta de resultado pendiente para este partido.', 'ok')
            return redirect(url_for('partidos_confirmar_resultado', partido_id=partido.id))

    if request.method == 'POST':
        # Este POST **propone** resultado (no lo cierra)
        ganador_id = request.form.get('ganador_pareja_id')
        sets_text  = (request.form.get('sets_text') or '').strip()

        if not ganador_id:
            flash('Elegí la pareja ganadora.', 'error')
            return redirect(url_for('partidos_resultado', partido_id=partido.id))

        try:
            ganador_id = int(ganador_id)
        except ValueError:
            flash('Ganador inválido.', 'error')
            return redirect(url_for('partidos_resultado', partido_id=partido.id))

        if ganador_id not in (partido.pareja1_id, partido.pareja2_id):
            flash('La pareja ganadora no corresponde a este partido.', 'error')
            return redirect(url_for('partidos_resultado', partido_id=partido.id))

        # Determinar si el proponente es pareja1 o pareja2
        soy_p1 = j.id in (partido.pareja1.jugador1_id, partido.pareja1.jugador2_id)

        # Crear registro de propuesta (si la tabla existe)
        if PartidoResultadoPropuesto:
            nueva_prop = PartidoResultadoPropuesto(
                partido_id=partido.id,
                propuesto_por_pareja_id=partido.pareja1_id if soy_p1 else partido.pareja2_id,
                ganador_pareja_id=ganador_id,
                sets_text=sets_text or None
            )
            db.session.add(nueva_prop)

        # Guardar también en campos "legacy" del Partido para compatibilidad
        partido.resultado_propuesto_ganador_pareja_id = ganador_id
        partido.resultado_propuesto_sets_text = sets_text or None
        partido.resultado_propuesto_por_id = j.id
        partido.resultado_propuesto_en = datetime.utcnow()   # ← NUEVO: timestamp de propuesta

        # Estado pasa a PROPUESTO y la pareja que propone queda auto-confirmada (=1)
        partido.estado = 'PROPUESTO'
        if soy_p1:
            partido.confirmo_pareja1 = 1
            partido.confirmo_pareja2 = None  # pendiente rival
        else:
            partido.confirmo_pareja2 = 1
            partido.confirmo_pareja1 = None  # pendiente rival

        db.session.commit()
        flash('Resultado propuesto. Ahora debe confirmarlo la otra pareja.', 'ok')
        return redirect(url_for('partidos_confirmar_resultado', partido_id=partido.id))

    # GET -> mostrar formulario para proponer
    return render_template('partidos_resultado.html', partido=partido)

@app.route('/partidos/<int:partido_id>/responder', methods=['GET', 'POST'])
def partidos_responder(partido_id):
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión para responder.', 'error')
        return redirect(url_for('login'))

    p = get_or_404(Partido, partido_id)

    # Sólo rivales pueden responder y el partido debe estar en invitación
    if p.estado not in ('PENDIENTE', 'POR_CONFIRMAR'):
        flash('Este partido ya no está pendiente.', 'error')
        return redirect(url_for('partidos_list'))

    if j.id not in (p.rival1_id, p.rival2_id):
        flash('Solo los rivales invitados pueden responder.', 'error')
        return redirect(url_for('partidos_list'))

    # Datos de los contrarios (creador + compañero)
    contrario_1 = p.creador
    contrario_2 = p.companero

    # Determinar mi compañero actual (si ya está seteado el otro slot rival)
    if j.id == p.rival1_id:
        mi_compa_id = p.rival2_id
        soy_rival1 = True
    else:
        mi_compa_id = p.rival1_id
        soy_rival1 = False

    mi_compa = db.session.query(Jugador).get(mi_compa_id) if mi_compa_id else None

    # Opciones de compañero (misma categoría, activo, y que no esté ya en el partido)
    ocupados_base = {pid for pid in [p.creador_id, p.companero_id, p.rival1_id, p.rival2_id] if pid}
    candidatos = (
        db.session.query(Jugador)
        .filter(Jugador.activo.is_(True),
                Jugador.categoria_id == j.categoria_id,
                Jugador.id != j.id)
        .order_by(Jugador.nombre_completo.asc())
        .all()
    )

    # Permitimos seleccionar siempre: si ya hay compa, se podrá "cambiar" (mostramos UI acorde)
    # Para armar el combo, quitamos ocupados EXCEPTO el actual (lo podemos ofrecer como opción "mantener")
    ocupados_para_filtrar = set(ocupados_base)
    if mi_compa:
        ocupados_para_filtrar.discard(mi_compa.id)

    opciones_companero = [c for c in candidatos if c.id not in ocupados_para_filtrar]

    # Flag de mi aceptación (para mensajes en la vista)
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
            p.estado = 'CANCELADO'
            db.session.commit()
            flash('Rechazaste la invitación. El partido fue cancelado.', 'ok')
            return redirect(url_for('partidos_list'))

        # ACEPTAR
        elegido_id = request.form.get('partner_id', type=int)

        # Caso A: no tengo compañero aún → debo elegir uno
        if not mi_compa:
            if not elegido_id:
                flash('Elegí un compañero antes de aceptar.', 'error')
                return redirect(url_for('partidos_responder', partido_id=p.id))

        # Caso B: tengo compañero → puedo mantenerlo o cambiarlo si viene partner_id distinto
        if elegido_id:
            if mi_compa and elegido_id == mi_compa.id:
                # Mantener actual: no hay cambios de compañero
                pass
            else:
                elegido = db.session.query(Jugador).get(elegido_id)
                if (not elegido) or (not elegido.activo) or (elegido.categoria_id != j.categoria_id):
                    flash('El compañero elegido no es válido.', 'error')
                    return redirect(url_for('partidos_responder', partido_id=p.id))
                # No debe estar ya en el partido (salvo que sea el actual)
                if elegido.id in ocupados_para_filtrar:
                    flash('Ese jugador ya está en este partido.', 'error')
                    return redirect(url_for('partidos_responder', partido_id=p.id))

                # Asignar/reemplazar compañero en mi lado y dejar su aceptación pendiente
                if soy_rival1:
                    p.rival2_id = elegido.id
                    p.rival2_acepto = None
                else:
                    p.rival1_id = elegido.id
                    p.rival1_acepto = None

                # Si había un compañero anterior (mi_compa), ya queda afuera del partido.

                # Estado coherente mientras falta la aceptación del nuevo
                if p.estado not in ('PENDIENTE', 'POR_CONFIRMAR'):
                    p.estado = 'POR_CONFIRMAR'

        # Marcar mi aceptación
        if soy_rival1:
            p.rival1_acepto = 1
        else:
            p.rival2_acepto = 1

        # ¿Ambos rivales aceptaron?
        if (p.rival1_id and p.rival2_id and p.rival1_acepto == 1 and p.rival2_acepto == 1):
            p.estado = 'PENDIENTE'
            flash('Ambos rivales aceptaron. El partido está listo para jugar.', 'ok')
        else:
            # Todavía falta aceptación del compañero (si se cambió) o del otro rival
            if p.estado not in ('PENDIENTE', 'POR_CONFIRMAR'):
                p.estado = 'POR_CONFIRMAR'
            flash('Respuesta registrada. Falta que el otro rival/compañero confirme.', 'ok')

        db.session.commit()
        return redirect(url_for('partidos_list'))

    # GET → mostrar vista con info de compañero y selector (si corresponde)
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

@app.route('/partidos/<int:partido_id>/confirmar-resultado', methods=['GET', 'POST'])
def partidos_confirmar_resultado(partido_id):
    p = get_or_404(Partido, partido_id)
    yo = get_current_jugador()
    if not yo:
        flash('Iniciá sesión.', 'error')
        return redirect(url_for('login'))

    # Estados válidos para confirmar/rechazar una propuesta
    if p.estado not in ('PENDIENTE', 'PROPUESTO'):
        flash('Este partido ya no está pendiente de confirmación.', 'error')
        return redirect(url_for('partidos_list'))

    # Buscar propuesta en la tabla (si existe), además de los campos legacy del Partido
    try:
        from .models import PartidoResultadoPropuesto
    except Exception:
        PartidoResultadoPropuesto = globals().get('PartidoResultadoPropuesto', None)

    prp = None
    if PartidoResultadoPropuesto:
        prp = (db.session.query(PartidoResultadoPropuesto)
               .filter_by(partido_id=p.id)
               .one_or_none())

    # Debe existir propuesta (tabla o legacy)
    if (p.resultado_propuesto_ganador_pareja_id is None) and (prp is None):
        flash('Aún no hay un resultado propuesto.', 'error')
        return redirect(url_for('partidos_list'))

    # Debe ser participante
    participantes_ids = {
        p.pareja1.jugador1_id, p.pareja1.jugador2_id,
        p.pareja2.jugador1_id, p.pareja2.jugador2_id
    }
    if yo.id not in participantes_ids:
        flash('Solo jugadores de este partido pueden confirmar el resultado.', 'error')
        return redirect(url_for('partidos_list'))

    soy_p1 = yo.id in (p.pareja1.jugador1_id, p.pareja1.jugador2_id)

    if request.method == 'POST':
        accion = (request.form.get('accion') or '').strip()  # 'aceptar' | 'rechazar'
        if accion not in ('aceptar', 'rechazar'):
            flash('Acción inválida.', 'error')
            return redirect(url_for('partidos_confirmar_resultado', partido_id=p.id))

        # --- RECHAZAR: limpiar propuesta (tabla + legacy) y volver a PENDIENTE
        if accion == 'rechazar':
            if prp:
                db.session.delete(prp)
            p.resultado_propuesto_ganador_pareja_id = None
            p.resultado_propuesto_sets_text = None
            p.resultado_propuesto_por_id = None
            p.confirmo_pareja1 = None
            p.confirmo_pareja2 = None

            # 🔴 NUEVO: registrar quién y cuándo rechazó
            p.rechazo_ultimo_por_id = yo.id
            p.rechazo_ultimo_en = datetime.utcnow()
            p.resultado_propuesto_en = None

            p.estado = 'PENDIENTE'
            db.session.commit()
            flash('Rechazaste la propuesta. El partido sigue pendiente sin resultado.', 'ok')
            return redirect(url_for('partidos_list'))

        # --- ACEPTAR: marcar confirmación de mi pareja
        if soy_p1:
            p.confirmo_pareja1 = 1
        else:
            p.confirmo_pareja2 = 1

        # ¿Ambas parejas confirmadas? → cerrar y aplicar puntos
        if (p.confirmo_pareja1 == 1) and (p.confirmo_pareja2 == 1):
            # Origen de la propuesta: priorizar tabla PRP; si no, legacy
            ganador_id = prp.ganador_pareja_id if prp else p.resultado_propuesto_ganador_pareja_id
            sets_text  = prp.sets_text if prp else p.resultado_propuesto_sets_text

            # === Tu lógica de cierre (puntos, bonus, desafíos, etc.) tal cual ===
            p1 = p.pareja1
            p2 = p.pareja2

            DELTA_WIN = globals().get('DELTA_WIN', -10)
            DELTA_LOSS = globals().get('DELTA_LOSS', +5)
            DELTA_WIN_BONUS = globals().get('DELTA_WIN_BONUS', -3)
            BONUS_APLICA_DESDE = globals().get('BONUS_APLICA_DESDE', 3)

            def clamp_por_jugador(j):
                cat = j.categoria
                if not cat:
                    return j.puntos
                return max(cat.puntos_min, min(cat.puntos_max, j.puntos))

            if ganador_id == p1.id:
                pareja_g = p1
                pareja_p = p2
            else:
                pareja_g = p2
                pareja_p = p1

            ganadores = [pareja_g.jugador1, pareja_g.jugador2]
            perdedores = [pareja_p.jugador1, pareja_p.jugador2]

            victorias_previas = (
                db.session.query(PartidoResultado)
                .join(Partido, PartidoResultado.partido_id == Partido.id)
                .filter(PartidoResultado.ganador_pareja_id == pareja_g.id)
                .filter(Partido.id != p.id)
                .count()
            )
            aplica_bonus = (victorias_previas + 1) >= BONUS_APLICA_DESDE

            for jg in ganadores:
                base = (jg.puntos or (jg.categoria.puntos_max if jg.categoria else 0))
                jg.puntos = base + DELTA_WIN + (DELTA_WIN_BONUS if aplica_bonus else 0)
                jg.puntos = clamp_por_jugador(jg)

            for jp in perdedores:
                base = (jp.puntos or (jp.categoria.puntos_max if jp.categoria else 0))
                jp.puntos = base + DELTA_LOSS
                jp.puntos = clamp_por_jugador(jp)

            pr = PartidoResultado(
                partido_id=p.id,
                ganador_pareja_id=ganador_id,
                sets_text=sets_text or None
            )
            p.estado = 'JUGADO'
            db.session.add(pr)

            # Desafío (si aplica)
            desafio = Desafio.query.filter_by(partido_id=p.id).first()
            msg_extra = ''
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

            # Limpiar propuesta (tabla + legacy) al cerrar
            if prp:
                db.session.delete(prp)
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

        # Aceptación parcial: mantener PROPUESTO (si aún no estaba) y avisar
        if p.estado != 'PROPUESTO':
            p.estado = 'PROPUESTO'
        db.session.commit()
        flash('Tu confirmación fue registrada. Falta la otra pareja.', 'ok')
        return redirect(url_for('partidos_list'))

    # GET → mostrar propuesta + botones aceptar/rechazar
    return render_template('partidos_confirmar_resultado.html',
                           partido=p, yo=yo, soy_p1=soy_p1, propuesta=prp)


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

    def clamp_por_jugador(j):
        cat = j.categoria
        if not cat:
            return j.puntos
        return max(cat.puntos_min, min(cat.puntos_max, j.puntos))

    for p in candidatos:
        # Si por alguna razón ambas confirmaciones están ok, lo salteamos (ya se habría cerrado)
        if p.confirmo_pareja1 == 1 and p.confirmo_pareja2 == 1:
            continue

        # Tomamos ganador + marcador desde PRP (si existe) o desde Partido (legacy)
        prp = None
        if PartidoResultadoPropuesto:
            prp = (
                db.session.query(PartidoResultadoPropuesto)
                .filter_by(partido_id=p.id)
                .one_or_none()
            )

        ganador_id = prp.ganador_pareja_id if prp else p.resultado_propuesto_ganador_pareja_id
        sets_text  = prp.sets_text if prp else p.resultado_propuesto_sets_text

        # Si falta info mínima, lo dejamos pasar (no cerramos)
        if not ganador_id:
            continue

        p1, p2 = p.pareja1, p.pareja2
        pareja_g = p1 if ganador_id == p1.id else p2
        pareja_p = p2 if ganador_id == p1.id else p1

        ganadores = [pareja_g.jugador1, pareja_g.jugador2]
        perdedores = [pareja_p.jugador1, pareja_p.jugador2]

        victorias_previas = (
            db.session.query(PartidoResultado)
            .join(Partido, PartidoResultado.partido_id == Partido.id)
            .filter(PartidoResultado.ganador_pareja_id == pareja_g.id)
            .filter(Partido.id != p.id)
            .count()
        )
        aplica_bonus = (victorias_previas + 1) >= BONUS_APLICA_DESDE

        # Aplicar puntos
        for jg in ganadores:
            base = (jg.puntos or (jg.categoria.puntos_max if jg.categoria else 0))
            jg.puntos = base + DELTA_WIN + (DELTA_WIN_BONUS if aplica_bonus else 0)
            jg.puntos = clamp_por_jugador(jg)

        for jp in perdedores:
            base = (jp.puntos or (jp.categoria.puntos_max if jp.categoria else 0))
            jp.puntos = base + DELTA_LOSS
            jp.puntos = clamp_por_jugador(jp)

        # Guardar resultado final
        pr = PartidoResultado(
            partido_id=p.id,
            ganador_pareja_id=ganador_id,
            sets_text=sets_text or None
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
            inferiores = [pareja_inferior.jugador1, pareja_inferior.jugador2]
            superiores = [pareja_superior.jugador1, pareja_superior.jugador2]

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


# === ENDPOINT HTTP: para cron (protegido por token) ===
@app.route('/tareas/propuestas/autocerrar')
def tareas_autocerrar_propuestas_vencidas():
    if request.args.get('token') != AUTOCRON_TOKEN:
        return jsonify({"error": "forbidden"}), 403
    cerrados = _cerrar_propuestas_vencidas_core()
    return jsonify({"cerrados": cerrados})


# === HOOK LAZY: lo corre como máximo 1 vez por minuto cuando hay tráfico ===
_last_autocierre_run = {'ts': None}

@app.before_request
def _autocierre_lazy_hook():
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

    partido = Partido(
        categoria_id=d.categoria_superior_id,
        pareja1_id=pareja_inferior.id,  # inferior
        pareja2_id=pareja_superior.id,  # superior
        estado='PENDIENTE'
    )
    db.session.add(partido)
    db.session.commit()

    d.partido_id = partido.id
    # Estado se mantiene en ACEPTADO hasta que se juegue
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

        # ACEPTAR
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

    pa = PartidoAbierto(categoria_id=cat.id, creador_id=creador.id, nota=nota or None, estado='ABIERTO')
    db.session.add(pa)
    db.session.flush()  # obtener id

    db.session.add(PartidoAbiertoJugador(pa_id=pa.id, jugador_id=creador.id))
    db.session.commit()

    flash('Partido abierto creado. Compartí el link para que se sumen.', 'ok')
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

    # Capacidad
    cupo = len(pa.inscriptos)
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
        ids_inscriptos = {it.jugador_id for it in pa.inscriptos}
        if pref_id == j.id:
            flash('No podés elegirte a vos mismo como compañero.', 'error')
            return redirect(url_for('abiertos_list'))
        if pref_id not in ids_inscriptos:
            flash('La preferencia debe ser alguien ya inscripto en este partido.', 'error')
            return redirect(url_for('abiertos_list'))
        partner_pref_id = pref_id

    # Inscribir
    db.session.add(PartidoAbiertoJugador(
        pa_id=pa.id,
        jugador_id=j.id,
        partner_pref_id=partner_pref_id
    ))

    # Actualizar estado si corresponde
    cupo += 1
    if cupo >= 4:
        pa.estado = 'LLENO'

    db.session.commit()

    msg_extra = ' Preferencia de compañero guardada.' if partner_pref_id else ''
    flash('Te uniste al partido abierto.' + msg_extra, 'ok')
    return redirect(url_for('abiertos_list'))


@app.route('/abiertos/<int:pa_id>/salir', methods=['POST'])
def abiertos_leave(pa_id):
    pa = get_or_404(PartidoAbierto, pa_id)
    jugador_id = request.form.get('jugador_id', type=int)
    r = PartidoAbiertoJugador.query.filter_by(pa_id=pa.id, jugador_id=jugador_id).first()
    if not r:
        flash('Ese jugador no estaba inscripto.', 'error')
        return redirect(url_for('abiertos_list'))

    db.session.delete(r)
    # Si estaba “LLENO” y alguien sale, vuelve a ABIERTO
    if pa.estado == 'LLENO':
        pa.estado = 'ABIERTO'
    db.session.commit()
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

@app.route('/olvide-pin', methods=['GET', 'POST'])
def olvide_pin():
    if request.method == 'POST':
        # Logs para diagnóstico rápido en Render
        current_app.logger.info(
            "POST /olvide-pin -> form_keys=%s args_keys=%s is_json=%s",
            list(request.form.keys()), list(request.args.keys()), request.is_json
        )

        email = _extraer_email_desde_request(request).lower()

        # Mensaje genérico (para no revelar si existe o no)
        generic_msg = 'Si el correo existe en el sistema, te enviamos un código de verificación.'

        # Validación básica de email
        if not email or not EMAIL_RE.match(email):
            current_app.logger.warning("Email ausente o inválido recibido: %r", email)
            flash(generic_msg, 'ok')
            return redirect(url_for('olvide_pin'))

        j = db.session.query(Jugador).filter(Jugador.email == email).first()
        if not j:
            # No revelamos existencia -> mismo mensaje
            current_app.logger.info("Solicitud olvide-pin para email no registrado: %s", email)
            flash(generic_msg, 'ok')
            return redirect(url_for('olvide_pin'))

        # invalidar códigos viejos no usados para este jugador
        try:
            db.session.query(PinReset).filter(
                PinReset.jugador_id == j.id,
                PinReset.used.is_(False),
                PinReset.expires_en > datetime.utcnow()
            ).update(
                {PinReset.expires_en: datetime.utcnow() - timedelta(seconds=1)},
                synchronize_session=False
            )
        except Exception as e:
            # No queremos romper el flujo, solo log
            current_app.logger.exception("Error invalidando PINs previos de %s: %s", email, e)

        code = _gen_code(6)
        pr = PinReset(
            jugador_id=j.id,
            code=code,
            created_en=datetime.utcnow(),
            expires_en=datetime.utcnow() + timedelta(minutes=15),
            used=False
        )
        db.session.add(pr)
        db.session.commit()

        # === URLs útiles para el email (botón y logo)
        try:
            confirmar_url = url_for('olvide_pin_confirmar', _external=True)
        except Exception:
            confirmar_url = request.url_root.rstrip('/') + '/olvide-pin-confirmar'

        # Resolver logo (priorizar PNG por compatibilidad)
        logo_url = None
        # 1) fuerza el path donde lo subiste
        try:
            logo_url = url_for('static', filename='logo/uplay.png', _external=True)
        except Exception:
            logo_url = None
        # 2) fallbacks por si cambia la ubicación
        if not logo_url:
            for candidate in (
                ('static', 'uplay.png'),
                ('static', 'logo/uplay.svg'),
                ('static', 'uplay.svg'),
            ):
                try:
                    logo_url = url_for(candidate[0], filename=candidate[1], _external=True)
                    if logo_url:
                        break
                except Exception:
                    continue

        current_app.logger.info("olvide-pin: logo_url=%s", logo_url)

        # === HTML con logo (soporta dark mode básico y botón)
        subject = f"UPLAY · Código para restablecer tu PIN ({code})"
        html_body = f"""\
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Restablecer PIN</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    @media (prefers-color-scheme: dark) {{
      body {{ background:#111111 !important; color:#ECECEC !important; }}
      .card {{ background:#1B1B1B !important; color:#ECECEC !important; }}
      .muted {{ color:#B5B9C0 !important; }}
      .code  {{ background:#0F2840 !important; color:#E6F0FF !important; }}
      .btn   {{ background:#2E7CF6 !important; color:#ffffff !important; }}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background:#F3F5F7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;">
    Tu código para restablecer el PIN: {code}. Válido por 15 minutos.
  </div>

  <table role="presentation" width="100%" style="width:100%;background:#F3F5F7;padding:24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:560px;">
          <tr>
            <td align="center" style="padding:8px 0 16px;">
              {(
                f'<img src="{logo_url}" alt="UPLAY" width="120" height="120" style="display:block;margin:0 auto;max-width:100%;height:auto;border:0;outline:0;">'
                if logo_url else
                '<div style="font-weight:700;font-size:20px;color:#0F172A;">UPLAY</div>'
              )}
            </td>
          </tr>

          <tr>
            <td class="card" style="background:#ffffff;border-radius:14px;padding:24px 22px;box-shadow:0 1px 3px rgba(16,24,40,0.08);">
              <h1 style="margin:0 0 8px;font-size:20px;line-height:1.3;color:#0F172A;">Restablecer tu PIN</h1>
              <p style="margin:0 0 14px;font-size:14px;line-height:1.6;color:#334155;">
                Hola <strong>{j.nombre_completo}</strong>, recibimos tu solicitud para restablecer el PIN.
              </p>

              <p style="margin:0 0 8px;font-size:14px;line-height:1.6;color:#334155;">
                Usá este código (expira en <strong>15 minutos</strong>):
              </p>

              <div role="text" aria-label="Código de verificación"
                   style="margin:12px 0 18px;font-size:24px;letter-spacing:4px;font-weight:700;text-align:center;background:#EEF2FF;color:#0F172A;border-radius:10px;padding:12px 16px;border:1px solid #E3E8EF;">
                {code}
              </div>

              <table role="presentation" align="center" style="margin:0 auto 16px;">
                <tr>
                  <td>
                    <a class="btn" href="{confirmar_url}"
                       style="display:inline-block;background:#2563EB;color:#ffffff;font-weight:600;font-size:14px;padding:12px 18px;border-radius:10px;text-decoration:none;">
                      Restablecer PIN
                    </a>
                  </td>
                </tr>
              </table>

              <p class="muted" style="margin:0 0 8px;font-size:12px;line-height:1.6;color:#64748B;">
                Si el botón no funciona, copiá y pegá este enlace en tu navegador:
              </p>
              <p style="margin:0 0 18px;word-break:break-all;font-size:12px;line-height:1.6;color:#334155;">
                {confirmar_url}
              </p>

              <hr style="border:none;border-top:1px solid #E5E7EB;margin:12px 0 16px;">

              <p class="muted" style="margin:0;font-size:12px;line-height:1.6;color:#64748B;">
                Si no solicitaste este cambio, podés ignorar este mensaje.
              </p>
            </td>
          </tr>

          <tr>
            <td align="center" style="padding:16px 6px;">
              <p class="muted" style="margin:0;font-size:12px;color:#94A3B8;">
                © {datetime.utcnow().year} UPLAY · Este email se generó automáticamente.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

        # Enviar email con el código (usa tu helper de SMTP ya configurado)
        try:
            subject = f"UPLAY · Código para restablecer tu PIN ({code})"
            body = (
                f"Hola {j.nombre_completo},\n\n"
                f"Usá este código para restablecer tu PIN (vale por 15 minutos):\n\n"
                f"{code}\n\n"
                f"Restablecer PIN:\n{confirmar_url}\n\n"
                "Si no solicitaste esto, ignorá este mensaje.\n"
            )
            ok = send_mail(
                subject=subject,
                body=body,           # fallback texto plano con URL visible
                html_body=html_body, # HTML con logo + botón
                to=[email]
            )
            current_app.logger.info("Resultado send_mail=%s; PIN enviado a %s (jugador_id=%s) logo_url=%s", ok, email, j.id, logo_url)
        except Exception:
            # No interrumpir el flujo de seguridad
            current_app.logger.exception("Error enviando PIN a %s", email)

        flash(generic_msg, 'ok')
        return redirect(url_for('olvide_pin'))

    # GET
    return render_template('olvide_pin_request.html')
    

@app.route('/olvide-pin/confirmar', methods=['GET', 'POST'])
def olvide_pin_confirmar():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        code = (request.form.get('code') or '').strip()
        pin1 = (request.form.get('pin1') or '').strip()
        pin2 = (request.form.get('pin2') or '').strip()

        if not email or not code or not pin1 or not pin2:
            flash('Completá email, código y el nuevo PIN (dos veces).', 'error')
            return redirect(url_for('olvide_pin_confirmar'))

        if pin1 != pin2:
            flash('Los PIN no coinciden.', 'error')
            return redirect(url_for('olvide_pin_confirmar'))

        if not (pin1.isdigit() and 4 <= len(pin1) <= 6):
            flash('El PIN debe tener 4–6 dígitos.', 'error')
            return redirect(url_for('olvide_pin_confirmar'))

        j = db.session.query(Jugador).filter(Jugador.email == email).first()
        if not j:
            flash('Código inválido o expirado.', 'error')  # genérico
            return redirect(url_for('olvide_pin_confirmar'))

        # Buscamos un reset válido (no usado, no vencido) con ese code
        pr = (db.session.query(PinReset)
              .filter(
                  PinReset.jugador_id == j.id,
                  PinReset.code == code,
                  PinReset.used.is_(False),
                  PinReset.expires_en >= datetime.utcnow()
              )
              .order_by(PinReset.created_en.desc())
              .first())

        if not pr:
            flash('Código inválido o expirado.', 'error')
            return redirect(url_for('olvide_pin_confirmar'))

        # Ok, actualizar PIN y marcar como usado
        j.pin = pin1
        pr.used = True
        db.session.commit()

        flash('Tu PIN fue actualizado. Ya podés iniciar sesión.', 'ok')
        return redirect(url_for('login'))

    # GET
    return render_template('olvide_pin_confirm.html')


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('jugador_id', None)
    flash('Sesión cerrada.', 'ok')
    return redirect(url_for('home'))

@app.route('/mi')
def mi_panel():
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión para ver tu panel.', 'error')
        return redirect(url_for('login'))

    # Parejas donde participa
    parejas_ids = [
        p.id for p in db.session.query(Pareja)
        .filter(or_(Pareja.jugador1_id == j.id, Pareja.jugador2_id == j.id))
        .all()
    ]

    # Partidos donde participa (ahora: TODO lo no JUGADO se considera "pendiente")
    partidos_pend = []
    partidos_jug = []
    if parejas_ids:
        partidos_q = (
            db.session.query(Partido)
            .filter(or_(Partido.pareja1_id.in_(parejas_ids),
                        Partido.pareja2_id.in_(parejas_ids)))
            .order_by(Partido.creado_en.desc())
        )
        for m in partidos_q.all():
            if m.estado == 'JUGADO':
                partidos_jug.append(m)
            else:
                partidos_pend.append(m)

    # Propuestas de resultado existentes para mis partidos pendientes
    propuestas_map = {}
    if partidos_pend:
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
        .filter(or_(
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
            or_(Desafio.estado == 'PENDIENTE', Desafio.estado == 'ACEPTADO_PARCIAL'),
            or_(
                and_(Desafio.rival1_id == j.id,
                     or_(Desafio.rival1_acepto.is_(False), Desafio.rival1_acepto.is_(None))),
                and_(Desafio.rival2_id == j.id,
                     or_(Desafio.rival2_acepto.is_(False), Desafio.rival2_acepto.is_(None)))
            )
        )
        .order_by(Desafio.creado_en.desc())
        .all()
    )

    # === PARTIDOS PARA RESPONDER INVITACIÓN
    partidos_para_responder = (
        db.session.query(Partido)
        .filter(
            Partido.estado == 'PENDIENTE',
            or_(
                and_(Partido.rival1_id == j.id, Partido.rival1_acepto.is_(None)),
                and_(Partido.rival2_id == j.id, Partido.rival2_acepto.is_(None))
            )
        )
        .order_by(Partido.creado_en.desc())
        .all()
    )

    # === PARTIDOS CREADOS POR MÍ esperando aceptación
    partidos_creados_pend = (
        db.session.query(Partido)
        .filter(
            Partido.estado == 'PENDIENTE',
            Partido.creador_id == j.id,
            or_(Partido.rival1_acepto.is_(None), Partido.rival2_acepto.is_(None))
        )
        .order_by(Partido.creado_en.desc())
        .all()
    )

    # Desafíos creados por mí
    desafios_creados_pend = (
        db.session.query(Desafio)
        .filter(
            Desafio.desafiante_id == j.id,
            or_(Desafio.estado == 'PENDIENTE', Desafio.estado == 'ACEPTADO_PARCIAL')
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
        .filter(PartidoAbierto.categoria_id == j.categoria_id)
        .order_by(PartidoAbierto.creado_en.desc())
        .all()
    )

    # === NUEVO: Suplencias ===
    # 1) Listado de suplencias del jugador (para el bloque "Suplencias activas")
    estados_activos = ['ABIERTO', 'LLENO', 'PARTIDO_CREADO']  # incluimos PARTIDO_CREADO si querés seguir viendo la suplencia
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

    # 2) Para el bloque "Unirme a un partido": necesitamos saber
    #    - si YA soy suplente en cada abierto mostrado
    #    - cuántos suplentes totales tiene cada abierto
    pa_ids = [pa.id for pa in abiertos_cat] if abiertos_cat else []
    mis_suplencias_pa_ids = set()
    suplentes_counts = {pid: 0 for pid in pa_ids}

    if pa_ids:
        # Traemos TODAS las suplencias de esos abiertos (sin filtrar por estado)
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

    # 1) "Listos para cargar"
    listos_para_cargar = []
    for m in partidos_pend:
        hubo_invitacion = (m.rival1_id is not None and m.rival2_id is not None)
        aceptado = (not hubo_invitacion) or (m.rival1_acepto == 1 and m.rival2_acepto == 1)
        tiene_propuesta = (m.id in propuestas_map)
        if aceptado and not tiene_propuesta and m.estado in ('PENDIENTE', 'POR_CONFIRMAR'):
            listos_para_cargar.append(m)

    # 2) Resultado propuesto y YO debo responder
    partidos_resultado_para_responder = [m for m in partidos_pend if m.necesita_respuesta_de(j.id)]

    # 3) Partidos sin resultado (candidatos a "Proponer resultado")
    partidos_sin_resultado = listos_para_cargar

    # Contadores
    cant_pend_sin_result = len(partidos_sin_resultado)
    cant_abiertos_mi_cat = len(abiertos_cat)
    puede_desafiar = bool(en_zona and cat_superior)

    cant_partidos_para_responder = len(partidos_para_responder)  # invitaciones
    cant_partidos_creados_pend = len(partidos_creados_pend)
    cant_partidos_resultado_para_responder = len(partidos_resultado_para_responder)

    return render_template(
        'mi.html',
        jugador=j,
        en_zona=en_zona,
        partidos_pend=partidos_pend,
        partidos_jug=partidos_jug[:5],          # últimos 5 jugados
        desafios_rel=desafios_rel[:10],         # últimos 10 desafíos (cualquier rol)
        desafios_para_responder=desafios_para_responder,
        desafios_creados_pend=desafios_creados_pend,
        desafios_creados_listos=desafios_creados_listos,

        # Partidos directos (invitaciones)
        partidos_para_responder=partidos_para_responder,
        partidos_creados_pend=partidos_creados_pend,
        cant_partidos_para_responder=cant_partidos_para_responder,
        cant_partidos_creados_pend=cant_partidos_creados_pend,

        # Propuestas de resultado
        propuestas_map=propuestas_map,

        # Abiertos y selects
        abiertos_cat=abiertos_cat[:10],
        cat_superior=cat_superior,
        rivales_superior=rivales_superior,
        jugadores_mi_cat=jugadores_mi_cat,

        # métricas
        cant_pend_sin_result=cant_pend_sin_result,
        cant_abiertos_mi_cat=cant_abiertos_mi_cat,
        puede_desafiar=puede_desafiar,

        # Resultado propuesto
        partidos_resultado_para_responder=partidos_resultado_para_responder,
        cant_partidos_resultado_para_responder=cant_partidos_resultado_para_responder,

        # Para botones "Proponer resultado"
        partidos_sin_resultado=partidos_sin_resultado,

        # Suplencias (bloque dedicado)
        suplencias=suplencias,
        cant_suplencias=cant_suplencias,

        # === NUEVO PARA UI de abiertos ===
        suplentes_counts=suplentes_counts,      # dict {pa_id: cantidad}
        mis_suplencias_pa_ids=mis_suplencias_pa_ids,  # set de pa_id donde YA soy suplente
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

def get_or_create_pareja(j1_id: int, j2_id: int, categoria_id: int):
    """Devuelve una Pareja (en esa categoría) con esos 2 jugadores, en cualquier orden.
       Si no existe, la crea con puntos informativos = promedio individual."""
    # normalizamos orden para buscar
    a, b = sorted([j1_id, j2_id])
    p = (db.session.query(Pareja)
         .filter(Pareja.categoria_id == categoria_id)
         .filter(
             db.or_(
                 db.and_(Pareja.jugador1_id == a, Pareja.jugador2_id == b),
                 db.and_(Pareja.jugador1_id == b, Pareja.jugador2_id == a)
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
PUBLIC_ENDPOINTS = {'home', 'login', 'alta_publica', 'static', 'ranking', 'categorias_list', 'olvide_pin',
    'olvide_pin_confirmar',}  # si querés sumar 'ranking', agregalo acá

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
    }

    recientes_partidos = (db.session.query(Partido)
                          .order_by(Partido.creado_en.desc())
                          .limit(5).all())
    recientes_abiertos = (db.session.query(PartidoAbierto)
                          .order_by(PartidoAbierto.creado_en.desc())
                          .limit(5).all())

    return render_template('admin.html',
                           counts=counts,
                           recientes_partidos=recientes_partidos,
                           recientes_abiertos=recientes_abiertos)

@app.route('/admin/solicitudes')
@admin_required
def admin_solicitudes_list():
    pend = (db.session.query(SolicitudAlta)
            .filter_by(estado='PENDIENTE')
            .order_by(SolicitudAlta.creado_en.desc())
            .all())
    hist = (db.session.query(SolicitudAlta)
            .filter(SolicitudAlta.estado != 'PENDIENTE')
            .order_by(SolicitudAlta.creado_en.desc())
            .limit(50).all())
    return render_template('admin_solicitudes.html', pendientes=pend, historial=hist)

@app.route('/admin/solicitudes/<int:sid>/aprobar', methods=['GET', 'POST'])
@admin_required
def admin_solicitudes_aprobar(sid):
    s = get_or_404(SolicitudAlta, sid)
    if s.estado != 'PENDIENTE':
        flash('Esta solicitud ya fue procesada.', 'error')
        return redirect(url_for('admin_solicitudes_list'))

    if request.method == 'POST':
        puntos = request.form.get('puntos', type=int)
        # pin enviado por el form ya no se usa (opción 1)
        _pin_ignorado = (request.form.get('pin') or '').strip()

        # Validaciones básicas
        cat = s.categoria
        if not cat:
            flash('La categoría de la solicitud no es válida.', 'error')
            return redirect(url_for('admin_solicitudes_list'))

        if puntos is None or not (cat.puntos_min <= puntos <= cat.puntos_max):
            flash(f'Los puntos deben estar entre {cat.puntos_min} y {cat.puntos_max}.', 'error')
            return redirect(url_for('admin_solicitudes_aprobar', sid=s.id))

        # Evitar duplicar email en Jugadores
        if s.email:
            ya = db.session.query(Jugador).filter(Jugador.email == s.email).first()
            if ya:
                flash(f'Ya existe un jugador con el email {s.email}. No se puede duplicar.', 'error')
                return redirect(url_for('admin_solicitudes_list'))

        # Crear jugador activo (sin PIN inicial; lo creará con el código)
        j = Jugador(
            nombre_completo=s.nombre_completo,
            email=s.email,
            telefono=s.telefono,
            puntos=puntos,
            categoria_id=s.categoria_id,
            activo=True
            # no seteamos 'pin' aquí (opción 1)
        )
        db.session.add(j)
        db.session.flush()  # obtener j.id antes del commit para el PinReset

        # Generar código de activación (PinReset) - vence en 24 h
        code = _gen_code(6)
        pr = PinReset(
            jugador_id=j.id,
            code=code,
            created_en=datetime.utcnow(),
            expires_en=datetime.utcnow() + timedelta(hours=24),
            used=False
        )
        db.session.add(pr)

        # Cerrar solicitud
        s.estado = 'APROBADA'
        s.resuelto_en = datetime.utcnow()
        db.session.commit()

        # URLs para el email
        try:
            confirmar_url = url_for('olvide_pin_confirmar', _external=True)
            login_url = url_for('login', _external=True)
        except Exception:
            confirmar_url = request.url_root.rstrip('/') + '/olvide-pin-confirmar'
            login_url = request.url_root.rstrip('/') + '/login'

        subject = "¡Bienvenido a UPLAY! Activá tu cuenta creando tu PIN"
        # Fallback texto plano (si no renderiza HTML)
        body = (
            f"Hola {j.nombre_completo},\n\n"
            "¡Tu alta fue aprobada! Para empezar, creá tu PIN.\n\n"
            f"Código: {code} (vence en 24 horas)\n"
            f"Crear PIN: {confirmar_url}\n\n"
            f"También podés iniciar sesión luego aquí: {login_url}\n\n"
            f"Categoría inicial: {j.categoria.nombre if j.categoria else '-'}\n"
            f"Puntos iniciales: {j.puntos}\n\n"
            "— Equipo UPLAY"
        )

        # HTML con logo inline (CID) + botón
        html_body = f"""\
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Bienvenido a UPLAY</title>
  <style>
    @media (prefers-color-scheme: dark) {{
      body {{ background:#111111 !important; color:#ECECEC !important; }}
      .card {{ background:#1B1B1B !important; color:#ECECEC !important; }}
      .muted {{ color:#B5B9C0 !important; }}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background:#F3F5F7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0F172A;">
  <table role="presentation" width="100%" style="width:100%;background:#F3F5F7;padding:24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:560px;">
          <tr>
            <td align="center" style="padding:8px 0 16px;">
              <img src="cid:uplay-logo" alt="UPLAY" width="120" style="display:block;margin:0 auto;max-width:100%;height:auto;border:0;outline:0;">
            </td>
          </tr>
          <tr>
            <td class="card" style="background:#ffffff;border-radius:14px;padding:24px 22px;box-shadow:0 1px 3px rgba(16,24,40,0.08);">
              <h1 style="margin:0 0 8px;font-size:20px;line-height:1.3;">¡Bienvenido/a a UPLAY!</h1>
              <p style="margin:0 0 12px;color:#334155;">Hola <strong>{j.nombre_completo}</strong>, para empezar creá tu PIN.</p>
              <p style="margin:0 0 8px;color:#334155;">Usá este código (vence en <strong>24 horas</strong>):</p>
              <div style="margin:8px 0 16px;font-size:24px;letter-spacing:4px;font-weight:700;text-align:center;background:#EEF2FF;color:#0F172A;border-radius:10px;padding:12px 16px;border:1px solid #E3E8EF;">
                {code}
              </div>
              <div style="text-align:center;margin-bottom:16px;">
                <a href="{confirmar_url}" style="display:inline-block;background:#2563EB;color:#ffffff;font-weight:600;font-size:14px;padding:12px 18px;border-radius:10px;text-decoration:none;">
                  Crear mi PIN
                </a>
              </div>
              <p class="muted" style="margin:0 0 8px;font-size:12px;color:#64748B;">Si el botón no funciona, copiá y pegá este enlace:</p>
              <p style="margin:0 0 16px;word-break:break-all;font-size:12px;color:#334155;">{confirmar_url}</p>

              <hr style="border:none;border-top:1px solid #E5E7EB;margin:12px 0 16px;">

              <p style="margin:0 0 6px;color:#334155;">Datos iniciales</p>
              <ul style="margin:0 0 10px 18px;padding:0;color:#334155;">
                <li>Categoría: {j.categoria.nombre if j.categoria else '-'}</li>
                <li>Puntos: {j.puntos}</li>
              </ul>
              <p class="muted" style="margin:0;font-size:12px;color:#64748B;">Luego podrás iniciar sesión aquí: {login_url}</p>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:16px 6px;">
              <p class="muted" style="margin:0;font-size:12px;color:#94A3B8;">© {datetime.utcnow().year} UPLAY</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

        # Enviar email (logo inline via CID)
        try:
            send_mail(
                subject=subject,
                body=body,                 # fallback texto plano
                html_body=html_body,       # HTML con botón + código + logo
                to=[j.email],
                inline_images={"uplay-logo": "static/logo/uplay.png"}  # usa el PNG que subiste
            )
            flash(f'Jugador creado y notificado por email: {j.nombre_completo}.', 'ok')
        except Exception as e:
            flash(f'Jugador creado, pero falló el envío de email: {e}', 'warning')

        return redirect(url_for('admin_solicitudes_list'))

    # GET -> sugerir puntos = puntos_max
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
    db.session.delete(pa)
    db.session.commit()
    flash('Abierto eliminado.', 'ok')
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

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()

        if action == 'reopen':
            # Reabrir partido: borrar resultado y volver a PENDIENTE
            if partido.resultado:
                db.session.delete(partido.resultado)
            partido.estado = 'PENDIENTE'
            db.session.commit()
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
            flash('Resultado actualizado. (Ojo: puntos NO se recalcularon automáticamente)', 'ok')
            return redirect(url_for('partidos_list'))

        else:
            flash('Acción inválida.', 'error')
            return redirect(url_for('admin_partido_resultado_editar', partido_id=partido.id))

    # GET -> mostrar formulario con datos actuales
    return render_template('admin_partido_resultado_edit.html', partido=partido, p1=p1, p2=p2)



if __name__ == '__main__':
    app.run(debug=True)
