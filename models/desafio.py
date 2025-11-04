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
