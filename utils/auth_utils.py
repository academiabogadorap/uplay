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
