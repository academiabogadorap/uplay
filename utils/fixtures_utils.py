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

def generar_zonas_con_llave(torneo_id: int, zonas: int, parejas_por_zona: int = 4) -> int:
    """
    Genera una fase de grupos tipo 'mini llave' (1v2, 3v4 → ganadores y perdedores)
    para varios grupos (zonas). Cada zona genera 2 partidos iniciales.
    """
    from sqlalchemy import func
    t = db.session.get(Torneo, torneo_id)
    if not t:
        raise RuntimeError("Torneo no encontrado")

    participantes = (
        db.session.query(TorneoParticipante)
        .filter_by(torneo_id=torneo_id)
        .order_by(TorneoParticipante.id.asc())
        .all()
    )
    total = len(participantes)
    if total < zonas * parejas_por_zona:
        raise RuntimeError(f"No hay suficientes inscripciones para {zonas} zonas de {parejas_por_zona} parejas (total={total}).")

    creados = 0
    for i in range(zonas):
        grupo = _get_or_create_grupo(t, None, f"Zona {chr(65+i)}", i+1)
        subset = participantes[i*parejas_por_zona:(i+1)*parejas_por_zona]
        if len(subset) < 4:
            continue

        a, b, c, d = subset

        # Ronda 1 - cruces iniciales
        db.session.add(TorneoPartido(
            torneo_id=torneo_id, grupo_id=grupo.id,
            participante_a_id=a.id, participante_b_id=b.id,
            ronda=1, estado='PENDIENTE'
        ))
        db.session.add(TorneoPartido(
            torneo_id=torneo_id, grupo_id=grupo.id,
            participante_a_id=c.id, participante_b_id=d.id,
            ronda=1, estado='PENDIENTE'
        ))
        creados += 2

    db.session.commit()
    return creados


def generar_partidos_ganadores_perdedores(torneo_id: int) -> int:
    """
    Crea los partidos de ganadores vs ganadores y perdedores vs perdedores
    para cada zona que ya tenga disputados los cruces iniciales.
    """
    from sqlalchemy import func

    partidos = (
        db.session.query(TorneoPartido)
        .filter(TorneoPartido.torneo_id == torneo_id)
        .filter(TorneoPartido.ronda == 1)
        .all()
    )

    creados = 0
    zonas = {}
    for p in partidos:
        zonas.setdefault(p.grupo_id, []).append(p)

    for grupo_id, lista in zonas.items():
        if len(lista) != 2:
            continue
        p1, p2 = lista
        if not (p1.ganador_id and p2.ganador_id and p1.perdedor_id and p2.perdedor_id):
            continue

        # Partido de ganadores
        db.session.add(TorneoPartido(
            torneo_id=torneo_id, grupo_id=grupo_id,
            participante_a_id=p1.ganador_id, participante_b_id=p2.ganador_id,
            ronda=2, estado='PENDIENTE'
        ))
        # Partido de perdedores
        db.session.add(TorneoPartido(
            torneo_id=torneo_id, grupo_id=grupo_id,
            participante_a_id=p1.perdedor_id, participante_b_id=p2.perdedor_id,
            ronda=2, estado='PENDIENTE'
        ))
        creados += 2

    db.session.commit()
    return creados



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
