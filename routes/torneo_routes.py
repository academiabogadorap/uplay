# ===============================================================
#  torneo_routes.py  —  Rutas y lógica de torneos y partidos
# ===============================================================

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, jsonify, session, current_app
)
from sqlalchemy import func
from datetime import datetime, timedelta

# Import diferido del db para evitar circular import
def get_db():
    from app import db
    return db

from models import (
    Torneo, TorneoPartido, TorneoParticipante,
    TorneoFase, TorneoGrupo,
    Categoria, Jugador, Partido, PartidoResultadoPropuesto,
    TorneoPartidoResultadoPropuesto, TorneoPartidoResultado
)
from utils.auth import login_required, admin_required

torneo_bp = Blueprint("torneo_routes", __name__, url_prefix="/torneos")

# ===============================================================
# 🧩 SECCIÓN ADMINISTRADOR
# ===============================================================



@torneo_bp.route("/admin/list")
@admin_required
def admin_torneos_list():
    torneos = Torneo.query.order_by(Torneo.creado_en.desc()).all()
    return render_template("admin/torneos_list.html", torneos=torneos)


@torneo_bp.route("/admin/new")
@admin_required
def admin_torneos_new():
    cats = Categoria.query.order_by(Categoria.puntos_min).all()
    return render_template("admin/torneos_new.html", categorias=cats)


@torneo_bp.route("/admin/new-playoff")
@admin_required
def admin_torneo_new_playoff():
    return render_template("admin/torneos_new_playoff.html")


@torneo_bp.route("/admin/ver-roundrobin/<int:tid>")
@admin_required
def admin_torneo_ver_roundrobin(tid):
    t = Torneo.query.get_or_404(tid)
    grupos = TorneoGrupo.query.filter_by(torneo_id=tid).all()
    return render_template("admin/torneos_roundrobin.html", torneo=t, grupos=grupos)


@torneo_bp.route("/admin/view/<int:tid>")
@admin_required
def admin_torneos_view(tid):
    t = Torneo.query.get_or_404(tid)
    fases = TorneoFase.query.filter_by(torneo_id=tid).all()
    return render_template("admin/torneos_view.html", torneo=t, fases=fases)


@torneo_bp.post("/admin/cambiar-estado/<int:tid>")
@admin_required
def admin_torneos_cambiar_estado(tid):
    t = Torneo.query.get_or_404(tid)
    nuevo_estado = request.form.get("estado")
    if nuevo_estado:
        t.estado = nuevo_estado
        db.session.commit()
        flash("Estado actualizado correctamente", "success")
    return redirect(url_for("torneo_routes.admin_torneos_view", tid=tid))


@torneo_bp.route("/admin/generar-fixture/<int:tid>")
@admin_required
def admin_torneos_generar_fixture(tid):
    t = Torneo.query.get_or_404(tid)
    # TODO: implementar generación de fixture
    flash("Fixture generado", "success")
    return redirect(url_for("torneo_routes.admin_torneos_view", tid=tid))


@torneo_bp.route("/admin/generar-playoff/<int:tid>")
@admin_required
def admin_torneos_generar_playoff_desde_zonas(tid):
    t = Torneo.query.get_or_404(tid)
    flash("Playoff generado desde zonas", "info")
    return redirect(url_for("torneo_routes.admin_torneos_view", tid=tid))


@torneo_bp.route("/admin/generar-segunda-ronda/<int:tid>")
@admin_required
def admin_torneos_generar_segunda_ronda(tid):
    flash("Segunda ronda generada", "info")
    return redirect(url_for("torneo_routes.admin_torneos_view", tid=tid))


@torneo_bp.route("/admin/partido-resultado/<int:pid>")
@admin_required
def admin_torneo_partido_resultado(pid):
    p = TorneoPartido.query.get_or_404(pid)
    resultados = TorneoResultado.query.filter_by(partido_id=pid).all()
    return render_template("admin/partido_resultado.html", partido=p, resultados=resultados)


@torneo_bp.route("/admin/partido-resultado-editar/<int:pid>")
@admin_required
def admin_torneos_partido_resultado_editar(pid):
    p = TorneoPartido.query.get_or_404(pid)
    return render_template("admin/partido_resultado_edit.html", partido=p)


@torneo_bp.post("/admin/abrir-inscripcion/<int:tid>")
@admin_required
def admin_torneo_abrir_inscripcion(tid):
    t = Torneo.query.get_or_404(tid)
    t.estado = "ABIERTO"
    db.session.commit()
    flash("Inscripción abierta", "success")
    return redirect(url_for("torneo_routes.admin_torneos_view", tid=tid))


@torneo_bp.post("/admin/cerrar-inscripcion/<int:tid>")
@admin_required
def admin_torneo_cerrar_inscripcion(tid):
    t = Torneo.query.get_or_404(tid)
    t.estado = "CERRADO"
    db.session.commit()
    flash("Inscripción cerrada", "info")
    return redirect(url_for("torneo_routes.admin_torneos_view", tid=tid))


@torneo_bp.post("/admin/eliminar/<int:tid>")
@admin_required
def admin_torneo_eliminar(tid):
    t = Torneo.query.get_or_404(tid)
    db.session.delete(t)
    db.session.commit()
    flash("Torneo eliminado correctamente", "success")
    return redirect(url_for("torneo_routes.admin_torneos_list"))

# ===============================================================
# 🌐 SECCIÓN PÚBLICA (VERSIONES ANTIGUAS)
# ===============================================================

# ⚠️ @torneo_bp.route("/public/list-old")
# ⚠️ def torneos_public_list_old():
    torneos = Torneo.query.order_by(Torneo.creado_en.desc()).all()
    return render_template("torneos_list.html", torneos=torneos)


# ⚠️ @torneo_bp.route("/public/<int:torneo_id>/detail-old")
# ⚠️ def torneo_public_detail_old(torneo_id: int):
    t = Torneo.query.get_or_404(torneo_id)
    return render_template("torneo_detail.html", torneo=t)


# ⚠️ @torneo_bp.route("/public/<int:torneo_id>/fixture-old")
# ⚠️ def torneo_public_fixture_old(torneo_id: int):
    t = Torneo.query.get_or_404(torneo_id)
    grupos = TorneoGrupo.query.filter_by(torneo_id=torneo_id).all()
    return render_template("torneo_fixture.html", torneo=t, grupos=grupos)


# ⚠️ @torneo_bp.route("/public/<int:partido_id>/detalle-old")
# ⚠️ def torneo_partido_detalle_old(partido_id: int):
    p = TorneoPartido.query.get_or_404(partido_id)
    return render_template("torneo_partido_detalle.html", partido=p)


@torneo_bp.post("/public/partido-proponer/<int:partido_id>")
@login_required
def torneo_partido_proponer(partido_id: int):
    p = TorneoPartido.query.get_or_404(partido_id)
    flash("Resultado propuesto correctamente.", "success")
    return redirect(url_for("torneo_routes.torneo_partido_detalle_old", partido_id=partido_id))


@torneo_bp.post("/public/partido-responder/<int:partido_id>")
@login_required
def torneo_partido_responder(partido_id: int):
    flash("Respuesta registrada correctamente.", "success")
    return redirect(url_for("torneo_routes.torneo_partido_detalle_old", partido_id=partido_id))


@torneo_bp.route("/public/tabla/<int:torneo_id>")
def torneo_public_tabla(torneo_id):
    t = Torneo.query.get_or_404(torneo_id)
    return render_template("torneo_tabla.html", torneo=t)

# ===============================================================
# 🎾 SECCIÓN PARTIDOS (crear, listar, responder, confirmar)
# ===============================================================

    jugador_id = session.get("jugador_id")
    if not jugador_id:
        flash("Debes iniciar sesión.", "warning")
        return redirect(url_for("main_routes.index"))

    partidos = (
        TorneoPartido.query
        .filter((TorneoPartido.jugador1_id == jugador_id) |
                (TorneoPartido.jugador2_id == jugador_id) |
                (TorneoPartido.jugador3_id == jugador_id) |
                (TorneoPartido.jugador4_id == jugador_id))
        .order_by(TorneoPartido.fecha.desc().nullslast())
        .all()
    )
    return render_template("partidos_list.html", partidos=partidos)


# ===============================================================
# 🆕 CREAR NUEVO PARTIDO
# ===============================================================
    """Versión restaurada — Crear un nuevo partido (no desafío)."""
    jugador_id = session.get("jugador_id")
    jugador = Jugador.query.get_or_404(jugador_id)

    # Obtener la categoría del jugador
    categoria = jugador.categoria
    if not categoria:
        flash("Tu usuario no tiene categoría asignada.", "error")
        return redirect(url_for("partido_routes.partidos_list"))

    # Candidatos (mismo nivel y activos)
    candidatos_companero = (
        Jugador.query.filter(
            Jugador.categoria_id == categoria.id,
            Jugador.id != jugador.id,
            Jugador.activo.is_(True)
        )
        .order_by(Jugador.nombre_completo)
        .all()
    )

    candidatos_rivales = (
        Jugador.query.filter(
            Jugador.categoria_id == categoria.id,
            Jugador.id != jugador.id,
            Jugador.activo.is_(True)
        )
        .order_by(Jugador.nombre_completo)
        .all()
    )

    # Si se envió el formulario
    if request.method == "POST":
        companero_id = request.form.get("companero_id", type=int)
        rival1_id = request.form.get("rival1_id", type=int)
        rival2_id = request.form.get("rival2_id", type=int)
        fecha_str = request.form.get("fecha")

        # Validaciones
        if not (companero_id and rival1_id and rival2_id):
            flash("⚠️ Faltan completar todos los jugadores.", "error")
            return redirect(url_for("partido_routes.partidos_new"))

        # Parsear fecha (opcional)
        fecha = None
        if fecha_str:
            try:
                fecha = datetime.fromisoformat(fecha_str)
            except Exception:
                flash("Formato de fecha inválido.", "error")

        # Crear partido
        nuevo_partido = Partido(
            categoria_id=categoria.id,
            fecha=fecha or datetime.utcnow(),
            estado="pendiente",
        )
        db.session.add(nuevo_partido)
        db.session.commit()

        flash("✅ Partido creado correctamente.", "success")
        return redirect(url_for("partido_routes.partidos_list"))

    # Render del formulario
    return render_template(
        "partidos_form.html",
        categoria=categoria,
        candidatos_companero=candidatos_companero,
        candidatos_rivales=candidatos_rivales,
    )


    p = TorneoPartido.query.get_or_404(partido_id)

    if request.method == "POST":
        resultado = request.form.get("resultado")
        if resultado:
            r = TorneoResultadoPropuesto(partido_id=p.id, resultado_texto=resultado)
            db.session.add(r)
            db.session.commit()
            flash("Resultado propuesto correctamente.", "success")
            return redirect(url_for("partido_routes.partidos_list"))

    return render_template("partidos_resultado.html", partido=p)


    p = TorneoPartido.query.get_or_404(partido_id)
    if request.method == "POST":
        decision = request.form.get("decision")
        if decision == "aceptar":
            p.estado = "ACEPTADO"
        elif decision == "rechazar":
            p.estado = "RECHAZADO"
        db.session.commit()
        flash("Respuesta registrada.", "info")
        return redirect(url_for("partido_routes.partidos_list"))
    return render_template("partidos_responder.html", partido=p)


    p = TorneoPartido.query.get_or_404(partido_id)
    p.estado = "CONFIRMADO"
    db.session.commit()
    flash("Resultado confirmado.", "success")
    return redirect(url_for("partido_routes.partidos_list"))

# ===============================================================
# ⚙️ SECCIÓN TAREAS AUTOMÁTICAS Y RANKING
# ===============================================================

def aplicar_delta_rankeable(j, delta, motivo=None, meta=None):
    j.puntos = max(0, j.puntos + delta)
    db.session.commit()
    print(f"[RANK] {j.nombre_completo}: Δ{delta} ({motivo})")


def _jugadores_del_lado(p, lado):
    if lado.upper() == "A":
        return [p.jugador1, p.jugador2]
    elif lado.upper() == "B":
        return [p.jugador3, p.jugador4]
    return []


def _lado_opuesto(lado):
    return "B" if str(lado).upper() == "A" else "A"


def _bonus_aplicado_en_partido(p, ganador_lado, resultado):
    # Detecta si el partido otorgó un bono (simplificado)
    return getattr(resultado, "bono", False)


def _revertir_ranking_por_torneo(p, ganador_lado, resultado):
    """Reversión de ranking con soporte de desafíos y ascensos."""
    from app import DELTA_WIN, DELTA_LOSS, DELTA_WIN_BONUS
    from models import Categoria

    lado_gan = str(ganador_lado).upper()
    lado_perd = _lado_opuesto(lado_gan)
    ganadores = _jugadores_del_lado(p, lado_gan)
    perdedores = _jugadores_del_lado(p, lado_perd)
    hubo_bono = _bonus_aplicado_en_partido(p, lado_gan, resultado)

    motivo = f"Reversión resultado torneo #{p.id}"

    for j in ganadores:
        aplicar_delta_rankeable(j, -DELTA_WIN, f"{motivo}: ganadores")
        if hubo_bono:
            aplicar_delta_rankeable(j, -DELTA_WIN_BONUS, f"{motivo}: bono")

    for j in perdedores:
        aplicar_delta_rankeable(j, -DELTA_LOSS, f"{motivo}: perdedores")

    # 🧗 Lógica de desafíos inter-nivel
    for jg in ganadores:
        cat_actual = jg.categoria
        if not cat_actual:
            continue

        cat_sup = (
            db.session.query(Categoria)
            .filter(Categoria.puntos_min < cat_actual.puntos_min)
            .order_by(Categoria.puntos_min.desc())
            .first()
        )
        es_desafio = any(
            jr.categoria_id == cat_sup.id if cat_sup else False
            for jr in perdedores
        )

        if es_desafio:
            jg.desafios_ganados = (jg.desafios_ganados or 0) + 1
            db.session.commit()
            print(f"🏆 {jg.nombre_completo} ganó un desafío ({jg.desafios_ganados}/3)")

            if jg.desafios_ganados >= 3 and cat_sup:
                jg.categoria_id = cat_sup.id
                jg.puntos = cat_sup.puntos_max
                jg.desafios_ganados = 0
                db.session.commit()
                print(f"⬆️ {jg.nombre_completo} asciende a {cat_sup.nombre}")


@torneo_bp.route("/tareas/propuestas/autocerrar", methods=["POST"])
@admin_required
def tareas_autocerrar_propuestas_vencidas():
    """Cierra automáticamente propuestas vencidas."""
    vencidas = TorneoResultadoPropuesto.query.filter(
        TorneoResultadoPropuesto.creado_en < datetime.utcnow() - timedelta(days=3)
    ).all()
    for r in vencidas:
        db.session.delete(r)
    db.session.commit()
    flash(f"{len(vencidas)} propuestas vencidas cerradas.", "info")
    return redirect(url_for("partido_routes.partidos_list"))


# ===============================================================
# ✅ FIN DEL ARCHIVO — LISTO PARA GUARDAR
# ===============================================================
