from flask import (
    Blueprint, render_template, request,
    redirect, url_for, flash, session
)
from datetime import datetime
from extensions import db
from models import Jugador, Partido
from utils.decorators import login_required

# ============================================================
# 🎾 PARTIDOS BLUEPRINT (rutas raíz /partidos)
# ============================================================

partido_bp = Blueprint("partido_routes", __name__, url_prefix="/partidos")


# 📋 LISTADO DE PARTIDOS
@partido_bp.route("/")
@login_required
def partidos_list():
    partidos = Partido.query.order_by(Partido.fecha.desc()).all()
    return render_template("partidos_list.html", partidos=partidos)


# ➕ CREAR NUEVO PARTIDO
@partido_bp.route("/nuevo", methods=["GET", "POST"])
@login_required
def partidos_new():
    jugador_id = session.get("jugador_id")
    jugador = Jugador.query.get_or_404(jugador_id)
    categoria = jugador.categoria

    candidatos_companero = (
        Jugador.query.filter(
            Jugador.categoria_id == categoria.id,
            Jugador.id != jugador.id,
            Jugador.activo.is_(True)
        ).order_by(Jugador.nombre_completo).all()
    )

    candidatos_rivales = (
        Jugador.query.filter(
            Jugador.categoria_id == categoria.id,
            Jugador.id != jugador.id,
            Jugador.activo.is_(True)
        ).order_by(Jugador.nombre_completo).all()
    )

    if request.method == "POST":
        companero_id = request.form.get("companero_id", type=int)
        rival1_id = request.form.get("rival1_id", type=int)
        rival2_id = request.form.get("rival2_id", type=int)
        fecha_str = request.form.get("fecha")

        if not (companero_id and rival1_id and rival2_id):
            flash("⚠️ Faltan completar todos los jugadores.", "error")
            return redirect(url_for("partido_routes.partidos_new"))

        try:
            fecha = datetime.fromisoformat(fecha_str) if fecha_str else datetime.utcnow()
        except Exception:
            flash("Formato de fecha inválido.", "error")
            fecha = datetime.utcnow()

        nuevo = Partido(
            categoria_id=categoria.id,
            fecha=fecha,
            estado="pendiente"
        )
        db.session.add(nuevo)
        db.session.commit()

        flash("✅ Partido creado correctamente.", "success")
        return redirect(url_for("partido_routes.partidos_list"))

    return render_template(
        "partidos_form.html",
        categoria=categoria,
        candidatos_companero=candidatos_companero,
        candidatos_rivales=candidatos_rivales,
    )


# 📝 RESULTADO
@partido_bp.route("/<int:partido_id>/resultado", methods=["GET", "POST"])
@login_required
def partidos_resultado(partido_id):
    partido = Partido.query.get_or_404(partido_id)
    return render_template("partidos_resultado.html", partido=partido)


# 🔁 RESPONDER
@partido_bp.route("/<int:partido_id>/responder", methods=["GET", "POST"])
@login_required
def partidos_responder(partido_id):
    partido = Partido.query.get_or_404(partido_id)
    return render_template("partidos_responder.html", partido=partido)


# ✅ CONFIRMAR RESULTADO
@partido_bp.route("/<int:partido_id>/confirmar-resultado", methods=["POST"])
@login_required
def partidos_confirmar_resultado(partido_id):
    partido = Partido.query.get_or_404(partido_id)
    partido.estado = "confirmado"
    db.session.commit()
    flash("✅ Resultado confirmado.", "success")
    return redirect(url_for("partido_routes.partidos_list"))
