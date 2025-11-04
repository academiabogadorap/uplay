from flask import Blueprint, render_template, request, redirect, url_for, flash

bp = Blueprint('${f%_routes}', __name__)

# --- Rutas asignadas a este módulo se agregarán aquí automáticamente ---
@app.route('/admin/solicitudes')
@admin_required
def admin_solicitudes_list():
    from sqlalchemy import func

@app.route('/admin/solicitudes/<int:sid>/aprobar', methods=['GET', 'POST'])
@admin_required
def admin_solicitudes_aprobar(sid):
    """Aprobación de solicitud de alta — crea jugador, asigna PIN y notifica por email."""
    from datetime import datetime, timezone
    import secrets, string, logging

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

@app.route('/admin/partidos/<int:partido_id>/eliminar', methods=['POST'])
@admin_required
def admin_partidos_eliminar(partido_id):
    p = get_or_404(Partido, partido_id)

@app.route('/admin/desafios/<int:desafio_id>/eliminar', methods=['POST'])
@admin_required
def admin_desafios_eliminar(desafio_id):
    d = get_or_404(Desafio, desafio_id)

@app.route('/admin/partidos/<int:partido_id>/resultado/editar', methods=['GET', 'POST'])
@admin_required
def admin_partido_resultado_editar(partido_id):
    partido = get_or_404(Partido, partido_id)

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

@app.route('/admin/torneos/new_playoff', methods=['GET', 'POST'])
@admin_required
def admin_torneo_new_playoff():
    categorias = Categoria.query.all()

@app.route("/admin/torneos/<int:tid>/ver_roundrobin")
@admin_required
def admin_torneo_ver_roundrobin(tid):
    t = get_or_404(Torneo, tid)
    fases = t.fases or []
    zonas = []
    for f in fases:
        for g in f.grupos:
            partidos = db.session.query(TorneoPartido).filter_by(grupo_id=g.id).all()
            zonas.append({
                "nombre": g.nombre,
                "partidos": partidos
            })
    return render_template("admin_torneo_new_roundrobin.html", t=t, zonas=zonas)

@app.route('/admin/torneos/<int:tid>', methods=['GET'])
@admin_required
def admin_torneos_view(tid):
    # Importar modelos necesarios al inicio (evita UnboundLocalError)
    from app import (
        Torneo,
        TorneoInscripcion,
        TorneoPartido,
        TorneoPartidoLado,
        TorneoPartidoResultado,
        TorneoPartidoResultadoPropuesto,
        Jugador
    )

@app.route('/admin/torneos/<int:tid>/estado', methods=['POST'])
@admin_required
def admin_torneos_cambiar_estado(tid):
    t = get_or_404(Torneo, tid)

@app.route('/admin/torneos/<int:tid>/generar_fixture', methods=['POST'])
@admin_required
def admin_torneos_generar_fixture(tid):
    from sqlalchemy import and_, or_, func

@app.route('/admin/torneos/<int:tid>/generar_playoff_desde_zonas', methods=['POST'])
@admin_required
def admin_torneos_generar_playoff_desde_zonas(tid):
    from app import db, Torneo
    t = get_or_404(Torneo, tid)
    EST_EN_JUEGO = globals().get('EST_EN_JUEGO', 'EN_JUEGO')

@app.route('/admin/torneos/<int:tid>/generar_segunda_ronda', methods=['POST'])
@admin_required
def admin_torneos_generar_segunda_ronda(tid):
    from app import db, Torneo
    t = get_or_404(Torneo, tid)
    EST_EN_JUEGO = globals().get('EST_EN_JUEGO', 'EN_JUEGO')

@app.route('/admin/torneos/partidos/<int:pid>/resultado', methods=['POST'])
@admin_required
def admin_torneo_partido_resultado(pid):
    m = get_or_404(TorneoPartido, pid)
    # MVP: almacenar resultado como texto libre o sets JSON
    resultado_txt = (request.form.get('resultado') or '').strip()
    ganador_id = request.form.get('ganador_participante_id', type=int)

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

@app.route('/admin/torneos/<int:tid>/abrir_inscripcion', methods=['POST'])
@admin_required
def admin_torneo_abrir_inscripcion(tid):
    t = get_or_404(Torneo, tid)

@app.route('/admin/torneos/<int:tid>/cerrar_inscripcion', methods=['POST'])
@admin_required
def admin_torneo_cerrar_inscripcion(tid):
    t = get_or_404(Torneo, tid)

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

