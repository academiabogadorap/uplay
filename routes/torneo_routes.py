from flask import Blueprint, render_template, request, redirect, url_for, flash

bp = Blueprint('${f%_routes}', __name__)

# --- Rutas asignadas a este módulo se agregarán aquí automáticamente ---
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

@app.route('/torneos/<int:tid>/inscribirme', methods=['GET', 'POST'])
def torneo_inscribirme(tid):
    # Requiere jugador logueado y activo
    j = get_current_jugador()
    if not j or not j.activo:
        flash('Necesitás iniciar sesión con un jugador activo.', 'error')
        return redirect(url_for('login'))

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

@app.route('/torneos', methods=['GET'])
def torneos_public_list():
    # Filtros de querystring
    estado = (request.args.get('estado') or '').upper().strip()
    categoria_id = request.args.get('categoria', type=int)

@app.route('/torneos/<int:torneo_id>', methods=['GET'])
def torneo_public_detail(torneo_id: int):
    # Obtener torneo o 404
    t = Torneo.query.get_or_404(torneo_id)

@app.route('/torneos/<int:torneo_id>/fixture', methods=['GET'])
def torneo_public_fixture(torneo_id: int):
    t = Torneo.query.get_or_404(torneo_id)
    if not getattr(t, 'es_publico', False) and not session.get('is_admin'):
        abort(404)

@app.route('/torneos/partidos/<int:partido_id>', methods=['GET'])
def torneo_partido_detalle(partido_id: int):
    # Partido o 404 (usa tu helper 2.x-friendly)
    p = get_or_404(TorneoPartido, partido_id)

@app.route('/torneos/partidos/<int:partido_id>/proponer', methods=['GET', 'POST'])
def torneo_partido_proponer(partido_id: int):
    """Crear/editar la propuesta de resultado de UN partido de torneo (aislado por partido_id)."""
    p = get_or_404(TorneoPartido, partido_id)
    j = get_current_jugador()
    if not j:
        abort(403)

@app.route('/torneos/partidos/<int:partido_id>/responder', methods=['GET', 'POST'])
def torneo_partido_responder(partido_id: int):
    """Responder una propuesta de resultado de UN partido de torneo (aislado por partido_id)."""
    p = get_or_404(TorneoPartido, partido_id)
    j = get_current_jugador()
    if not j:
        abort(403)

@app.route('/torneos/<int:torneo_id>/tabla')
def torneo_public_tabla(torneo_id):
    from sqlalchemy import or_ as sa_or

