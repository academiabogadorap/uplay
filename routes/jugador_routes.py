from flask import Blueprint, render_template, request, redirect, url_for, flash

bp = Blueprint('${f%_routes}', __name__)

# --- Rutas asignadas a este módulo se agregarán aquí automáticamente ---
@app.route('/jugadores')
def jugadores_list():
    from flask import g
    from sqlalchemy import func  # para DISTINCT en provincias/ciudades

@app.route('/jugadores/nuevo', methods=['GET', 'POST'])
def jugadores_new():
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()

@app.route('/jugadores/<int:jugador_id>/editar', methods=['GET', 'POST'])
def jugadores_edit(jugador_id):
    j = get_or_404(Jugador, jugador_id)
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()

@app.route('/jugadores/<int:jugador_id>/eliminar', methods=['POST'])
@admin_required
def jugadores_delete(jugador_id):
    j = get_or_404(Jugador, jugador_id)

@app.route('/jugadores/<int:jugador_id>/desactivar', methods=['POST'])
@admin_required
def jugadores_deactivate(jugador_id):
    j = get_or_404(Jugador, jugador_id)

@app.route('/jugadores/<int:jugador_id>/reactivar', methods=['POST'])
@admin_required
def jugadores_activate(jugador_id):
    j = get_or_404(Jugador, jugador_id)

