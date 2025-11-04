from flask import Blueprint, render_template, request, redirect, url_for, flash

bp = Blueprint('${f%_routes}', __name__)

# --- Rutas asignadas a este módulo se agregarán aquí automáticamente ---
@app.route('/alta', methods=['GET', 'POST'])
def alta_publica():
    categorias = Categoria.query.order_by(Categoria.puntos_min.desc()).all()

@app.route('/ranking')
def ranking():
    # Filtro opcional de rama (?rama=CABALLEROS|DAMAS|MIXTA)
    rama_filtro = (request.args.get('rama') or '').upper().strip()
    rama_filtro = rama_filtro if rama_filtro in ('CABALLEROS', 'DAMAS', 'MIXTA') else ''

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

