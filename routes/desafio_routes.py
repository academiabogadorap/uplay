from flask import Blueprint, render_template, request, redirect, url_for, flash

bp = Blueprint('${f%_routes}', __name__)

# --- Rutas asignadas a este módulo se agregarán aquí automáticamente ---
@app.route('/desafios')
def desafios_list():
    desafios = (db.session.query(Desafio)
                .order_by(Desafio.creado_en.desc())
                .all())
    return render_template('desafios_list.html', desafios=desafios)

@app.route('/desafios/<int:desafio_id>/programar', methods=['POST'])
def desafios_programar(desafio_id):
    d = get_or_404(Desafio, desafio_id)

@app.route('/desafios/nuevo', methods=['GET', 'POST'])
def desafios_new():
    # --- Debe haber sesión ---
    desafiante = get_current_jugador()
    if not desafiante:
        flash('Iniciá sesión para crear un desafío.', 'error')
        return redirect(url_for('login'))

@app.route('/desafios/<int:desafio_id>/responder', methods=['GET', 'POST'])
def desafios_responder(desafio_id):
    j = get_current_jugador()
    if not j:
        flash('Iniciá sesión para responder desafíos.', 'error')
        return redirect(url_for('login'))

@app.route('/admin/desafios/<int:desafio_id>/eliminar', methods=['POST'])
@admin_required
def admin_desafios_eliminar(desafio_id):
    d = get_or_404(Desafio, desafio_id)

