class Pareja(db.Model):
    __tablename__ = 'parejas'
    id = db.Column(db.Integer, primary_key=True)
    categoria_id = db.Column(db.Integer, db.ForeignKey('categorias.id'), nullable=False)
    jugador1_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    jugador2_id = db.Column(db.Integer, db.ForeignKey('jugadores.id'), nullable=False)
    puntos = db.Column(db.Integer, nullable=False)  # puntaje de la pareja en el nivel
    victorias_vs_superior = db.Column(db.Integer, default=0)
    derrotas_vs_inferior = db.Column(db.Integer, default=0)
    creada_en = db.Column(db.DateTime, default=datetime.utcnow)

    jugador1 = db.relationship('Jugador', foreign_keys=[jugador1_id])
    jugador2 = db.relationship('Jugador', foreign_keys=[jugador2_id])
    categoria = db.relationship('Categoria', foreign_keys=[categoria_id])

    __table_args__ = (
        db.UniqueConstraint('categoria_id', 'jugador1_id', 'jugador2_id', name='uq_pareja_cat_j1_j2'),
    )

class Partido(db.Model):
