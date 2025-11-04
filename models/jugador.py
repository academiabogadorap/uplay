class Categoria(db.Model):
    __tablename__ = 'categorias'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), unique=True, nullable=False)
    puntos_min = db.Column(db.Integer, nullable=False)
    puntos_max = db.Column(db.Integer, nullable=False)
    creada_en = db.Column(db.DateTime, default=datetime.utcnow)

    jugadores = db.relationship('Jugador', backref='categoria', lazy=True)

    def rango(self):
        return f"{self.puntos_min}–{self.puntos_max}"

class Jugador(db.Model):
