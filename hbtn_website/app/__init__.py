from flask import Flask
from app.config import Config
from app.models.user import db, bcrypt  # Aynı satırda tanımlayabilirsiniz
from app.services.auth import login_manager,jwt


app = Flask(__name__)
app.config.from_object(Config)   


db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
jwt.init_app(app)


# Uygulama bağlamı içinde veritabanını oluşturma
# with app.app_context():
#     db.create_all()

from app.routes import login
