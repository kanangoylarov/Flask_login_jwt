# from flask import Flask, render_template, request, redirect, url_for, jsonify, session
# from app.models.user import User
# from app.services.auth import login_manager
# from flask_login import login_user, login_required, logout_user, current_user
# from app.models.user import db
# from app.services.auth import jwt
# from datetime import datetime, timedelta
# from functools import wraps
# from app import app



# # JWT Token doğrulayıcı
# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
        
#         # Token 'Authorization' başlığından alınır
#         if 'Authorization' in request.headers:
#             token = request.headers['Authorization'].split(" ")[1]  # "Bearer token" formatında gelir
        
#         if not token:
#             return jsonify({'Alert!': 'Token is missing!'}), 401

#         try:
#             data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
#             current_user = User.query.filter_by(username=data['user']).first()
#         except:
#             return jsonify({'Message': 'Invalid token'}), 403

#         return f(current_user, *args, **kwargs)
#     return decorated


# with app.app_context():
#     db.create_all()

# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))

# @app.route("/", methods=["GET"])
# def login_page():
#     return render_template("login.html")

# # Kayıt işlemi
# @app.route("/register", methods=["POST", "GET"])
# def register():
#     if request.method == "POST":
#         username = request.form["username"]
#         password = request.form["password"]

#         # Kullanıcı daha önce var mı kontrol et
#         existing_user = User.query.filter_by(username=username).first()
#         if existing_user:
#             return redirect(url_for("register"))

#         # Yeni kullanıcı oluştur
#         new_user = User(username=username)
#         new_user.set_password(password)
#         db.session.add(new_user)
#         db.session.commit()
#         return redirect(url_for("login_page"))
#     return render_template("register.html")

# # Giriş işlemi ve JWT token oluşturma
# @app.route("/login", methods=["POST", "GET"])
# def login():
#     if request.method == "GET":
#         return render_template("login.html")

#     username = request.form["username"]
#     password = request.form["password"]

#     user = User.query.filter_by(username=username).first()
#     if user and user.check_password(password):
#         # Token oluşturma (30 dakika geçerli)
#         token = jwt.encode({
#             'user': username,
#             'exp': datetime.utcnow() + timedelta(minutes=30)
#         }, app.config['SECRET_KEY'], algorithm="HS256")
#         return jsonify({'token': token}), 200
#     else:
#         return jsonify({'message': 'Invalid credentials'}), 401

# # Çıkış işlemi
# @app.route("/logout")
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for("login_page"))

# # Dashboard (JWT koruması ile)
# @app.route("/dashboard")
# @token_required
# def dashboard(current_user):
#     return f"<h2>Welcome to the dashboard, {current_user.username}!</h2>"

#--------------------------------------------------------------------------------------------------------------------
# from flask import Flask, render_template, request, redirect, url_for, jsonify, session
# from app.models.user import User
# from app.services.auth import login_manager
# from flask_login import login_user, login_required, logout_user, current_user
# from app.models.user import db
# from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# from datetime import datetime, timedelta
# from functools import wraps
# from app import app


# from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
# from flask import Flask, render_template, request, redirect, url_for, jsonify, session
# from app.models.user import User
# from app.services.auth import login_manager
# from flask_login import login_user, login_required, logout_user, current_user
# from app.models.user import db
# from app.services.auth import jwt
# from datetime import datetime, timedelta
# from functools import wraps
# from app import app

# # # JWT uzantısını başlatıyoruz
# # app.config['SECRET_KEY'] = 'your_secret_key'  # Bunu güvenli bir hale getirin!
# # app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # JWT için ayrı bir gizli anahtar
# # jwt = JWTManager(app)

# # JWT Token doğrulayıcı
# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None

#         # Token 'Authorization' başlığından alınır
#         if 'Authorization' in request.headers:
#             token = request.headers['Authorization'].split(" ")[1]  # "Bearer token" formatında gelir

#         if not token:
#             return jsonify({'Alert!': 'Token is missing!'}), 401

#         try:
#             data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
#             current_user = User.query.filter_by(username=data['sub']).first()
#         except:
#             return jsonify({'Message': 'Invalid token'}), 403

#         return f(current_user, *args, **kwargs)
#     return decorated

# # with app.app_context():
# #     db.create_all()

# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))

# @app.route("/", methods=["GET"])
# def login_page():
#     return render_template("login.html")

# # Kayıt işlemi
# @app.route("/register", methods=["POST", "GET"])
# def register():
#     if request.method == "POST":
#         username = request.form["username"]
#         password = request.form["password"]

#         # Kullanıcı daha önce var mı kontrol et
#         existing_user = User.query.filter_by(username=username).first()
#         if existing_user:
#             return jsonify({'message': 'User already exists'}), 409  # Conflict durumu

#         # Yeni kullanıcı oluştur
#         new_user = User(username=username)
#         new_user.set_password(password)
#         db.session.add(new_user)
#         db.session.commit()
#         return redirect(url_for("login_page"))
#     return render_template("register.html")

# # Giriş işlemi ve JWT token oluşturma
# @app.route("/login", methods=["POST", "GET"])
# def login():
#     if request.method == "GET":
#         return render_template("login.html")

#     username = request.form["username"]
#     password = request.form["password"]

#     user = User.query.filter_by(username=username).first()
#     if user and user.check_password(password):
#         # Token oluşturma (30 dakika geçerli)
#         token = create_access_token(identity=username, expires_delta=timedelta(minutes=30))
#         return jsonify({'token': token}), 200
#     else:
#         return jsonify({'message': 'Invalid credentials'}), 401

# # Çıkış işlemi
# @app.route("/logout")
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for("login_page"))

# # Dashboard (JWT koruması ile)
# @app.route("/dashboard")
# @jwt_required()
# def dashboard():
#     current_user = get_jwt_identity()
#     return f"<h2>Welcome to the dashboard, {current_user}!</h2>"



from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from app.models.user import User
from app.services.auth import login_manager
from flask_login import login_user, login_required, logout_user
from app.models.user import db
from datetime import timedelta
from app import app

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/", methods=["GET"])
def login_page():
    return render_template("login.html")

# Kayıt işlemi
@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Kullanıcı daha önce var mı kontrol et
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'message': 'User already exists'}), 409  # Conflict durumu

        # Yeni kullanıcı oluştur
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login_page"))
    return render_template("register.html")

# Giriş işlemi ve JWT token oluşturma
@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form["username"]
    password = request.form["password"]

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        # Token oluşturma (30 dakika geçerli)
        token = create_access_token(identity=username, expires_delta=timedelta(minutes=30))
        return jsonify({'token': token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Çıkış işlemi
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login_page"))

# Dashboard (JWT koruması ile)
@app.route("/dashboard")
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()  # Mevcut kullanıcının adını al
    return f"<h2>Hello, {current_user}!</h2>"

