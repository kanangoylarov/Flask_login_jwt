from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
login_manager = LoginManager()
jwt = JWTManager()
login_manager.login_view = "login_page"