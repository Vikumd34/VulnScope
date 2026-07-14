from flask import Flask, render_template
from routes.dashboard import dashboard_bp
from routes.scanner import scanner_bp
from routes.history import history_bp
from routes.auth import auth_bp
from database.database import db
from flask_login import LoginManager
from models.user import User

app = Flask(__name__)
app.config.from_object("config")
db.init_app(app)
app.register_blueprint(dashboard_bp)
app.register_blueprint(scanner_bp)
app.register_blueprint(history_bp)
app.register_blueprint(auth_bp)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

with app.app_context():
    db.create_all()

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(debug=True)