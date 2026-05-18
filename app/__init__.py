from flask import Flask, session, redirect, url_for, request, flash
from flask_login import LoginManager, current_user, logout_user
from config import Config
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from app.extensions import mongo
from app.models import MongoUser
from bson import ObjectId
import os
from dotenv import load_dotenv



login_manager = LoginManager()
scheduler = BackgroundScheduler()


def create_app():
    load_dotenv()
    app = Flask(__name__)
    app.config.from_object(Config)

    app.config["MONGO_URI"] = os.environ.get("MONGO_URI")
    mongo.init_app(app)

    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)

    upload_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
    app.config["UPLOAD_FOLDER"] = upload_folder
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    login_manager.init_app(app)
    login_manager.login_view = "main.login"
    login_manager.login_message = "Please login to continue."
    login_manager.login_message_category = "warning"

    from app.routes import bp
    app.register_blueprint(bp)

    @login_manager.user_loader
    def load_user(user_id):
        try:
            user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
            if user:
                return MongoUser(user)
        except Exception:
            return None

        return None

    @login_manager.unauthorized_handler
    def unauthorized():
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for("main.home"))

    @app.before_request
    def handle_session_timeout():
        session.permanent = True

        allowed_endpoints = {
            "main.home",
            "main.login",
            "static"
        }

        if request.endpoint in allowed_endpoints:
            return

        if current_user.is_authenticated:
            now = datetime.utcnow()
            last_activity = session.get("last_activity")

            if last_activity:
                try:
                    last_activity = datetime.fromisoformat(last_activity)

                    if now - last_activity > timedelta(minutes=15):
                        logout_user()
                        session.clear()
                        flash("Session timed out due to inactivity. Please login again.", "warning")
                        return redirect(url_for("main.home"))
                except Exception:
                    session.clear()
                    return redirect(url_for("main.home"))

            session["last_activity"] = now.isoformat()

    return app