import os
from flask import Flask
from config import Config
from app.extensions import socketio


def create_app():
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )
    app.config.from_object(Config)
    app.secret_key = "secret"

    upload_folder = os.path.join(app.static_folder, "uploads")
    os.makedirs(upload_folder, exist_ok=True)

    app.config["UPLOAD_FOLDER"] = upload_folder
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    socketio.init_app(app)

    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.chat import chat_bp
    from app.routes.profile import profile_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(profile_bp)

    from app.sockets import events  # noqa: F401

    return app