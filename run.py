from app import create_app
from app.extensions import socketio
from app.db.queries import fill_missing_user_hash

app = create_app()

if __name__ == "__main__":
    with app.app_context():
        fill_missing_user_hash()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)