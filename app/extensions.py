from flask_socketio import SocketIO

socketio = SocketIO(async_mode="threading")
users_online = {}