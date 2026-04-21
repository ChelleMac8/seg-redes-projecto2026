from datetime import datetime
from flask import request
from flask_socketio import emit

from app.extensions import socketio, users_online
from app.db.queries import save_message


@socketio.on("login")
def handle_login(data):
    user_id = data.get("user_id")
    if not user_id:
        return

    users_online[user_id] = request.sid
    print(f"[SOCKET] User {user_id} conectado")

    emit("user_status_changed", {
        "user_id": user_id,
        "status": "online"
    }, broadcast=True)


@socketio.on("disconnect")
def handle_disconnect():
    sid = request.sid
    user_to_remove = None

    for user_id, stored_sid in users_online.items():
        if stored_sid == sid:
            user_to_remove = user_id
            break

    if user_to_remove is not None:
        users_online.pop(user_to_remove, None)
        print(f"[SOCKET] User {user_to_remove} desconectado")

        emit("user_status_changed", {
            "user_id": user_to_remove,
            "status": "offline"
        }, broadcast=True)


@socketio.on("send_message")
def handle_send_message(data):
    sender = data.get("from")
    receiver = data.get("to")
    content = (data.get("content") or "").strip()

    if not sender or not receiver or not content:
        print("[SOCKET] dados inválidos")
        return

    print(f"[MSG] {sender} -> {receiver}: {content}")

    save_message(sender, receiver, content)

    payload = {
        "from": sender,
        "content": content,
        "time": datetime.now().strftime("%H:%M")
    }

    if receiver in users_online:
        emit("receive_message", payload, to=users_online[receiver])