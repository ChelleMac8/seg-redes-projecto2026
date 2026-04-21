from flask import Blueprint, render_template, request, redirect, url_for, session, flash

from app.utils.user_utils import require_login
from app.db.queries import (
    get_user_by_hash,
    get_chat_list,
    get_messages_between_users,
    insert_message_with_file,
)
from app.services.message_service import save_uploaded_file, attach_integrity_status
from app.extensions import users_online
from app.db.queries import create_secure_session_if_not_exists

chat_bp = Blueprint("chat", __name__)


@chat_bp.route("/start_chat/<user_hash>")
def start_chat(user_hash):
    if not require_login():
        return redirect(url_for("auth.login"))

    other_user = get_user_by_hash(user_hash)

    if not other_user:
        flash("Utilizador não encontrado.")
        return redirect(url_for("main.inbox"))

    if other_user["id"] == session["user_id"]:
        flash("Não podes criar conversa contigo mesma.")
        return redirect(url_for("main.inbox"))

    return redirect(url_for("chat.chat", user_hash=user_hash))


@chat_bp.route("/chat/<user_hash>", methods=["GET", "POST"])
def chat(user_hash):
    if not require_login():
        return redirect(url_for("auth.login"))

    current_user_id = session["user_id"]
    other_user = get_user_by_hash(user_hash)

    if not other_user:
        flash("Utilizador não encontrado.")
        return redirect(url_for("main.inbox"))

    other_user_id = other_user["id"]

    if other_user_id == current_user_id:
        flash("Não podes abrir conversa contigo mesma.")
        return redirect(url_for("main.inbox"))

    if request.method == "POST":
        message_text = request.form.get("message", "").strip()
        uploaded_file = request.files.get("file")

        file_name = None
        file_type = None

        if uploaded_file and uploaded_file.filename:
            try:
                file_name, file_type = save_uploaded_file(uploaded_file)
            except ValueError as e:
                flash(str(e))
                return redirect(url_for("chat.chat", user_hash=user_hash))

        if not message_text and not file_name:
            flash("Escreve uma mensagem ou escolhe um ficheiro.")
            return redirect(url_for("chat.chat", user_hash=user_hash))

        insert_message_with_file(
            sender_id=current_user_id,
            receiver_id=other_user_id,
            message_text=message_text,
            file_name=file_name,
            file_type=file_type
        )
        return redirect(url_for("chat.chat", user_hash=user_hash))

    messages = get_messages_between_users(current_user_id, other_user_id)
    messages = attach_integrity_status(messages, current_user_id)
    conversations = get_chat_list(current_user_id)
    is_other_online = other_user_id in users_online
    secure_session = create_secure_session_if_not_exists(current_user_id, other_user_id)

    return render_template(
        "chat.html",
        user=session["username"],
        current_user_id=current_user_id,
        other_user=other_user,
        conversations=conversations,
        messages=messages,
        conversation_id=other_user_id,
        user_id=other_user_id,
        receiver_id=other_user_id,
        is_other_online=is_other_online,
        secure_session = secure_session
    )