from flask import Blueprint, render_template, redirect, url_for, session

from app.utils.user_utils import require_login
from app.db.queries import get_chat_list, get_all_other_users_with_last_message

main_bp = Blueprint("main", __name__)


@main_bp.route("/menu")
def menu():
    if not require_login():
        return redirect(url_for("auth.login"))
    return render_template("menu.html", user=session["username"])


@main_bp.route("/inbox")
def inbox():
    if not require_login():
        return redirect(url_for("auth.login"))

    current_user_id = session["user_id"]
    conversations = get_chat_list(current_user_id)

    return render_template(
        "inbox.html",
        user=session["username"],
        conversations=conversations,
        users=[],
        has_conversations=len(conversations) > 0,
        contact_query="",
        conversation_query=""
    )


@main_bp.route("/new_chat")
def new_chat():
    if not require_login():
        return redirect(url_for("auth.login"))

    current_user_id = session["user_id"]
    users = get_all_other_users_with_last_message(current_user_id)

    return render_template("new_chat.html", users=users, user=session["username"])


@main_bp.route("/send", methods=["GET", "POST"])
def send():
    if not require_login():
        return redirect(url_for("auth.login"))
    return redirect(url_for("main.new_chat"))