from flask import Blueprint, render_template, redirect, url_for, session

from app.utils.user_utils import require_login
from app.db.queries import get_user_by_id, get_user_by_hash

profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/perfil")
def perfil():
    if not require_login():
        return redirect(url_for("auth.login"))

    current_user = get_user_by_id(session["user_id"])
    return render_template(
        "perfil.html",
        user=session["username"],
        current_user=current_user
    )


@profile_bp.route("/profile", endpoint="profile")
def profile_alias():
    return redirect(url_for("profile.perfil"))


@profile_bp.route("/definicoes")
def definicoes():
    if not require_login():
        return redirect(url_for("auth.login"))

    current_user = get_user_by_id(session["user_id"])
    return render_template(
        "definicoes.html",
        user=session["username"],
        current_user=current_user
    )


@profile_bp.route("/settings", endpoint="settings")
def settings_alias():
    return redirect(url_for("profile.definicoes"))


@profile_bp.route("/profile/<user_hash>")
def profile_by_hash(user_hash):
    if not require_login():
        return redirect(url_for("auth.login"))

    user = get_user_by_hash(user_hash)

    if not user:
        return "Utilizador não encontrado", 404

    if user["id"] != session["user_id"]:
        return "Acesso negado", 403

    return render_template("perfil.html", user=session["username"], current_user=user)