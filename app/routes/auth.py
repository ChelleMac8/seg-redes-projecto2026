from flask import Blueprint, render_template, request, redirect, url_for, session, flash

from app.utils.user_utils import require_login
from app.utils.auth_utils import hash_password, verify_password
from app.db.queries import create_user, user_exists, get_user_by_username

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    if not require_login():
        return redirect(url_for("auth.login"))
    return redirect(url_for("main.menu"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if len(username) < 3:
            flash("O username deve ter pelo menos 3 caracteres.")
            return redirect(url_for("auth.register"))

        if not email:
            flash("O email é obrigatório.")
            return redirect(url_for("auth.register"))

        if len(password) < 4:
            flash("A senha deve ter pelo menos 4 caracteres.")
            return redirect(url_for("auth.register"))

        if password != confirm:
            flash("As senhas não coincidem.")
            return redirect(url_for("auth.register"))

        existing_user = user_exists(username, email)
        if existing_user:
            flash("Esse username ou email já existe.")
            return redirect(url_for("auth.register"))

        pwd_hash = hash_password(password)
        create_user(username, email, pwd_hash)

        flash("Conta criada com sucesso! Faça o login.")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if require_login():
        return redirect(url_for("main.menu"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Preencha o utilizador e a senha.")
            return redirect(url_for("auth.login"))

        user = get_user_by_username(username)

        if not user:
            flash("Utilizador não encontrado.")
            return redirect(url_for("auth.login"))

        if not verify_password(password, user["password_hash"]):
            flash("Senha incorreta.")
            return redirect(url_for("auth.login"))

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["user_hash"] = user.get("user_hash")

        flash("Login feito com sucesso!")
        return redirect(url_for("main.menu"))

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("Sessão terminada com sucesso.")
    return redirect(url_for("auth.login"))