import os
import hashlib
import secrets
from datetime import datetime

import pymysql
from flask import Flask, render_template, request, redirect, url_for, session, flash
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db_connection():
    return pymysql.connect(
        host=app.config["MYSQL_HOST"],
        user=app.config["MYSQL_USER"],
        password=app.config["MYSQL_PASSWORD"],
        database=app.config["MYSQL_DB"],
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex() + ":" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return dk.hex() == dk_hex
    except Exception:
        return False


def require_login():
    return "user_id" in session


def get_current_user():
    if not require_login():
        return None

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
            return cursor.fetchone()
    finally:
        connection.close()


@app.route("/")
def index():
    if not require_login():
        return redirect(url_for("login"))
    return redirect(url_for("inbox"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if len(username) < 3:
            flash("O username deve ter pelo menos 3 caracteres.")
            return redirect(url_for("register"))

        if not email:
            flash("O email é obrigatório.")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("A senha deve ter pelo menos 6 caracteres.")
            return redirect(url_for("register"))

        if password != confirm:
            flash("As senhas não coincidem.")
            return redirect(url_for("register"))

        pwd_hash = hash_password(password)

        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT id FROM users WHERE username = %s OR email = %s",
                    (username, email)
                )
                existing_user = cursor.fetchone()

                if existing_user:
                    flash("Esse username ou email já existe.")
                    return redirect(url_for("register"))

                cursor.execute(
                    """
                    INSERT INTO users (username, email, password_hash, created_at)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (username, email, pwd_hash, datetime.now())
                )
            connection.commit()
        finally:
            connection.close()

        flash("Conta criada com sucesso! Agora faz login.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Preencha o utilizador e a senha.")
            return redirect(url_for("login"))

        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM users WHERE username = %s",
                    (username,)
                )
                user = cursor.fetchone()
        finally:
            connection.close()

        if not user:
            flash("Utilizador não encontrado.")
            return redirect(url_for("login"))

        if not verify_password(password, user["password_hash"]):
            flash("Senha incorreta.")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["username"] = user["username"]

        flash("Login feito com sucesso!")
        return redirect(url_for("inbox"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Sessão terminada com sucesso.")
    return redirect(url_for("login"))


@app.route("/inbox")
def inbox():
    if not require_login():
        return redirect(url_for("login"))

    current_user_id = session["user_id"]

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    c.id AS conversation_id,
                    u.id AS other_user_id,
                    u.username AS other_username,
                    (
                        SELECT m.message_text
                        FROM messages m
                        WHERE m.conversation_id = c.id
                        ORDER BY m.created_at DESC, m.id DESC
                        LIMIT 1
                    ) AS last_message,
                    (
                        SELECT m.created_at
                        FROM messages m
                        WHERE m.conversation_id = c.id
                        ORDER BY m.created_at DESC, m.id DESC
                        LIMIT 1
                    ) AS last_message_time
                FROM conversations c
                JOIN users u
                    ON u.id = CASE
                        WHEN c.user1_id = %s THEN c.user2_id
                        ELSE c.user1_id
                    END
                WHERE c.user1_id = %s OR c.user2_id = %s
                ORDER BY last_message_time DESC, c.created_at DESC
                """,
                (current_user_id, current_user_id, current_user_id)
            )
            conversations = cursor.fetchall()
    finally:
        connection.close()

    return render_template(
        "inbox.html",
        user=session["username"],
        conversations=conversations
    )


@app.route("/new_chat", methods=["GET", "POST"])
def new_chat():
    if not require_login():
        return redirect(url_for("login"))

    current_user_id = session["user_id"]

    connection = get_db_connection()
    try:
        if request.method == "POST":
            other_user_id = request.form.get("other_user_id")

            if not other_user_id:
                flash("Escolhe um utilizador.")
                return redirect(url_for("new_chat"))

            other_user_id = int(other_user_id)

            if other_user_id == current_user_id:
                flash("Não podes criar conversa contigo mesma.")
                return redirect(url_for("new_chat"))

            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id FROM conversations
                    WHERE (user1_id = %s AND user2_id = %s)
                       OR (user1_id = %s AND user2_id = %s)
                    """,
                    (current_user_id, other_user_id, other_user_id, current_user_id)
                )
                existing_conversation = cursor.fetchone()

                if existing_conversation:
                    return redirect(
                        url_for("chat", conversation_id=existing_conversation["id"])
                    )

                cursor.execute(
                    """
                    INSERT INTO conversations (user1_id, user2_id, created_at)
                    VALUES (%s, %s, %s)
                    """,
                    (current_user_id, other_user_id, datetime.now())
                )
                conversation_id = cursor.lastrowid

            connection.commit()
            flash("Nova conversa criada com sucesso!")
            return redirect(url_for("chat", conversation_id=conversation_id))

        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username
                FROM users
                WHERE id != %s
                ORDER BY username ASC
                """,
                (current_user_id,)
            )
            users = cursor.fetchall()

    finally:
        connection.close()

    return render_template("new_chat.html", users=users, user=session["username"])


@app.route("/chat/<int:conversation_id>", methods=["GET", "POST"])
def chat(conversation_id):
    if not require_login():
        return redirect(url_for("login"))

    current_user_id = session["user_id"]

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM conversations
                WHERE id = %s
                  AND (user1_id = %s OR user2_id = %s)
                """,
                (conversation_id, current_user_id, current_user_id)
            )
            conversation = cursor.fetchone()

            if not conversation:
                flash("Conversa não encontrada.")
                return redirect(url_for("inbox"))

            if request.method == "POST":
                message_text = request.form.get("message", "").strip()

                image = request.files.get("image")
                image_path = None

                if image and image.filename:
                    ext = os.path.splitext(image.filename)[1].lower()
                    filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}{ext}"
                    save_path = os.path.join(UPLOAD_FOLDER, filename)
                    image.save(save_path)
                    image_path = save_path.replace("\\", "/")

                if not message_text and not image_path:
                    flash("Escreve uma mensagem ou escolhe uma imagem.")
                    return redirect(url_for("chat", conversation_id=conversation_id))

                cursor.execute(
                    """
                    INSERT INTO messages (
                        conversation_id,
                        sender_id,
                        message_text,
                        image_path,
                        created_at
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (conversation_id, current_user_id, message_text, image_path, datetime.now())
                )
                connection.commit()
                return redirect(url_for("chat", conversation_id=conversation_id))

            other_user_id = (
                conversation["user2_id"]
                if conversation["user1_id"] == current_user_id
                else conversation["user1_id"]
            )

            cursor.execute(
                "SELECT id, username FROM users WHERE id = %s",
                (other_user_id,)
            )
            other_user = cursor.fetchone()

            cursor.execute(
                """
                SELECT
                    c.id AS conversation_id,
                    u.username AS other_username
                FROM conversations c
                JOIN users u
                    ON u.id = CASE
                        WHEN c.user1_id = %s THEN c.user2_id
                        ELSE c.user1_id
                    END
                WHERE c.user1_id = %s OR c.user2_id = %s
                ORDER BY c.created_at DESC
                """,
                (current_user_id, current_user_id, current_user_id)
            )
            conversations = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    m.id,
                    m.sender_id,
                    m.message_text,
                    m.image_path,
                    m.created_at,
                    u.username AS sender_username
                FROM messages m
                JOIN users u ON u.id = m.sender_id
                WHERE m.conversation_id = %s
                ORDER BY m.created_at ASC, m.id ASC
                """,
                (conversation_id,)
            )
            messages = cursor.fetchall()

    finally:
        connection.close()

    return render_template(
        "chat.html",
        user=session["username"],
        current_user_id=current_user_id,
        other_user=other_user,
        conversations=conversations,
        messages=messages,
        conversation_id=conversation_id
    )


@app.route("/send", methods=["GET", "POST"])
def send():
    if not require_login():
        return redirect(url_for("login"))
    return redirect(url_for("new_chat"))


if __name__ == "__main__":
    app.run(debug=True)