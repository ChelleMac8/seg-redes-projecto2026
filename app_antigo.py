from flask_socketio import SocketIO, emit
import uuid
import hashlib
import os
import secrets
from datetime import datetime

import pymysql
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename

from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = "secret"

# SocketIO
socketio = SocketIO(app, async_mode="threading")
users_online = {}

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "mp3", "wav", "ogg", "m4a"}


def generate_user_hash():
    raw = str(uuid.uuid4())
    return hashlib.sha256(raw.encode()).hexdigest()

def generate_message_hash_sha3(content: str) -> str:
    return hashlib.sha3_512(content.encode("utf-8")).hexdigest()

def verify_message_integrity_sha3(message_text: str, stored_hash: str):
    if message_text is None:
        return None

    if not stored_hash:
        return None

    calculated_hash = generate_message_hash_sha3(message_text)
    return calculated_hash == stored_hash

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_file_type(filename):
    ext = filename.rsplit(".", 1)[1].lower()
    if ext in {"png", "jpg", "jpeg", "gif", "webp"}:
        return "image"
    if ext in {"mp3", "wav", "ogg", "m4a"}:
        return "audio"
    return None


def get_db_connection():
    return pymysql.connect(
        host=app.config["MYSQL_HOST"],
        user=app.config["MYSQL_USER"],
        password=app.config["MYSQL_PASSWORD"],
        database=app.config["MYSQL_DB"],
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False
    )
def generate_message_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def verify_message_integrity(message_text: str, stored_hash: str) -> bool:
    if message_text is None:
        return True

    if not stored_hash:
        return False

    calculated_hash = generate_message_hash(message_text)
    return calculated_hash == stored_hash

def save_message(sender, receiver, content):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            message_hash = generate_message_hash(content)
            message_hash_sha3 = generate_message_hash_sha3(content)

            sql = """
                INSERT INTO messages (sender_id, receiver_id, message, message_hash, message_hash_sha3, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(
                sql,
                (sender, receiver, content, message_hash, message_hash_sha3, datetime.now())
            )
        conn.commit()
    finally:
        conn.close()

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


def fill_missing_user_hash():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE user_hash IS NULL OR user_hash = ''")
            users = cursor.fetchall()

            for user in users:
                cursor.execute(
                    "UPDATE users SET user_hash = %s WHERE id = %s",
                    (generate_user_hash(), user["id"])
                )
        connection.commit()
    finally:
        connection.close()


def get_chat_list(current_user_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    u.id,
                    u.username,
                    u.email,
                    u.user_hash,
                    (
                        SELECT
                            CASE
                                WHEN m.file_type = 'image' THEN 'Imagem'
                                WHEN m.file_type = 'audio' THEN 'Áudio'
                                ELSE m.message
                            END
                        FROM messages m
                        WHERE
                            (m.sender_id = %s AND m.receiver_id = u.id)
                            OR
                            (m.sender_id = u.id AND m.receiver_id = %s)
                        ORDER BY m.created_at DESC, m.id DESC
                        LIMIT 1
                    ) AS last_message,
                    (
                        SELECT m.created_at
                        FROM messages m
                        WHERE
                            (m.sender_id = %s AND m.receiver_id = u.id)
                            OR
                            (m.sender_id = u.id AND m.receiver_id = %s)
                        ORDER BY m.created_at DESC, m.id DESC
                        LIMIT 1
                    ) AS last_message_time
                FROM users u
                WHERE u.id != %s
                ORDER BY
                    CASE WHEN last_message_time IS NULL THEN 1 ELSE 0 END,
                    last_message_time DESC,
                    u.username ASC
                """,
                (
                    current_user_id, current_user_id,
                    current_user_id, current_user_id,
                    current_user_id
                )
            )
            rows = cursor.fetchall()

            conversations = []
            for row in rows:
                conversations.append({
                    "conversation_id": row["id"],
                    "user_id": row["id"],
                    "other_user_id": row["id"],
                    "other_username": row["username"],
                    "other_email": row["email"],
                    "other_user_hash": row["user_hash"],
                    "last_message": row["last_message"],
                    "last_message_time": row["last_message_time"]
                })

            return conversations
    finally:
        connection.close()


# =========================
# SOCKET EVENTS
# =========================

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


# =========================
# ROTAS
# =========================

@app.route("/")
def index():
    if not require_login():
        return redirect(url_for("login"))
    return redirect(url_for("menu"))


@app.route("/menu")
def menu():
    if not require_login():
        return redirect(url_for("login"))
    return render_template("menu.html", user=session["username"])


@app.route("/perfil")
def perfil():
    if not require_login():
        return redirect(url_for("login"))

    current_user = get_current_user()
    return render_template(
        "perfil.html",
        user=session["username"],
        current_user=current_user
    )


@app.route("/profile", endpoint="profile")
def profile_alias():
    return redirect(url_for("perfil"))


@app.route("/definicoes")
def definicoes():
    if not require_login():
        return redirect(url_for("login"))

    current_user = get_current_user()
    return render_template(
        "definicoes.html",
        user=session["username"],
        current_user=current_user
    )


@app.route("/settings", endpoint="settings")
def settings_alias():
    return redirect(url_for("definicoes"))


@app.route("/profile/<user_hash>")
def profile_by_hash(user_hash):
    if not require_login():
        return redirect(url_for("login"))

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE user_hash = %s", (user_hash,))
            user = cursor.fetchone()
    finally:
        connection.close()

    if not user:
        return "Utilizador não encontrado", 404

    if user["id"] != session["user_id"]:
        return "Acesso negado", 403

    return render_template("perfil.html", user=session["username"], current_user=user)


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

        if len(password) < 4:
            flash("A senha deve ter pelo menos 4 caracteres.")
            return redirect(url_for("register"))

        if password != confirm:
            flash("As senhas não coincidem.")
            return redirect(url_for("register"))

        pwd_hash = hash_password(password)
        user_hash = generate_user_hash()

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
                    INSERT INTO users (username, email, password_hash, user_hash, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (username, email, pwd_hash, user_hash, datetime.now())
                )
            connection.commit()
        finally:
            connection.close()

        flash("Conta criada com sucesso! Faça o login.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if require_login():
        return redirect(url_for("menu"))

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
        session["user_hash"] = user.get("user_hash")

        flash("Login feito com sucesso!")
        return redirect(url_for("menu"))

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


@app.route("/start_chat/<user_hash>")
def start_chat(user_hash):
    if not require_login():
        return redirect(url_for("login"))

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE user_hash = %s", (user_hash,))
            other_user = cursor.fetchone()
    finally:
        connection.close()

    if not other_user:
        flash("Utilizador não encontrado.")
        return redirect(url_for("inbox"))

    if other_user["id"] == session["user_id"]:
        flash("Não podes criar conversa contigo mesma.")
        return redirect(url_for("inbox"))

    return redirect(url_for("chat", user_hash=user_hash))


@app.route("/new_chat")
def new_chat():
    if not require_login():
        return redirect(url_for("login"))

    current_user_id = session["user_id"]

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    u.id,
                    u.username,
                    u.email,
                    u.user_hash,
                    (
                        SELECT
                            CASE
                                WHEN m.file_type = 'image' THEN 'Imagem'
                                WHEN m.file_type = 'audio' THEN 'Áudio'
                                ELSE m.message
                            END
                        FROM messages m
                        WHERE
                            (m.sender_id = %s AND m.receiver_id = u.id)
                            OR
                            (m.sender_id = u.id AND m.receiver_id = %s)
                        ORDER BY m.created_at DESC, m.id DESC
                        LIMIT 1
                    ) AS last_message,
                    (
                        SELECT m.created_at
                        FROM messages m
                        WHERE
                            (m.sender_id = %s AND m.receiver_id = u.id)
                            OR
                            (m.sender_id = u.id AND m.receiver_id = %s)
                        ORDER BY m.created_at DESC, m.id DESC
                        LIMIT 1
                    ) AS last_message_time
                FROM users u
                WHERE u.id != %s
                ORDER BY
                    CASE WHEN last_message_time IS NULL THEN 1 ELSE 0 END,
                    last_message_time DESC,
                    u.username ASC
                """,
                (
                    current_user_id, current_user_id,
                    current_user_id, current_user_id,
                    current_user_id
                )
            )
            users = cursor.fetchall()
    finally:
        connection.close()

    return render_template("new_chat.html", users=users, user=session["username"])


@app.route("/chat/<user_hash>", methods=["GET", "POST"])
def chat(user_hash):
    if not require_login():
        return redirect(url_for("login"))

    current_user_id = session["user_id"]
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, username, email, user_hash FROM users WHERE user_hash = %s",
                (user_hash,)
            )
            other_user = cursor.fetchone()

            if not other_user:
                flash("Utilizador não encontrado.")
                return redirect(url_for("inbox"))

            other_user_id = other_user["id"]

            if other_user_id == current_user_id:
                flash("Não podes abrir conversa contigo mesma.")
                return redirect(url_for("inbox"))

            if request.method == "POST":
                message_text = request.form.get("message", "").strip()
                uploaded_file = request.files.get("file")

                file_name = None
                file_type = None

                if uploaded_file and uploaded_file.filename:
                    if not allowed_file(uploaded_file.filename):
                        flash("Tipo de ficheiro não permitido.")
                        return redirect(url_for("chat", user_hash=user_hash))

                    original_name = secure_filename(uploaded_file.filename)
                    ext = os.path.splitext(original_name)[1].lower()
                    new_file_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(6)}{ext}"

                    save_path = os.path.join(app.config["UPLOAD_FOLDER"], new_file_name)
                    uploaded_file.save(save_path)

                    file_name = new_file_name
                    file_type = get_file_type(original_name)

                if not message_text and not file_name:
                    flash("Escreve uma mensagem ou escolhe um ficheiro.")
                    return redirect(url_for("chat", user_hash=user_hash))
                message_hash = generate_message_hash(message_text) if message_text else None
                message_hash_sha3 = generate_message_hash_sha3(message_text) if message_text else None

                cursor.execute(
                    """
                  INSERT INTO messages (sender_id, receiver_id, message, message_hash, message_hash_sha3, file_name, file_type, created_at)
                  VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        (
                            current_user_id,
                            other_user_id,
                            message_text if message_text else None,
                            message_hash,
                            message_hash_sha3,
                            file_name,
                            file_type,
                            datetime.now()
                        )
                    )
                )
                connection.commit()
                return redirect(url_for("chat", user_hash=user_hash))

            cursor.execute(
                """
                SELECT
                    m.id,
                    m.sender_id,
                    m.receiver_id,
                    m.message,
                    m.message_hash,
                    m.message_hash_sha3,
                    m.file_name,
                    m.file_type,
                    m.created_at,
                    u.username AS sender_username
                FROM messages m
                JOIN users u ON u.id = m.sender_id
                WHERE
                    (m.sender_id = %s AND m.receiver_id = %s)
                    OR
                    (m.sender_id = %s AND m.receiver_id = %s)
                ORDER BY m.created_at ASC, m.id ASC
                """,
                (current_user_id, other_user_id, other_user_id, current_user_id)
            )
            messages = cursor.fetchall()

            for msg in messages:
                msg["is_valid"] = verify_message_integrity(
                    msg.get("message"),
                    msg.get("message_hash")
                )

                msg["is_valid_sha3"] = verify_message_integrity_sha3(
                    msg.get("message"),
                    msg.get("message_hash_sha3")
                )

        conversations = get_chat_list(current_user_id)

    finally:
        connection.close()

        is_other_online = other_user_id in users_online

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
        is_other_online = is_other_online
    )


@app.route("/send", methods=["GET", "POST"])
def send():
    if not require_login():
        return redirect(url_for("login"))
    return redirect(url_for("new_chat"))

if __name__ == "__main__":
    fill_missing_user_hash()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)