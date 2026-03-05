import os
import sqlite3
import hashlib
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "troca_isto_por_uma_chave_forte"

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DB_PATH = "secure_chat.db"


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                text TEXT NOT NULL,
                image_path TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


def hash_password(password: str) -> str:
    # PBKDF2 (seguro, padrão)
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex() + ":" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, dk_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return dk.hex() == dk_hex


def require_login():
    return "user" in session and session["user"]


init_db()


@app.route("/")
def index():
    if not require_login():
        return redirect(url_for("login"))
    return render_template("index.html", user=session["user"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if len(username) < 3:
            flash("O username deve ter pelo menos 3 caracteres.")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("A senha deve ter pelo menos 6 caracteres.")
            return redirect(url_for("register"))
        if password != confirm:
            flash("As senhas não coincidem.")
            return redirect(url_for("register"))

        pwd_hash = hash_password(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, pwd_hash, created_at),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            flash("Esse username já existe. Escolhe outro.")
            return redirect(url_for("register"))

        flash("Conta criada com sucesso! Agora faz login.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if not user or not verify_password(password, user["password_hash"]):
            flash("Login inválido.")
            return redirect(url_for("login"))

        session["user"] = username
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/send", methods=["GET", "POST"])
def send():
    if not require_login():
        return redirect(url_for("login"))

    current_user = session["user"]

    with db() as conn:
        recipients = conn.execute(
            "SELECT username FROM users WHERE username != ? ORDER BY username ASC",
            (current_user,),
        ).fetchall()

    if request.method == "POST":
        recipient = request.form.get("to", "").strip()
        text = request.form.get("message", "").strip()

        if not recipient:
            flash("Escolhe um destinatário.")
            return redirect(url_for("send"))

        image = request.files.get("image")
        image_path = None

        if image and image.filename:
            ext = os.path.splitext(image.filename)[1].lower()
            filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}{ext}"
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            image.save(save_path)
            image_path = save_path.replace("\\", "/")

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with db() as conn:
            conn.execute("""
                INSERT INTO messages (sender, recipient, text, image_path, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (current_user, recipient, text, image_path, created_at))
            conn.commit()

        flash("Mensagem enviada!")
        return redirect(url_for("inbox"))

    return render_template("send.html", user=current_user, recipients=recipients)


@app.route("/inbox")
def inbox():
    if not require_login():
        return redirect(url_for("login"))

    current_user = session["user"]

    with db() as conn:
        messages = conn.execute("""
            SELECT * FROM messages
            WHERE recipient = ?
            ORDER BY id DESC
        """, (current_user,)).fetchall()

    return render_template("inbox.html", user=current_user, messages=messages)


if __name__ == "__main__":
    app.run(debug=True)