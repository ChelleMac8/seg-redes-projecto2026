from datetime import datetime

from app.db.connection import get_db_connection
from app.utils.user_utils import generate_user_hash
from app.utils.hash_utils import generate_message_hash, generate_message_hash_sha3

from app.services.rsa_utils import (
    gerar_chaves_rsa,
    serializar_chave_privada,
    serializar_chave_publica,
    assinar_rsa,
)

from app.services.dh_utils import (
    gerar_par_dh,
    calcular_segredo_partilhado,
    derivar_chave_sessao,
)


def get_user_by_id(user_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            return cursor.fetchone()
    finally:
        connection.close()


def get_user_by_username(username):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            return cursor.fetchone()
    finally:
        connection.close()


def get_user_by_hash(user_hash):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE user_hash = %s", (user_hash,))
            return cursor.fetchone()
    finally:
        connection.close()


def user_exists(username, email):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM users WHERE username = %s OR email = %s",
                (username, email)
            )
            return cursor.fetchone()
    finally:
        connection.close()


def create_user(username, email, password_hash):
    chave_privada, chave_publica = gerar_chaves_rsa()
    private_pem = serializar_chave_privada(chave_privada)
    public_pem = serializar_chave_publica(chave_publica)

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users (
                    username,
                    email,
                    password_hash,
                    user_hash,
                    rsa_private_key,
                    rsa_public_key,
                    created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    username,
                    email,
                    password_hash,
                    generate_user_hash(),
                    private_pem,
                    public_pem,
                    datetime.now()
                )
            )
        connection.commit()
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


def save_message(sender, receiver, content):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            message_hash = generate_message_hash(content)
            message_hash_sha3 = generate_message_hash_sha3(content)

            sql = """
                INSERT INTO messages (
                    sender_id,
                    receiver_id,
                    message,
                    message_hash,
                    message_hash_sha3,
                    created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(
                sql,
                (sender, receiver, content, message_hash, message_hash_sha3, datetime.now())
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


def get_all_other_users_with_last_message(current_user_id):
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
            return cursor.fetchall()
    finally:
        connection.close()


def get_messages_between_users(current_user_id, other_user_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    m.id,
                    m.sender_id,
                    m.receiver_id,
                    m.message,
                    m.message_hash,
                    m.message_hash_sha3,
                    m.signature,
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
            return cursor.fetchall()
    finally:
        connection.close()


def insert_message_with_file(sender_id, receiver_id, message_text, file_name, file_type):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            message_hash = generate_message_hash(message_text) if message_text else None
            message_hash_sha3 = generate_message_hash_sha3(message_text) if message_text else None

            cursor.execute("SELECT rsa_private_key FROM users WHERE id = %s", (sender_id,))
            sender = cursor.fetchone()

            signature = None
            if message_text and sender and sender.get("rsa_private_key"):
                assinatura_bytes = assinar_rsa(
                    sender["rsa_private_key"],
                    message_text.encode("utf-8")
                )
                signature = assinatura_bytes.hex()

            cursor.execute(
                """
                INSERT INTO messages
                (
                    sender_id,
                    receiver_id,
                    message,
                    message_hash,
                    message_hash_sha3,
                    signature,
                    file_name,
                    file_type,
                    created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    sender_id,
                    receiver_id,
                    message_text if message_text else None,
                    message_hash,
                    message_hash_sha3,
                    signature,
                    file_name,
                    file_type,
                    datetime.now()
                )
            )
        connection.commit()
    finally:
        connection.close()


def get_secure_session(user1_id, user2_id):
    a, b = sorted([user1_id, user2_id])

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT * FROM secure_sessions
                WHERE user1_id = %s AND user2_id = %s
                """,
                (a, b)
            )
            return cursor.fetchone()
    finally:
        connection.close()


def create_secure_session_if_not_exists(user1_id, user2_id):
    a, b = sorted([user1_id, user2_id])

    existing = get_secure_session(a, b)
    if existing:
        return existing

    priv_a, pub_a = gerar_par_dh()
    priv_b, pub_b = gerar_par_dh()

    segredo_a = calcular_segredo_partilhado(priv_a, pub_b)
    segredo_b = calcular_segredo_partilhado(priv_b, pub_a)

    if segredo_a != segredo_b:
        raise ValueError("Erro ao calcular o segredo partilhado Diffie-Hellman.")

    shared_key = derivar_chave_sessao(segredo_a)

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO secure_sessions
                (
                    user1_id,
                    user2_id,
                    dh_private_user1,
                    dh_public_user1,
                    dh_private_user2,
                    dh_public_user2,
                    shared_key
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    a, b,
                    str(priv_a), str(pub_a),
                    str(priv_b), str(pub_b),
                    shared_key
                )
            )
        connection.commit()
    finally:
        connection.close()

    return get_secure_session(a, b)