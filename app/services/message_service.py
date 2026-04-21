import os
import secrets
from datetime import datetime

from flask import current_app
from werkzeug.utils import secure_filename

from app.utils.file_utils import allowed_file, get_file_type
from app.utils.hash_utils import verify_message_integrity, verify_message_integrity_sha3

from app.services.rsa_utils import verificar_assinatura_rsa
from app.db.connection import get_db_connection

def save_uploaded_file(uploaded_file):
    if not allowed_file(uploaded_file.filename):
        raise ValueError("Tipo de ficheiro não permitido.")

    original_name = secure_filename(uploaded_file.filename)
    ext = os.path.splitext(original_name)[1].lower()
    new_file_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(6)}{ext}"

    save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], new_file_name)
    uploaded_file.save(save_path)

    file_type = get_file_type(original_name)
    return new_file_name, file_type

def attach_integrity_status(messages):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            for msg in messages:
                msg["is_valid"] = verify_message_integrity(
                    msg.get("message"),
                    msg.get("message_hash")
                )

                msg["is_valid_sha3"] = verify_message_integrity_sha3(
                    msg.get("message"),
                    msg.get("message_hash_sha3")
                )

                msg["signature_valid"] = None

                if msg.get("message") and msg.get("signature"):
                    cursor.execute("SELECT rsa_public_key FROM users WHERE id = %s", (msg["sender_id"],))
                    sender = cursor.fetchone()

                    if sender and sender.get("rsa_public_key"):
                        msg["signature_valid"] = verificar_assinatura_rsa(
                            sender["rsa_public_key"],
                            msg["message"].encode("utf-8"),
                            bytes.fromhex(msg["signature"])
                        )
    finally:
        connection.close()

    return messages