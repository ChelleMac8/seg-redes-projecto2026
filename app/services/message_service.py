import os
import secrets
from datetime import datetime

from flask import current_app
from werkzeug.utils import secure_filename

from app.utils.file_utils import allowed_file, get_file_type
from app.utils.hash_utils import verify_message_integrity, verify_message_integrity_sha3
from app.services.rsa_utils import (
    verificar_assinatura_rsa,
    decifrar_mensagem_longa
)
from app.db.connection import get_db_connection
from app.services.crypto_utils import decifrar_mensagem_longa


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
                msg["signature_valid"] = None
                msg["is_valid"] = False
                msg["is_valid_sha3"] = False

                # =====================================================
                # 1. DECIFRAR A MENSAGEM COM O NOVO MODELO HÍBRIDO
                # =====================================================
                try:
                    if (
                        msg.get("mensagem_cifrada")
                        and msg.get("chave_simetrica_cifrada")
                        and msg.get("signature")
                    ):
                        # chave privada do destinatário
                        cursor.execute(
                            "SELECT rsa_private_key FROM users WHERE id = %s",
                            (msg["receiver_id"],)
                        )
                        receiver = cursor.fetchone()

                        # chave pública do remetente
                        cursor.execute(
                            "SELECT rsa_public_key FROM users WHERE id = %s",
                            (msg["sender_id"],)
                        )
                        sender = cursor.fetchone()

                        if receiver and sender and receiver.get("rsa_private_key") and sender.get("rsa_public_key"):
                            texto_decifrado = decifrar_mensagem_longa(
                                private_key_pem_destinatario=receiver["rsa_private_key"],
                                public_key_pem_remetente=sender["rsa_public_key"],
                                mensagem_cifrada_b64=msg["mensagem_cifrada"],
                                chave_simetrica_cifrada_b64=msg["chave_simetrica_cifrada"],
                                assinatura_b64=msg["signature"]
                            )

                            msg["message"] = texto_decifrado
                            msg["signature_valid"] = True
                        else:
                            msg["message"] = "[CHAVES NÃO ENCONTRADAS]"
                    else:
                        # fallback: manter mensagem em claro se existir
                        if not msg.get("message"):
                            msg["message"] = "[MENSAGEM INDISPONÍVEL]"

                except Exception:
                    msg["message"] = "[ERRO AO DECIFRAR]"
                    msg["signature_valid"] = False

                # =====================================================
                # 2. VERIFICAR INTEGRIDADE DEPOIS DE DECIFRAR
                # =====================================================
                if msg.get("message") and msg["message"] not in [
                    "[ERRO AO DECIFRAR]",
                    "[CHAVES NÃO ENCONTRADAS]",
                    "[MENSAGEM INDISPONÍVEL]"
                ]:
                    msg["is_valid"] = verify_message_integrity(
                        msg.get("message"),
                        msg.get("message_hash")
                    )

                    msg["is_valid_sha3"] = verify_message_integrity_sha3(
                        msg.get("message"),
                        msg.get("message_hash_sha3")
                    )

    finally:
        connection.close()

    return messages