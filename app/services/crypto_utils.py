import base64
import hashlib
from cryptography.fernet import Fernet

from app.services.rsa_utils import (
    cifrar_mensagem_longa as rsa_cifrar_mensagem_longa,
    decifrar_mensagem_longa as rsa_decifrar_mensagem_longa,
)


# =========================================================
# LÓGICA ANTIGA (DH + FERNET)
# MANTIDA PARA COMPATIBILIDADE
# =========================================================

def gerar_chave_fernet(shared_key: str) -> bytes:
    key_bytes = shared_key.encode()
    key_hash = hashlib.sha256(key_bytes).digest()
    return base64.urlsafe_b64encode(key_hash)


def cifrar_mensagem(texto: str, shared_key: str) -> str:
    chave = gerar_chave_fernet(shared_key)
    f = Fernet(chave)
    return f.encrypt(texto.encode()).decode()


def decifrar_mensagem(texto_cifrado: str, shared_key: str) -> str:
    chave = gerar_chave_fernet(shared_key)
    f = Fernet(chave)
    return f.decrypt(texto_cifrado.encode()).decode()


# =========================================================
# NOVA LÓGICA (PGP STYLE)
# WRAPPERS PARA FACILITAR IMPORTS
# =========================================================

def cifrar_mensagem_longa(public_key_pem_destinatario: str, private_key_pem_remetente: str, texto: str) -> dict:
    return rsa_cifrar_mensagem_longa(
        public_key_pem_destinatario=public_key_pem_destinatario,
        private_key_pem_remetente=private_key_pem_remetente,
        texto=texto
    )


def decifrar_mensagem_longa(
    private_key_pem_destinatario: str,
    public_key_pem_remetente: str,
    mensagem_cifrada_b64: str,
    chave_simetrica_cifrada_b64: str,
    assinatura_b64: str
) -> str:
    return rsa_decifrar_mensagem_longa(
        private_key_pem_destinatario=private_key_pem_destinatario,
        public_key_pem_remetente=public_key_pem_remetente,
        mensagem_cifrada_b64=mensagem_cifrada_b64,
        chave_simetrica_cifrada_b64=chave_simetrica_cifrada_b64,
        assinatura_b64=assinatura_b64
    )