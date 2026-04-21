import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# =========================================================
# GERAR CHAVES RSA
# =========================================================

def gerar_chaves_rsa():
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica


# =========================================================
# SERIALIZAR / CARREGAR CHAVES
# =========================================================

def serializar_chave_privada(chave_privada) -> str:
    pem = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode("utf-8")


def serializar_chave_publica(chave_publica) -> str:
    pem = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode("utf-8")


def carregar_chave_privada_do_texto(private_key_pem: str):
    return serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )


def carregar_chave_publica_do_texto(public_key_pem: str):
    return serialization.load_pem_public_key(
        public_key_pem.encode("utf-8")
    )


# =========================================================
# RSA DIRETO (PARA DADOS PEQUENOS)
# =========================================================

def cifrar_rsa(public_key_pem: str, mensagem: bytes) -> bytes:
    chave_publica = carregar_chave_publica_do_texto(public_key_pem)
    return chave_publica.encrypt(
        mensagem,
        padding.PKCS1v15()
    )


def decifrar_rsa(private_key_pem: str, cifra: bytes) -> bytes:
    chave_privada = carregar_chave_privada_do_texto(private_key_pem)
    return chave_privada.decrypt(
        cifra,
        padding.PKCS1v15()
    )


# =========================================================
# ASSINATURA DIGITAL RSA
# =========================================================

def assinar_rsa(private_key_pem: str, mensagem: bytes) -> bytes:
    chave_privada = carregar_chave_privada_do_texto(private_key_pem)
    return chave_privada.sign(
        mensagem,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def verificar_assinatura_rsa(public_key_pem: str, mensagem: bytes, assinatura: bytes) -> bool:
    try:
        chave_publica = carregar_chave_publica_do_texto(public_key_pem)
        chave_publica.verify(
            assinatura,
            mensagem,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# =========================================================
# CIFRA SIMÉTRICA
# =========================================================

def gerar_chave_simetrica() -> bytes:
    return Fernet.generate_key()


def cifrar_mensagem_simetrica(texto: str, chave_simetrica: bytes) -> bytes:
    f = Fernet(chave_simetrica)
    return f.encrypt(texto.encode("utf-8"))


def decifrar_mensagem_simetrica(mensagem_cifrada: bytes, chave_simetrica: bytes) -> str:
    f = Fernet(chave_simetrica)
    return f.decrypt(mensagem_cifrada).decode("utf-8")


# =========================================================
# CHAVE SIMÉTRICA PROTEGIDA COM RSA
# =========================================================

def cifrar_chave_simetrica_com_rsa(public_key_pem: str, chave_simetrica: bytes) -> bytes:
    chave_publica = carregar_chave_publica_do_texto(public_key_pem)
    return chave_publica.encrypt(
        chave_simetrica,
        padding.PKCS1v15()
    )


def decifrar_chave_simetrica_com_rsa(private_key_pem: str, chave_cifrada: bytes) -> bytes:
    chave_privada = carregar_chave_privada_do_texto(private_key_pem)
    return chave_privada.decrypt(
        chave_cifrada,
        padding.PKCS1v15()
    )


# =========================================================
# CIFRAGEM HÍBRIDA (ESTILO PGP)
# =========================================================

def cifrar_mensagem_longa(public_key_pem_destinatario: str, private_key_pem_remetente: str, texto: str) -> dict:
    chave_simetrica = gerar_chave_simetrica()
    mensagem_cifrada = cifrar_mensagem_simetrica(texto, chave_simetrica)
    chave_simetrica_cifrada = cifrar_chave_simetrica_com_rsa(
        public_key_pem_destinatario,
        chave_simetrica
    )
    assinatura = assinar_rsa(private_key_pem_remetente, mensagem_cifrada)

    return {
        "mensagem_cifrada": base64.b64encode(mensagem_cifrada).decode("utf-8"),
        "chave_simetrica_cifrada": base64.b64encode(chave_simetrica_cifrada).decode("utf-8"),
        "assinatura": base64.b64encode(assinatura).decode("utf-8")
    }


def decifrar_mensagem_longa(
    private_key_pem_destinatario: str,
    public_key_pem_remetente: str,
    mensagem_cifrada_b64: str,
    chave_simetrica_cifrada_b64: str,
    assinatura_b64: str
) -> str:
    mensagem_cifrada = base64.b64decode(mensagem_cifrada_b64)
    chave_simetrica_cifrada = base64.b64decode(chave_simetrica_cifrada_b64)
    assinatura = base64.b64decode(assinatura_b64)

    chave_simetrica = decifrar_chave_simetrica_com_rsa(
        private_key_pem_destinatario,
        chave_simetrica_cifrada
    )

    assinatura_valida = verificar_assinatura_rsa(
        public_key_pem_remetente,
        mensagem_cifrada,
        assinatura
    )

    if not assinatura_valida:
        raise ValueError("Assinatura inválida.")

    return decifrar_mensagem_simetrica(mensagem_cifrada, chave_simetrica)