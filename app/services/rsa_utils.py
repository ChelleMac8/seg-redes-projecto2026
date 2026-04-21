from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def gerar_chaves_rsa():
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica


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