from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


# =========================================================
# GERAR CHAVE PRIVADA RSA
# =========================================================

def gerar_chave_privada_ca():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


# =========================================================
# SERIALIZAR / CARREGAR CHAVES E CERTIFICADOS
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


def serializar_certificado(certificado) -> str:
    return certificado.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def carregar_certificado_do_texto(cert_pem: str):
    return x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))


# =========================================================
# CA RAIZ AUTOASSINADA
# =========================================================

def gerar_certificado_ca(nome_ca="CA Raiz Secure Chat"):
    chave_privada_ca = gerar_chave_privada_ca()
    chave_publica_ca = chave_privada_ca.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, nome_ca),
    ])

    certificado_ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(chave_publica_ca)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .sign(chave_privada_ca, hashes.SHA256())
    )

    return {
        "private_key_pem": serializar_chave_privada(chave_privada_ca),
        "public_key_pem": serializar_chave_publica(chave_publica_ca),
        "certificate_pem": serializar_certificado(certificado_ca)
    }


# =========================================================
# CERTIFICADO DE UTILIZADOR ASSINADO PELA CA
# =========================================================

def gerar_certificado_utilizador(
    username: str,
    user_public_key_pem: str,
    ca_private_key_pem: str,
    ca_certificate_pem: str
):
    user_public_key = carregar_chave_publica_do_texto(user_public_key_pem)
    ca_private_key = carregar_chave_privada_do_texto(ca_private_key_pem)
    ca_cert = carregar_certificado_do_texto(ca_certificate_pem)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    issuer = ca_cert.subject

    certificado_user = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    return serializar_certificado(certificado_user)


# =========================================================
# VERIFICAR CERTIFICADO DE UTILIZADOR
# =========================================================


def verificar_certificado_utilizador(user_certificate_pem: str, ca_certificate_pem: str) -> bool:
    try:
        user_cert = carregar_certificado_do_texto(user_certificate_pem)
        ca_cert = carregar_certificado_do_texto(ca_certificate_pem)

        agora = datetime.utcnow()

        if agora < user_cert.not_valid_before or agora > user_cert.not_valid_after:
            return False

        if user_cert.issuer != ca_cert.subject:
            return False

        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm
        )

        return True

    except Exception:
        return False