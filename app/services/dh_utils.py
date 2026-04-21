import secrets
import hashlib

# Parâmetros DH para simulação laboratorial
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
G = 2


def gerar_numero_privado_128_bits():
    return secrets.randbits(128)


def gerar_par_dh():
    chave_privada = gerar_numero_privado_128_bits()
    chave_publica = pow(G, chave_privada, P)
    return chave_privada, chave_publica


def calcular_segredo_partilhado(chave_privada: int, chave_publica_remota: int) -> int:
    return pow(chave_publica_remota, chave_privada, P)


def derivar_chave_sessao(segredo_partilhado: int) -> str:
    segredo_bytes = str(segredo_partilhado).encode("utf-8")
    return hashlib.sha256(segredo_bytes).hexdigest()