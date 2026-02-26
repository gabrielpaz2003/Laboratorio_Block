import random
import secrets

from Crypto.Cipher import DES3


def generate_des_key() -> bytes:
    return secrets.token_bytes(8)


def generate_3des_key(opcion_clave: int | None = None) -> bytes:
    if opcion_clave is None:
        opcion_clave = random.choice((2, 3))

    if opcion_clave == 2:
        longitud_clave = 16
    elif opcion_clave == 3:
        longitud_clave = 24
    else:
        raise ValueError("opcion_clave debe ser 2 (16 bytes) o 3 (24 bytes)")

    while True:
        clave = secrets.token_bytes(longitud_clave)
        try:
            return DES3.adjust_key_parity(clave)
        except ValueError:
            continue


def generate_aes_key(tamano_clave: int = 256) -> bytes:
    if tamano_clave not in (128, 192, 256):
        raise ValueError("tamano_clave debe ser 128, 192 o 256")
    return secrets.token_bytes(tamano_clave // 8)


def generate_iv(tamano_bloque: int = 8) -> bytes:
    return secrets.token_bytes(tamano_bloque)
