import secrets
from Crypto.Cipher import DES3


def generar_clave_des() -> bytes:
    return secrets.token_bytes(8)


def generar_clave_3des(n_claves: int = 2) -> bytes:
    longitud = 16 if n_claves == 2 else 24
    while True:
        clave = secrets.token_bytes(longitud)
        try:
            return DES3.adjust_key_parity(clave)
        except ValueError:
            continue


def generar_clave_aes(bits: int = 256) -> bytes:
    return secrets.token_bytes(bits // 8)


def generar_iv(tamano: int = 8) -> bytes:
    return secrets.token_bytes(tamano)


def generar_nonce(tamano: int = 8) -> bytes:
    return secrets.token_bytes(tamano)


# Padding PKCS#7 implementado manualmente (requerido por la sección 1.1)
def rellenar_pkcs7(datos: bytes, tamano_bloque: int = 8) -> bytes:
    n = tamano_bloque - (len(datos) % tamano_bloque)
    return datos + bytes([n]) * n


def quitar_relleno_pkcs7(datos: bytes) -> bytes:
    n = datos[-1]
    return datos[:-n]
