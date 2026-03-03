from Crypto.Cipher import DES
from src.utils import rellenar_pkcs7, quitar_relleno_pkcs7

TAMANO_BLOQUE = 8


def cifrar_des_ecb(texto_plano: bytes, clave: bytes) -> bytes:
    cifrador = DES.new(clave, DES.MODE_ECB)
    return cifrador.encrypt(rellenar_pkcs7(texto_plano, TAMANO_BLOQUE))


def descifrar_des_ecb(texto_cifrado: bytes, clave: bytes) -> bytes:
    cifrador = DES.new(clave, DES.MODE_ECB)
    return quitar_relleno_pkcs7(cifrador.decrypt(texto_cifrado))


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from src.utils import generar_clave_des

    clave = generar_clave_des()
    mensaje = b"Hola DES!"

    cifrado = cifrar_des_ecb(mensaje, clave)
    descifrado = descifrar_des_ecb(cifrado, clave)

    print(f"Original  : {mensaje}")
    print(f"Cifrado   : {cifrado.hex()}")
    print(f"Descifrado: {descifrado}")
    print(f"Coincide  : {mensaje == descifrado}")
