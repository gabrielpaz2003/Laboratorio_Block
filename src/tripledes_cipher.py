from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

TAMANO_BLOQUE = 8


def cifrar_3des_cbc(texto_plano: bytes, clave: bytes, iv: bytes) -> bytes:
    clave = DES3.adjust_key_parity(clave)
    cifrador = DES3.new(clave, DES3.MODE_CBC, iv=iv)
    return cifrador.encrypt(pad(texto_plano, TAMANO_BLOQUE))


def descifrar_3des_cbc(texto_cifrado: bytes, clave: bytes, iv: bytes) -> bytes:
    clave = DES3.adjust_key_parity(clave)
    cifrador = DES3.new(clave, DES3.MODE_CBC, iv=iv)
    return unpad(cifrador.decrypt(texto_cifrado), TAMANO_BLOQUE)


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from src.utils import generar_clave_3des, generar_iv

    clave = generar_clave_3des(n_claves=2)
    iv = generar_iv(TAMANO_BLOQUE)
    mensaje = b"Laboratorio 3DES CBC"

    cifrado = cifrar_3des_cbc(mensaje, clave, iv)
    descifrado = descifrar_3des_cbc(cifrado, clave, iv)

    print(f"Original  : {mensaje}")
    print(f"Clave     : {clave.hex()} ({len(clave)} bytes)")
    print(f"IV        : {iv.hex()}")
    print(f"Cifrado   : {cifrado.hex()}")
    print(f"Descifrado: {descifrado}")
    print(f"Coincide  : {mensaje == descifrado}")
