from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

from generar_llaves import generate_3des_key, generate_iv


TAMANO_BLOQUE_DES = 8


def encrypt_3des_cbc(texto_plano: bytes, clave: bytes, iv: bytes) -> bytes:
    clave_ajustada = DES3.adjust_key_parity(clave)
    cifrador = DES3.new(clave_ajustada, DES3.MODE_CBC, iv=iv)
    texto_con_relleno = pad(texto_plano, TAMANO_BLOQUE_DES)
    return cifrador.encrypt(texto_con_relleno)


def decrypt_3des_cbc(texto_cifrado: bytes, clave: bytes, iv: bytes) -> bytes:
    clave_ajustada = DES3.adjust_key_parity(clave)
    cifrador = DES3.new(clave_ajustada, DES3.MODE_CBC, iv=iv)
    texto_descifrado = cifrador.decrypt(texto_cifrado)
    return unpad(texto_descifrado, TAMANO_BLOQUE_DES)


if __name__ == "__main__":
    clave = generate_3des_key()
    iv = generate_iv(TAMANO_BLOQUE_DES)
    mensaje = b"Laboratorio Block - 3DES CBC"

    texto_cifrado = encrypt_3des_cbc(mensaje, clave, iv)
    texto_descifrado = decrypt_3des_cbc(texto_cifrado, clave, iv)

    print(f"Mensaje original: {mensaje}")
    print(f"Texto cifrado (hex): {texto_cifrado.hex()}")
    print(f"Mensaje descifrado: {texto_descifrado}")
