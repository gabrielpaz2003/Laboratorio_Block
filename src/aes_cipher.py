from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image

TAMANO_BLOQUE = 16


def cifrar_aes_ecb(texto_plano: bytes, clave: bytes) -> bytes:
    return AES.new(clave, AES.MODE_ECB).encrypt(pad(texto_plano, TAMANO_BLOQUE))


def descifrar_aes_ecb(texto_cifrado: bytes, clave: bytes) -> bytes:
    return unpad(AES.new(clave, AES.MODE_ECB).decrypt(texto_cifrado), TAMANO_BLOQUE)


def cifrar_aes_cbc(texto_plano: bytes, clave: bytes, iv: bytes) -> bytes:
    return AES.new(clave, AES.MODE_CBC, iv=iv).encrypt(pad(texto_plano, TAMANO_BLOQUE))


def descifrar_aes_cbc(texto_cifrado: bytes, clave: bytes, iv: bytes) -> bytes:
    return unpad(AES.new(clave, AES.MODE_CBC, iv=iv).decrypt(texto_cifrado), TAMANO_BLOQUE)


def cifrar_aes_ctr(texto_plano: bytes, clave: bytes, nonce: bytes) -> bytes:
    return AES.new(clave, AES.MODE_CTR, nonce=nonce).encrypt(texto_plano)


def descifrar_aes_ctr(texto_cifrado: bytes, clave: bytes, nonce: bytes) -> bytes:
    return AES.new(clave, AES.MODE_CTR, nonce=nonce).decrypt(texto_cifrado)


def cifrar_imagen_ecb(ruta_entrada: str, clave: bytes, ruta_salida: str):
    img = Image.open(ruta_entrada).convert("RGB")
    datos = img.tobytes()
    cifrado = AES.new(clave, AES.MODE_ECB).encrypt(pad(datos, TAMANO_BLOQUE))[: len(datos)]
    Image.frombytes("RGB", img.size, cifrado).save(ruta_salida)


def cifrar_imagen_cbc(ruta_entrada: str, clave: bytes, iv: bytes, ruta_salida: str):
    img = Image.open(ruta_entrada).convert("RGB")
    datos = img.tobytes()
    cifrado = AES.new(clave, AES.MODE_CBC, iv=iv).encrypt(pad(datos, TAMANO_BLOQUE))[: len(datos)]
    Image.frombytes("RGB", img.size, cifrado).save(ruta_salida)


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from src.utils import generar_clave_aes, generar_iv, generar_nonce

    clave = generar_clave_aes(256)
    iv = generar_iv(TAMANO_BLOQUE)
    nonce = generar_nonce(8)
    mensaje = b"Mensaje AES secreto"

    assert descifrar_aes_ecb(cifrar_aes_ecb(mensaje, clave), clave) == mensaje
    print(f"AES-ECB OK: {cifrar_aes_ecb(mensaje, clave).hex()}")

    assert descifrar_aes_cbc(cifrar_aes_cbc(mensaje, clave, iv), clave, iv) == mensaje
    print(f"AES-CBC OK: {cifrar_aes_cbc(mensaje, clave, iv).hex()}")

    assert descifrar_aes_ctr(cifrar_aes_ctr(mensaje, clave, nonce), clave, nonce) == mensaje
    print(f"AES-CTR OK: {cifrar_aes_ctr(mensaje, clave, nonce).hex()}")
