"""
Demostración simplificada de Padding Oracle Attack sobre AES-CBC.
El oráculo simula un servidor que revela si el padding PKCS#7 es válido.
Vulnerabilidades reales: POODLE (2014), Lucky 13 (2013).
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

TAMANO_BLOQUE = 16


def oraculo(texto_cifrado: bytes, clave: bytes) -> bool:
    iv = texto_cifrado[:TAMANO_BLOQUE]
    ct = texto_cifrado[TAMANO_BLOQUE:]
    try:
        descifrado = AES.new(clave, AES.MODE_CBC, iv=iv).decrypt(ct)
        unpad(descifrado, TAMANO_BLOQUE)
        return True
    except ValueError:
        return False


def ataque_oraculo_relleno(texto_cifrado: bytes, clave: bytes) -> bytes:
    bloques = [texto_cifrado[i: i + TAMANO_BLOQUE] for i in range(0, len(texto_cifrado), TAMANO_BLOQUE)]
    recuperado = bytearray()

    for b in range(1, len(bloques)):
        anterior = bytearray(bloques[b - 1])
        actual = bloques[b]
        intermedio = bytearray(TAMANO_BLOQUE)

        for pos in range(TAMANO_BLOQUE - 1, -1, -1):
            valor_relleno = TAMANO_BLOQUE - pos
            modificado = bytearray(anterior)

            for k in range(pos + 1, TAMANO_BLOQUE):
                modificado[k] = intermedio[k] ^ valor_relleno

            for intento in range(256):
                modificado[pos] = intento
                if oraculo(bytes(modificado) + actual, clave):
                    intermedio[pos] = intento ^ valor_relleno
                    break

        for i in range(TAMANO_BLOQUE):
            recuperado.append(intermedio[i] ^ anterior[i])

    try:
        return bytes(unpad(bytes(recuperado), TAMANO_BLOQUE))
    except ValueError:
        return bytes(recuperado)


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from src.utils import generar_clave_aes, generar_iv

    clave = generar_clave_aes(256)
    iv = generar_iv(TAMANO_BLOQUE)
    texto_plano = b"Secreto del servidor!!"

    ct = iv + AES.new(clave, AES.MODE_CBC, iv=iv).encrypt(pad(texto_plano, TAMANO_BLOQUE))

    print("Ejecutando Padding Oracle Attack...")
    print(f"  Original  : {texto_plano}")
    recuperado = ataque_oraculo_relleno(ct, clave)
    print(f"  Recuperado: {recuperado}")
    print(f"  Exitoso   : {texto_plano == recuperado}")
