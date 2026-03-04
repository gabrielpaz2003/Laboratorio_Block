import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.utils import (
    generar_clave_des, generar_clave_3des, generar_clave_aes,
    generar_iv, generar_nonce, rellenar_pkcs7, quitar_relleno_pkcs7,
)
from src.des_cipher import cifrar_des_ecb, descifrar_des_ecb
from src.tripledes_cipher import cifrar_3des_cbc, descifrar_3des_cbc
from src.aes_cipher import (
    cifrar_aes_ecb, descifrar_aes_ecb,
    cifrar_aes_cbc, descifrar_aes_cbc,
    cifrar_aes_ctr, descifrar_aes_ctr,
)


# ── PKCS#7 ───────────────────────────────────────────────────────────────────

def test_relleno_5_bytes():
    # 5 bytes → 3 bytes de padding (0x03)
    assert rellenar_pkcs7(b"ABCDE", 8) == b"ABCDE\x03\x03\x03"

def test_relleno_8_bytes():
    # múltiplo exacto → bloque completo de padding (0x08 × 8)
    relleno = rellenar_pkcs7(b"ABCDEFGH", 8)
    assert len(relleno) == 16 and relleno[-1] == 8

def test_relleno_10_bytes():
    # 10 bytes → 6 bytes de padding (0x06)
    relleno = rellenar_pkcs7(b"ABCDEFGHIJ", 8)
    assert len(relleno) == 16 and relleno[-1] == 6

def test_relleno_ida_vuelta():
    for msg in [b"X" * 5, b"X" * 8, b"X" * 10, b"X" * 16]:
        assert quitar_relleno_pkcs7(rellenar_pkcs7(msg, 8)) == msg


# ── DES-ECB ──────────────────────────────────────────────────────────────────

def test_des_ecb_cifrar_descifrar():
    clave = generar_clave_des()
    for msg in [b"Hola!", b"A" * 8, b"Mensaje mas largo que un bloque"]:
        assert descifrar_des_ecb(cifrar_des_ecb(msg, clave), clave) == msg

def test_des_ecb_bloques_identicos():
    # ECB: bloques de plaintext idénticos → bloques de ciphertext idénticos
    clave = generar_clave_des()
    bloque = b"ATACAR!!"
    cifrado = cifrar_des_ecb(bloque * 3, clave)
    assert cifrado[0:8] == cifrado[8:16] == cifrado[16:24]

def test_des_clave_longitud():
    assert len(generar_clave_des()) == 8


# ── 3DES-CBC ─────────────────────────────────────────────────────────────────

def test_3des_cbc_2_claves():
    clave = generar_clave_3des(n_claves=2)
    iv = generar_iv(8)
    msg = b"Mensaje 3DES 2 claves"
    assert descifrar_3des_cbc(cifrar_3des_cbc(msg, clave, iv), clave, iv) == msg

def test_3des_cbc_3_claves():
    clave = generar_clave_3des(n_claves=3)
    iv = generar_iv(8)
    msg = b"Mensaje 3DES 3 claves"
    assert descifrar_3des_cbc(cifrar_3des_cbc(msg, clave, iv), clave, iv) == msg

def test_3des_longitud_claves():
    assert len(generar_clave_3des(2)) == 16
    assert len(generar_clave_3des(3)) == 24

def test_3des_iv_distinto_ciphertext_distinto():
    clave = generar_clave_3des()
    msg = b"Mismo mensaje"
    ct1 = cifrar_3des_cbc(msg, clave, generar_iv(8))
    ct2 = cifrar_3des_cbc(msg, clave, generar_iv(8))
    assert ct1 != ct2

def test_3des_mismo_iv_mismo_ciphertext():
    clave = generar_clave_3des()
    iv = generar_iv(8)
    msg = b"Mismo mensaje"
    assert cifrar_3des_cbc(msg, clave, iv) == cifrar_3des_cbc(msg, clave, iv)


# ── AES-ECB ──────────────────────────────────────────────────────────────────

def test_aes_ecb_cifrar_descifrar():
    clave = generar_clave_aes(256)
    for msg in [b"corto", b"B" * 16, b"B" * 32, b"longitud variable"]:
        assert descifrar_aes_ecb(cifrar_aes_ecb(msg, clave), clave) == msg

def test_aes_ecb_bloques_identicos():
    clave = generar_clave_aes(256)
    bloque = b"ATAQUE!!ATAQUE!!"   # 16 bytes exactos
    cifrado = cifrar_aes_ecb(bloque * 3, clave)
    assert cifrado[0:16] == cifrado[16:32] == cifrado[32:48]

def test_aes_longitud_clave():
    assert len(generar_clave_aes(256)) == 32
    assert len(generar_clave_aes(128)) == 16


# ── AES-CBC ──────────────────────────────────────────────────────────────────

def test_aes_cbc_cifrar_descifrar():
    clave = generar_clave_aes(256)
    iv = generar_iv(16)
    for msg in [b"corto", b"C" * 16, b"mensaje de longitud variable"]:
        assert descifrar_aes_cbc(cifrar_aes_cbc(msg, clave, iv), clave, iv) == msg

def test_aes_cbc_iv_distinto_ciphertext_distinto():
    clave = generar_clave_aes(256)
    msg = b"Mismo mensaje secreto"
    ct1 = cifrar_aes_cbc(msg, clave, generar_iv(16))
    ct2 = cifrar_aes_cbc(msg, clave, generar_iv(16))
    assert ct1 != ct2

def test_aes_cbc_sin_bloques_identicos():
    clave = generar_clave_aes(256)
    iv = generar_iv(16)
    bloque = b"ATAQUE!!ATAQUE!!"
    cifrado = cifrar_aes_cbc(bloque * 3, clave, iv)
    assert not (cifrado[0:16] == cifrado[16:32] == cifrado[32:48])


# ── AES-CTR ──────────────────────────────────────────────────────────────────

def test_aes_ctr_cifrar_descifrar():
    clave = generar_clave_aes(256)
    nonce = generar_nonce(8)
    for msg in [b"sin padding", b"D" * 16, b"longitud arbitraria 99"]:
        assert descifrar_aes_ctr(cifrar_aes_ctr(msg, clave, nonce), clave, nonce) == msg

def test_aes_ctr_sin_padding():
    # CTR no agrega bytes: el ciphertext tiene la misma longitud que el plaintext
    clave = generar_clave_aes(256)
    nonce = generar_nonce(8)
    msg = b"exactamente16!!!"
    assert len(cifrar_aes_ctr(msg, clave, nonce)) == len(msg)

def test_aes_ctr_nonce_distinto_ciphertext_distinto():
    clave = generar_clave_aes(256)
    msg = b"mismo mensaje"
    ct1 = cifrar_aes_ctr(msg, clave, generar_nonce(8))
    ct2 = cifrar_aes_ctr(msg, clave, generar_nonce(8))
    assert ct1 != ct2


if __name__ == "__main__":
    tests = [
        test_relleno_5_bytes, test_relleno_8_bytes, test_relleno_10_bytes,
        test_relleno_ida_vuelta,
        test_des_ecb_cifrar_descifrar, test_des_ecb_bloques_identicos, test_des_clave_longitud,
        test_3des_cbc_2_claves, test_3des_cbc_3_claves, test_3des_longitud_claves,
        test_3des_iv_distinto_ciphertext_distinto, test_3des_mismo_iv_mismo_ciphertext,
        test_aes_ecb_cifrar_descifrar, test_aes_ecb_bloques_identicos, test_aes_longitud_clave,
        test_aes_cbc_cifrar_descifrar, test_aes_cbc_iv_distinto_ciphertext_distinto,
        test_aes_cbc_sin_bloques_identicos,
        test_aes_ctr_cifrar_descifrar, test_aes_ctr_sin_padding, test_aes_ctr_nonce_distinto_ciphertext_distinto,
    ]
    for t in tests:
        t()
        print(f"  PASS  {t.__name__}")
    print(f"\nTotal: {len(tests)} tests pasados.")
