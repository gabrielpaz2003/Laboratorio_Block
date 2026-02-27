# Laboratorio Block

Implementación base para el laboratorio de cifrado por bloques.

## Avance 1.2 - 3DES en modo CBC

Se implementaron funciones reutilizables para cifrado y descifrado con Triple DES (3DES) en modo CBC:

- Generación de llave 3DES segura (16 o 24 bytes) con `secrets`
- Selección dinámica de tamaño de llave con `random`
- Generación de IV aleatorio por operación
- Uso de `pad` y `unpad` de `Crypto.Util.Padding`

## Archivos principales

- `generar_llaves.py`: funciones de generación de llaves e IV
- `3des.py`: funciones `encrypt_3des_cbc(...)` y `decrypt_3des_cbc(...)`

## Dependencia

Instalar PyCryptodome:

```bash
py -m pip install pycryptodome
```

## Uso rápido

```python
from generar_llaves import generate_3des_key, generate_iv
import importlib

mod_3des = importlib.import_module("3des")
encrypt_3des_cbc = mod_3des.encrypt_3des_cbc
decrypt_3des_cbc = mod_3des.decrypt_3des_cbc

key = generate_3des_key()   # 16 o 24 bytes
iv = generate_iv(8)         # IV para DES/3DES
msg = b"Mensaje secreto"

ciphertext = encrypt_3des_cbc(msg, key, iv)
plaintext = decrypt_3des_cbc(ciphertext, key, iv)
```

También puedes ejecutar una prueba directa:

```bash
py 3des.py
```
