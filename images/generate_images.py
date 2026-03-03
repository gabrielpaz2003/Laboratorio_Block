"""
Genera original.png con patrones claros y la cifra con AES-256
en modo ECB y CBC para demostrar visualmente la diferencia de seguridad.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PIL import Image, ImageDraw, ImageFont
from src.utils import generar_clave_aes, generar_iv
from src.aes_cipher import cifrar_imagen_ecb, cifrar_imagen_cbc

ORIGINAL = os.path.join(os.path.dirname(__file__), "original.png")
SALIDA_ECB = os.path.join(os.path.dirname(__file__), "aes_ecb.png")
SALIDA_CBC = os.path.join(os.path.dirname(__file__), "aes_cbc.png")

W, H = 300, 300


def crear_imagen_original():
    img = Image.new("RGB", (W, H), "white")
    draw = ImageDraw.Draw(img)

    draw.rectangle([0,   0, W,  60], fill=(220, 50,  50))
    draw.rectangle([0,  60, W, 120], fill=(50, 180,  50))
    draw.rectangle([0, 120, W, 180], fill=(50,  50, 220))
    draw.rectangle([0, 180, W, 240], fill=(220, 220,  50))
    draw.rectangle([0, 240, W, 300], fill=(180,  50, 180))

    draw.rectangle([60, 110, 240, 190], fill=(255, 255, 255))
    try:
        fuente = ImageFont.truetype("arial.ttf", 18)
    except OSError:
        fuente = ImageFont.load_default()
    draw.text((90, 140), "UVG  2026", fill=(0, 0, 0), font=fuente)

    img.save(ORIGINAL)
    print(f"[OK] {ORIGINAL}")


if __name__ == "__main__":
    crear_imagen_original()

    clave = generar_clave_aes(256)
    iv = generar_iv(16)

    cifrar_imagen_ecb(ORIGINAL, clave, SALIDA_ECB)
    print(f"[OK] {SALIDA_ECB}")

    cifrar_imagen_cbc(ORIGINAL, clave, iv, SALIDA_CBC)
    print(f"[OK] {SALIDA_CBC}")

    print("\nImágenes guardadas en images/")
