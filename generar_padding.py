def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size debe estar entre 1 y 255")

    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size

    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Datos vacíos; no se puede quitar padding")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > 255:
        raise ValueError("Padding inválido (valor fuera de rango)")

    if pad_len > len(data):
        raise ValueError("Padding inválido (más grande que los datos)")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding inválido (bytes no coinciden)")

    return data[:-pad_len]
