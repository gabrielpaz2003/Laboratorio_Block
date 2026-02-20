import secrets


def generate_des_key() -> bytes:
    return secrets.token_bytes(8)


def generate_3des_key(key_option: int = 2) -> bytes:
    if key_option == 2:
        return secrets.token_bytes(16)
    elif key_option == 3:
        return secrets.token_bytes(24)
    else:
        raise ValueError("key_option debe ser 2 (16 bytes) o 3 (24 bytes)")


def generate_aes_key(key_size: int = 256) -> bytes:
    if key_size not in (128, 192, 256):
        raise ValueError("key_size debe ser 128, 192 o 256")
    return secrets.token_bytes(key_size // 8)


def generate_iv(block_size: int = 8) -> bytes:
    if block_size <= 0:
        raise ValueError("block_size debe ser mayor que 0")
    return secrets.token_bytes(block_size)
