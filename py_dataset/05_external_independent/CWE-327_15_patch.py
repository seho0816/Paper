from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def encrypt_export(
    content: bytes,
    key: bytes,
) -> bytes:
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )

    return iv + cipher.encrypt(
        pad(
            content,
            AES.block_size,
        )
    )