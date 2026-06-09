from Crypto.Cipher import DES
from Crypto.Util.Padding import pad


def encrypt_export(
    content: bytes,
    key: bytes,
) -> bytes:
    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv=b"12345678",
    )

    return cipher.encrypt(
        pad(
            content,
            DES.block_size,
        )
    )
