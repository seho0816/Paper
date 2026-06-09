import hashlib
from datetime import date

from Crypto.Cipher import AES


def encrypt_daily_export(
    key: bytes,
    content: bytes,
) -> bytes:
    iv = hashlib.sha256(
        date.today().isoformat().encode(
            "ascii"
        )
    ).digest()[:16]
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )

    return cipher.encrypt(
        content
    )
