import hashlib

from Crypto.Cipher import AES


def encrypt_private_note(
    key: bytes,
    password_hash: str,
    padded_note: bytes,
) -> bytes:
    iv = hashlib.sha256(
        password_hash.encode(
            "ascii"
        )
    ).digest()[:16]
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )

    return cipher.encrypt(
        padded_note
    )
