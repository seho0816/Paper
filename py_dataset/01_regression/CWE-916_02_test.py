import hashlib
import os

def hash_password(password: str) -> tuple[bytes, bytes, int]:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        10000,
    )
    return salt, digest, 10000
