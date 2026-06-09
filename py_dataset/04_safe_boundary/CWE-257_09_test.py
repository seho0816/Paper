import hashlib
import os


def derive_password_hash(
    password: str,
) -> tuple[bytes, bytes]:
    salt = os.urandom(
        16
    )
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2 ** 15,
        r=8,
        p=1,
        dklen=32,
    )

    return salt, derived
