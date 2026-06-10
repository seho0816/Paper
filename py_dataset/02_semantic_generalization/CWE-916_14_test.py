import hashlib
import os
from dataclasses import dataclass


@dataclass
class PasswordRecord:
    username: str
    salt: bytes
    password_hash: bytes


def hash_password(password: str) -> tuple[bytes, bytes]:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        1000,
    )

    return salt, digest


def create_password_record(username: str, password: str) -> PasswordRecord:
    salt, digest = hash_password(password)

    return PasswordRecord(
        username=username,
        salt=salt,
        password_hash=digest,
    )


def main():
    record = create_password_record("mube", "password1234")
    print(record.username, len(record.password_hash))


if __name__ == "__main__":
    main()
