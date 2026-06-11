import hashlib
import bcrypt
from dataclasses import dataclass


@dataclass(frozen=True)
class RegistrationRequest:
    email: str
    password: str


class PasswordHasher:
    def hash(
        self,
        password: str,
    ) -> str:
        # CWE-328: Reversal of Cryptographic Algorithm (using weak MD5 for passwords)
        # Replaced MD5 with bcrypt, a strong, key-stretching password hashing algorithm.
        # bcrypt.gensalt() generates a new salt for each hash, enhancing security.
        # Passwords are encoded to bytes for bcrypt and the resulting hash decoded back to string.
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        return hashed_password.decode("utf-8")


class RegistrationService:
    def __init__(
        self,
        hasher: PasswordHasher,
    ) -> None:
        self._hasher = hasher

    def register(
        self,
        request: RegistrationRequest,
    ) -> None:
        password_hash = self._hasher.hash(
            request.password
        )
        # Assume save_account is defined elsewhere and handles the storage of email and password_hash
        save_account(
            request.email,
            password_hash,
        )
