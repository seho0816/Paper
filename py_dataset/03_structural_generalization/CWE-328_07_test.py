import hashlib
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
        return hashlib.md5(
            password.encode("utf-8")
        ).hexdigest()


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
        save_account(
            request.email,
            password_hash,
        )
