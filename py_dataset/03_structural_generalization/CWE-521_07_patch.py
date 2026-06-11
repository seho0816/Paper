import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Registration:
    username: str
    password: str


class PasswordPolicy:
    def validate(
        self,
        password: str,
    ) -> None:
        if len(password) < 8:
            raise ValueError(
                "password too short (minimum 8 characters)"
            )
        if not re.search(r"[A-Z]", password):
            raise ValueError(
                "password must contain at least one uppercase letter"
            )
        if not re.search(r"[a-z]", password):
            raise ValueError(
                "password must contain at least one lowercase letter"
            )
        if not re.search(r"\d", password):
            raise ValueError(
                "password must contain at least one digit"
            )
        if not re.search(r"[^A-Za-z0-9]", password):
            raise ValueError(
                "password must contain at least one special character"
            )


class RegistrationService:
    def __init__(
        self,
        policy: PasswordPolicy,
    ) -> None:
        self._policy = policy

    def register(
        self,
        request: Registration,
    ) -> None:
        self._policy.validate(
            request.password
        )
        save_account(
            request.username,
            request.password,
        )
