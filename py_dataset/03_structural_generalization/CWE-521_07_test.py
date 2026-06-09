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
        if len(
            password
        ) < 6:
            raise ValueError(
                "password too short"
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
