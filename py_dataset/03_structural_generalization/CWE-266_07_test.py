from dataclasses import dataclass


@dataclass(frozen=True)
class Registration:
    email: str
    password_hash: str


class AccountFactory:
    def create(
        self,
        request: Registration,
    ) -> dict:
        return {
            "email": request.email,
            "password_hash": request.password_hash,
            "role": "admin",
            "active": True,
        }


class RegistrationService:
    def __init__(
        self,
        factory: AccountFactory,
    ) -> None:
        self._factory = factory

    def register(
        self,
        request: Registration,
    ) -> dict:
        return account_repository.save(
            self._factory.create(
                request
            )
        )
