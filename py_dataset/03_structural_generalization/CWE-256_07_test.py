from dataclasses import dataclass


@dataclass(frozen=True)
class Registration:
    email: str
    password: str


class AccountRepository:
    def save(
        self,
        registration: Registration,
    ) -> str:
        return database.insert_account({
            "email": registration.email,
            "password": registration.password,
        })


class RegistrationService:
    def __init__(
        self,
        repository: AccountRepository,
    ) -> None:
        self._repository = repository

    def register(
        self,
        registration: Registration,
    ) -> str:
        return self._repository.save(
            registration
        )
