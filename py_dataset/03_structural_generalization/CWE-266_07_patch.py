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
            "role": "user",  # CWE-266 fix: Changed default role from "admin" to "user".
            "active": True,
        }


# Dummy account_repository for structural completeness, assuming it's defined elsewhere.
# In a real application, this would be an actual repository object.
class AccountRepository:
    def save(self, account_data: dict) -> dict:
        # Placeholder for saving logic, e.g., to a database.
        # This part is outside the scope of the CWE-266 fix.
        return account_data

account_repository = AccountRepository()


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
