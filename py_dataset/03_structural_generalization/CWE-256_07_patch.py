from dataclasses import dataclass
import bcrypt


@dataclass(frozen=True)
class Registration:
    email: str
    password: str


class AccountRepository:
    def save(
        self,
        registration: Registration,
    ) -> str:
        # CWE-256 fix: Hash the password before storing it.
        # bcrypt.hashpw expects bytes for password and salt.
        # bcrypt.gensalt() generates a new salt each time.
        # The result is decoded to utf-8 string for storage.
        hashed_password = bcrypt.hashpw(registration.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        return database.insert_account({
            "email": registration.email,
            "password": hashed_password,
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
