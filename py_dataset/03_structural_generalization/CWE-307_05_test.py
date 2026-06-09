from dataclasses import dataclass


@dataclass(frozen=True)
class LoginCommand:
    username: str
    password: str


class UserRepository:
    def find(self, username: str) -> dict | None:
        return database.find_user(username)


class PasswordVerifier:
    def verify(
        self,
        submitted: str,
        stored_hash: str,
    ) -> bool:
        return verify_password_hash(
            submitted,
            stored_hash,
        )


class AuthenticationService:
    def __init__(
        self,
        repository: UserRepository,
        verifier: PasswordVerifier,
    ) -> None:
        self._repository = repository
        self._verifier = verifier

    def authenticate(
        self,
        command: LoginCommand,
    ) -> bool:
        user = self._repository.find(
            command.username,
        )

        if user is None:
            return False

        return self._verifier.verify(
            command.password,
            user["password_hash"],
        )
