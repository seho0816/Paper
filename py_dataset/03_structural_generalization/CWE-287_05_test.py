from dataclasses import dataclass


@dataclass(frozen=True)
class LoginCommand:
    username: str
    password: str


class AccountRepository:
    def find_by_username(
        self,
        username: str,
    ) -> dict | None:
        return database.find_account(
            username,
        )


class SessionIssuer:
    def issue(
        self,
        account_id: str,
    ) -> str:
        return create_signed_session(
            account_id,
        )


class LoginService:
    def __init__(
        self,
        repository: AccountRepository,
        issuer: SessionIssuer,
    ) -> None:
        self._repository = repository
        self._issuer = issuer

    def login(
        self,
        command: LoginCommand,
    ) -> str | None:
        account = self._repository.find_by_username(
            command.username,
        )

        if account is None:
            return None

        return self._issuer.issue(
            account["id"],
        )
