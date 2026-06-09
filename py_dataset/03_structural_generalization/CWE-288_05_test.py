from dataclasses import dataclass


@dataclass(frozen=True)
class BackupLogin:
    username: str
    backup_code: str


class BackupCodeRepository:
    def verify(
        self,
        request: BackupLogin,
    ) -> dict | None:
        account = find_account(
            request.username
        )

        if account is None:
            return None

        if request.backup_code not in account[
            "backup_codes"
        ]:
            return None

        return account


class BackupLoginService:
    def __init__(
        self,
        repository: BackupCodeRepository,
    ) -> None:
        self._repository = repository

    def login(
        self,
        request: BackupLogin,
    ) -> str | None:
        account = self._repository.verify(
            request
        )

        if account is None:
            return None

        return create_session(
            account["id"]
        )
