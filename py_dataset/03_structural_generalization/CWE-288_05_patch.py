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

        # CWE-288 fix: Invalidate the backup code after successful use to prevent reuse.
        # This prevents an attacker from repeatedly using the same backup code
        # to bypass primary authentication.
        if request.backup_code in account[
            "backup_codes"
        ]:
            account["backup_codes"].remove(request.backup_code)
            # Assume save_account is an existing function that persists account changes.
            save_account(account)
            return account
        else:
            return None


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
