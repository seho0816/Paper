from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordChange:
    account_id: str
    password_hash: str


class PasswordRepository:
    def replace(
        self,
        request: PasswordChange,
    ) -> None:
        # Assume 'database' is an existing global or imported object/module
        database.update_password(
            request.account_id,
            request.password_hash,
        )


class PasswordService:
    def __init__(
        self,
        repository: PasswordRepository,
    ) -> None:
        self._repository = repository

    def change(
        self,
        request: PasswordChange,
    ) -> None:
        self._repository.replace(
            request
        )
        # CWE-613 fix: Invalidate all existing sessions for the account
        # after a password change to ensure old sessions are no longer valid.
        # Assume 'invalidate_all_sessions' is an existing global or imported function
        # that handles session invalidation (e.g., by deleting session tokens).
        invalidate_all_sessions(
            request.account_id
        )
        # Assume 'send_password_changed_email' is an existing global or imported function
        send_password_changed_email(
            request.account_id
        )
