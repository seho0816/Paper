from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordReset:
    account_id: str
    new_password: str


class PasswordResetRepository:
    def replace(
        self,
        request: PasswordReset,
    ) -> None:
        database.execute(
            (
                "UPDATE accounts "
                "SET password = ? "
                "WHERE account_id = ?"
            ),
            (
                request.new_password,
                request.account_id,
            ),
        )


class PasswordResetService:
    def __init__(
        self,
        repository: PasswordResetRepository,
    ) -> None:
        self._repository = repository

    def reset(
        self,
        request: PasswordReset,
    ) -> None:
        self._repository.replace(
            request
        )
