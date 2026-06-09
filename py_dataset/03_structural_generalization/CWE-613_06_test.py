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
        send_password_changed_email(
            request.account_id
        )
