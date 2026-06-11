from dataclasses import dataclass
import bcrypt


@dataclass(frozen=True)
class PasswordReset:
    account_id: str
    new_password: str


class PasswordResetRepository:
    def replace(
        self,
        request: PasswordReset,
    ) -> None:
        # Hash the new password using bcrypt before storing it
        hashed_password = bcrypt.hashpw(request.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        database.execute(
            (
                "UPDATE accounts "
                "SET password = ? "
                "WHERE account_id = ?"
            ),
            (
                hashed_password,
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
