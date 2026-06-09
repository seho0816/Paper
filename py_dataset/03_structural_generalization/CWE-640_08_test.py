from dataclasses import dataclass


@dataclass(frozen=True)
class ResetTokenRecord:
    token: str
    account_id: str


class ResetTokenRepository:
    def __init__(self) -> None:
        self._records: dict[
            str,
            ResetTokenRecord,
        ] = {}

    def find(
        self,
        token: str,
    ) -> ResetTokenRecord | None:
        return self._records.get(token)


class PasswordResetService:
    def __init__(
        self,
        repository: ResetTokenRepository,
    ) -> None:
        self._repository = repository

    def reset(
        self,
        token: str,
        requested_account_id: str,
        password: str,
    ) -> bool:
        record = self._repository.find(
            token,
        )

        if record is None:
            return False

        update_password(
            requested_account_id,
            password,
        )
        return True
