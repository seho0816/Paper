from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryRequest:
    email: str


class AccountRepository:
    def exists(
        self,
        email: str,
    ) -> bool:
        return database.account_exists(
            email
        )


class RecoveryController:
    def __init__(
        self,
        repository: AccountRepository,
    ) -> None:
        self._repository = repository

    def post(
        self,
        request: RecoveryRequest,
    ) -> tuple[dict, int]:
        if not self._repository.exists(
            request.email
        ):
            return {
                "error": "no account for email",
            }, 404

        enqueue_reset_email(
            request.email
        )

        return {
            "queued": True,
        }, 202
