class AccountRepository:
    def disable(
        self,
        account_id: str,
    ) -> int:
        return database.execute(
            """
            UPDATE accounts
            SET active = 0
            WHERE account_id = ?
            """,
            (
                account_id,
            ),
        )


class AccountService:
    def __init__(
        self,
        repository: AccountRepository,
    ) -> None:
        self._repository = repository

    def disable(
        self,
        account_id: str,
    ) -> dict:
        self._repository.disable(
            account_id
        )

        return {
            "disabled": True,
        }
