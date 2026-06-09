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
        rows_affected = self._repository.disable(
            account_id
        )

        # CWE-252: Unchecked Return Value - The return value of _repository.disable was previously ignored.
        # Now, we check the number of rows affected to determine if the operation was successful.
        if rows_affected > 0:
            return {
                "disabled": True,
            }
        else:
            # If no rows were affected, the account was likely not found or already disabled.
            # We return False to accurately reflect the operation's outcome.
            return {
                "disabled": False,
            }
