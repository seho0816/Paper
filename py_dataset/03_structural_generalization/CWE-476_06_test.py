from dataclasses import dataclass


@dataclass(frozen=True)
class AccountView:
    account_id: str


class AccountRepository:
    def find(
        self,
        account_id: str,
    ) -> dict | None:
        return database.find_account(
            account_id
        )


class AccountViewService:
    def __init__(
        self,
        repository: AccountRepository,
    ) -> None:
        self._repository = repository

    def create(
        self,
        request: AccountView,
    ) -> dict:
        account = self._repository.find(
            request.account_id
        )

        return {
            "email": account["email"],
            "role": account["role"],
        }
