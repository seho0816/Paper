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

        # CWE-476: Null Pointer Dereference vulnerability fix
        # The 'account' variable can be None if _repository.find returns None (account not found).
        # Accessing 'account["email"]' or 'account["role"]' when 'account' is None
        # would result in a TypeError (e.g., 'NoneType' object is not subscriptable).
        # We add a check to explicitly handle the None case, preventing the dereference.
        if account is None:
            # Raising an error is a suitable way to indicate that the requested account
            # was not found, preventing the subsequent access to a None object.
            # This maintains the function's implicit contract that a valid account
            # dict will be returned, or an error if it cannot be constructed.
            raise ValueError(f"Account with ID '{request.account_id}' not found.")

        return {
            "email": account["email"],
            "role": account["role"],
        }
