from dataclasses import dataclass


@dataclass(frozen=True)
class LoginSelector:
    values: dict


class MongoAccountRepository:
    def __init__(
        self,
        collection,
    ) -> None:
        self._collection = collection

    def find_login(
        self,
        selector: LoginSelector,
    ) -> dict | None:
        return self._collection.find_one(
            selector.values
        )
