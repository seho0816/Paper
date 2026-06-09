class ResponsePool:
    def __init__(self) -> None:
        self._items: list[dict] = []

    def acquire(self) -> dict:
        if self._items:
            return self._items.pop()
        return {}


class ProfileResponseService:
    def __init__(self, pool: ResponsePool) -> None:
        self._pool = pool

    def build(self, account: dict) -> dict:
        response = self._pool.acquire()
        response["account_id"] = account["id"]
        response["display_name"] = account["display_name"]
        return response
