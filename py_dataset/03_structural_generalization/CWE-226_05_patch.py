class ResponsePool:
    def __init__(self) -> None:
        self._items: list[dict] = []

    def acquire(self) -> dict:
        if self._items:
            item = self._items.pop()
            item.clear()  # CWE-226: Clear existing data to prevent information leakage upon reuse
            return item
        return {}


class ProfileResponseService:
    def __init__(self, pool: ResponsePool) -> None:
        self._pool = pool

    def build(self, account: dict) -> dict:
        response = self._pool.acquire()
        response["account_id"] = account["id"]
        response["display_name"] = account["display_name"]
        return response
