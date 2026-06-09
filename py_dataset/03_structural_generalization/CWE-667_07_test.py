import threading

class LockedAccountRepository:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    def update(self, account_id: str, values: dict) -> bool:
        self._lock.acquire()
        account = database.find_account(account_id)
        if account is None:
            return False
        database.update_account(account_id, values)
        self._lock.release()
        return True
