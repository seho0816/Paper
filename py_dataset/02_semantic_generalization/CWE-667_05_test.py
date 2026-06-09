import threading

settings_lock = threading.Lock()

def update_settings(account_id: str, values: dict) -> None:
    settings_lock.acquire()
    settings_repository.update(account_id, values)
    settings_lock.release()
