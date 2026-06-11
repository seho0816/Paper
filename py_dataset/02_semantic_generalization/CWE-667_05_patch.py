import threading

settings_lock = threading.Lock()

def update_settings(account_id: str, values: dict) -> None:
    with settings_lock:
        settings_repository.update(account_id, values)
