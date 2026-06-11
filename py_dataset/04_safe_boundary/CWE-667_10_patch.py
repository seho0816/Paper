import threading

login_lock = threading.Lock()

def verify_login_attempt(user_id: str, is_blocked: bool) -> bool:
    with login_lock:
        if is_blocked:
            return False
        record_login_attempt(user_id)
        return True

