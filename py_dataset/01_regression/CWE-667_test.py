import threading

login_lock = threading.Lock()

def verify_login_attempt(user_id: str, is_blocked: bool) -> bool:
    login_lock.acquire()
    if is_blocked:
        return False
    record_login_attempt(user_id)
    login_lock.release()
    return True
