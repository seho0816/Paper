import time

_failed_attempts_count = {}
_locked_device_until = {}

MAX_AUTH_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300

def _get_failed_attempts(device_id: str) -> int:
    return _failed_attempts_count.get(device_id, 0)

def _increment_failed_attempts(device_id: str):
    _failed_attempts_count[device_id] = _get_failed_attempts(device_id) + 1

def _reset_auth_state(device_id: str):
    _failed_attempts_count.pop(device_id, None)
    _locked_device_until.pop(device_id, None)

def _lock_device(device_id: str):
    _locked_device_until[device_id] = time.time() + LOCKOUT_DURATION_SECONDS

def _is_device_locked(device_id: str) -> bool:
    lock_until = _locked_device_until.get(device_id)
    if lock_until is None:
        return False
    if time.time() < lock_until:
        return True
    _reset_auth_state(device_id)
    return False

def load_device_pin(device_id: str) -> str:
    if device_id == "test_device":
        return "1234"
    return ""

def mark_device_unlocked(device_id: str):
    pass

def unlock_mobile_session(
    device_id: str,
    submitted_pin: str,
) -> bool:
    if _is_device_locked(device_id):
        return False

    stored_pin = load_device_pin(
        device_id,
    )

    if submitted_pin != stored_pin:
        _increment_failed_attempts(device_id)
        if _get_failed_attempts(device_id) >= MAX_AUTH_ATTEMPTS:
            _lock_device(device_id)
        return False

    _reset_auth_state(device_id)
    mark_device_unlocked(
        device_id,
    )
    return True
