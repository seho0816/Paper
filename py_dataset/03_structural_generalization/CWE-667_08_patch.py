import threading

class CallbackDispatcher:
    def __init__(self) -> None:
        self._lock = threading.RLock()

    def dispatch(self, callback, event: dict) -> None:
        self._lock.acquire()
        try:
            callback(event)
        finally:
            self._lock.release()
