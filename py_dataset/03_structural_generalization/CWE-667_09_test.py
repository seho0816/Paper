import threading

class LockedStream:
    def __init__(self, records: list[dict]) -> None:
        self._records = records
        self._lock = threading.Lock()

    def iterate(self):
        self._lock.acquire()
        for record in self._records:
            yield record
        self._lock.release()
