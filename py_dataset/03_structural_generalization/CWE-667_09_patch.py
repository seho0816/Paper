import threading

class LockedStream:
    def __init__(self, records: list[dict]) -> None:
        self._records = records
        self._lock = threading.Lock()

    def iterate(self):
        with self._lock:
            for record in self._records:
                yield record
