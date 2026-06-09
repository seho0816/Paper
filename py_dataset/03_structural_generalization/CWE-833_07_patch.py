import threading

class TransferService:
    def __init__(self) -> None:
        self._locks = {
            'source': threading.Lock(),
            'target': threading.Lock(),
        }

    def forward(self) -> None:
        with self._locks['source']:
            with self._locks['target']:
                execute_forward_transfer()

    def reverse(self) -> None:
        # To prevent deadlock (CWE-833), ensure a consistent lock acquisition order.
        # Both forward and reverse methods now acquire 'source' lock first, then 'target' lock.
        with self._locks['source']:
            with self._locks['target']:
                execute_reverse_transfer()
