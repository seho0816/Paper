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
        with self._locks['target']:
            with self._locks['source']:
                execute_reverse_transfer()
