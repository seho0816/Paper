from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


@dataclass(frozen=True)
class BatchCommand:
    item_ids: list[str]


class BatchProcessor:
    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor()

    def process(
        self,
        command: BatchCommand,
    ) -> list:
        futures = [
            self._executor.submit(
                process_item,
                item_id,
            )
            for item_id in command.item_ids
        ]

        return [
            future.result()
            for future in futures
        ]
