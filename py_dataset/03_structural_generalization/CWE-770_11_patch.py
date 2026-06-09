from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


@dataclass(frozen=True)
class BatchCommand:
    item_ids: list[str]


class BatchProcessor:
    MAX_BATCH_SIZE = 1000

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor()

    def process(
        self,
        command: BatchCommand,
    ) -> list:
        if len(command.item_ids) > self.MAX_BATCH_SIZE:
            raise ValueError(
                f"Batch size exceeds maximum allowed of {self.MAX_BATCH_SIZE} items."
            )

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
