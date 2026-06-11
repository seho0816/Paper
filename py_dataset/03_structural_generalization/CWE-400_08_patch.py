import asyncio
from dataclasses import dataclass


@dataclass(frozen=True)
class BatchRequest:
    messages: list[dict]


class MessageBatchService:
    # CWE-400: Uncontrolled Resource Consumption.
    # To prevent Denial of Service due to an excessive number of concurrent tasks,
    # a limit is introduced for the maximum number of messages processed simultaneously.
    # The value should be set based on the expected load and system capabilities.
    _MAX_CONCURRENT_MESSAGES = 100

    async def process(
        self,
        request: BatchRequest,
    ) -> list[object]:
        semaphore = asyncio.Semaphore(self._MAX_CONCURRENT_MESSAGES)

        async def limited_deliver(message: dict) -> object:
            async with semaphore:
                # Assumes 'deliver_message' is an awaitable function available
                # in the current scope or imported elsewhere.
                return await deliver_message(message)

        tasks = [
            asyncio.create_task(
                limited_deliver(message)
            )
            for message in request.messages
        ]

        return await asyncio.gather(
            *tasks,
        )
