import asyncio
from dataclasses import dataclass


@dataclass(frozen=True)
class BatchRequest:
    messages: list[dict]


class MessageBatchService:
    async def process(
        self,
        request: BatchRequest,
    ) -> list[object]:
        tasks = [
            asyncio.create_task(
                deliver_message(
                    message
                )
            )
            for message in request.messages
        ]

        return await asyncio.gather(
            *tasks,
        )
