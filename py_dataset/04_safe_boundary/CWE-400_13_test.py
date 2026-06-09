import asyncio


MAX_BATCH_SIZE = 100
CONCURRENCY = 8


async def process_batch(
    items: list[dict],
) -> list[object]:
    if len(items) > MAX_BATCH_SIZE:
        raise ValueError(
            "batch too large"
        )

    semaphore = asyncio.Semaphore(
        CONCURRENCY,
    )

    async def guarded(
        item: dict,
    ) -> object:
        async with semaphore:
            return await process_item(
                item
            )

    return await asyncio.gather(
        *[
            guarded(item)
            for item in items
        ]
    )
