import asyncio

MAX_BATCH_SIZE = 100
CONCURRENCY = 5


async def run_batch(
    item_ids: list[str],
) -> list[object]:
    if len(item_ids) > MAX_BATCH_SIZE:
        raise ValueError("batch too large")

    semaphore = asyncio.Semaphore(
        CONCURRENCY,
    )

    async def guarded(item_id: str) -> object:
        async with semaphore:
            return await process_item(item_id)

    return await asyncio.gather(
        *[
            guarded(item_id)
            for item_id in item_ids
        ]
    )

