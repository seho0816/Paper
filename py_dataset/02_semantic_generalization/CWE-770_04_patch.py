import asyncio


MAX_BATCH_SIZE = 1000


async def run_batch(
    requested_count: int,
) -> list[object]:
    effective_count = min(requested_count, MAX_BATCH_SIZE)

    tasks = [
        asyncio.create_task(
            process_item(index)
        )
        for index in range(effective_count)
    ]

    return await asyncio.gather(
        *tasks,
    )
