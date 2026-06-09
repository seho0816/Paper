import asyncio


async def run_batch(
    requested_count: int,
) -> list[object]:
    tasks = [
        asyncio.create_task(
            process_item(index)
        )
        for index in range(requested_count)
    ]

    return await asyncio.gather(
        *tasks,
    )
