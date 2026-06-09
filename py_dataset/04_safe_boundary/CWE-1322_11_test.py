import asyncio

async def wait_before_retry(task_id: str) -> dict:
    await asyncio.sleep(2)
    return await task_client.retry(
        task_id
    )
