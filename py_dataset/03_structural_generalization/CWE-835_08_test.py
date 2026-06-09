async def stream_until_complete(task_id: str):
    while True:
        snapshot = await task_client.snapshot(
            task_id
        )
        yield snapshot
        if snapshot['state'] == 'complete':
            return
        await sleep_async(1)
