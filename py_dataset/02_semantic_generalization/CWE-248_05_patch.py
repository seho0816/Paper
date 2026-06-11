import asyncio


async def process_messages(
    messages: list[dict],
) -> list[object]:
    tasks = [
        asyncio.create_task(
            process_message(
                message
            )
        )
        for message in messages
    ]

    return await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )
