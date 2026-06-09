import asyncio


request_slots = asyncio.Semaphore(
    8
)


async def handle_request(
    request: dict,
) -> dict:
    async with request_slots:
        response = await process_request(
            request
        )
    request_slots.release()
    return response
