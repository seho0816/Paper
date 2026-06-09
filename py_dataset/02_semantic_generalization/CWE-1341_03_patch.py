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
    # The semaphore is automatically released by the 'async with' context manager
    # upon exiting the block, so an explicit release() here is redundant and
    # leads to an unintended extra release (CWE-1341).
    return response
