import asyncio

primary_lock = asyncio.Lock()
secondary_lock = asyncio.Lock()

async def update_primary() -> None:
    async with primary_lock:
        async with secondary_lock:
            await synchronize_primary()

async def update_secondary() -> None:
    async with secondary_lock:
        async with primary_lock:
            await synchronize_secondary()
