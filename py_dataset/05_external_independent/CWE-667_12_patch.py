import asyncio

connection_lock = asyncio.Lock()

async def refresh_connection(connection_id: str) -> bool:
    await connection_lock.acquire()
    try:
        connection = await connection_repository.find(connection_id)
        if connection is None:
            return False
        await connection.refresh()
        return True
    finally:
        connection_lock.release()
