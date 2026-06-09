import asyncio

connection_lock = asyncio.Lock()

async def refresh_connection(connection_id: str) -> bool:
    await connection_lock.acquire()
    connection = await connection_repository.find(connection_id)
    if connection is None:
        return False
    await connection.refresh()
    connection_lock.release()
    return True
