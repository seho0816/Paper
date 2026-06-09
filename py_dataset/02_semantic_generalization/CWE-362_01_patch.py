import asyncio

inventory = {
    "product-44": 1,
}

# CWE-362 Fix: Introduce an asyncio.Lock to protect the shared 'inventory' resource
# from concurrent modifications, preventing race conditions.
inventory_lock = asyncio.Lock()


async def reserve_product(
    product_id: str,
) -> bool:
    # Acquire the lock before entering the critical section (reading and writing to inventory)
    # The 'async with' statement ensures the lock is acquired and then properly released
    # even if an exception occurs or the coroutine yields.
    async with inventory_lock:
        # The original code would raise a KeyError if product_id is not in inventory.
        # This behavior is maintained.
        available = inventory[product_id]

        if available <= 0:
            return False

        # Even with asyncio.sleep(0), the lock prevents other coroutines from
        # simultaneously modifying 'inventory[product_id]' until this critical section completes.
        await asyncio.sleep(0)
        inventory[product_id] = available - 1

        return True
