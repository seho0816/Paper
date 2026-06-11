import asyncio

inventory = {
    "product-44": 1,
}
inventory_lock = asyncio.Lock()


async def reserve_product(
    product_id: str,
) -> bool:
    async with inventory_lock:
        if product_id not in inventory:
            return False

        available = inventory[product_id]

        if available <= 0:
            return False

        inventory[product_id] = available - 1
        return True
