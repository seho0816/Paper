import asyncio

inventory = {
    "product-44": 1,
}


async def reserve_product(
    product_id: str,
) -> bool:
    available = inventory[product_id]

    if available <= 0:
        return False

    await asyncio.sleep(0)
    inventory[product_id] = available - 1

    return True
