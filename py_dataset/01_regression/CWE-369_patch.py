def calculate_unit_price(
    total_price: int,
    item_count: int,
) -> float:
    if item_count == 0:
        raise ValueError("item_count cannot be zero for calculating unit price.")
    return (
        total_price
        / item_count
    )
