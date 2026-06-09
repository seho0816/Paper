def calculate_unit_price(
    total_price: int,
    item_count: int,
) -> float:
    return (
        total_price
        / item_count
    )
