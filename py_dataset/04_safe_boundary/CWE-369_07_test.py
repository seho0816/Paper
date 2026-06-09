def calculate_unit_price(
    total_price: int,
    item_count: int,
) -> float:
    if item_count <= 0:
        raise ValueError(
            "item_count must be positive"
        )

    return (
        total_price
        / item_count
    )
