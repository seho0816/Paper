def calculate_promotional_total(
    order_total: int,
    promotion: dict,
) -> int:
    return max(
        0,
        order_total - promotion["discount"]
    )
