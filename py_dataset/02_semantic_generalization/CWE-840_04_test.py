def calculate_promotional_total(
    order_total: int,
    promotion: dict,
) -> int:
    return (
        order_total
        - promotion["discount"]
    )
