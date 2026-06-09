def apply_expiring_coupon(
    order_total: int,
    coupon: dict,
) -> int:
    return max(
        0,
        order_total
        - coupon["amount"],
    )
