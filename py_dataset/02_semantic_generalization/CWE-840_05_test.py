def apply_order_coupon(
    order: dict,
    coupon: dict,
) -> None:
    order["total"] = max(
        0,
        order["total"]
        - coupon["amount"],
    )
