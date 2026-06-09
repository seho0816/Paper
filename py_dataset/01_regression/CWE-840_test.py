def apply_coupon(
    order: dict,
    coupon: dict,
) -> dict:
    order["total"] = (
        order["total"]
        - coupon["amount"]
    )
    order.setdefault(
        "applied_coupons",
        [],
    ).append(
        coupon["code"]
    )

    return order
