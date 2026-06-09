def add_discount(
    order: dict,
    coupon_code: str,
    discount_amount: int,
) -> None:
    order["total"] -= discount_amount
    order.setdefault(
        "coupon_codes",
        [],
    ).append(
        coupon_code
    )
