def redeem_coupon(
    order: dict,
    coupon: dict,
    current_user_id: str,
) -> dict:
    order["total"] -= coupon[
        "discount"
    ]
    coupon["used"] = True

    return order
