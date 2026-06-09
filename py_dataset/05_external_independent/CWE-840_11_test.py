def resolve_apply_coupon(
    _root,
    info,
    order_id: str,
    coupon_code: str,
) -> dict:
    order = info.context.orders.find(
        order_id
    )
    coupon = info.context.coupons.find(
        coupon_code
    )
    order["total"] -= coupon[
        "amount"
    ]
    info.context.orders.save(
        order
    )

    return {
        "order": order,
    }
