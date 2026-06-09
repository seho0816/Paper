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

    # CWE-840 fix: Business Logic Errors
    # 1. Ensure the order actually exists. If the order is not found (e.g., None or empty dict),
    #    the coupon cannot be applied. Returning {"order": None} indicates the order was not found
    #    without crashing the application.
    if not order:
        return {"order": None}

    # 2. Ensure the coupon actually exists and has a valid positive amount.
    #    If the coupon is not found, or if it doesn't have an 'amount' key,
    #    or if the 'amount' is non-positive (zero or negative), it indicates an invalid
    #    coupon for application according to typical business rules.
    #    A negative 'amount' would effectively increase the order total, which is a severe
    #    business logic flaw. A zero 'amount' implies no discount, making the application pointless.
    #    In such cases, the coupon application should fail, and the original (unmodified) order
    #    should be returned to indicate no change.
    if not coupon or "amount" not in coupon or coupon["amount"] <= 0:
        return {"order": order}

    # If all business logic checks pass, apply the coupon.
    order["total"] -= coupon["amount"]
    info.context.orders.save(
        order
    )

    return {
        "order": order,
    }
