def apply_coupon(
    order: dict,
    coupon: dict,
) -> dict:
    applied_coupons = order.setdefault("applied_coupons", [])
    coupon_code = coupon["code"]
    coupon_amount = coupon["amount"]

    # CWE-840 Fix 1: Prevent applying the same coupon code multiple times to the same order.
    # This prevents over-discounting due to repeated application of the same coupon.
    if coupon_code in applied_coupons:
        return order

    # CWE-840 Fix 2: Ensure coupon amount is positive (a discount, not a surcharge).
    # A negative coupon amount would improperly increase the order total,
    # which is a business logic error for a discount coupon.
    # A zero-amount coupon provides no discount, so it shouldn't alter the total.
    if coupon_amount <= 0:
        return order

    # Calculate the new total after discount.
    new_total = order["total"] - coupon_amount

    # CWE-840 Fix 3: Ensure the order total does not drop below zero.
    # Allowing a negative total could lead to unintended credits or financial discrepancies,
    # which is a common business logic error for order processing.
    if new_total < 0:
        order["total"] = 0
    else:
        order["total"] = new_total

    # Record the coupon as applied only if it passed all business logic checks.
    applied_coupons.append(coupon_code)

    return order
