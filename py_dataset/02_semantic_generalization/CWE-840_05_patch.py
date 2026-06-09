def apply_order_coupon(
    order: dict,
    coupon: dict,
) -> None:
    # CWE-840: Business Logic Error - Ensure coupon amount does not increase the order total.
    # A negative coupon amount would otherwise increase the total.
    # We ensure that the effective discount is always non-negative.
    effective_discount = max(0, coupon["amount"])
    order["total"] = max(
        0,
        order["total"] - effective_discount,
    )
