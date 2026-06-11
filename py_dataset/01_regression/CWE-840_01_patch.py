def add_discount(
    order: dict,
    coupon_code: str,
    discount_amount: int,
) -> None:
    # CWE-840: Business Logic Errors: Accessing Non-existent Object
    # Ensure 'total' key exists before attempting to subtract from it.
    # If 'total' is not present, it will be initialized to 0, which is a common
    # and safe default for a monetary total before any items are added or calculations made.
    order.setdefault("total", 0)
    order["total"] -= discount_amount
    order.setdefault(
        "coupon_codes",
        [],
    ).append(
        coupon_code
    )
