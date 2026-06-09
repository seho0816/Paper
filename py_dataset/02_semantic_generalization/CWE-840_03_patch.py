import datetime

def apply_expiring_coupon(
    order_total: int,
    coupon: dict,
) -> int:
    # CWE-840: Business Logic Error - Missing check for coupon expiry.
    # The function name 'apply_expiring_coupon' implies a check for expiration.
    # We assume 'coupon' dict might contain an 'expiry_date' key as a datetime object.
    if "expiry_date" in coupon and isinstance(coupon["expiry_date"], datetime.datetime):
        if coupon["expiry_date"] < datetime.datetime.now():
            # Coupon is expired, do not apply it. Return the original order total.
            return order_total
    
    # If the coupon is not expired (or no expiry date is provided), apply the discount.
    return max(
        0,
        order_total
        - coupon["amount"],
    )
