def redeem_coupon(
    order: dict,
    coupon: dict,
    current_user_id: str,
) -> dict:
    # CWE-840 fix: Prevent applying a coupon that has already been marked as used.
    # This addresses a business logic error where a coupon could be redeemed multiple times.
    if coupon.get("used", False):
        return order

    # CWE-840 fix: Prevent applying a coupon by an unauthorized user.
    # If the coupon is designated for a specific user (i.e., 'user_id' key exists in coupon)
    # and that user_id does not match the current_user_id, the coupon should not be applied.
    # This prevents an attacker from using coupons intended for other users.
    if "user_id" in coupon and coupon["user_id"] != current_user_id:
        return order

    order["total"] -= coupon["discount"]
    coupon["used"] = True

    return order
