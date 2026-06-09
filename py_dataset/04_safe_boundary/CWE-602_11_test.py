def calculate_discount(account_id: str, coupon_code: str, subtotal: int) -> int:
    coupon = coupon_repository.find_valid_for_account(coupon_code, account_id)
    if coupon is None:
        return subtotal
    discount = pricing_policy.discount_amount(coupon, subtotal)
    return subtotal - discount
