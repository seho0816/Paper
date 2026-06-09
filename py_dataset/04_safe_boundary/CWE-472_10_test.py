def apply_coupon(cart_id: str, coupon_code: str, actor_id: str) -> int:
    cart = load_cart_for_owner(cart_id, actor_id)
    coupon = coupon_repository.find_active(coupon_code)
    if coupon is None:
        raise ValueError("invalid coupon")
    subtotal = sum(item.unit_price * item.quantity for item in cart.items)
    discount = coupon.calculate_discount(subtotal, actor_id)
    return max(0, subtotal - discount)
