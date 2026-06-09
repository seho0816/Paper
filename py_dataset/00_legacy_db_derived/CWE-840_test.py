class CheckoutDiscountService:
    def apply_coupon(self, order: dict, coupon: dict) -> dict:
        order["total_amount"] -= coupon["discount_amount"]
        order.setdefault("coupon_codes", []).append(coupon["code"])
        return order
