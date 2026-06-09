class CheckoutDiscountService:
    def apply_coupon(self, order: dict, coupon: dict) -> dict:
        # CWE-840: Business Logic Error - Discount could potentially make total_amount negative.
        # To prevent the total amount from dropping below zero, the discount applied
        # should be capped at the current total_amount.
        
        current_total = order["total_amount"]
        discount_amount = coupon["discount_amount"]

        # Ensure the discount_amount is non-negative. A discount should not increase the total amount.
        # This also guards against malicious or erroneous negative discount values.
        effective_discount = max(0, discount_amount)

        # Only apply a discount if the current total is positive.
        # Applying a discount to a zero or negative total typically implies incorrect business logic.
        if current_total > 0:
            # The actual amount to deduct is the lesser of the effective discount
            # and the current positive total, ensuring the total_amount does not go below zero.
            actual_deduction = min(effective_discount, current_total)
            order["total_amount"] -= actual_deduction
        # If current_total is 0 or negative, no discount is applied to total_amount.

        order.setdefault("coupon_codes", []).append(coupon["code"])
        return order
