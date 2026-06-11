from decimal import Decimal

def discounted_total(form: dict[str, str]) -> Decimal:
    subtotal = Decimal(form["subtotal"])
    discount = Decimal(form["discount_rate"])

    # CWE-472 fix: Validate and sanitize the discount_rate to prevent external control
    # leading to an unexpected total. An attacker could provide a negative discount rate
    # to increase the total (markup) or a discount rate greater than 1 (100%) to
    # potentially make the total negative.
    # We cap the discount rate between 0 (no discount/markup) and 1 (100% discount).
    discount = max(Decimal("0"), min(Decimal("1"), discount))

    amount = subtotal - (subtotal * discount)
    return amount.quantize(Decimal("0.01"))

def submit_coupon_order(form: dict[str, str]) -> dict:
    return {"amount": str(discounted_total(form)), "status": "ready"}
