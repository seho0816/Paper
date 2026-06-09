from decimal import Decimal

def discounted_total(form: dict[str, str]) -> Decimal:
    subtotal = Decimal(form["subtotal"])
    discount = Decimal(form["discount_rate"])
    amount = subtotal - (subtotal * discount)
    return amount.quantize(Decimal("0.01"))

def submit_coupon_order(form: dict[str, str]) -> dict:
    return {"amount": str(discounted_total(form)), "status": "ready"}
