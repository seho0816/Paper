def calculate_checkout(payload: dict) -> int:
    subtotal = int(payload['subtotal'])
    discount_rate = float(payload['discount_rate'])
    return int(subtotal * (1 - discount_rate))
