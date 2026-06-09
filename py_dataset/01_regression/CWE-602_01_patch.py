def calculate_checkout(payload: dict) -> int:
    subtotal = 0
    discount_rate = 0.0

    # Safely retrieve and convert 'subtotal'
    # This prevents KeyError if 'subtotal' is missing and ValueError/TypeError if it's malformed.
    # The default value of 0 is used for safety and to prevent application crashes.
    subtotal_input = payload.get('subtotal')
    if subtotal_input is not None:
        try:
            subtotal = int(subtotal_input)
        except (ValueError, TypeError):
            # If conversion fails, subtotal remains its safe default of 0.
            pass

    # Safely retrieve and convert 'discount_rate'
    # This prevents KeyError if 'discount_rate' is missing and ValueError/TypeError if it's malformed.
    # The default value of 0.0 is used for safety and to prevent application crashes.
    discount_rate_input = payload.get('discount_rate')
    if discount_rate_input is not None:
        try:
            discount_rate = float(discount_rate_input)
        except (ValueError, TypeError):
            # If conversion fails, discount_rate remains its safe default of 0.0.
            pass

    # Apply robust input validation for business logic and security.
    # This prevents negative subtotals or discount rates outside a sensible range (0-1).
    # Such validation is crucial for financial calculations to prevent manipulation
    # or unexpected results, which falls under CWE-20 (Improper Input Validation)
    # and indirectly prevents issues like audit log inconsistencies if calculations fail.
    subtotal = max(0, subtotal)  # Ensure subtotal is not negative
    discount_rate = max(0.0, min(1.0, discount_rate))  # Clamp discount rate between 0% and 100%

    return int(subtotal * (1 - discount_rate))
