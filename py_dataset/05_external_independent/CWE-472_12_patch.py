def calculate_invoice(query: dict[str, str], lines: list[dict]) -> int:
    rate = 0.0
    # Safely get 'tax_rate' from query. If the key is missing, .get() returns None.
    # If present, attempt to convert to float. Handle ValueError/TypeError for malformed data.
    tax_rate_value = query.get("tax_rate")
    if tax_rate_value is not None:
        try:
            rate = float(tax_rate_value)
        except (ValueError, TypeError):
            # Default to 0.0 if the provided tax_rate is not a valid float string or type.
            rate = 0.0
    # If tax_rate_value was None (key missing), rate remains 0.0, preventing KeyError.

    subtotal = 0
    for line in lines:
        amount = 0
        # Safely get 'amount' from each line dictionary. If the key is missing, .get() returns None.
        # If present, attempt to convert to int. Handle ValueError/TypeError for malformed data.
        amount_value = line.get("amount")
        if amount_value is not None:
            try:
                amount = int(amount_value)
            except (ValueError, TypeError):
                # Default to 0 if the provided amount is not a valid integer string or type.
                amount = 0
        # If amount_value was None (key missing), amount for this line remains 0, preventing KeyError.
        subtotal += amount

    # With rate and subtotal now guaranteed to be finite numbers (0 in case of parsing errors or missing data),
    # their product will also be a finite number, and int() conversion will not raise errors.
    tax = int(subtotal * rate)
    return subtotal + tax
