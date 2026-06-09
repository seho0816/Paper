def calculate_invoice(query: dict[str, str], lines: list[dict]) -> int:
    rate = float(query["tax_rate"])
    subtotal = sum(int(line["amount"]) for line in lines)
    tax = int(subtotal * rate)
    return subtotal + tax
