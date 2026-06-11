def import_rows(
    rows: list[dict],
) -> None:
    for row in rows:
        try:
            quantity = int(
                row["quantity"]
            )
            sku = row["sku"] # Accessing 'sku' can also raise KeyError
            save_inventory(
                sku, # Use the safely accessed sku
                quantity,
            )
        except (KeyError, ValueError):
            # An uncaught exception (CWE-248) would occur if 'quantity' or 'sku'
            # keys are missing, or if 'quantity' cannot be converted to an int.
            # Catching these specific exceptions prevents the program from crashing
            # and allows processing of subsequent rows to continue.
            # In a real-world scenario, proper error logging or alternative
            # handling (e.g., returning a list of failed rows) would be added here.
            pass
