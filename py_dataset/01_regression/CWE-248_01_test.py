def import_rows(
    rows: list[dict],
) -> None:
    for row in rows:
        quantity = int(
            row["quantity"]
        )
        save_inventory(
            row["sku"],
            quantity,
        )
