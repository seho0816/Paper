def import_customers(
    rows: list[dict],
) -> None:
    for row in rows:
        try:
            create_customer(
                email=row["email"],
                phone=row["phone"],
                country=row["country"],
            )
        except Exception as e:
            print(f"Failed to import customer from row: {row}. Error: {e}")
