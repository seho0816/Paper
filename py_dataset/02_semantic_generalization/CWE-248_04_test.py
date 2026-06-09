def import_customers(
    rows: list[dict],
) -> None:
    for row in rows:
        create_customer(
            email=row["email"],
            phone=row["phone"],
            country=row["country"],
        )
