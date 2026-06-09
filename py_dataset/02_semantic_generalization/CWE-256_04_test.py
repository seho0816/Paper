def import_accounts(
    rows: list[dict],
) -> int:
    imported = 0

    for row in rows:
        user_repository.create({
            "username": row["username"],
            "password": row["password"],
        })
        imported += 1

    return imported
