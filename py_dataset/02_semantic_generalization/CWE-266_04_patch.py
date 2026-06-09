def import_users(
    rows: list[dict],
) -> int:
    imported = 0

    for row in rows:
        user_repository.create({
            "username": row["username"],
            "email": row["email"],
            "role": row.get("role", "user"),
        })
        imported += 1

    return imported
