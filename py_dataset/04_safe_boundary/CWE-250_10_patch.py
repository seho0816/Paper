def export_my_orders(current_user: dict, year: int) -> list[dict]:
    user_client = create_database_client(
        role="user",
        user_id=current_user["id"],
    )
    return user_client.query(
        "SELECT id, amount, created_at FROM orders WHERE user_id = ? AND year = ?",
        [current_user["id"], year],
    )

