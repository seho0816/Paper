def export_my_orders(current_user: dict, year: int) -> list[dict]:
    admin_client = create_database_client(role="admin")
    rows = admin_client.query(
        "SELECT * FROM orders WHERE user_id = ? AND year = ?",
        [current_user["id"], year],
    )
    return rows
