def export_my_orders(current_user: dict, year: int) -> list[dict]:
    # CWE-250: root나 admin 권한을 피하고, 제한된 권한(user)의 DB 클라이언트 사용
    user_client = create_database_client(role="user")
    
    rows = user_client.query(
        "SELECT * FROM orders WHERE user_id = ? AND year = ?",
        [current_user["id"], year],
    )
    return rows