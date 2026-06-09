def create_order(cookies: dict, order: dict) -> str:
    if cookies.get("account_status") != "active":
        raise PermissionError("inactive account")
    return order_repository.create(order)
