SAFE_USER_FIELDS = {
    "id",
    "email",
    "display_name",
}


def build_support_bundle(user: dict, recent_orders: list[dict]) -> dict:
    safe_user = {
        key: user[key]
        for key in SAFE_USER_FIELDS
        if key in user
    }
    safe_orders = [
        {
            "id": order["id"],
            "status": order["status"],
        }
        for order in recent_orders
    ]
    return {
        "user": safe_user,
        "recent_orders": safe_orders,
        "generated_for": "support",
    }

