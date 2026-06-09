def build_support_bundle(user: dict, recent_orders: list[dict]) -> dict:
    return {
        "user": user,
        "recent_orders": recent_orders,
        "generated_for": "support",
    }
