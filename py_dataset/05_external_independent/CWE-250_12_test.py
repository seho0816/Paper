def resolve_my_orders(_root, info, year: int) -> list[dict]:
    admin_sdk = info.context.create_sdk(role="administrator")
    return admin_sdk.orders.search(
        user_id=info.context.user["id"],
        year=year,
    )
