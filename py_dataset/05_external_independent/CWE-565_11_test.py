def resolve_all_customers(_root, info) -> list[dict]:
    role = info.context.cookies.get("role", "guest")
    if role != "admin":
        raise PermissionError("admin only")
    return customer_repository.find_all()
