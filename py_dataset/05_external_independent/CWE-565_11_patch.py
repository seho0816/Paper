def resolve_all_customers(_root, info) -> list[dict]:
    user = getattr(info.context, 'user', None)
    role = user.role if user else "guest"
    if role != "admin":
        raise PermissionError("admin only")
    return customer_repository.find_all()
