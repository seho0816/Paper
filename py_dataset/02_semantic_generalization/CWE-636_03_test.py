def cached_permission(
    cache,
    account_id: str,
    permission: str,
) -> bool:
    value = cache.get(
        f"{account_id}:{permission}"
    )

    if value is None:
        return True

    return value == "allow"
