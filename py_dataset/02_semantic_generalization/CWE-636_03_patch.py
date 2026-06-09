def cached_permission(
    cache,
    account_id: str,
    permission: str,
) -> bool:
    value = cache.get(
        f"{account_id}:{permission}"
    )

    if value is None:
        # CWE-636: Incorrect Handling of Unusual Conditions.
        # If a permission is not found in the cache, the default secure behavior
        # should be to deny access ("fail-safe" or "deny by default"),
        # rather than implicitly granting it.
        return False

    return value == "allow"
