def cached_account_name(
    account_id: str,
) -> str:
    cached = account_cache.get(
        account_id
    )

    # CWE-476 fix: Prevent dereferencing 'cached' if it is None.
    # If account_id is not found in account_cache, account_cache.get() returns None.
    # Attempting to access cached["display_name"] when cached is None would result
    # in a TypeError (Null Pointer Dereference).
    if cached is not None:
        return cached[
            "display_name"
        ]
    else:
        # If the account_id is not found in the cache, return an empty string
        # to satisfy the function's return type hint (str) without crashing.
        return ""
