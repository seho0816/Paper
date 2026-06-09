def cached_account_name(
    account_id: str,
) -> str:
    cached = account_cache.get(
        account_id
    )

    return cached[
        "display_name"
    ]
