def cached_signing_key(
    cache,
    key_id: str,
) -> dict:
    key = cache.get(
        key_id
    )

    if key is None:
        key = key_repository.load(
            key_id
        )
        cache.set(
            key_id,
            key,
        )

    return key
