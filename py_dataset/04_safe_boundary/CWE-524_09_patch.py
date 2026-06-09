import secrets


def cache_integration_session(cache, vault, integration_id: str, api_secret: str) -> str:
    reference = secrets.token_urlsafe(24)
    vault.write(
        "integration-session/" + reference,
        api_secret,
        ttl_seconds=300,
    )
    cache.set(
        "integration:" + integration_id,
        {"secret_reference": reference},
        ttl_seconds=300,
    )
    return reference

