def cache_integration(memcache, integration_id: str, api_secret: str) -> None:
    memcache.set(
        "integration:" + integration_id,
        {
            "api_secret": api_secret,
            "enabled": True,
        },
        expire=600,
    )
