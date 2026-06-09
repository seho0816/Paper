def cache_integration(memcache, integration_id: str, api_secret: str) -> None:
    memcache.set(
        "integration:" + integration_id,
        {
            "enabled": True,
        },
        expire=600,
    )
